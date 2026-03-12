import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { loadServersFromFile } from '../loader/file-loader.js';
import type { Finding } from '../types.js';

const SNAPSHOT_DIR = join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.mcp-vet',
  'snapshots',
);

interface Snapshot {
  serverName: string;
  tools: Record<string, string>; // tool name → description hash
  timestamp: string;
}

function hashDescription(desc: string): string {
  return createHash('sha256').update(desc).digest('hex').substring(0, 16);
}

/**
 * Key snapshots by the resolved absolute file path (not server name).
 * This prevents a malicious server with the same name as a known-safe
 * server from overwriting its snapshot.
 */
function getSnapshotPath(targetFilePath: string): string {
  const absPath = resolve(targetFilePath);
  const pathHash = createHash('sha256').update(absPath).digest('hex').substring(0, 16);
  return join(SNAPSHOT_DIR, `${pathHash}.json`);
}

export function runDiff(targetPath: string): { findings: Finding[]; isFirstRun: boolean } {
  const servers = loadServersFromFile(targetPath);
  const server = servers[0]; // diff operates on the primary/first server
  const findings: Finding[] = [];

  if (!existsSync(SNAPSHOT_DIR)) {
    mkdirSync(SNAPSHOT_DIR, { recursive: true });
  }

  const snapshotPath = getSnapshotPath(targetPath);
  const currentTools: Record<string, string> = {};
  for (const tool of server.tools) {
    currentTools[tool.name] = hashDescription(tool.description);
  }

  if (!existsSync(snapshotPath)) {
    // First run — save snapshot
    const snapshot: Snapshot = {
      serverName: server.name,
      tools: currentTools,
      timestamp: new Date().toISOString(),
    };
    writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));
    return { findings, isFirstRun: true };
  }

  // Compare with existing snapshot
  const previousSnapshot: Snapshot = JSON.parse(readFileSync(snapshotPath, 'utf-8'));

  for (const [toolName, currentHash] of Object.entries(currentTools)) {
    const previousHash = previousSnapshot.tools[toolName];

    if (!previousHash) {
      // New tool added
      findings.push({
        id: 'TP-003',
        vector: 'TOOL_POISONING',
        severity: 'INFO',
        title: 'New Tool Added',
        description: `Tool "${toolName}" was added since last scan.`,
        toolName,
        evidence: `Tool not present in snapshot from ${previousSnapshot.timestamp}`,
        recommendation: 'Review the new tool to ensure it is legitimate.',
        confidence: 0.9,
      });
    } else if (previousHash !== currentHash) {
      // Description changed
      const tool = server.tools.find((t) => t.name === toolName);
      const desc = tool?.description || '';

      // Check if the change introduces PI-001 or PI-002 patterns (escalate to CRITICAL)
      const piPatterns = [
        /ignore\s+(all\s+)?(previous|prior|above|earlier)/i,
        /do\s+not\s+(mention|tell|reveal|disclose)/i,
        /<\s*(?:IMPORTANT|SYSTEM|instructions?)\s*>/i,
      ];
      const hasDangerousChange = piPatterns.some((p) => p.test(desc));

      findings.push({
        id: 'TP-003',
        vector: 'TOOL_POISONING',
        severity: hasDangerousChange ? 'CRITICAL' : 'INFO',
        title: 'Description Changed',
        description: `Tool "${toolName}" description changed since last scan.${hasDangerousChange ? ' New description contains injection patterns!' : ''}`,
        toolName,
        evidence: `Description hash changed from ${previousHash} to ${currentHash}`,
        recommendation: hasDangerousChange
          ? 'URGENT: Review the description change — it introduces injection patterns.'
          : 'Review the description change to ensure it is benign.',
        confidence: 0.9,
      });
    }
  }

  // Check for removed tools
  for (const toolName of Object.keys(previousSnapshot.tools)) {
    if (!currentTools[toolName]) {
      findings.push({
        id: 'TP-003',
        vector: 'TOOL_POISONING',
        severity: 'INFO',
        title: 'Tool Removed',
        description: `Tool "${toolName}" was removed since last scan.`,
        toolName,
        evidence: `Tool present in snapshot from ${previousSnapshot.timestamp} but not in current scan`,
        recommendation: 'Verify that tool removal was intentional.',
        confidence: 0.9,
      });
    }
  }

  // Update snapshot
  const snapshot: Snapshot = {
    serverName: server.name,
    tools: currentTools,
    timestamp: new Date().toISOString(),
  };
  writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));

  return { findings, isFirstRun: false };
}
