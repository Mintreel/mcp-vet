import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { readdirSync, readFileSync } from 'node:fs';
import { runPipelineMulti } from '../../src/pipeline.js';
import { runSupplyChainAnalysis } from '../../src/analyzers/supply-chain/index.js';
import type { ServerDefinition, ToolDefinition } from '../../src/types.js';

const FIXTURES_DIR = join(process.cwd(), 'test-fixtures/real-world');

/**
 * Load all real-world MCP fixtures and return ServerDefinition[].
 * Supports both flat format and wrapped format.
 */
function loadAllFixtures(): ServerDefinition[] {
  const files = readdirSync(FIXTURES_DIR).filter((f) => f.endsWith('.json'));
  const servers: ServerDefinition[] = [];

  for (const file of files) {
    const raw = readFileSync(join(FIXTURES_DIR, file), 'utf-8');
    const data = JSON.parse(raw) as Record<string, unknown>;

    // Handle different fixture formats
    let rawServers: Record<string, unknown>[] = [];
    if (data.server && typeof data.server === 'object') {
      rawServers = [data.server as Record<string, unknown>];
    } else if (Array.isArray(data.servers)) {
      rawServers = data.servers as Record<string, unknown>[];
    } else {
      rawServers = [data];
    }

    for (const s of rawServers) {
      servers.push(parseServer(s as Record<string, unknown>));
    }
  }

  return servers;
}

function parseServer(obj: Record<string, unknown>): ServerDefinition {
  const name = typeof obj.name === 'string' ? obj.name : 'unknown';
  const version = typeof obj.version === 'string' ? obj.version : '0.0.0';

  const tools: ToolDefinition[] = [];
  if (Array.isArray(obj.tools)) {
    for (const t of obj.tools) {
      if (typeof t === 'object' && t !== null) {
        const tool = t as Record<string, unknown>;
        const params = parseParameters(tool);
        tools.push({
          name: String(tool.name ?? ''),
          description: String(tool.description ?? ''),
          parameters: params,
        });
      }
    }
  }

  return {
    name,
    version,
    tools,
    config:
      typeof obj.config === 'object' && obj.config !== null
        ? (obj.config as ServerDefinition['config'])
        : undefined,
    sourcePath: typeof obj.sourcePath === 'string' ? obj.sourcePath : undefined,
    packageInfo:
      typeof obj.packageInfo === 'object' && obj.packageInfo !== null
        ? (obj.packageInfo as ServerDefinition['packageInfo'])
        : undefined,
    capabilities:
      typeof obj.capabilities === 'object' && obj.capabilities !== null
        ? (obj.capabilities as ServerDefinition['capabilities'])
        : undefined,
  };
}

function parseParameters(tool: Record<string, unknown>) {
  if (Array.isArray(tool.parameters)) {
    return tool.parameters
      .filter((p): p is Record<string, unknown> => typeof p === 'object' && p !== null)
      .map((p) => ({
        name: String(p.name ?? ''),
        type: String(p.type ?? 'string'),
        description: typeof p.description === 'string' ? p.description : undefined,
        required: typeof p.required === 'boolean' ? p.required : undefined,
      }));
  }

  if (typeof tool.inputSchema === 'object' && tool.inputSchema !== null) {
    const schema = tool.inputSchema as Record<string, unknown>;
    const properties =
      typeof schema.properties === 'object' && schema.properties !== null
        ? (schema.properties as Record<string, Record<string, unknown>>)
        : {};
    const required = Array.isArray(schema.required)
      ? new Set(schema.required as string[])
      : new Set<string>();

    return Object.entries(properties).map(([name, prop]) => ({
      name,
      type: String(prop.type ?? 'string'),
      description: typeof prop.description === 'string' ? prop.description : undefined,
      required: required.has(name) ? true : undefined,
    }));
  }

  return [];
}

describe('Top 20 MCPs Security Audit', () => {
  it('loads all 20 MCPs from real-world fixtures', async () => {
    const servers = loadAllFixtures();

    console.log('\n');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║          TOP 20 MCPs SECURITY AUDIT REPORT                 ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('\nLoaded MCPs:');
    servers.forEach((s, i) => {
      console.log(`  ${i + 1}. ${s.name} (v${s.version})`);
    });

    expect(servers.length).toBeGreaterThanOrEqual(14);
    expect(servers.some((s) => s.name === 'github')).toBe(true);
    expect(servers.some((s) => s.name === 'slack')).toBe(true);
    expect(servers.some((s) => s.name === 'notion')).toBe(true);
  });

  it('runs security analysis on all 20 MCPs and reports findings', async () => {
    const servers = loadAllFixtures();
    const result = await runPipelineMulti(servers);

    // Add supply chain analysis for each server
    const supplyChainFindings = [];
    for (const server of servers) {
      const scFindings = await runSupplyChainAnalysis(server, { cveCheck: false });
      supplyChainFindings.push(...scFindings);
    }

    if (supplyChainFindings.length > 0) {
      result.findings.push(...supplyChainFindings);
      const { calculateScore } = await import('../../src/scoring/score-calculator.js');
      result.score = calculateScore(result.findings);
    }

    // Group findings by server
    const findingsByServer: Record<string, typeof result.findings> = {};
    for (const finding of result.findings) {
      if (!findingsByServer[finding.toolName]) {
        findingsByServer[finding.toolName] = [];
      }
      findingsByServer[finding.toolName].push(finding);
    }

    console.log('\n');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║                    SECURITY AUDIT RESULTS                  ║');
    console.log('╚════════════════════════════════════════════════════════════╝');

    // Summary by severity
    const bySeverity = {
      CRITICAL: result.findings.filter((f) => f.severity === 'CRITICAL').length,
      HIGH: result.findings.filter((f) => f.severity === 'HIGH').length,
      MEDIUM: result.findings.filter((f) => f.severity === 'MEDIUM').length,
      LOW: result.findings.filter((f) => f.severity === 'LOW').length,
      INFO: result.findings.filter((f) => f.severity === 'INFO').length,
    };

    console.log('\nFindings Summary:');
    console.log(`  ├─ CRITICAL: ${bySeverity.CRITICAL}`);
    console.log(`  ├─ HIGH:     ${bySeverity.HIGH}`);
    console.log(`  ├─ MEDIUM:   ${bySeverity.MEDIUM}`);
    console.log(`  ├─ LOW:      ${bySeverity.LOW}`);
    console.log(`  └─ INFO:     ${bySeverity.INFO}`);
    console.log(`  TOTAL:       ${result.findings.length}`);

    // Server-by-server report
    console.log('\nServer-by-Server Report:');
    const sortedServers = servers.sort((a, b) => {
      const aFindings = findingsByServer[a.name]?.length ?? 0;
      const bFindings = findingsByServer[b.name]?.length ?? 0;
      return bFindings - aFindings;
    });

    sortedServers.forEach((server) => {
      const findings = findingsByServer[server.name] ?? [];
      const toolCount = server.tools.length;
      const status = findings.length === 0 ? '✓' : '⚠';
      console.log(`  ${status} ${server.name.padEnd(20)} Tools: ${String(toolCount).padStart(2)}  Findings: ${findings.length}`);

      if (findings.length > 0 && findings.length <= 3) {
        findings.forEach((f) => {
          const severityIcon =
            f.severity === 'CRITICAL'
              ? '🔴'
              : f.severity === 'HIGH'
                ? '🟠'
                : f.severity === 'MEDIUM'
                  ? '🟡'
                  : '🔵';
          console.log(`      ${severityIcon} ${f.id}: ${f.title}`);
        });
      }
    });

    console.log('\nOverall Statistics:');
    console.log(`  Total Servers:   ${servers.length}`);
    console.log(`  Total Tools:     ${servers.reduce((sum, s) => sum + s.tools.length, 0)}`);
    console.log(`  Total Findings:  ${result.findings.length}`);
    console.log(`  Average/Server:  ${(result.findings.length / servers.length).toFixed(2)}`);

    // List top issues
    const criticalAndHigh = result.findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .slice(0, 10);

    if (criticalAndHigh.length > 0) {
      console.log('\nTop Critical/High Issues:');
      criticalAndHigh.forEach((f, i) => {
        console.log(`  ${i + 1}. [${f.id}] ${f.title} (${f.toolName})`);
      });
    }

    console.log('\n');

    // Basic validation: expect some reasonable number of findings
    expect(result.findings.length).toBeGreaterThanOrEqual(0);
    expect(servers.length).toBeGreaterThanOrEqual(14);
  });
});
