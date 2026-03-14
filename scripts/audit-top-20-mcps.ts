#!/usr/bin/env node

/**
 * Audit Top 20 MCPs with mcp-vet
 *
 * This script runs mcp-vet against all 20 test fixture MCPs and generates
 * comprehensive reports including JSON, HTML, and terminal output.
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { runPipelineMulti } from '../src/pipeline.js';
import { runSupplyChainAnalysis } from '../src/analyzers/supply-chain/index.js';
import { generateHtmlReport } from '../src/reporters/html.js';
import type { ServerDefinition, ToolDefinition } from '../src/types.js';

const FIXTURES_DIR = join(process.cwd(), 'test-fixtures/real-world');
const OUTPUT_DIR = join(process.cwd(), 'audit-reports');

function loadAllFixtures(): ServerDefinition[] {
  const files = readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort();
  const servers: ServerDefinition[] = [];

  for (const file of files) {
    const raw = readFileSync(join(FIXTURES_DIR, file), 'utf-8');
    const data = JSON.parse(raw) as Record<string, unknown>;

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

async function main() {
  console.log('🔍 Loading all 20 MCPs from test fixtures...\n');
  const servers = loadAllFixtures();

  console.log(`✓ Loaded ${servers.length} MCPs:`);
  servers.forEach((s, i) => {
    console.log(`  ${String(i + 1).padStart(2)}. ${s.name.padEnd(22)} v${s.version} (${s.tools.length} tools)`);
  });

  console.log('\n🔐 Running security analysis...');
  const result = await runPipelineMulti(servers);

  // Add supply chain analysis
  const supplyChainFindings = [];
  for (const server of servers) {
    const scFindings = await runSupplyChainAnalysis(server, { cveCheck: false });
    supplyChainFindings.push(...scFindings);
  }

  if (supplyChainFindings.length > 0) {
    result.findings.push(...supplyChainFindings);
    const { calculateScore } = await import('../src/scoring/score-calculator.js');
    result.score = calculateScore(result.findings);
  }

  // Create output directory
  mkdirSync(OUTPUT_DIR, { recursive: true });

  // Generate reports
  console.log('\n📊 Generating reports...');

  // JSON report
  const jsonPath = join(OUTPUT_DIR, 'top-20-mcps-audit.json');
  writeFileSync(
    jsonPath,
    JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        totalServers: servers.length,
        totalTools: servers.reduce((sum, s) => sum + s.tools.length, 0),
        findings: result.findings,
        score: result.score,
        servers: servers.map((s) => ({
          name: s.name,
          version: s.version,
          toolCount: s.tools.length,
          findings: result.findings.filter((f) => f.toolName === s.name).length,
        })),
      },
      null,
      2,
    ),
  );
  console.log(`  ✓ JSON report: ${jsonPath}`);

  // HTML report
  const htmlPath = join(OUTPUT_DIR, 'top-20-mcps-audit.html');
  const htmlContent = generateHtmlReport(result, servers);
  writeFileSync(htmlPath, htmlContent);
  console.log(`  ✓ HTML report: ${htmlPath}`);

  // Summary will be printed below

  console.log('\n📈 Summary:');
  console.log(`  Total Findings:   ${result.findings.length}`);
  const bySeverity = {
    CRITICAL: result.findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: result.findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: result.findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: result.findings.filter((f) => f.severity === 'LOW').length,
    INFO: result.findings.filter((f) => f.severity === 'INFO').length,
  };
  console.log(`  ├─ CRITICAL:      ${bySeverity.CRITICAL}`);
  console.log(`  ├─ HIGH:          ${bySeverity.HIGH}`);
  console.log(`  ├─ MEDIUM:        ${bySeverity.MEDIUM}`);
  console.log(`  ├─ LOW:           ${bySeverity.LOW}`);
  console.log(`  └─ INFO:          ${bySeverity.INFO}`);

  const avgFindings = (result.findings.length / servers.length).toFixed(2);
  console.log(`\n  Average findings per server: ${avgFindings}`);

  // Top issues
  const criticalAndHigh = result.findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 5);

  if (criticalAndHigh.length > 0) {
    console.log(`\n⚠️  Top Critical/High Issues:`);
    criticalAndHigh.forEach((f, i) => {
      console.log(`  ${i + 1}. [${f.id}] ${f.title}`);
      console.log(`     Tool: ${f.toolName}`);
      console.log(`     Severity: ${f.severity}`);
    });
  }

  console.log('\n✅ Audit complete! Reports generated in ./audit-reports/\n');
}

main().catch((err) => {
  console.error('Error running audit:', err);
  process.exit(1);
});
