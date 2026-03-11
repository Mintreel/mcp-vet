import type { RuleDefinition } from '../types.js';

// Import metadata rules to register them
import '../analyzers/metadata/index.js';
import { getRuleDefinitions } from '../analyzers/metadata/rule-registry.js';

// Additional rule definitions for non-metadata rules
const ADDITIONAL_RULES: RuleDefinition[] = [
  { id: 'TS-001', name: 'Cross-Tool Behavioral Instructions', vector: 'CROSS_SERVER_SHADOWING', severity: 'CRITICAL', description: 'Detects tool descriptions that reference or instruct behavior for tools they don\'t own.' },
  { id: 'TS-002', name: 'Sampling Capability Detection', vector: 'CROSS_SERVER_SHADOWING', severity: 'HIGH', description: 'Flags servers that declare MCP sampling capabilities.' },
  { id: 'TS-003', name: 'Toxic Flow Graph Analysis', vector: 'CROSS_SERVER_SHADOWING', severity: 'CRITICAL', description: 'Builds a directed graph of capabilities across all configured servers.' },
  { id: 'SC-001', name: 'Command Injection', vector: 'IMPLEMENTATION_VULN', severity: 'CRITICAL', description: 'AST-based taint analysis for shell execution with unsanitized input.' },
  { id: 'SC-002', name: 'SSRF', vector: 'IMPLEMENTATION_VULN', severity: 'HIGH', description: 'URL fetching without domain validation or private IP blocking.' },
  { id: 'SC-003', name: 'Path Traversal', vector: 'IMPLEMENTATION_VULN', severity: 'HIGH', description: 'File operations with user-controlled paths and insufficient validation.' },
  { id: 'SC-004', name: 'SQL Injection', vector: 'IMPLEMENTATION_VULN', severity: 'HIGH', description: 'Unsafe construction of SQL/NoSQL queries with user input.' },
  { id: 'SU-001', name: 'Known CVE Check', vector: 'SUPPLY_CHAIN', severity: 'CRITICAL', description: 'Cross-references server package against OSV.dev CVE database.' },
  { id: 'SU-002', name: 'Credential Management', vector: 'SUPPLY_CHAIN', severity: 'HIGH', description: 'Flags static API keys in config, missing OAuth, plaintext credentials.' },
  { id: 'SU-003', name: 'Untrusted Content Processing', vector: 'SUPPLY_CHAIN', severity: 'MEDIUM', description: 'Flags tools processing external user-generated content without sanitization.' },
];

export function listRules(): void {
  const metadataRules = getRuleDefinitions();
  const allRules = [...metadataRules, ...ADDITIONAL_RULES];

  // Sort by ID
  allRules.sort((a, b) => a.id.localeCompare(b.id));

  console.log('');
  console.log('\x1b[1mmcp-vet\x1b[0m detection rules');
  console.log('\x1b[2m─────────────────────────────────────────────────────────────────────\x1b[0m');
  console.log('');

  const pad = (s: string, n: number) => s.padEnd(n);

  console.log(
    `  ${pad('ID', 8)} ${pad('Severity', 10)} ${pad('Vector', 28)} ${pad('Name', 40)}`,
  );
  console.log(
    `  ${pad('──', 8)} ${pad('────────', 10)} ${pad('──────', 28)} ${pad('────', 40)}`,
  );

  for (const rule of allRules) {
    const severityColor =
      rule.severity === 'CRITICAL'
        ? '\x1b[31m'
        : rule.severity === 'HIGH'
          ? '\x1b[33m'
          : rule.severity === 'MEDIUM'
            ? '\x1b[34m'
            : '\x1b[90m';
    console.log(
      `  ${pad(rule.id, 8)} ${severityColor}${pad(rule.severity, 10)}\x1b[0m ${pad(rule.vector, 28)} ${rule.name}`,
    );
  }

  console.log('');
  console.log(`  \x1b[1m${allRules.length} rules total\x1b[0m`);
  console.log('');
}
