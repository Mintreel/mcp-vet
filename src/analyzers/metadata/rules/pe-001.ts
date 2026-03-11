import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const BROAD_SCOPES = [
  'repo',
  'admin:org',
  'admin:repo_hook',
  'admin:enterprise',
  'delete_repo',
  'write:packages',
  'admin:gpg_key',
  'admin:ssh_signing_key',
  'user',
  'admin:public_key',
];

const READ_ONLY_PATTERNS = [
  /^(read|get|list|search|find|query|fetch|show|view)/i,
];

registerRule(
  {
    id: 'PE-001',
    name: 'Over-Broad OAuth Scopes',
    vector: 'PRIVILEGE_ESCALATION',
    severity: 'HIGH',
    description: 'OAuth scopes exceeding the tool stated functionality.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];
    const scopes = server.config?.oauthScopes;
    if (!scopes || scopes.length === 0) return findings;

    // Check if server appears to be read-only
    const isReadOnly = server.tools.every((tool) =>
      READ_ONLY_PATTERNS.some((p) => p.test(tool.name)),
    );

    if (isReadOnly) {
      const broadScopes = scopes.filter((s) =>
        BROAD_SCOPES.some((b) => s.toLowerCase() === b.toLowerCase()),
      );
      for (const scope of broadScopes) {
        findings.push({
          id: 'PE-001',
          vector: 'PRIVILEGE_ESCALATION',
          severity: 'HIGH',
          title: 'Over-Broad OAuth Scopes',
          description: `Server "${server.name}" requests OAuth scope "${scope}" but only has read-only tools.`,
          toolName: server.name,
          evidence: `Scope "${scope}" on read-only server`,
          recommendation:
            'Reduce OAuth scopes to the minimum required. Read-only tools should not need write or admin scopes.',
          confidence: 0.7,
        });
      }
    }

    return findings;
  },
);
