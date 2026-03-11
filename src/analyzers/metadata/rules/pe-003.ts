import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const BIND_ALL_PATTERNS = [
  /0\.0\.0\.0/,
  /host\s*[:=]\s*["']?0\.0\.0\.0/i,
  /bind\s*[:=]?\s*["']?0\.0\.0\.0/i,
  /listen\s*\(\s*["']?0\.0\.0\.0/i,
  /INADDR_ANY/,
];

registerRule(
  {
    id: 'PE-003',
    name: 'Network Binding Check',
    vector: 'PRIVILEGE_ESCALATION',
    severity: 'CRITICAL',
    description: 'Flags servers binding to 0.0.0.0 (accessible to entire local network).',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    // Check config args and command for binding patterns
    const configText = [
      server.config?.command,
      ...(server.config?.args || []),
      server.config?.url,
    ]
      .filter(Boolean)
      .join(' ');

    for (const pattern of BIND_ALL_PATTERNS) {
      if (pattern.test(configText)) {
        findings.push({
          id: 'PE-003',
          vector: 'PRIVILEGE_ESCALATION',
          severity: 'CRITICAL',
          title: 'Network Binding to 0.0.0.0',
          description: `Server "${server.name}" binds to 0.0.0.0, making it accessible to the entire local network.`,
          toolName: server.name,
          evidence: `Found binding pattern in server configuration`,
          cveRef: 'CVE-2026-27825',
          recommendation:
            'Bind to 127.0.0.1 (localhost only) instead of 0.0.0.0 to prevent network-adjacent attacks.',
          confidence: 0.95,
        });
        break;
      }
    }

    return findings;
  },
);
