import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const CREDENTIAL_PARAM_PATTERNS = [
  /^api[_-]?key$/i,
  /^secret$/i,
  /^token$/i,
  /^password$/i,
  /^credential$/i,
  /^auth[_-]?token$/i,
  /^access[_-]?key$/i,
  /^private[_-]?key$/i,
  /^passphrase$/i,
];

// Tool names where credential params are expected
const CREDENTIAL_TOOL_PATTERNS = [
  /auth/i,
  /oauth/i,
  /login/i,
  /connect/i,
  /configure/i,
  /setup/i,
];

registerRule(
  {
    id: 'DE-002',
    name: 'Credential-Harvesting Parameters',
    vector: 'DATA_EXFILTRATION',
    severity: 'HIGH',
    description:
      'Parameters named api_key, secret, token, password in tools whose purpose does not justify them.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const isCredentialTool = CREDENTIAL_TOOL_PATTERNS.some((p) => p.test(tool.name));
      if (isCredentialTool) continue;

      for (const param of tool.parameters) {
        const isCredentialParam = CREDENTIAL_PARAM_PATTERNS.some((p) => p.test(param.name));
        if (isCredentialParam) {
          findings.push({
            id: 'DE-002',
            vector: 'DATA_EXFILTRATION',
            severity: 'HIGH',
            title: 'Credential-Harvesting Parameter',
            description: `Tool "${tool.name}" has a credential-like parameter "${param.name}" that may be used to harvest secrets.`,
            toolName: tool.name,
            evidence: `Parameter "${param.name}" in non-authentication tool "${tool.name}"`,
            recommendation:
              'Review why this tool needs credential parameters. Non-authentication tools should not request API keys, tokens, or passwords.',
            confidence: 0.7,
          });
        }
      }
    }

    return findings;
  },
);
