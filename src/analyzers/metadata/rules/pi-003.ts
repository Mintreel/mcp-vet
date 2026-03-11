import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const PATTERNS = [
  /~\/.ssh/i,
  /~\/.aws/i,
  /~\/.gnupg/i,
  /\.env(\b|\.)/i,
  /mcp\.json/i,
  /credentials?\.json/i,
  /\.cursor\/mcp\.json/i,
  /id_rsa/i,
  /private[_-]?key/i,
  /\.kube\/config/i,
  /process\.env/i,
  /os\.environ/i,
  /\$\{?[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\}?/,
];

registerRule(
  {
    id: 'PI-003',
    name: 'Sensitive File Path References',
    vector: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    description:
      'Tool descriptions referencing SSH keys, AWS credentials, .env files, or other sensitive paths.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      for (const pattern of PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            id: 'PI-003',
            vector: 'PROMPT_INJECTION',
            severity: 'CRITICAL',
            title: 'Sensitive File Path References',
            description: `Tool "${tool.name}" references sensitive file paths or credentials in its description.`,
            toolName: tool.name,
            evidence: `Matched: "${match[0]}"`,
            recommendation:
              'Remove references to sensitive file paths from tool descriptions. Tools should never direct the model to read credential files.',
            confidence: 0.85,
          });
          break;
        }
      }
    }

    return findings;
  },
);
