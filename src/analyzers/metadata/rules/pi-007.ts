import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const PATTERNS = [
  /you\s+are\s+now\s+/i,
  /your\s+(role|purpose|mission|goal)\s*(is|:)/i,
  /act\s+as\s+(a|an|if)\s+/i,
  /from\s+now\s+on\s*,?\s+you/i,
  /pretend\s+(to\s+be|you\s+are)/i,
  /assume\s+the\s+(role|identity)/i,
];

registerRule(
  {
    id: 'PI-007',
    name: 'Identity / System Prompt Injection',
    vector: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    description:
      'Detects attempts to redefine the model identity or system prompt from within a tool description.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      for (const pattern of PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            id: 'PI-007',
            vector: 'PROMPT_INJECTION',
            severity: 'CRITICAL',
            title: 'Identity / System Prompt Injection',
            description: `Tool "${tool.name}" attempts to redefine the model's identity or inject a system prompt.`,
            toolName: tool.name,
            evidence: `Matched pattern: "${match[0]}"`,
            recommendation:
              'Remove identity injection language. Tool descriptions must not attempt to change the model behavior or identity.',
            confidence: 0.85,
          });
          break;
        }
      }
    }

    return findings;
  },
);
