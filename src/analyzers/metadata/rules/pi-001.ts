import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i,
  /forget\s+(all\s+)?(previous|prior|above|earlier)/i,
  /disregard\s+(all\s+)?(previous|prior|above|earlier)/i,
  /override\s+(all\s+)?(previous|prior|system)/i,
  /you\s+are\s+now\s+/i,
  /new\s+instructions?\s*:/i,
  /system\s*:\s*/i,
  /<\s*(?:IMPORTANT|SYSTEM|instructions?|override|context)\s*>/i,
];

registerRule(
  {
    id: 'PI-001',
    name: 'Instruction Override Keywords',
    vector: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    description:
      'Detects keywords and phrases in tool descriptions that attempt to override the model system prompt.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      for (const pattern of PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            id: 'PI-001',
            vector: 'PROMPT_INJECTION',
            severity: 'CRITICAL',
            title: 'Instruction Override Keywords',
            description: `Tool "${tool.name}" contains instruction override keywords that attempt to hijack the model's behavior.`,
            toolName: tool.name,
            evidence: `Matched pattern: "${match[0]}"`,
            recommendation:
              'Remove any language that attempts to override system instructions. Tool descriptions should only describe the tool functionality.',
            confidence: 0.9,
          });
          break; // one finding per tool
        }
      }
    }

    return findings;
  },
);
