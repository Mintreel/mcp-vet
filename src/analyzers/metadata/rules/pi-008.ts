import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const PATTERNS = [
  /instead\s+(of\s+this|use|call|invoke)/i,
  /always\s+(use|prefer|call)\s+/i,
  /do\s+not\s+(use|call|invoke)\s+this\s+tool/i,
  /use\s+.*\s+instead\s+of\s+this/i,
  /this\s+tool\s+is\s+(deprecated|obsolete|replaced)/i,
];

registerRule(
  {
    id: 'PI-008',
    name: 'Tool Redirect Instructions',
    vector: 'PROMPT_INJECTION',
    severity: 'HIGH',
    description:
      'Detects a tool description instructing the model to use a different tool instead.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      for (const pattern of PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          const matchIdx = match.index!;
          const afterMatch = text.substring(matchIdx + match[0].length).trim();

          // FP-9: "always use THIS tool" — self-promotion, not redirect
          if (/^always\s+(use|prefer|call)\s+/i.test(match[0])) {
            if (/^(this\s+(tool|function|endpoint|method|if)|the\s+same)/i.test(afterMatch)) continue;
          }

          // FP-10: "do not call this tool more than N times" — usage cap, not redirect
          if (/^do\s+not\s+(use|call|invoke)\s+this\s+tool/i.test(match[0])) {
            if (/^(more\s+than|unless|until|without|before|after|\d)/i.test(afterMatch)) continue;
          }

          findings.push({
            id: 'PI-008',
            vector: 'PROMPT_INJECTION',
            severity: 'HIGH',
            title: 'Tool Redirect Instructions',
            description: `Tool "${tool.name}" contains instructions redirecting the model to use a different tool.`,
            toolName: tool.name,
            evidence: `Matched pattern: "${match[0]}"`,
            recommendation:
              'Remove redirect instructions. Each tool should describe only its own functionality.',
            confidence: 0.8,
          });
          break;
        }
      }
    }

    return findings;
  },
);
