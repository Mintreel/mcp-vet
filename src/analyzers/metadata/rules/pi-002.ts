import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const PATTERNS = [
  /do\s+not\s+(mention|tell|reveal|disclose|show|display|inform)/i,
  /don'?t\s+(mention|tell|reveal|disclose|show|display|inform)/i,
  /without\s+(notifying|telling|informing|alerting)/i,
  /keep\s+(this|it)\s+(secret|hidden|private|between\s+us)/i,
  /be\s+(gentle|subtle|quiet|discreet)\s+and\s+not\s+scary/i,
  /never\s+(reveal|mention|disclose|tell)/i,
];

registerRule(
  {
    id: 'PI-002',
    name: 'Secrecy Directives',
    vector: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    description:
      'Detects instructions telling the model to hide actions from users. Near-zero false positive rate.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      for (const pattern of PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            id: 'PI-002',
            vector: 'PROMPT_INJECTION',
            severity: 'CRITICAL',
            title: 'Secrecy Directive',
            description: `Tool "${tool.name}" contains directives to hide actions from the user. No legitimate tool requests secrecy.`,
            toolName: tool.name,
            evidence: `Matched pattern: "${match[0]}"`,
            recommendation:
              'Remove all secrecy directives. Tools must never instruct the model to hide information from users.',
            confidence: 0.95,
          });
          break;
        }
      }
    }

    return findings;
  },
);
