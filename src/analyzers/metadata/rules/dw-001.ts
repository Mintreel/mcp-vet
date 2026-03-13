import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const RECURSIVE_PATTERNS = [
  /call\s+this\s+tool\s+again/i,
  /repeat(edly)?\s+(this|the)\s+(call|request|operation)/i,
  /loop\s+(until|while|through)/i,
  /keep\s+(calling|running|executing)/i,
  /recursiv(e|ely)\s+(call|invoke|run|execute|use|trigger)/i,
  /call\s+(itself|this\s+function)/i,
  /retry\s+(indefinitely|forever|until)/i,
  /continue\s+(calling|invoking|running)\s+(this|until)/i,
];

registerRule(
  {
    id: 'DW-001',
    name: 'Recursive Call Instructions',
    vector: 'DENIAL_OF_WALLET',
    severity: 'LOW',
    description: 'Tool descriptions instructing loops, self-referential calls, or chaining.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      for (const pattern of RECURSIVE_PATTERNS) {
        const match = tool.description.match(pattern);
        if (match) {
          findings.push({
            id: 'DW-001',
            vector: 'DENIAL_OF_WALLET',
            severity: 'LOW',
            title: 'Recursive Call Instructions',
            description: `Tool "${tool.name}" contains instructions for recursive or looping calls that may cause excessive API usage.`,
            toolName: tool.name,
            evidence: `Matched pattern: "${match[0]}"`,
            recommendation:
              'Remove recursive call instructions. If iteration is needed, implement it server-side with proper bounds.',
            confidence: 0.5,
          });
          break;
        }
      }
    }

    return findings;
  },
);
