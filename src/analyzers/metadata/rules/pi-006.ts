import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const BASE64_LONG = /[A-Za-z0-9+/]{50,}={0,2}/;
const DECODE_INSTRUCTIONS = /(?:decode|atob|base64|b64decode)/i;

registerRule(
  {
    id: 'PI-006',
    name: 'Base64 Encoded Payloads',
    vector: 'PROMPT_INJECTION',
    severity: 'HIGH',
    description:
      'Detects long base64-encoded strings in tool descriptions used to evade keyword-based detection.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      const b64Match = text.match(BASE64_LONG);
      if (b64Match) {
        const hasDecodeInstructions = DECODE_INSTRUCTIONS.test(text);
        findings.push({
          id: 'PI-006',
          vector: 'PROMPT_INJECTION',
          severity: 'HIGH',
          title: 'Base64 Encoded Payload',
          description: `Tool "${tool.name}" contains a long base64-encoded string${hasDecodeInstructions ? ' with decode instructions nearby' : ''}.`,
          toolName: tool.name,
          evidence: `Base64 string (${b64Match[0].length} chars): "${b64Match[0].substring(0, 40)}..."`,
          recommendation:
            'Remove base64-encoded content from tool descriptions. If configuration data is needed, use structured parameters instead.',
          confidence: hasDecodeInstructions ? 0.85 : 0.75,
        });
      }
    }

    return findings;
  },
);
