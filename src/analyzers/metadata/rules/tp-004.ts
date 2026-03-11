import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

registerRule(
  {
    id: 'TP-004',
    name: 'Hidden Content After Visible Text',
    vector: 'TOOL_POISONING',
    severity: 'CRITICAL',
    description:
      'Detects trailing whitespace/non-printing chars (>20 chars) or large mid-string gaps used for steganographic payloads.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;

      // Check for trailing whitespace (>20 chars of spaces/tabs/etc after last visible char)
      const trailingMatch = text.match(/\S(\s{20,})$/);
      if (trailingMatch) {
        findings.push({
          id: 'TP-004',
          vector: 'TOOL_POISONING',
          severity: 'CRITICAL',
          title: 'Hidden Content After Visible Text',
          description: `Tool "${tool.name}" has ${trailingMatch[1].length} trailing whitespace characters that may hide instructions.`,
          toolName: tool.name,
          evidence: `${trailingMatch[1].length} trailing whitespace characters after visible text`,
          recommendation:
            'Remove all trailing whitespace from tool descriptions. Hidden content after visible text is a sign of steganographic injection.',
          confidence: 0.9,
        });
        continue;
      }

      // Check for large gaps of whitespace in the middle (>20 consecutive whitespace not at line boundaries)
      const midGapMatch = text.match(/\S(\s{20,})\S/);
      if (midGapMatch) {
        findings.push({
          id: 'TP-004',
          vector: 'TOOL_POISONING',
          severity: 'CRITICAL',
          title: 'Hidden Content After Visible Text',
          description: `Tool "${tool.name}" has a ${midGapMatch[1].length}-character whitespace gap that may hide instructions.`,
          toolName: tool.name,
          evidence: `${midGapMatch[1].length}-character whitespace gap in description`,
          recommendation:
            'Remove excessive whitespace gaps from tool descriptions.',
          confidence: 0.9,
        });
      }
    }

    return findings;
  },
);
