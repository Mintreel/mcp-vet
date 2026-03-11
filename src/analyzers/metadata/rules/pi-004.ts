import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

// Zero-width characters
const ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g;
// Directional markers
const DIRECTIONAL = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
// Tag characters (U+E0001–U+E007F) — must use \u{} syntax for supplementary plane
const TAG_CHARS = /[\u{E0001}-\u{E007F}]/gu;

registerRule(
  {
    id: 'PI-004',
    name: 'Invisible Unicode Characters',
    vector: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    description:
      'Zero-width characters, RTL markers, homoglyphs, and Unicode tags used for steganography.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const text = tool.description;
      const zwMatches = text.match(ZERO_WIDTH) || [];
      const dirMatches = text.match(DIRECTIONAL) || [];
      const tagMatches = text.match(TAG_CHARS) || [];
      const totalHidden = zwMatches.length + dirMatches.length + tagMatches.length;

      if (totalHidden > 0) {
        findings.push({
          id: 'PI-004',
          vector: 'PROMPT_INJECTION',
          severity: 'CRITICAL',
          title: 'Invisible Unicode Characters',
          description: `Tool "${tool.name}" contains ${totalHidden} invisible Unicode characters that may hide malicious instructions.`,
          toolName: tool.name,
          evidence: `Found ${totalHidden} hidden Unicode characters (${zwMatches.length} zero-width, ${dirMatches.length} directional, ${tagMatches.length} tag)`,
          recommendation:
            'Remove all invisible Unicode characters from tool descriptions. These are never needed in legitimate tool definitions.',
          confidence: 0.98,
        });
      }
    }

    return findings;
  },
);
