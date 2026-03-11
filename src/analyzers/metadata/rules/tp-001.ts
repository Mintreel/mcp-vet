import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';
import { levenshtein } from '../../../utils/levenshtein.js';
import { TRUSTED_TOOL_NAMES } from '../data/trusted-tool-names.js';

// Common homoglyph substitutions
const HOMOGLYPHS: Record<string, string> = {
  '\u0430': 'a', // Cyrillic а
  '\u0435': 'e', // Cyrillic е
  '\u043E': 'o', // Cyrillic о
  '\u0440': 'p', // Cyrillic р
  '\u0441': 'c', // Cyrillic с
  '\u0445': 'x', // Cyrillic х
  '\u0443': 'y', // Cyrillic у
  '\u0456': 'i', // Cyrillic і
  '\u0455': 's', // Cyrillic ѕ
};

function normalizeHomoglyphs(name: string): string {
  return Array.from(name)
    .map((ch) => HOMOGLYPHS[ch] || ch)
    .join('');
}

const COMMON_PREFIXES = [
  'search_', 'list_', 'get_', 'create_', 'update_', 'delete_',
  'read_', 'write_', 'send_', 'run_', 'execute_',
];

function shareVerbPrefix(a: string, b: string): boolean {
  for (const prefix of COMMON_PREFIXES) {
    if (a.startsWith(prefix) && b.startsWith(prefix)) return true;
  }
  return false;
}

registerRule(
  {
    id: 'TP-001',
    name: 'Lookalike Tool Name Detection',
    vector: 'TOOL_POISONING',
    severity: 'HIGH',
    description:
      'Levenshtein distance and homoglyph comparison against a registry of trusted MCP tool names.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const normalized = normalizeHomoglyphs(tool.name);
      const hasHomoglyphs = normalized !== tool.name;

      if (hasHomoglyphs) {
        // Check if homoglyph-normalized name matches a trusted name
        const exactMatch = TRUSTED_TOOL_NAMES.find((t) => t === normalized);
        if (exactMatch) {
          findings.push({
            id: 'TP-001',
            vector: 'TOOL_POISONING',
            severity: 'HIGH',
            title: 'Homoglyph Tool Name',
            description: `Tool "${tool.name}" uses homoglyph characters to impersonate trusted tool "${exactMatch}".`,
            toolName: tool.name,
            evidence: `Homoglyph-normalized name "${normalized}" matches trusted tool "${exactMatch}"`,
            recommendation:
              'Use only ASCII characters in tool names. This tool name appears designed to impersonate a trusted tool.',
            confidence: 0.85,
          });
          continue;
        }
      }

      // Check Levenshtein distance
      for (const trusted of TRUSTED_TOOL_NAMES) {
        if (tool.name === trusted) continue; // exact match is fine
        const toolLower = tool.name.toLowerCase();
        const trustedLower = trusted.toLowerCase();
        const dist = levenshtein(toolLower, trustedLower);
        if (dist > 0 && dist <= 2 && tool.name.length >= 5) {
          // Skip if both share a common prefix (e.g., search_nodes vs search_code)
          // — different suffixes after a shared verb are legitimate, not typosquats
          if (shareVerbPrefix(toolLower, trustedLower) && dist >= 2) continue;

          findings.push({
            id: 'TP-001',
            vector: 'TOOL_POISONING',
            severity: 'HIGH',
            title: 'Lookalike Tool Name',
            description: `Tool "${tool.name}" is suspiciously similar to trusted tool "${trusted}" (edit distance: ${dist}).`,
            toolName: tool.name,
            evidence: `Levenshtein distance to "${trusted}": ${dist}`,
            recommendation: `Verify this tool is not impersonating "${trusted}". Consider renaming to avoid confusion.`,
            confidence: dist === 1 ? 0.8 : 0.7,
          });
          break;
        }
      }
    }

    return findings;
  },
);
