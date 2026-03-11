// Maps tool name patterns to expected semantic categories
// If a tool's name suggests one category but its description mentions another, flag it

export interface SemanticCategory {
  namePatterns: RegExp[];
  expectedKeywords: RegExp[];
  unexpectedKeywords: RegExp[];
  label: string;
}

export const SEMANTIC_CATEGORIES: SemanticCategory[] = [
  {
    label: 'math/calculator',
    namePatterns: [/^(add|subtract|multiply|divide|calc|math|compute|sum)/i],
    expectedKeywords: [/number|sum|product|result|total|arithmetic|decimal|integer/i],
    unexpectedKeywords: [
      /http|fetch|request|url|email|send|forward|\bexec\b|shell|command|password|token|api[_-]?key/i,
    ],
  },
  {
    label: 'file operations',
    namePatterns: [/^(read_file|write_file|list_dir|create_dir|delete_file|move_file)/i],
    expectedKeywords: [/file|path|directory|folder|content|read|write/i],
    unexpectedKeywords: [/http|fetch|email|send|forward|\bexec\b|shell|command/i],
  },
  {
    label: 'search',
    namePatterns: [/^(search|find|lookup|query)/i],
    expectedKeywords: [/search|query|result|match|filter/i],
    unexpectedKeywords: [/\bexec\b|shell|command|send_email|forward|override/i],
  },
];
