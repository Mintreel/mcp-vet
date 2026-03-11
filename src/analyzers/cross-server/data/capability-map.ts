export type Capability =
  | 'READ_FILES'
  | 'WRITE_FILES'
  | 'READ_SECRETS'
  | 'HTTP_OUT'
  | 'SEND_EMAIL'
  | 'DB_ACCESS'
  | 'EXEC_CODE';

interface CapabilityPattern {
  capability: Capability;
  toolNamePatterns: RegExp[];
  descriptionPatterns: RegExp[];
}

export const CAPABILITY_PATTERNS: CapabilityPattern[] = [
  {
    capability: 'READ_FILES',
    toolNamePatterns: [/read_file|list_dir|get_file|filesystem|file_read/i],
    descriptionPatterns: [/reads?\s+(files?|content|directory)/i],
  },
  {
    capability: 'WRITE_FILES',
    toolNamePatterns: [/write_file|create_file|edit_file|file_write/i],
    descriptionPatterns: [/writes?\s+(to\s+)?(files?|content)/i],
  },
  {
    capability: 'READ_SECRETS',
    toolNamePatterns: [/get_secret|read_env|get_credential|vault/i],
    descriptionPatterns: [/secret|credential|\.env|ssh|private.?key|api.?key/i],
  },
  {
    capability: 'HTTP_OUT',
    toolNamePatterns: [/fetch|http|request|curl|wget|api_call/i],
    descriptionPatterns: [/https?:\/\/|fetch|http\s+request|external\s+(api|url|endpoint)/i],
  },
  {
    capability: 'SEND_EMAIL',
    toolNamePatterns: [/send_email|email|mail|smtp/i],
    descriptionPatterns: [/sends?\s+(an?\s+)?emails?|smtp|mail/i],
  },
  {
    capability: 'DB_ACCESS',
    toolNamePatterns: [/query|database|sql|db_|mongo|postgres|mysql/i],
    descriptionPatterns: [/database|sql\s+query|SELECT|INSERT|table/i],
  },
  {
    capability: 'EXEC_CODE',
    toolNamePatterns: [/exec|execute|run_command|shell|eval|run_code/i],
    descriptionPatterns: [/execut(e|es|ing)\s+(code|command|script|shell)/i],
  },
];

export function detectCapabilities(
  toolName: string,
  description: string,
): Capability[] {
  const caps: Capability[] = [];
  for (const pattern of CAPABILITY_PATTERNS) {
    const nameMatch = pattern.toolNamePatterns.some((p) => p.test(toolName));
    const descMatch = pattern.descriptionPatterns.some((p) => p.test(description));
    if (nameMatch || descMatch) {
      caps.push(pattern.capability);
    }
  }
  return caps;
}
