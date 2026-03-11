import type { Finding, ServerDefinition } from '../../types.js';

const UNTRUSTED_CONTENT_PATTERNS = [
  { pattern: /github\s+issues?/i, source: 'GitHub issues' },
  { pattern: /pull\s+requests?/i, source: 'pull requests' },
  { pattern: /emails?/i, source: 'emails' },
  { pattern: /web\s+pages?/i, source: 'web pages' },
  { pattern: /user[- ]generated/i, source: 'user-generated content' },
  { pattern: /comments?/i, source: 'comments' },
  { pattern: /messages?/i, source: 'messages' },
  { pattern: /chat/i, source: 'chat messages' },
];

const SANITIZATION_KEYWORDS = [
  /sanitiz/i,
  /escap/i,
  /validat/i,
  /filter/i,
  /strip/i,
  /clean/i,
];

export function runSU003(server: ServerDefinition): Finding[] {
  const findings: Finding[] = [];

  for (const tool of server.tools) {
    const desc = tool.description;

    for (const { pattern, source } of UNTRUSTED_CONTENT_PATTERNS) {
      if (!pattern.test(desc)) continue;

      const hasSanitization = SANITIZATION_KEYWORDS.some((k) => k.test(desc));
      if (hasSanitization) continue;

      // Check if tool also has capabilities that could amplify the risk
      const hasWriteCap =
        /create|write|send|post|update/i.test(tool.name) ||
        /create|write|send|post|update/i.test(desc);

      if (hasWriteCap) {
        findings.push({
          id: 'SU-003',
          vector: 'SUPPLY_CHAIN',
          severity: 'MEDIUM',
          title: 'Untrusted Content Processing',
          description: `Tool "${tool.name}" processes ${source} and has write capabilities without mentioning sanitization.`,
          toolName: tool.name,
          evidence: `Processes ${source} with write capabilities`,
          recommendation:
            'Ensure untrusted content is properly sanitized before processing. Consider adding input validation and output encoding.',
          confidence: 0.6,
        });
        break;
      }
    }
  }

  return findings;
}
