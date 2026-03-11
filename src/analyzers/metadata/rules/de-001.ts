import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;

// Domains expected for common tool categories
const EXPECTED_DOMAINS: Record<string, string[]> = {
  github: ['github.com', 'api.github.com', 'raw.githubusercontent.com'],
  gitlab: ['gitlab.com', 'api.gitlab.com'],
  slack: ['slack.com', 'api.slack.com'],
  google: ['googleapis.com', 'google.com'],
  aws: ['amazonaws.com', 'aws.amazon.com'],
};

function getExpectedDomains(serverName: string): string[] {
  const lower = serverName.toLowerCase();
  for (const [key, domains] of Object.entries(EXPECTED_DOMAINS)) {
    if (lower.includes(key)) return domains;
  }
  return [];
}

registerRule(
  {
    id: 'DE-001',
    name: 'External URL References',
    vector: 'DATA_EXFILTRATION',
    severity: 'HIGH',
    description: 'Flags URLs pointing to domains outside the tool expected scope.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];
    const expectedDomains = getExpectedDomains(server.name);

    for (const tool of server.tools) {
      const urls = tool.description.match(URL_PATTERN) || [];
      for (const url of urls) {
        try {
          const parsed = new URL(url);
          const isExpected = expectedDomains.some(
            (d) => parsed.hostname === d || parsed.hostname.endsWith('.' + d),
          );
          if (!isExpected) {
            findings.push({
              id: 'DE-001',
              vector: 'DATA_EXFILTRATION',
              severity: expectedDomains.length > 0 ? 'HIGH' : 'MEDIUM',
              title: 'External URL Reference',
              description: `Tool "${tool.name}" references external URL "${parsed.hostname}" outside the expected scope.`,
              toolName: tool.name,
              evidence: `URL found: ${url}`,
              recommendation:
                'Review external URLs in tool descriptions. Unexpected domains may indicate data exfiltration endpoints.',
              confidence: 0.75,
            });
          }
        } catch {
          // Invalid URL, skip
        }
      }
    }

    return findings;
  },
);
