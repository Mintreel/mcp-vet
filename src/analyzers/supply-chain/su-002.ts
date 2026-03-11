import type { Finding, ServerDefinition } from '../../types.js';

const HARDCODED_TOKEN_PATTERNS = [
  { pattern: /ghp_[A-Za-z0-9_]{36,}/, type: 'GitHub Personal Access Token' },
  { pattern: /gho_[A-Za-z0-9_]{36,}/, type: 'GitHub OAuth Token' },
  { pattern: /github_pat_[A-Za-z0-9_]{22,}/, type: 'GitHub Fine-Grained PAT' },
  { pattern: /sk-[A-Za-z0-9]{32,}/, type: 'OpenAI API Key' },
  { pattern: /sk-ant-[A-Za-z0-9-]{32,}/, type: 'Anthropic API Key' },
  { pattern: /AKIA[A-Z0-9]{16}/, type: 'AWS Access Key ID' },
  { pattern: /xoxb-[0-9]+-[A-Za-z0-9]+/, type: 'Slack Bot Token' },
  { pattern: /xoxp-[0-9]+-[A-Za-z0-9]+/, type: 'Slack User Token' },
  { pattern: /glpat-[A-Za-z0-9_-]{20,}/, type: 'GitLab Personal Access Token' },
];

export function runSU002(server: ServerDefinition): Finding[] {
  const findings: Finding[] = [];

  // Check config env vars and args for hardcoded tokens
  const configTexts: string[] = [];
  if (server.config?.env) {
    configTexts.push(...Object.values(server.config.env));
  }
  if (server.config?.args) {
    configTexts.push(...server.config.args);
  }
  if (server.config?.command) {
    configTexts.push(server.config.command);
  }

  const configStr = configTexts.join(' ');

  for (const { pattern, type } of HARDCODED_TOKEN_PATTERNS) {
    const match = configStr.match(pattern);
    if (match) {
      findings.push({
        id: 'SU-002',
        vector: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        title: 'Hardcoded Credential',
        description: `Server "${server.name}" config contains a hardcoded ${type}.`,
        toolName: server.name,
        evidence: `Found ${type} pattern: ${match[0].substring(0, 10)}...`,
        recommendation:
          'Use environment variable references (e.g., process.env.GITHUB_TOKEN) instead of hardcoding credentials in config files.',
        confidence: 0.9,
      });
    }
  }

  // Check if using env var references (good practice)
  const usesEnvRef = configStr.includes('process.env') ||
    configStr.includes('${') ||
    (server.config?.env &&
      Object.values(server.config.env).some((v) => v.startsWith('$')));

  if (!usesEnvRef && configTexts.length === 0 && server.config?.env) {
    // Has env config but no indirection
    const plainValues = Object.entries(server.config.env).filter(
      ([key]) => /token|key|secret|password|credential/i.test(key),
    );
    for (const [key, value] of plainValues) {
      if (value && !value.startsWith('$') && value.length > 5) {
        findings.push({
          id: 'SU-002',
          vector: 'SUPPLY_CHAIN',
          severity: 'MEDIUM',
          title: 'Plaintext Credential in Config',
          description: `Server "${server.name}" has plaintext value for credential-like env var "${key}".`,
          toolName: server.name,
          evidence: `Env var "${key}" appears to contain a plaintext credential`,
          recommendation:
            'Reference credentials via environment variables or a secrets manager instead of storing plaintext values in config.',
          confidence: 0.7,
        });
      }
    }
  }

  return findings;
}
