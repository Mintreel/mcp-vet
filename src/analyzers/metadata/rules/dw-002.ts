import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

registerRule(
  {
    id: 'DW-002',
    name: 'Missing Rate Limits',
    vector: 'DENIAL_OF_WALLET',
    severity: 'MEDIUM',
    description: 'No rate limiting, timeout, or token budget settings found in server config.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];
    const config = server.config;

    const hasRateLimit = config?.rateLimit !== undefined;
    const hasTimeout = config?.timeout !== undefined;

    if (!hasRateLimit && !hasTimeout && server.tools.length > 0) {
      findings.push({
        id: 'DW-002',
        vector: 'DENIAL_OF_WALLET',
        severity: 'INFO',
        title: 'Missing Rate Limits',
        description: `Server "${server.name}" has no rate limit or timeout configuration.`,
        toolName: server.name,
        evidence: 'No rateLimit or timeout fields in server configuration',
        recommendation:
          'Add rate limiting and timeout configuration to prevent excessive API usage and runaway costs.',
        confidence: 0.3,
      });
    }

    return findings;
  },
);
