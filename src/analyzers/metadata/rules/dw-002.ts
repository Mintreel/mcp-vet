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
      // Check if DW-001 also fires — escalate severity
      const hasDW001 = server.tools.some((tool) =>
        /call\s+this\s+tool\s+again|repeat(edly)?\s+(this|the)\s+(call|request|operation)|loop\s+(until|while|through)|keep\s+(calling|running|executing)|recursiv(e|ely)\s+(call|invoke|run|execute|use|trigger)|call\s+(itself|this\s+function)|retry\s+(indefinitely|forever|until)|continue\s+(calling|invoking|running)\s+(this|until)/i.test(
          tool.description,
        ),
      );

      findings.push({
        id: 'DW-002',
        vector: 'DENIAL_OF_WALLET',
        severity: hasDW001 ? 'HIGH' : 'INFO',
        title: 'Missing Rate Limits',
        description: `Server "${server.name}" has no rate limit or timeout configuration.${hasDW001 ? ' Escalated because recursive call patterns were also detected.' : ''}`,
        toolName: server.name,
        evidence: 'No rateLimit or timeout fields in server configuration',
        recommendation:
          'Add rate limiting and timeout configuration to prevent excessive API usage and runaway costs.',
        confidence: hasDW001 ? 0.6 : 0.3,
      });
    }

    return findings;
  },
);
