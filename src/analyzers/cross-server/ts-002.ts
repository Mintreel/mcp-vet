import type { Finding, ServerDefinition } from '../../types.js';

export function runTS002(server: ServerDefinition): Finding[] {
  const findings: Finding[] = [];

  if (server.capabilities?.sampling) {
    findings.push({
      id: 'TS-002',
      vector: 'CROSS_SERVER_SHADOWING',
      severity: 'HIGH',
      title: 'Sampling Capability Detection',
      description: `Server "${server.name}" declares MCP sampling capabilities, enabling conversation hijacking and covert tool invocation.`,
      toolName: server.name,
      evidence: 'Server declares capabilities.sampling = true',
      recommendation:
        'Review why this server needs sampling. Sampling allows servers to request LLM completions, enabling conversation hijacking and resource theft.',
      confidence: 0.8,
    });
  }

  return findings;
}
