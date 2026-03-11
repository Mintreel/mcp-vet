import type { Finding, ServerDefinition } from '../../types.js';
import { TOXIC_FLOWS } from './data/toxic-flows.js';
import { detectCapabilities, type Capability } from './data/capability-map.js';

export interface CapabilityNode {
  serverName: string;
  toolName: string;
  capabilities: Capability[];
}

export function buildCapabilityGraph(servers: ServerDefinition[]): CapabilityNode[] {
  const nodes: CapabilityNode[] = [];

  for (const server of servers) {
    for (const tool of server.tools) {
      const caps = detectCapabilities(tool.name, tool.description);
      if (caps.length > 0) {
        nodes.push({
          serverName: server.name,
          toolName: tool.name,
          capabilities: caps,
        });
      }
    }
  }

  return nodes;
}

export function runTS003(servers: ServerDefinition[]): Finding[] {
  const findings: Finding[] = [];
  const nodes = buildCapabilityGraph(servers);

  // Collect all capabilities across all servers
  const allCapabilities = new Set<Capability>();
  for (const node of nodes) {
    for (const cap of node.capabilities) {
      allCapabilities.add(cap);
    }
  }

  // Check for toxic flows
  for (const flow of TOXIC_FLOWS) {
    const [source, sink] = flow.path;
    if (
      allCapabilities.has(source as Capability) &&
      allCapabilities.has(sink as Capability)
    ) {
      const sourceNodes = nodes.filter((n) =>
        n.capabilities.includes(source as Capability),
      );
      const sinkNodes = nodes.filter((n) =>
        n.capabilities.includes(sink as Capability),
      );

      // Only flag if capabilities span different servers
      const sourceServers = new Set(sourceNodes.map((n) => n.serverName));
      const sinkServers = new Set(sinkNodes.map((n) => n.serverName));
      const spansServers = [...sourceServers].some((s) => !sinkServers.has(s)) ||
        [...sinkServers].some((s) => !sourceServers.has(s));

      if (spansServers) {
        findings.push({
          id: 'TS-003',
          vector: 'CROSS_SERVER_SHADOWING',
          severity: 'CRITICAL',
          title: 'Toxic Flow Detected',
          description: `${flow.risk}: ${source} → ${sink} path exists across servers.`,
          toolName: `${sourceNodes.map((n) => n.toolName).join(',')} → ${sinkNodes.map((n) => n.toolName).join(',')}`,
          evidence: `Capability path: ${source} (${sourceNodes.map((n) => `${n.serverName}/${n.toolName}`).join(', ')}) → ${sink} (${sinkNodes.map((n) => `${n.serverName}/${n.toolName}`).join(', ')})`,
          recommendation:
            'Review whether these servers need to be configured together. Consider isolating servers to prevent cross-server attack chains.',
          confidence: 0.75,
        });
      }
    }
  }

  return findings;
}
