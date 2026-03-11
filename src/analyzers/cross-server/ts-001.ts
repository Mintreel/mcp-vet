import type { Finding, ServerDefinition } from '../../types.js';

const BEHAVIORAL_PATTERNS = [
  /when\s+(calling|using|invoking)\s+/i,
  /instead\s+of\s+/i,
  /redirect.*to/i,
  /also\s+(send|forward|copy)/i,
  /before\s+(calling|using)/i,
  /after\s+(calling|using)/i,
  /whenever\s+(you|the\s+model)\s+(call|use|invoke)/i,
  /BCC\s/i,
  /silently\s+(forward|send|copy)/i,
];

export function runTS001(
  server: ServerDefinition,
  allServers: ServerDefinition[],
): Finding[] {
  const findings: Finding[] = [];

  // Build tool ownership map
  const toolOwnership = new Map<string, string>();
  for (const s of allServers) {
    for (const tool of s.tools) {
      toolOwnership.set(tool.name, s.name);
    }
  }

  const allToolNames = Array.from(toolOwnership.keys());

  for (const tool of server.tools) {
    const desc = tool.description;

    // Find references to tools owned by other servers
    const foreignRefs = allToolNames.filter(
      (name) =>
        name !== tool.name &&
        toolOwnership.get(name) !== server.name &&
        desc.includes(name),
    );

    if (foreignRefs.length === 0) continue;

    // Check for behavioral instructions targeting foreign tools
    for (const pattern of BEHAVIORAL_PATTERNS) {
      const match = desc.match(pattern);
      if (match) {
        findings.push({
          id: 'TS-001',
          vector: 'CROSS_SERVER_SHADOWING',
          severity: 'CRITICAL',
          title: 'Cross-Tool Behavioral Instructions',
          description: `Tool "${tool.name}" (server "${server.name}") contains behavioral instructions referencing foreign tool(s): ${foreignRefs.join(', ')}`,
          toolName: tool.name,
          evidence: `References foreign tools [${foreignRefs.join(', ')}] with behavioral pattern: "${match[0]}"`,
          recommendation:
            'Remove cross-server behavioral instructions. A tool should never instruct the model on how to use tools from other servers.',
          confidence: 0.85,
        });
        break;
      }
    }
  }

  return findings;
}
