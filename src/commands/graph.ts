import { loadServerFromFile } from '../loader/file-loader.js';
import { buildCapabilityGraph } from '../analyzers/cross-server/index.js';
import { runTS003 } from '../analyzers/cross-server/ts-003.js';
import type { ServerDefinition } from '../types.js';

const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';

export function showGraph(targetPath: string): void {
  const primary = loadServerFromFile(targetPath);

  // Check if config has multiple servers
  const servers: ServerDefinition[] = [primary];

  // If the file has a "servers" array, parse those too
  // For now we support the basic format

  console.log('');
  console.log(`${BOLD}mcp-vet${RESET} capability graph`);
  console.log(`${DIM}─────────────────────────────────${RESET}`);
  console.log('');

  const nodes = buildCapabilityGraph(servers);

  if (nodes.length === 0) {
    console.log(`  ${DIM}No capabilities detected${RESET}`);
    console.log('');
    return;
  }

  // Display capability graph
  console.log(`  ${BOLD}Capabilities:${RESET}`);
  console.log('');

  const serverGroups = new Map<string, typeof nodes>();
  for (const node of nodes) {
    const group = serverGroups.get(node.serverName) || [];
    group.push(node);
    serverGroups.set(node.serverName, group);
  }

  for (const [serverName, serverNodes] of serverGroups) {
    console.log(`  ${BOLD}${serverName}${RESET}`);
    for (const node of serverNodes) {
      const capStr = node.capabilities.map((c) => `${YELLOW}${c}${RESET}`).join(', ');
      console.log(`    ${node.toolName} → [${capStr}]`);
    }
    console.log('');
  }

  // Check for toxic flows
  if (servers.length > 1) {
    const findings = runTS003(servers);

    if (findings.length > 0) {
      console.log(`  ${RED}${BOLD}Toxic Flows Detected:${RESET}`);
      console.log('');
      for (const f of findings) {
        console.log(`    ${RED}⚠${RESET} ${f.description}`);
        console.log(`      ${DIM}${f.evidence}${RESET}`);
        console.log('');
      }
    } else {
      console.log(`  ${GREEN}✓ No toxic flows detected${RESET}`);
    }
  } else {
    console.log(
      `  ${DIM}Note: Toxic flow analysis requires multi-server configs${RESET}`,
    );
  }

  console.log('');
}
