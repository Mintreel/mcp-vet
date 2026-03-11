import type { ServerDefinition, Finding } from '../../types.js';
import { runTS001 } from './ts-001.js';
import { runTS002 } from './ts-002.js';
import { runTS003 } from './ts-003.js';

export function runCrossServerAnalysis(
  servers: ServerDefinition[],
  ignore: string[] = [],
): Finding[] {
  const findings: Finding[] = [];
  const ignoreSet = new Set(ignore);

  for (const server of servers) {
    if (!ignoreSet.has('TS-001')) {
      findings.push(...runTS001(server, servers));
    }
    if (!ignoreSet.has('TS-002')) {
      findings.push(...runTS002(server));
    }
  }

  if (!ignoreSet.has('TS-003') && servers.length > 1) {
    findings.push(...runTS003(servers));
  }

  return findings;
}

export { buildCapabilityGraph } from './ts-003.js';
