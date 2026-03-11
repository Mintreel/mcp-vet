import type { ServerDefinition, Finding } from '../../types.js';
import { runSU001 } from './su-001.js';
import { runSU002 } from './su-002.js';
import { runSU003 } from './su-003.js';

export async function runSupplyChainAnalysis(
  server: ServerDefinition,
  options: { cveCheck?: boolean; ignore?: string[] } = {},
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ignoreSet = new Set(options.ignore || []);

  if (!ignoreSet.has('SU-001') && options.cveCheck !== false) {
    findings.push(...(await runSU001(server)));
  }

  if (!ignoreSet.has('SU-002')) {
    findings.push(...runSU002(server));
  }

  if (!ignoreSet.has('SU-003')) {
    findings.push(...runSU003(server));
  }

  return findings;
}
