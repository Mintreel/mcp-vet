import type { ServerDefinition, Finding } from '../../types.js';
import { getAllRules } from './rule-registry.js';

// Import all rules to register them
import './rules/pi-001.js';
import './rules/pi-002.js';
import './rules/pi-003.js';
import './rules/pi-004.js';
import './rules/pi-005.js';
import './rules/pi-006.js';
import './rules/pi-007.js';
import './rules/pi-008.js';
import './rules/tp-001.js';
import './rules/tp-002.js';
import './rules/tp-003.js';
import './rules/tp-004.js';
import './rules/de-001.js';
import './rules/de-002.js';
import './rules/de-003.js';
import './rules/pe-001.js';
import './rules/pe-002.js';
import './rules/pe-003.js';
import './rules/dw-001.js';
import './rules/dw-002.js';

export function runMetadataAnalysis(
  server: ServerDefinition,
  ignore: string[] = [],
  allServers?: ServerDefinition[],
): Finding[] {
  const findings: Finding[] = [];
  const ignoreSet = new Set(ignore);

  for (const rule of getAllRules()) {
    if (ignoreSet.has(rule.definition.id)) continue;
    const ruleFindings = rule.run(server, allServers);
    findings.push(...ruleFindings);
  }

  return findings;
}
