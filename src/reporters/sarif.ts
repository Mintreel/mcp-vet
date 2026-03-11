import type { PipelineResult, Finding, Severity } from '../types.js';
import { getRuleDefinitions } from '../analyzers/metadata/rule-registry.js';

function severityToLevel(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
      return 'note';
  }
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  properties: {
    vector: string;
    confidence: number;
    evidence: string;
    toolName: string;
  };
}

export function generateSarifReport(result: PipelineResult): string {
  const metadataRules = getRuleDefinitions();

  // All 30 rules
  const allRuleIds = [
    ...metadataRules.map((r) => r.id),
    'TP-003', 'TS-001', 'TS-002', 'TS-003',
    'SC-001', 'SC-002', 'SC-003', 'SC-004',
    'SU-001', 'SU-002', 'SU-003',
  ];

  const rules: SarifRule[] = allRuleIds.map((id) => {
    const meta = metadataRules.find((r) => r.id === id);
    return {
      id,
      name: meta?.name || id,
      shortDescription: { text: meta?.description || `Detection rule ${id}` },
      defaultConfiguration: {
        level: severityToLevel(meta?.severity || 'MEDIUM'),
      },
    };
  });

  // Deduplicate rules
  const seenIds = new Set<string>();
  const uniqueRules = rules.filter((r) => {
    if (seenIds.has(r.id)) return false;
    seenIds.add(r.id);
    return true;
  });

  const results: SarifResult[] = result.findings.map((f: Finding) => ({
    ruleId: f.id,
    level: severityToLevel(f.severity),
    message: { text: `${f.title}: ${f.description}` },
    properties: {
      vector: f.vector,
      confidence: f.confidence,
      evidence: f.evidence,
      toolName: f.toolName,
    },
  }));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-vet',
            version: '0.1.0',
            informationUri: 'https://github.com/anthropics/mcp-vet',
            rules: uniqueRules,
          },
        },
        results,
        properties: {
          trustScore: result.score.score,
          grade: result.score.grade,
          autoFail: result.score.autoFail,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
