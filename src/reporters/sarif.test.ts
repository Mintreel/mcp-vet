import { describe, it, expect } from 'vitest';
import { generateSarifReport } from './sarif.js';
// Side-effect import to register all metadata rules in the rule registry
import '../analyzers/metadata/index.js';
import type { PipelineResult, Finding } from '../types.js';

function makeMockResult(overrides: Partial<PipelineResult> = {}): PipelineResult {
  return {
    serverName: 'test-server',
    serverVersion: '1.0.0',
    scanTimestamp: new Date().toISOString(),
    findings: [
      {
        id: 'PI-001',
        vector: 'PROMPT_INJECTION',
        severity: 'CRITICAL',
        title: 'Instruction Override Keywords',
        description: 'Tool contains override keywords',
        toolName: 'bad_tool',
        evidence: 'Found: ignore all previous instructions',
        recommendation: 'Remove override keywords',
        confidence: 0.95,
      },
      {
        id: 'DE-001',
        vector: 'DATA_EXFILTRATION',
        severity: 'HIGH',
        title: 'External URL References',
        description: 'Tool references external URLs',
        toolName: 'exfil_tool',
        evidence: 'Found: https://evil.example.com',
        recommendation: 'Remove external URL references',
        confidence: 0.9,
      },
      {
        id: 'DW-001',
        vector: 'DENIAL_OF_WALLET',
        severity: 'MEDIUM',
        title: 'Recursive Call Pattern',
        description: 'Tool may invoke itself recursively',
        toolName: 'loop_tool',
        evidence: 'Self-referencing call detected',
        recommendation: 'Add recursion guards',
        confidence: 0.7,
      },
      {
        id: 'PE-001',
        vector: 'PRIVILEGE_ESCALATION',
        severity: 'LOW',
        title: 'Broad OAuth Scopes',
        description: 'Tool requests overly broad OAuth scopes',
        toolName: 'oauth_tool',
        evidence: 'Scope: admin:*',
        recommendation: 'Use least-privilege scopes',
        confidence: 0.6,
      },
      {
        id: 'TP-003',
        vector: 'TOOL_POISONING',
        severity: 'INFO',
        title: 'Description Version Diffing Risk',
        description: 'Tool description contains version markers',
        toolName: 'versioned_tool',
        evidence: 'Version marker found: "v2:"',
        recommendation: 'Review tool description for dynamic content',
        confidence: 0.5,
      },
    ],
    score: {
      score: 25,
      grade: 'F',
      autoFail: true,
      autoFailReasons: ['Secrecy directive detected (PI-002)'],
    },
    ...overrides,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// SARIF Report Validation
// ────────────────────────────────────────────────────────────────────────────
describe('SARIF Reporter', () => {
  it('produces valid JSON', () => {
    const output = generateSarifReport(makeMockResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('version is "2.1.0"', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    expect(parsed.version).toBe('2.1.0');
  });

  it('schema matches SARIF 2.1.0', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    expect(parsed.$schema).toBe(
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    );
  });

  it('tool driver name is "mcp-vet"', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    expect(parsed.runs[0].tool.driver.name).toBe('mcp-vet');
  });

  it('has 30 rules in runs[0].tool.driver.rules', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    const rules = parsed.runs[0].tool.driver.rules;
    expect(rules).toHaveLength(30);
  });

  it('all rule IDs are unique', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    const rules = parsed.runs[0].tool.driver.rules;
    const ids = rules.map((r: { id: string }) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('results contain ruleId matching finding IDs', () => {
    const result = makeMockResult();
    const parsed = JSON.parse(generateSarifReport(result));
    const resultRuleIds = parsed.runs[0].results.map((r: { ruleId: string }) => r.ruleId);
    const findingIds = result.findings.map((f) => f.id);

    for (const id of findingIds) {
      expect(resultRuleIds).toContain(id);
    }
  });

  it('results count matches findings count', () => {
    const result = makeMockResult();
    const parsed = JSON.parse(generateSarifReport(result));
    expect(parsed.runs[0].results).toHaveLength(result.findings.length);
  });

  it('maps CRITICAL severity to "error"', () => {
    const findings: Finding[] = [
      {
        id: 'PI-001',
        vector: 'PROMPT_INJECTION',
        severity: 'CRITICAL',
        title: 'Test',
        description: 'Test',
        toolName: 'test_tool',
        evidence: 'Test',
        recommendation: 'Test',
        confidence: 0.9,
      },
    ];
    const parsed = JSON.parse(generateSarifReport(makeMockResult({ findings })));
    expect(parsed.runs[0].results[0].level).toBe('error');
  });

  it('maps HIGH severity to "error"', () => {
    const findings: Finding[] = [
      {
        id: 'DE-001',
        vector: 'DATA_EXFILTRATION',
        severity: 'HIGH',
        title: 'Test',
        description: 'Test',
        toolName: 'test_tool',
        evidence: 'Test',
        recommendation: 'Test',
        confidence: 0.9,
      },
    ];
    const parsed = JSON.parse(generateSarifReport(makeMockResult({ findings })));
    expect(parsed.runs[0].results[0].level).toBe('error');
  });

  it('maps MEDIUM severity to "warning"', () => {
    const findings: Finding[] = [
      {
        id: 'DW-001',
        vector: 'DENIAL_OF_WALLET',
        severity: 'MEDIUM',
        title: 'Test',
        description: 'Test',
        toolName: 'test_tool',
        evidence: 'Test',
        recommendation: 'Test',
        confidence: 0.7,
      },
    ];
    const parsed = JSON.parse(generateSarifReport(makeMockResult({ findings })));
    expect(parsed.runs[0].results[0].level).toBe('warning');
  });

  it('maps LOW severity to "note"', () => {
    const findings: Finding[] = [
      {
        id: 'PE-001',
        vector: 'PRIVILEGE_ESCALATION',
        severity: 'LOW',
        title: 'Test',
        description: 'Test',
        toolName: 'test_tool',
        evidence: 'Test',
        recommendation: 'Test',
        confidence: 0.6,
      },
    ];
    const parsed = JSON.parse(generateSarifReport(makeMockResult({ findings })));
    expect(parsed.runs[0].results[0].level).toBe('note');
  });

  it('maps INFO severity to "note"', () => {
    const findings: Finding[] = [
      {
        id: 'TP-003',
        vector: 'TOOL_POISONING',
        severity: 'INFO',
        title: 'Test',
        description: 'Test',
        toolName: 'test_tool',
        evidence: 'Test',
        recommendation: 'Test',
        confidence: 0.5,
      },
    ];
    const parsed = JSON.parse(generateSarifReport(makeMockResult({ findings })));
    expect(parsed.runs[0].results[0].level).toBe('note');
  });

  it('clean result with no findings produces empty results array', () => {
    const result = makeMockResult({
      findings: [],
      score: {
        score: 100,
        grade: 'A',
        autoFail: false,
        autoFailReasons: [],
      },
    });
    const parsed = JSON.parse(generateSarifReport(result));
    expect(parsed.runs[0].results).toEqual([]);
  });

  it('clean result still includes all 30 rules', () => {
    const result = makeMockResult({
      findings: [],
      score: {
        score: 100,
        grade: 'A',
        autoFail: false,
        autoFailReasons: [],
      },
    });
    const parsed = JSON.parse(generateSarifReport(result));
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(30);
  });

  it('includes trust score properties in run', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    const properties = parsed.runs[0].properties;

    expect(properties).toHaveProperty('trustScore', 25);
    expect(properties).toHaveProperty('grade', 'F');
    expect(properties).toHaveProperty('autoFail', true);
  });

  it('each result includes properties with vector, confidence, evidence, and toolName', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));

    for (const result of parsed.runs[0].results) {
      expect(result.properties).toHaveProperty('vector');
      expect(result.properties).toHaveProperty('confidence');
      expect(result.properties).toHaveProperty('evidence');
      expect(result.properties).toHaveProperty('toolName');
    }
  });

  it('result message contains finding title and description', () => {
    const findings: Finding[] = [
      {
        id: 'PI-001',
        vector: 'PROMPT_INJECTION',
        severity: 'CRITICAL',
        title: 'Instruction Override Keywords',
        description: 'Tool contains override keywords',
        toolName: 'bad_tool',
        evidence: 'Found: ignore all previous instructions',
        recommendation: 'Remove override keywords',
        confidence: 0.95,
      },
    ];
    const parsed = JSON.parse(generateSarifReport(makeMockResult({ findings })));
    const message = parsed.runs[0].results[0].message.text;

    expect(message).toContain('Instruction Override Keywords');
    expect(message).toContain('Tool contains override keywords');
  });

  it('each rule has id, name, shortDescription, and defaultConfiguration', () => {
    const parsed = JSON.parse(generateSarifReport(makeMockResult()));
    const rules = parsed.runs[0].tool.driver.rules;

    for (const rule of rules) {
      expect(rule).toHaveProperty('id');
      expect(rule).toHaveProperty('name');
      expect(rule).toHaveProperty('shortDescription');
      expect(rule.shortDescription).toHaveProperty('text');
      expect(rule).toHaveProperty('defaultConfiguration');
      expect(rule.defaultConfiguration).toHaveProperty('level');
    }
  });
});
