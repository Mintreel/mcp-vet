import { describe, it, expect } from 'vitest';
import { formatJsonReport } from './json.js';
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
// JSON Report Validation
// ────────────────────────────────────────────────────────────────────────────
describe('JSON Reporter', () => {
  it('produces valid JSON', () => {
    const output = formatJsonReport(makeMockResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('contains score, grade, findings array, serverName, and scanTimestamp', () => {
    const result = makeMockResult();
    const parsed = JSON.parse(formatJsonReport(result));

    expect(parsed).toHaveProperty('score', 25);
    expect(parsed).toHaveProperty('grade', 'F');
    expect(parsed).toHaveProperty('serverName', 'test-server');
    expect(parsed).toHaveProperty('scanTimestamp');
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it('each finding has id, vector, severity, title, description, evidence, recommendation, and confidence', () => {
    const parsed = JSON.parse(formatJsonReport(makeMockResult()));

    for (const finding of parsed.findings) {
      expect(finding).toHaveProperty('id');
      expect(finding).toHaveProperty('vector');
      expect(finding).toHaveProperty('severity');
      expect(finding).toHaveProperty('title');
      expect(finding).toHaveProperty('description');
      expect(finding).toHaveProperty('evidence');
      expect(finding).toHaveProperty('recommendation');
      expect(finding).toHaveProperty('confidence');
    }
  });

  it('confidence values are between 0 and 1', () => {
    const parsed = JSON.parse(formatJsonReport(makeMockResult()));

    for (const finding of parsed.findings) {
      expect(finding.confidence).toBeGreaterThanOrEqual(0);
      expect(finding.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('preserves finding data accurately', () => {
    const result = makeMockResult();
    const parsed = JSON.parse(formatJsonReport(result));

    expect(parsed.findings).toHaveLength(result.findings.length);

    const first = parsed.findings[0];
    expect(first.id).toBe('PI-001');
    expect(first.vector).toBe('PROMPT_INJECTION');
    expect(first.severity).toBe('CRITICAL');
    expect(first.title).toBe('Instruction Override Keywords');
    expect(first.description).toBe('Tool contains override keywords');
    expect(first.evidence).toBe('Found: ignore all previous instructions');
    expect(first.recommendation).toBe('Remove override keywords');
    expect(first.confidence).toBe(0.95);
  });

  it('includes autoFail and autoFailReasons', () => {
    const parsed = JSON.parse(formatJsonReport(makeMockResult()));

    expect(parsed).toHaveProperty('autoFail', true);
    expect(parsed).toHaveProperty('autoFailReasons');
    expect(parsed.autoFailReasons).toContain('Secrecy directive detected (PI-002)');
  });

  it('includes serverVersion and mcpVetVersion', () => {
    const parsed = JSON.parse(formatJsonReport(makeMockResult()));

    expect(parsed).toHaveProperty('serverVersion', '1.0.0');
    expect(parsed).toHaveProperty('mcpVetVersion');
    expect(typeof parsed.mcpVetVersion).toBe('string');
  });

  it('clean result with no findings produces valid output with empty findings array', () => {
    const result = makeMockResult({
      findings: [],
      score: {
        score: 100,
        grade: 'A',
        autoFail: false,
        autoFailReasons: [],
      },
    });
    const parsed = JSON.parse(formatJsonReport(result));

    expect(parsed.findings).toEqual([]);
    expect(parsed.score).toBe(100);
    expect(parsed.grade).toBe('A');
    expect(parsed.autoFail).toBe(false);
    expect(parsed.autoFailReasons).toEqual([]);
  });

  it('handles findings with optional cveRef field', () => {
    const findings: Finding[] = [
      {
        id: 'SU-001',
        vector: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        title: 'Known CVE',
        description: 'Package has known CVE',
        toolName: 'vuln_tool',
        evidence: 'CVE-2024-1234',
        cveRef: 'CVE-2024-1234',
        recommendation: 'Update the package',
        confidence: 1.0,
      },
    ];
    const parsed = JSON.parse(formatJsonReport(makeMockResult({ findings })));

    expect(parsed.findings[0].cveRef).toBe('CVE-2024-1234');
  });
});
