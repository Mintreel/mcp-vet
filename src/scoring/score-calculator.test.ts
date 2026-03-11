import { describe, it, expect } from 'vitest';
import { calculateScore, checkAutoFail } from './score-calculator.js';
import type { Finding } from '../types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'PI-001',
    vector: 'PROMPT_INJECTION',
    severity: 'CRITICAL',
    title: 'Test finding',
    description: 'Test',
    toolName: 'test-tool',
    evidence: 'test evidence',
    recommendation: 'Fix it',
    confidence: 0.9,
    ...overrides,
  };
}

describe('calculateScore', () => {
  it('returns 100/A for no findings', () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
    expect(result.autoFail).toBe(false);
  });

  it('deducts for a single CRITICAL finding', () => {
    const findings = [makeFinding({ severity: 'CRITICAL', confidence: 0.9 })];
    const result = calculateScore(findings);
    // deduction = 25 * 0.9 * 1.0 = 22.5 → score ~78 → B
    expect(result.score).toBe(78);
    expect(result.grade).toBe('B');
  });

  it('deducts for multiple findings across vectors', () => {
    const findings = [
      makeFinding({ id: 'PI-001', vector: 'PROMPT_INJECTION', severity: 'CRITICAL', confidence: 0.9 }),
      makeFinding({ id: 'DE-001', vector: 'DATA_EXFILTRATION', severity: 'HIGH', confidence: 0.75 }),
      makeFinding({ id: 'DW-002', vector: 'DENIAL_OF_WALLET', severity: 'MEDIUM', confidence: 0.6 }),
    ];
    const result = calculateScore(findings);
    // PI: 25*0.9*1.0=22.5, DE: 15*0.75*0.5=5.625, DW: 8*0.6*0.25=1.2 → total=29.325 → ~71 → C
    expect(result.grade).toBe('C');
  });

  it('auto-fails on PI-002 secrecy directive', () => {
    const findings = [makeFinding({ id: 'PI-002', severity: 'CRITICAL', confidence: 0.95 })];
    const result = calculateScore(findings);
    expect(result.grade).toBe('F');
    expect(result.autoFail).toBe(true);
    expect(result.autoFailReasons).toContain('Secrecy directive detected (PI-002)');
  });

  it('auto-fails on PI-004 with >50 hidden chars', () => {
    const findings = [
      makeFinding({
        id: 'PI-004',
        severity: 'CRITICAL',
        confidence: 0.98,
        evidence: 'Found 75 hidden Unicode characters',
      }),
    ];
    const result = calculateScore(findings);
    expect(result.grade).toBe('F');
    expect(result.autoFail).toBe(true);
  });

  it('does not auto-fail on PI-004 with <=50 hidden chars', () => {
    const findings = [
      makeFinding({
        id: 'PI-004',
        severity: 'CRITICAL',
        confidence: 0.98,
        evidence: 'Found 10 hidden Unicode characters',
      }),
    ];
    const result = calculateScore(findings);
    expect(result.autoFailReasons).not.toContain(
      expect.stringContaining('PI-004'),
    );
  });

  it('auto-fails on TS-001 cross-server override', () => {
    const findings = [
      makeFinding({
        id: 'TS-001',
        vector: 'CROSS_SERVER_SHADOWING',
        severity: 'CRITICAL',
        confidence: 0.85,
      }),
    ];
    const result = calculateScore(findings);
    expect(result.grade).toBe('F');
    expect(result.autoFail).toBe(true);
  });

  it('auto-fails on SC-001 command injection', () => {
    const findings = [
      makeFinding({
        id: 'SC-001',
        vector: 'IMPLEMENTATION_VULN',
        severity: 'CRITICAL',
        confidence: 0.85,
      }),
    ];
    const result = calculateScore(findings);
    expect(result.grade).toBe('F');
    expect(result.autoFail).toBe(true);
  });

  it('auto-fails on SU-001 with CVSS >= 9.0', () => {
    const findings = [
      makeFinding({
        id: 'SU-001',
        vector: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 1.0,
        evidence: 'CVE-2025-6514 (CVSS: 9.6)',
      }),
    ];
    const result = calculateScore(findings);
    expect(result.grade).toBe('F');
    expect(result.autoFail).toBe(true);
  });

  it('auto-fails on 3+ CRITICAL from different vectors', () => {
    const findings = [
      makeFinding({ id: 'PI-001', vector: 'PROMPT_INJECTION', severity: 'CRITICAL' }),
      makeFinding({ id: 'TS-003', vector: 'CROSS_SERVER_SHADOWING', severity: 'CRITICAL', confidence: 0.5 }),
      makeFinding({ id: 'SC-001', vector: 'IMPLEMENTATION_VULN', severity: 'CRITICAL' }),
    ];
    const result = calculateScore(findings);
    expect(result.grade).toBe('F');
    expect(result.autoFail).toBe(true);
    expect(result.autoFailReasons).toContain('3+ CRITICAL findings from different attack vectors');
  });

  it('floors score at 0', () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding({
        id: `PI-00${i}`,
        severity: 'CRITICAL',
        confidence: 0.9,
      }),
    );
    const result = calculateScore(findings);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('F');
  });

  it('confidence affects deduction magnitude', () => {
    const lowConf = calculateScore([makeFinding({ confidence: 0.5 })]);
    const highConf = calculateScore([makeFinding({ confidence: 0.9 })]);
    expect(lowConf.score).toBeGreaterThan(highConf.score);
  });

  it('vector weight affects deduction magnitude', () => {
    const pi = calculateScore([
      makeFinding({ vector: 'PROMPT_INJECTION', severity: 'HIGH', confidence: 0.8 }),
    ]);
    const dw = calculateScore([
      makeFinding({ vector: 'DENIAL_OF_WALLET', severity: 'HIGH', confidence: 0.8 }),
    ]);
    // PI weight 1.0 > DW weight 0.25, so PI should have lower score
    expect(pi.score).toBeLessThan(dw.score);
  });
});
