import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { runPipeline } from '../../src/pipeline.js';

const FIXTURES = join(process.cwd(), 'test-fixtures');

describe('Pipeline Integration', () => {
  it('clean calculator scores A', async () => {
    const result = await runPipeline(join(FIXTURES, 'clean/simple-calculator.json'));
    expect(result.score.grade).toBe('A');
    expect(result.score.score).toBeGreaterThanOrEqual(90);
  });

  it('malicious override scores F with auto-fail', async () => {
    const result = await runPipeline(
      join(FIXTURES, 'malicious/prompt-injection-override.json'),
    );
    expect(result.score.grade).toBe('F');
    expect(result.score.autoFail).toBe(true);
    expect(result.findings.some((f) => f.id === 'PI-001')).toBe(true);
    expect(result.findings.some((f) => f.id === 'PI-002')).toBe(true);
    expect(result.findings.some((f) => f.id === 'PI-003')).toBe(true);
  });

  it('secrecy directive scores F', async () => {
    const result = await runPipeline(
      join(FIXTURES, 'malicious/prompt-injection-secrecy.json'),
    );
    expect(result.score.grade).toBe('F');
    expect(result.score.autoFailReasons).toContain('Secrecy directive detected (PI-002)');
  });

  it('empty server scores A', async () => {
    const result = await runPipeline(join(FIXTURES, 'edge-cases/empty-server.json'));
    expect(result.score.grade).toBe('A');
    expect(result.score.score).toBe(100);
  });

  it('ignore option suppresses rules', async () => {
    const result = await runPipeline(
      join(FIXTURES, 'malicious/prompt-injection-override.json'),
      { ignore: ['PI-001', 'PI-002', 'PI-003', 'DW-002'] },
    );
    expect(result.findings.every((f) => f.id !== 'PI-001')).toBe(true);
    expect(result.findings.every((f) => f.id !== 'PI-002')).toBe(true);
  });

  it('returns correct server name and version', async () => {
    const result = await runPipeline(join(FIXTURES, 'clean/simple-calculator.json'));
    expect(result.serverName).toBe('simple-calc');
    expect(result.serverVersion).toBe('1.0.0');
  });

  it('has a valid scan timestamp', async () => {
    const result = await runPipeline(join(FIXTURES, 'clean/simple-calculator.json'));
    const date = new Date(result.scanTimestamp);
    expect(date.getTime()).not.toBeNaN();
  });

  it('official filesystem server scores A', async () => {
    const result = await runPipeline(join(FIXTURES, 'clean/official-filesystem.json'));
    expect(result.score.grade).toBe('A');
  });

  it('legitimate long description still scores B or above', async () => {
    const result = await runPipeline(
      join(FIXTURES, 'clean/legitimate-long-description.json'),
    );
    // PI-005 may fire at MEDIUM for long descriptions, but grade should stay high
    expect(result.score.grade).toMatch(/^[AB]$/);
    expect(result.score.autoFail).toBeFalsy();
  });

  it('very large config (55 tools) completes in under 5 seconds', async () => {
    const start = Date.now();
    const result = await runPipeline(join(FIXTURES, 'edge-cases/very-large-config.json'));
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(5000);
    expect(result.score.grade).toBe('A');
  });

  it('well-written DB tool scores A or B', async () => {
    const result = await runPipeline(join(FIXTURES, 'clean/well-written-db-tool.json'));
    expect(result.score.grade).toMatch(/^[AB]$/);
  });
});
