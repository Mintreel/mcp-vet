import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { runPipeline } from '../../src/pipeline.js';

const FIXTURES = join(process.cwd(), 'test-fixtures/real-world');

const SERVERS = [
  { file: 'server-github.json', name: 'github' },
  { file: 'server-filesystem.json', name: 'filesystem' },
  { file: 'server-fetch.json', name: 'fetch' },
  { file: 'server-memory.json', name: 'memory' },
  { file: 'server-postgres.json', name: 'postgres' },
];

describe('Real-world server validation', () => {
  for (const { file, name } of SERVERS) {
    describe(name, () => {
      it(`${name} scores Grade A or B`, async () => {
        const result = await runPipeline(join(FIXTURES, file), {
          cveCheck: false,
          sourceAnalysis: false,
        });

        expect(
          ['A', 'B'].includes(result.score.grade),
          `Expected ${name} to score A or B, got ${result.score.grade} (score: ${result.score.score}). Findings: ${JSON.stringify(result.findings.map((f) => `${f.id}: ${f.title}`), null, 2)}`,
        ).toBe(true);
      });

      it(`${name} has no CRITICAL findings`, async () => {
        const result = await runPipeline(join(FIXTURES, file), {
          cveCheck: false,
          sourceAnalysis: false,
        });

        const criticals = result.findings.filter((f) => f.severity === 'CRITICAL');
        expect(
          criticals,
          `Expected no CRITICAL findings for ${name}, found: ${JSON.stringify(criticals.map((f) => f.id))}`,
        ).toHaveLength(0);
      });

      it(`${name} does not auto-fail`, async () => {
        const result = await runPipeline(join(FIXTURES, file), {
          cveCheck: false,
          sourceAnalysis: false,
        });

        expect(
          result.score.autoFail,
          `Expected ${name} not to auto-fail, reasons: ${result.score.autoFailReasons.join(', ')}`,
        ).toBe(false);
      });
    });
  }
});
