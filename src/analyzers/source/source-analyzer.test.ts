import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import os from 'node:os';
import { writeFileSync, unlinkSync } from 'node:fs';
import { analyzeTypeScriptFile } from './ts-analyzer.js';
import { analyzePythonFile } from './py-analyzer.js';

const FIXTURES = join(process.cwd(), 'test-fixtures/malicious');
const ROOT_FIXTURES = join(process.cwd(), 'test-fixtures');

describe('SC-001: Command Injection', () => {
  it('detects template literal in exec()', () => {
    const findings = analyzeTypeScriptFile(join(FIXTURES, 'source-command-injection/dangerous.ts'));
    const sc001 = findings.filter((f) => f.id === 'SC-001');
    expect(sc001.length).toBeGreaterThanOrEqual(1);
    expect(sc001[0].severity).toBe('CRITICAL');
  });

  it('does not flag static string in execSync()', () => {
    const findings = analyzeTypeScriptFile(join(FIXTURES, 'source-command-injection/safe.ts'));
    const sc001 = findings.filter((f) => f.id === 'SC-001');
    expect(sc001.length).toBe(0);
  });

  it('detects Python f-string in os.system()', async () => {
    const findings = await analyzePythonFile(join(FIXTURES, 'source-command-injection/dangerous.py'));
    const sc001 = findings.filter((f) => f.id === 'SC-001');
    expect(sc001.length).toBeGreaterThanOrEqual(1);
    expect(sc001[0].severity).toBe('CRITICAL');
  });

  it('does not flag Python subprocess.run with list arguments (safe)', async () => {
    const findings = await analyzePythonFile(join(ROOT_FIXTURES, 'source-cmd-injection/safe.py'));
    const sc001 = findings.filter((f) => f.id === 'SC-001');
    expect(sc001.length).toBe(0);
  });

  it('does not flag static variable reassignment passed to exec()', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-command-injection/edge-static.ts'),
    );
    const sc001 = findings.filter((f) => f.id === 'SC-001');
    expect(sc001.length).toBe(0);
  });

  // The current analyzer resolves sink functions by call expression name only.
  // Aliased functions (const run = exec; run(input)) are not matched because
  // "run" does not appear in the EXEC_SINKS list. This test documents the
  // known limitation and should be unskipped when alias resolution is added.
  it.todo('detects aliased exec function with tainted argument', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-command-injection/edge-alias.ts'),
    );
    const sc001 = findings.filter((f) => f.id === 'SC-001');
    expect(sc001.length).toBeGreaterThanOrEqual(1);
    expect(sc001[0].severity).toBe('CRITICAL');
  });
});

describe('SC-002: SSRF', () => {
  it('detects unvalidated URL in fetch()', () => {
    const findings = analyzeTypeScriptFile(join(FIXTURES, 'source-ssrf/dangerous.ts'));
    const sc002 = findings.filter((f) => f.id === 'SC-002');
    expect(sc002.length).toBeGreaterThanOrEqual(1);
    expect(sc002[0].severity).toBe('HIGH');
  });

  it('does not flag static URL in fetch()', () => {
    const findings = analyzeTypeScriptFile(join(FIXTURES, 'source-ssrf/safe.ts'));
    const sc002 = findings.filter((f) => f.id === 'SC-002');
    expect(sc002.length).toBe(0);
  });

  it('detects Python unvalidated URL in urllib.request.urlopen()', async () => {
    const findings = await analyzePythonFile(join(FIXTURES, 'source-ssrf/dangerous.py'));
    const sc002 = findings.filter((f) => f.id === 'SC-002');
    expect(sc002.length).toBeGreaterThanOrEqual(1);
    expect(sc002[0].severity).toBe('HIGH');
  });

  it('does not flag fetch() when validateUrl() is called first', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-ssrf/edge-validated.ts'),
    );
    const sc002 = findings.filter((f) => f.id === 'SC-002');
    expect(sc002.length).toBe(0);
  });

  it('does not flag fetch() when allowlist check is present', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-ssrf/edge-allowlist.ts'),
    );
    const sc002 = findings.filter((f) => f.id === 'SC-002');
    expect(sc002.length).toBe(0);
  });

  it('does not flag fetch with hardcoded-base-URL template literal as SC-002', () => {
    const tmpFile = join(os.tmpdir(), `sc002-template-safe-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      const API_SERVER = 'https://api.example.com';
      async function log(id: string) {
        const fixedPath = '/one/mcp/log';
        await fetch(\`\${API_SERVER}\${fixedPath}\`);
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc002 = findings.filter((f) => f.id === 'SC-002');
      expect(sc002.length).toBe(0);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('still flags fetch with user-controlled path in template literal as SC-002', () => {
    const tmpFile = join(os.tmpdir(), `sc002-template-tainted-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      const BASE = 'https://api.example.com';
      async function handler(req: any) {
        await fetch(\`\${BASE}/\${req.params.path}\`);
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc002 = findings.filter((f) => f.id === 'SC-002');
      expect(sc002.length).toBeGreaterThanOrEqual(1);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('still flags fetch(userUrl) function parameter as SC-002', () => {
    const tmpFile = join(os.tmpdir(), `sc002-param-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      async function handler(userUrl: string) {
        await fetch(userUrl);
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc002 = findings.filter((f) => f.id === 'SC-002');
      expect(sc002.length).toBeGreaterThanOrEqual(1);
    } finally {
      unlinkSync(tmpFile);
    }
  });
});

describe('SC-003: Path Traversal', () => {
  it('detects unvalidated path in readFileSync()', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-path-traversal/dangerous.ts'),
    );
    const sc003 = findings.filter((f) => f.id === 'SC-003');
    expect(sc003.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag static path or properly validated path', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-path-traversal/safe.ts'),
    );
    const sc003 = findings.filter((f) => f.id === 'SC-003');
    expect(sc003.length).toBe(0);
  });

  it('flags startsWith without path.resolve as prefix bypass (HIGH)', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-path-traversal/edge-prefix-only.ts'),
    );
    const sc003 = findings.filter((f) => f.id === 'SC-003');
    expect(sc003.length).toBeGreaterThanOrEqual(1);
    expect(sc003[0].severity).toBe('HIGH');
    expect(sc003[0].title).toContain('Prefix Bypass');
  });

  it('does not flag path.resolve() + startsWith() (proper containment)', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-path-traversal/edge-proper-resolve.ts'),
    );
    const sc003 = findings.filter((f) => f.id === 'SC-003');
    expect(sc003.length).toBe(0);
  });

  it('does not flag realpathSync before file access', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-path-traversal/edge-realpath.ts'),
    );
    const sc003 = findings.filter((f) => f.id === 'SC-003');
    expect(sc003.length).toBe(0);
  });

  it('does not flag readdirSync with any path as SC-003', () => {
    const tmpFile = join(os.tmpdir(), `readdirSync-test-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      function list(startPath: string) {
        return fs.readdirSync(startPath);
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      expect(sc003.length).toBe(0);
    } finally {
      unlinkSync(tmpFile);
    }
  });
});

describe('SC-004: SQL Injection', () => {
  it('detects template literal in db.query()', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-sql-injection/dangerous.ts'),
    );
    const sc004 = findings.filter((f) => f.id === 'SC-004');
    expect(sc004.length).toBeGreaterThanOrEqual(1);
    expect(sc004[0].severity).toBe('HIGH');
  });

  it('detects Python f-string in cursor.execute()', async () => {
    const findings = await analyzePythonFile(join(FIXTURES, 'source-sql-injection/dangerous.py'));
    const sc004 = findings.filter((f) => f.id === 'SC-004');
    expect(sc004.length).toBeGreaterThanOrEqual(1);
    expect(sc004[0].severity).toBe('HIGH');
  });

  it('does not flag parameterized query', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-sql-injection/safe.ts'),
    );
    const sc004 = findings.filter((f) => f.id === 'SC-004');
    expect(sc004.length).toBe(0);
  });

  it('does not flag tagged template literal (parameterized by tag function)', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-sql-injection/edge-tagged-template.ts'),
    );
    const sc004 = findings.filter((f) => f.id === 'SC-004');
    expect(sc004.length).toBe(0);
  });

  it('detects string concatenation in db.query()', () => {
    const findings = analyzeTypeScriptFile(
      join(FIXTURES, 'source-sql-injection/edge-concat.ts'),
    );
    const sc004 = findings.filter((f) => f.id === 'SC-004');
    expect(sc004.length).toBeGreaterThanOrEqual(1);
    expect(sc004[0].severity).toBe('HIGH');
  });
});
