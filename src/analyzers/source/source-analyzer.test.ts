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

  it('still flags fetch with user-controlled base URL in template literal as SC-002', () => {
    const tmpFile = join(os.tmpdir(), `sc002-template-tainted-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      async function handler(req: any) {
        await fetch(\`\${req.params.baseUrl}/\${req.params.path}\`);
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

  it('reports SC-003 as MEDIUM (not HIGH) when path comes from internal helper (UNKNOWN taint)', () => {
    const tmpFile = join(os.tmpdir(), `sc003-unknown-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      function getCachePath(version: string): string {
        return '/cache/' + version + '.json';
      }
      function readCache(version: string) {
        const p = getCachePath(version);
        return fs.readFileSync(p, 'utf8');
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      if (sc003.length > 0) {
        expect(['LOW', 'MEDIUM']).toContain(sc003[0].severity);
        expect(sc003[0].confidence ?? 1).toBeLessThan(0.5);
      }
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('still flags SC-003 as HIGH when path is a direct function parameter', () => {
    const tmpFile = join(os.tmpdir(), `sc003-param-high-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      function readIt(args: { filePath: string }) {
        return fs.readFileSync(args.filePath, 'utf8');
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      expect(sc003.length).toBeGreaterThanOrEqual(1);
      expect(sc003[0].severity).toBe('HIGH');
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

// ────────────────────────────────────────────────────────────────────────────
// False positive regression tests
// ────────────────────────────────────────────────────────────────────────────
describe('FP regressions: SC-002 SSRF', () => {
  it('FP-1: does not flag fetch with hardcoded scheme+host template', () => {
    const tmpFile = join(os.tmpdir(), `fp1-hardcoded-host-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      async function getItem(id: string) {
        const res = await fetch(\`https://api.example.com/items/\${id}\`);
        return res.json();
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

  it('FP-1: does not flag fetch with safe const base URL template', () => {
    const tmpFile = join(os.tmpdir(), `fp1-const-base-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      const API_BASE = 'https://api.example.com';
      async function getItem(id: string) {
        const res = await fetch(\`\${API_BASE}/items/\${id}\`);
        return res.json();
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

  it('FP-1c: does not flag fetch when base URL is a cross-file import (module-level const)', () => {
    const tmpFile = join(os.tmpdir(), `fp1c-import-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import { AUTH_SERVER_URL } from './lib/constants.js';
      const authServerUrl = AUTH_SERVER_URL;
      async function handler() {
        await fetch(\`\${authServerUrl}/.well-known/oauth-authorization-server\`);
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

  it('FP-1d: does not flag fetch(url) where url is assigned a hardcoded-base template', () => {
    const tmpFile = join(os.tmpdir(), `fp1d-indirect-template-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      async function cacheApi(version: string) {
        const url = \`https://cdn.jsdelivr.net/npm/vuetify@\${version}/dist/json/web-types.json\`;
        const text = await fetch(url).then(r => r.text());
        return text;
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

  it('FP-2: does not flag fetch to localhost', () => {
    const tmpFile = join(os.tmpdir(), `fp2-localhost-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      async function healthCheck(port: number) {
        const res = await fetch(\`http://localhost:\${port}/api\`);
        return res.ok;
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
});

describe('FP regressions: SC-003 Path Traversal', () => {
  it('FP-3: does not flag readFileSync(join(__dirname, ...))', () => {
    const tmpFile = join(os.tmpdir(), `fp3-dirname-join-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import { join } from 'path';
      import { readFileSync } from 'fs';
      const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      expect(sc003.length).toBe(0);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('FP-4: does not flag constructor param used in method', () => {
    const tmpFile = join(os.tmpdir(), `fp4-constructor-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      class DB {
        private dbPath: string;
        constructor(dbPath: string) {
          this.dbPath = dbPath;
        }
        read() {
          return fs.readFileSync(this.dbPath, 'utf8');
        }
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

  it('FP-5: does not flag unlinkSync with UNKNOWN path', () => {
    const tmpFile = join(os.tmpdir(), `fp5-unlink-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import { unlinkSync } from 'fs';
      function cleanup() {
        const tmp = createTempFile();
        unlinkSync(tmp);
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

  it('FP-5: still flags fs.unlinkSync with TAINTED path', () => {
    const tmpFile = join(os.tmpdir(), `fp5-unlink-tainted-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      function handler(args: { filePath: string }) {
        fs.unlinkSync(args.filePath);
      }
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      expect(sc003.length).toBeGreaterThanOrEqual(1);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('FP-6: does not flag writeFileSync(process.argv[2], ...)', () => {
    const tmpFile = join(os.tmpdir(), `fp6-argv-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      fs.writeFileSync(process.argv[2], 'data');
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      expect(sc003.length).toBe(0);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('FP-3b: does not flag readFileSync(file) where file = join(dir, hardcoded-filename)', () => {
    const tmpFile = join(os.tmpdir(), `fp3b-join-hardcoded-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import { join } from 'path';
      import { readFileSync, existsSync } from 'fs';
      function getApi(version: string) {
        const dir = getApiCacheDir(version);
        const file = join(dir, 'web-types.json');
        if (existsSync(file) && version !== 'latest') {
          return readFileSync(file, 'utf8');
        }
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

  it('FP-7: does not flag forEach over hardcoded array', () => {
    const tmpFile = join(os.tmpdir(), `fp7-array-foreach-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import fs from 'fs';
      ['/a', '/b', '/c'].forEach(f => fs.accessSync(f));
    `);
    try {
      const findings = analyzeTypeScriptFile(tmpFile);
      const sc003 = findings.filter((f) => f.id === 'SC-003');
      expect(sc003.length).toBe(0);
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it('FP-8: does not flag when ensureExtension is in function body', () => {
    const tmpFile = join(os.tmpdir(), `fp8-ensure-${Date.now()}.ts`);
    writeFileSync(tmpFile, `
      import { unlinkSync } from 'fs';
      function removeFile(p: string) {
        const safe = ensureExtension(p, '.tmp');
        unlinkSync(safe);
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
