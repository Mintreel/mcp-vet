import { describe, it, expect } from 'vitest';
import { analyzePythonFile } from './py-analyzer.js';
import { join } from 'node:path';
import { writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

const FIXTURES = join(process.cwd(), 'test-fixtures');
const TMP = join(tmpdir(), 'mcp-vet-py-test-' + Date.now());

function writeTmpPy(name: string, content: string): string {
  mkdirSync(TMP, { recursive: true });
  const path = join(TMP, name);
  writeFileSync(path, content);
  return path;
}

describe('Python AST analyzer', () => {
  // SC-001: Command Injection
  describe('SC-001: Command Injection', () => {
    it('detects f-string in os.system()', async () => {
      const file = join(FIXTURES, 'malicious/source-command-injection/dangerous.py');
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-001')).toBe(true);
    });

    it('ignores static string in os.system()', async () => {
      const file = writeTmpPy('static_cmd.py', `
import os
def run():
    os.system("echo hello")
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-001')).toBe(false);
    });

    it('ignores subprocess.run without shell=True', async () => {
      const file = writeTmpPy('safe_subprocess.py', `
import subprocess
def run(cmd):
    subprocess.run(["ls", cmd])
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-001')).toBe(false);
    });

    it('detects subprocess.run with shell=True and f-string', async () => {
      const file = writeTmpPy('shell_true.py', `
import subprocess
def run(cmd):
    subprocess.run(f"echo {cmd}", shell=True)
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-001')).toBe(true);
    });
  });

  // SC-002: SSRF
  describe('SC-002: SSRF', () => {
    it('detects unvalidated URL parameter in requests.get()', async () => {
      const file = writeTmpPy('ssrf.py', `
import requests
def fetch(url):
    return requests.get(url)
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-002')).toBe(true);
    });

    it('ignores hardcoded URL', async () => {
      const file = writeTmpPy('safe_fetch.py', `
import requests
def fetch():
    return requests.get("https://api.example.com/data")
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-002')).toBe(false);
    });

    it('ignores URL with validation in scope', async () => {
      const file = writeTmpPy('validated_fetch.py', `
import requests
from urllib.parse import urlparse
def fetch(url):
    parsed = urlparse(url)
    if not is_valid_url(parsed):
        raise ValueError("bad url")
    return requests.get(url)
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-002')).toBe(false);
    });
  });

  // SC-003: Path Traversal
  describe('SC-003: Path Traversal', () => {
    it('detects user-controlled path in open()', async () => {
      const file = join(FIXTURES, 'malicious/source-path-traversal/dangerous.py');
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-003')).toBe(true);
    });

    it('ignores open() with os.path.realpath validation', async () => {
      const file = writeTmpPy('safe_path.py', `
import os
def read(user_path):
    real = os.path.realpath(user_path)
    if not real.startswith("/allowed/"):
        raise ValueError("bad path")
    with open(real) as f:
        return f.read()
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-003')).toBe(false);
    });

    it('ignores open(__file__)', async () => {
      const file = writeTmpPy('self_read.py', `
import os
def read_self():
    with open(__file__) as f:
        return f.read()
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-003')).toBe(false);
    });
  });

  // SC-004: SQL Injection
  describe('SC-004: SQL Injection', () => {
    it('detects f-string in cursor.execute()', async () => {
      const file = writeTmpPy('sqli.py', `
def query(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-004')).toBe(true);
    });

    it('ignores parameterized query with %s', async () => {
      const file = writeTmpPy('safe_query.py', `
def query(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-004')).toBe(false);
    });

    it('ignores static SQL string', async () => {
      const file = writeTmpPy('static_query.py', `
def query(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")
`);
      const findings = await analyzePythonFile(file);
      expect(findings.some((f) => f.id === 'SC-004')).toBe(false);
    });
  });

  // Clean fixtures
  describe('clean fixtures', () => {
    it('produces no findings for safe.py', async () => {
      const file = join(FIXTURES, 'clean/source-safe/safe.py');
      const findings = await analyzePythonFile(file);
      expect(findings).toHaveLength(0);
    });
  });
});
