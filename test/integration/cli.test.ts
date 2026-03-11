import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const CLI = join(process.cwd(), 'dist/cli.js');
const FIXTURES = join(process.cwd(), 'test-fixtures');

function run(args: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execSync(`node ${CLI} ${args}`, {
      encoding: 'utf-8',
      timeout: 30000,
    });
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; status?: number };
    return { stdout: e.stdout || '', exitCode: e.status || 1 };
  }
}

describe('CLI Integration', () => {
  it('shows version', () => {
    const { stdout } = run('--version');
    expect(stdout.trim()).toBe('0.1.0');
  });

  it('no-args with no configs exits 0 with helpful message', () => {
    const { stdout, exitCode } = run('--project');
    // --project scans only CWD project configs; in test env there are none
    expect(exitCode).toBe(0);
    expect(stdout).toContain('No MCP server configs found');
    expect(stdout).toContain('~/.claude/claude_desktop_config.json');
    expect(stdout).toContain('npx mcp-vet audit');
    expect(stdout).toContain('list-rules');
  });

  it('clean server gets grade A', () => {
    const { stdout, exitCode } = run(`audit ${FIXTURES}/clean/simple-calculator.json`);
    expect(stdout).toContain('Grade:');
    expect(stdout).toMatch(/A/);
    expect(exitCode).toBe(0);
  });

  it('malicious server gets grade F', () => {
    const { stdout } = run(`audit ${FIXTURES}/malicious/prompt-injection-override.json`);
    expect(stdout).toContain('AUTO-FAIL');
    expect(stdout).toMatch(/F/);
  });

  it('--ci exits 1 on critical/high findings', () => {
    const { exitCode } = run(
      `audit ${FIXTURES}/malicious/prompt-injection-override.json --ci`,
    );
    expect(exitCode).toBe(1);
  });

  it('--ci exits 0 on clean server', () => {
    const { exitCode } = run(`audit ${FIXTURES}/clean/simple-calculator.json --ci`);
    expect(exitCode).toBe(0);
  });

  it('--json produces valid JSON', () => {
    const { stdout } = run(
      `audit ${FIXTURES}/malicious/prompt-injection-override.json --json`,
    );
    const parsed = JSON.parse(stdout);
    expect(parsed.score).toBeTypeOf('number');
    expect(parsed.grade).toMatch(/^[A-F]$/);
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it('--json output has required fields', () => {
    const { stdout } = run(
      `audit ${FIXTURES}/malicious/prompt-injection-override.json --json`,
    );
    const parsed = JSON.parse(stdout);
    expect(parsed.serverName).toBe('evil-calculator');
    expect(parsed.findings.length).toBeGreaterThan(0);
    for (const f of parsed.findings) {
      expect(f.id).toBeDefined();
      expect(f.vector).toBeDefined();
      expect(f.severity).toBeDefined();
      expect(f.title).toBeDefined();
      expect(f.description).toBeDefined();
      expect(f.evidence).toBeDefined();
      expect(f.recommendation).toBeDefined();
      expect(f.confidence).toBeGreaterThanOrEqual(0);
      expect(f.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('--report creates HTML file', () => {
    const htmlPath = '/tmp/mcp-vet-integration-test.html';
    if (existsSync(htmlPath)) unlinkSync(htmlPath);

    run(`audit ${FIXTURES}/clean/simple-calculator.json --report ${htmlPath}`);

    expect(existsSync(htmlPath)).toBe(true);
    const html = readFileSync(htmlPath, 'utf-8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('mcp-vet');
    expect(html).toContain('Trust Score');
    // Self-contained: no external stylesheets
    expect(html).not.toMatch(/<link\s+rel="stylesheet"/);
    unlinkSync(htmlPath);
  });

  it('--sarif creates valid SARIF 2.1.0 file', () => {
    const sarifPath = '/tmp/mcp-vet-integration-test.sarif';
    if (existsSync(sarifPath)) unlinkSync(sarifPath);

    run(`audit ${FIXTURES}/malicious/prompt-injection-override.json --sarif ${sarifPath}`);

    expect(existsSync(sarifPath)).toBe(true);
    const sarif = JSON.parse(readFileSync(sarifPath, 'utf-8'));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('mcp-vet');
    expect(sarif.runs[0].tool.driver.rules.length).toBe(30);
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);

    // Severity mapping
    for (const result of sarif.runs[0].results) {
      expect(['error', 'warning', 'note']).toContain(result.level);
    }

    unlinkSync(sarifPath);
  });

  it('list-rules shows 30 rules', () => {
    const { stdout } = run('list-rules');
    expect(stdout).toContain('30 rules total');
    expect(stdout).toContain('PI-001');
    expect(stdout).toContain('SC-004');
    expect(stdout).toContain('SU-003');
  });

  it('invalid path exits with code 2', () => {
    const { exitCode } = run('audit /nonexistent/file.json');
    expect(exitCode).toBe(2);
  });

  it('empty server gets grade A', () => {
    const { stdout } = run(`audit ${FIXTURES}/edge-cases/empty-server.json`);
    expect(stdout).toMatch(/A/);
  });

  it('malicious without --ci exits 0', () => {
    const { stdout, exitCode } = run(
      `audit ${FIXTURES}/malicious/prompt-injection-override.json`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain('AUTO-FAIL');
  });

  it('diff creates snapshot on first run', () => {
    const snapshotPath = join(
      process.env.HOME || process.env.USERPROFILE || '.',
      '.mcp-vet',
      'snapshots',
      'simple-calc.json',
    );
    // Clean up any existing snapshot to ensure first-run behavior
    if (existsSync(snapshotPath)) unlinkSync(snapshotPath);

    try {
      const { stdout, exitCode } = run(`diff ${FIXTURES}/clean/simple-calculator.json`);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('Snapshot created');
      expect(existsSync(snapshotPath)).toBe(true);
    } finally {
      // Always clean up to avoid affecting other test runs
      if (existsSync(snapshotPath)) unlinkSync(snapshotPath);
    }
  });

  it('graph shows capability info', () => {
    const { stdout, exitCode } = run(`graph ${FIXTURES}/clean/simple-calculator.json`);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('capability graph');
  });

  it('--no-source skips SC rules', () => {
    const { stdout, exitCode } = run(
      `audit ${FIXTURES}/malicious/prompt-injection-override.json --no-source --json`,
    );
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const scFindings = parsed.findings.filter((f: { id: string }) =>
      f.id.startsWith('SC-'),
    );
    expect(scFindings.length).toBe(0);
  });

  it('--no-cve skips SU-001', () => {
    const { stdout, exitCode } = run(
      `audit ${FIXTURES}/clean/simple-calculator.json --no-cve --json`,
    );
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const su001Findings = parsed.findings.filter(
      (f: { id: string }) => f.id === 'SU-001',
    );
    expect(su001Findings.length).toBe(0);
  });
});
