import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { listRules } from './list-rules.js';
import { runDiff } from './diff.js';
import { showGraph } from './graph.js';

const FIXTURE_PATH = resolve(__dirname, '../../test-fixtures/clean/simple-calculator.json');

// The simple-calculator.json fixture has server name "simple-calc",
// so the snapshot will be at ~/.mcp-vet/snapshots/simple-calc.json
const SNAPSHOT_DIR = join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.mcp-vet',
  'snapshots',
);
const SNAPSHOT_PATH = join(SNAPSHOT_DIR, 'simple-calc.json');

// ────────────────────────────────────────────────────────────────────────────
// list-rules
// ────────────────────────────────────────────────────────────────────────────
describe('listRules', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('outputs all 30 rules total', () => {
    listRules();

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('30 rules total');
  });

  it('outputs prompt injection rule IDs (PI-001)', () => {
    listRules();

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('PI-001');
  });

  it('outputs source code analysis rule IDs (SC-004)', () => {
    listRules();

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('SC-004');
  });

  it('includes rule vectors and severities', () => {
    listRules();

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('PROMPT_INJECTION');
    expect(allOutput).toContain('CRITICAL');
    expect(allOutput).toContain('SUPPLY_CHAIN');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// diff
// ────────────────────────────────────────────────────────────────────────────
describe('runDiff', () => {
  function cleanupSnapshot() {
    try {
      if (existsSync(SNAPSHOT_PATH)) {
        unlinkSync(SNAPSHOT_PATH);
      }
    } catch {
      // ignore cleanup errors
    }
  }

  beforeEach(() => {
    cleanupSnapshot();
  });

  afterEach(() => {
    cleanupSnapshot();
  });

  it('first run creates snapshot and returns isFirstRun: true with empty findings', () => {
    const result = runDiff(FIXTURE_PATH);

    expect(result.isFirstRun).toBe(true);
    expect(result.findings).toEqual([]);
    expect(existsSync(SNAPSHOT_PATH)).toBe(true);
  });

  it('second run with same data returns isFirstRun: false with empty findings', () => {
    // First run — creates the snapshot
    const first = runDiff(FIXTURE_PATH);
    expect(first.isFirstRun).toBe(true);

    // Second run — compares against existing snapshot, no changes
    const second = runDiff(FIXTURE_PATH);
    expect(second.isFirstRun).toBe(false);
    expect(second.findings).toEqual([]);
  });

  it('detects description changes between scans', () => {
    // First run with the original fixture
    runDiff(FIXTURE_PATH);

    // Manually modify the snapshot to simulate a description change
    const { readFileSync, writeFileSync } = require('node:fs');
    const snap = JSON.parse(readFileSync(SNAPSHOT_PATH, 'utf-8'));
    // Change a tool hash to simulate a description change
    const toolNames = Object.keys(snap.tools);
    if (toolNames.length > 0) {
      snap.tools[toolNames[0]] = 'aaaaaaaaaaaaaaaa'; // fake old hash
    }
    writeFileSync(SNAPSHOT_PATH, JSON.stringify(snap));

    const result = runDiff(FIXTURE_PATH);
    expect(result.isFirstRun).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].title).toBe('Description Changed');
    expect(result.findings[0].id).toBe('TP-003');
  });

  it('detects new tools added since snapshot', () => {
    // First run
    runDiff(FIXTURE_PATH);

    // Remove a tool from the snapshot to simulate a tool being added
    const { readFileSync, writeFileSync } = require('node:fs');
    const snap = JSON.parse(readFileSync(SNAPSHOT_PATH, 'utf-8'));
    const toolNames = Object.keys(snap.tools);
    if (toolNames.length > 1) {
      delete snap.tools[toolNames[toolNames.length - 1]];
    }
    writeFileSync(SNAPSHOT_PATH, JSON.stringify(snap));

    const result = runDiff(FIXTURE_PATH);
    expect(result.isFirstRun).toBe(false);
    const newToolFinding = result.findings.find((f) => f.title === 'New Tool Added');
    expect(newToolFinding).toBeDefined();
    expect(newToolFinding!.id).toBe('TP-003');
  });

  it('detects removed tools since snapshot', () => {
    // First run
    runDiff(FIXTURE_PATH);

    // Add a fake tool to the snapshot to simulate a tool being removed
    const { readFileSync, writeFileSync } = require('node:fs');
    const snap = JSON.parse(readFileSync(SNAPSHOT_PATH, 'utf-8'));
    snap.tools['fake_removed_tool'] = 'deadbeef12345678';
    writeFileSync(SNAPSHOT_PATH, JSON.stringify(snap));

    const result = runDiff(FIXTURE_PATH);
    expect(result.isFirstRun).toBe(false);
    const removedFinding = result.findings.find((f) => f.title === 'Tool Removed');
    expect(removedFinding).toBeDefined();
    expect(removedFinding!.toolName).toBe('fake_removed_tool');
  });

  it('escalates to CRITICAL when changed description has injection patterns', () => {
    // Use the malicious fixture to get a snapshot with injection patterns
    const maliciousPath = resolve(
      __dirname,
      '../../test-fixtures/malicious/prompt-injection-override.json',
    );
    const maliciousSnapPath = join(SNAPSHOT_DIR, 'evil-calculator.json');

    try {
      // First run creates snapshot
      runDiff(maliciousPath);

      // Modify snapshot to simulate a previous benign description
      const { readFileSync, writeFileSync } = require('node:fs');
      const snap = JSON.parse(readFileSync(maliciousSnapPath, 'utf-8'));
      const toolNames = Object.keys(snap.tools);
      if (toolNames.length > 0) {
        snap.tools[toolNames[0]] = 'bbbbbbbbbbbbbbbb'; // fake old hash
      }
      writeFileSync(maliciousSnapPath, JSON.stringify(snap));

      const result = runDiff(maliciousPath);
      const criticalFinding = result.findings.find((f) => f.severity === 'CRITICAL');
      expect(criticalFinding).toBeDefined();
      expect(criticalFinding!.description).toContain('injection patterns');
    } finally {
      try {
        unlinkSync(maliciousSnapPath);
      } catch {
        // ignore
      }
    }
  });
});

// ────────────────────────────────────────────────────────────────────────────
// graph
// ────────────────────────────────────────────────────────────────────────────
describe('showGraph', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('outputs capability graph heading', () => {
    showGraph(FIXTURE_PATH);

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('capability graph');
  });

  it('shows capabilities for filesystem server', () => {
    const fsFixture = resolve(
      __dirname,
      '../../test-fixtures/clean/official-filesystem.json',
    );
    showGraph(fsFixture);

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('Capabilities:');
    expect(allOutput).toContain('read_file');
    expect(allOutput).toContain('READ_FILES');
  });

  it('shows "No capabilities" for empty server', () => {
    const emptyFixture = resolve(
      __dirname,
      '../../test-fixtures/edge-cases/empty-server.json',
    );
    showGraph(emptyFixture);

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('No capabilities detected');
  });

  it('shows single-server note when only one server with capabilities', () => {
    const fsFixture = resolve(
      __dirname,
      '../../test-fixtures/clean/official-filesystem.json',
    );
    showGraph(fsFixture);

    const allOutput = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allOutput).toContain('Toxic flow analysis requires multi-server configs');
  });
});
