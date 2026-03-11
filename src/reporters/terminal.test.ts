import { describe, it, expect } from 'vitest';
import { formatTerminalReport, formatMultiServerReport } from './terminal.js';
import type { PipelineResult, MultiPipelineResult, Finding } from '../types.js';

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
// Terminal Report Validation
// ────────────────────────────────────────────────────────────────────────────
describe('Terminal Reporter', () => {
  it('contains server name', () => {
    const result = makeMockResult({ serverName: 'my-custom-server' });
    const output = formatTerminalReport(result);
    expect(output).toContain('my-custom-server');
  });

  it('contains grade letter', () => {
    const output = formatTerminalReport(makeMockResult());
    expect(output).toContain('F');

    const outputC = formatTerminalReport(
      makeMockResult({
        score: { score: 72, grade: 'C', autoFail: false, autoFailReasons: [] },
      }),
    );
    expect(outputC).toContain('C');
  });

  it('contains trust score number', () => {
    const output = formatTerminalReport(makeMockResult());
    expect(output).toContain('25/100');

    const output85 = formatTerminalReport(
      makeMockResult({
        score: { score: 85, grade: 'B', autoFail: false, autoFailReasons: [] },
      }),
    );
    expect(output85).toContain('85/100');
  });

  it('lists finding IDs', () => {
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
    ];

    const output = formatTerminalReport(makeMockResult({ findings }));
    for (const finding of findings) {
      expect(output).toContain(finding.id);
    }
  });

  it('shows severity labels (CRITICAL, HIGH, etc.)', () => {
    const findings: Finding[] = [
      {
        id: 'PI-001',
        vector: 'PROMPT_INJECTION',
        severity: 'CRITICAL',
        title: 'Override',
        description: 'desc',
        toolName: 'tool',
        evidence: 'ev',
        recommendation: 'rec',
        confidence: 0.9,
      },
      {
        id: 'DE-001',
        vector: 'DATA_EXFILTRATION',
        severity: 'HIGH',
        title: 'Exfil',
        description: 'desc',
        toolName: 'tool',
        evidence: 'ev',
        recommendation: 'rec',
        confidence: 0.8,
      },
      {
        id: 'PE-001',
        vector: 'PRIVILEGE_ESCALATION',
        severity: 'MEDIUM',
        title: 'Escalation',
        description: 'desc',
        toolName: 'tool',
        evidence: 'ev',
        recommendation: 'rec',
        confidence: 0.7,
      },
    ];

    const output = formatTerminalReport(makeMockResult({ findings }));
    expect(output).toContain('CRITICAL');
    expect(output).toContain('HIGH');
    expect(output).toContain('MEDIUM');
  });

  it('shows AUTO-FAIL when autoFail is true', () => {
    const result = makeMockResult({
      score: {
        score: 10,
        grade: 'F',
        autoFail: true,
        autoFailReasons: ['Secrecy directive detected (PI-002)'],
      },
    });
    const output = formatTerminalReport(result);
    expect(output).toContain('AUTO-FAIL');
    expect(output).toContain('Secrecy directive detected (PI-002)');
  });

  it('clean result (no findings) shows grade A and no findings section', () => {
    const result = makeMockResult({
      findings: [],
      score: {
        score: 100,
        grade: 'A',
        autoFail: false,
        autoFailReasons: [],
      },
    });
    const output = formatTerminalReport(result);
    expect(output).toContain('A');
    expect(output).toContain('100/100');
    expect(output).toContain('No security issues found');
  });

  it('shows recommendation text', () => {
    const findings: Finding[] = [
      {
        id: 'PI-001',
        vector: 'PROMPT_INJECTION',
        severity: 'CRITICAL',
        title: 'Instruction Override Keywords',
        description: 'Tool contains override keywords',
        toolName: 'bad_tool',
        evidence: 'Found: ignore all previous instructions',
        recommendation: 'Remove override keywords from the tool description',
        confidence: 0.95,
      },
      {
        id: 'DE-002',
        vector: 'DATA_EXFILTRATION',
        severity: 'HIGH',
        title: 'Credential-Harvesting Parameters',
        description: 'Tool requests credential parameters',
        toolName: 'cred_tool',
        evidence: 'Found: api_key parameter',
        recommendation: 'Avoid requesting credentials in non-auth tools',
        confidence: 0.85,
      },
    ];

    const output = formatTerminalReport(makeMockResult({ findings }));
    for (const finding of findings) {
      expect(output).toContain(finding.recommendation);
    }
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Multi-Server Report Validation
// ────────────────────────────────────────────────────────────────────────────
describe('Multi-Server Terminal Reporter', () => {
  function makeMultiResult(overrides: Partial<MultiPipelineResult> = {}): MultiPipelineResult {
    return {
      results: [
        {
          serverName: 'github',
          serverVersion: '1.0.0',
          findings: [],
          score: { score: 100, grade: 'A', autoFail: false, autoFailReasons: [] },
          scanTimestamp: new Date().toISOString(),
        },
        {
          serverName: 'filesystem',
          serverVersion: '1.0.0',
          findings: [
            {
              id: 'DE-001',
              vector: 'DATA_EXFILTRATION',
              severity: 'MEDIUM',
              title: 'External URL',
              description: 'desc',
              toolName: 'fetch',
              evidence: 'ev',
              recommendation: 'rec',
              confidence: 0.7,
            },
          ],
          score: { score: 92, grade: 'A', autoFail: false, autoFailReasons: [] },
          scanTimestamp: new Date().toISOString(),
        },
      ],
      combinedFindings: [
        {
          id: 'DE-001',
          vector: 'DATA_EXFILTRATION',
          severity: 'MEDIUM',
          title: 'External URL',
          description: 'desc',
          toolName: 'fetch',
          evidence: 'ev',
          recommendation: 'rec',
          confidence: 0.7,
        },
      ],
      combinedScore: { score: 96, grade: 'A', autoFail: false, autoFailReasons: [] },
      discoveredConfigs: ['/home/.claude/config.json', '.mcp.json'],
      scanTimestamp: new Date().toISOString(),
      ...overrides,
    };
  }

  it('shows server count and config count', () => {
    const output = formatMultiServerReport(makeMultiResult());
    expect(output).toContain('2 found');
    expect(output).toContain('2 files discovered');
  });

  it('shows per-server summary with grades', () => {
    const output = formatMultiServerReport(makeMultiResult());
    expect(output).toContain('github');
    expect(output).toContain('filesystem');
  });

  it('shows combined trust score', () => {
    const output = formatMultiServerReport(makeMultiResult());
    expect(output).toContain('96/100');
    expect(output).toContain('Combined Score');
  });

  it('shows auto-fail when combined score auto-fails', () => {
    const output = formatMultiServerReport(
      makeMultiResult({
        combinedScore: {
          score: 10,
          grade: 'F',
          autoFail: true,
          autoFailReasons: ['Secrecy directive detected (PI-002)'],
        },
      }),
    );
    expect(output).toContain('AUTO-FAIL');
  });

  it('shows cross-server findings section', () => {
    const crossFinding: Finding = {
      id: 'TS-001',
      vector: 'CROSS_SERVER_SHADOWING',
      severity: 'CRITICAL',
      title: 'Cross-Server Override',
      description: 'Server A overrides Server B behavior',
      toolName: 'tool',
      evidence: 'ev',
      recommendation: 'rec',
      confidence: 0.9,
    };
    const output = formatMultiServerReport(
      makeMultiResult({
        combinedFindings: [crossFinding],
      }),
    );
    expect(output).toContain('Cross-Server Analysis');
    expect(output).toContain('TS-001');
  });

  it('shows no issues message when no findings', () => {
    const output = formatMultiServerReport(
      makeMultiResult({ combinedFindings: [] }),
    );
    expect(output).toContain('No security issues found');
  });

  it('shows connection status indicators', () => {
    const output = formatMultiServerReport(
      makeMultiResult({
        results: [
          {
            serverName: 'live-server',
            serverVersion: '1.0.0',
            findings: [],
            score: { score: 100, grade: 'A', autoFail: false, autoFailReasons: [] },
            scanTimestamp: new Date().toISOString(),
            connectionStatus: 'connected',
            toolCount: 5,
          },
          {
            serverName: 'broken-server',
            serverVersion: '0.0.0',
            findings: [],
            score: { score: 100, grade: 'A', autoFail: false, autoFailReasons: [] },
            scanTimestamp: new Date().toISOString(),
            connectionStatus: 'failed',
            connectionError: 'ENOENT',
            connectionErrorMessage: 'Package found but no executable entry point.',
          },
        ],
      }),
    );
    expect(output).toContain('✓');
    expect(output).toContain('✗');
    expect(output).toContain('live-server');
    expect(output).toContain('broken-server');
  });

  it('shows categorized error messages in errors section', () => {
    const output = formatMultiServerReport(
      makeMultiResult({
        results: [
          {
            serverName: 'missing-pkg',
            serverVersion: '0.0.0',
            findings: [],
            score: { score: 100, grade: 'A', autoFail: false, autoFailReasons: [] },
            scanTimestamp: new Date().toISOString(),
            connectionStatus: 'failed',
            connectionError: 'npm error code E404',
            connectionErrorCategory: 'package_not_found',
            connectionErrorMessage: 'Package "missing-pkg" not found on npm. Check the package name and try again.',
          },
        ],
      }),
    );
    expect(output).toContain('Errors');
    expect(output).toContain('not found on npm');
    expect(output).not.toContain('Server may require specific env vars');
  });

  it('uses tree chars in finding output', () => {
    const output = formatTerminalReport(makeMockResult());
    expect(output).toContain('├─');
    expect(output).toContain('└─');
  });
});
