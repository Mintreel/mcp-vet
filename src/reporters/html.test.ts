import { describe, it, expect } from 'vitest';
import { generateHtmlReport } from './html.js';
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
// HTML Report Validation
// ────────────────────────────────────────────────────────────────────────────
describe('HTML Reporter', () => {
  it('is self-contained with no external stylesheet links', () => {
    const html = generateHtmlReport(makeMockResult());
    expect(html).not.toContain('<link rel="stylesheet"');
    // Verify styles are inlined
    expect(html).toContain('<style>');
  });

  it('contains grade element', () => {
    const html = generateHtmlReport(makeMockResult());
    // The grade letter should appear inside the grade circle
    expect(html).toContain('class="grade"');
    expect(html).toMatch(/<span class="grade">[A-F]<\/span>/);
  });

  it('includes all finding IDs in the output', () => {
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

    const html = generateHtmlReport(makeMockResult({ findings }));
    for (const finding of findings) {
      expect(html).toContain(finding.id);
    }
  });

  it('includes recommendation for each finding', () => {
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

    const html = generateHtmlReport(makeMockResult({ findings }));
    for (const finding of findings) {
      expect(html).toContain(finding.recommendation);
    }
  });

  it('contains scan metadata: server name, mcp-vet branding, and Trust Score', () => {
    const result = makeMockResult({
      serverName: 'my-custom-server',
      score: {
        score: 72,
        grade: 'C',
        autoFail: false,
        autoFailReasons: [],
      },
    });
    const html = generateHtmlReport(result);

    // Server name appears in the report
    expect(html).toContain('my-custom-server');

    // mcp-vet branding
    expect(html).toContain('mcp-vet');

    // Trust Score text with the numeric value
    expect(html).toContain('Trust Score');
    expect(html).toContain('72');
  });
});
