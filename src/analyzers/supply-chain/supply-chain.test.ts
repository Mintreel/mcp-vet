import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runSU001 } from './su-001.js';
import { runSU002 } from './su-002.js';
import { runSU003 } from './su-003.js';
import { runSupplyChainAnalysis } from './index.js';
import {
  makeTool,
  makeServer,
  makeMultiToolServer,
  expectFinding,
  expectNoFinding,
} from '../../../test/helpers.js';
import type { ServerDefinition } from '../../types.js';

describe('SU-001: Known CVE Check', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('reports CVEs when OSV returns vulnerabilities', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulns: [
          {
            id: 'GHSA-1234-abcd-5678',
            summary: 'Remote code execution in example-package',
            severity: [{ type: 'CVSS_V3', score: '9.8' }],
          },
        ],
      }),
    }) as unknown as typeof fetch;

    const server = makeServer('some_tool', 'Does something', {
      name: 'vuln-server',
      packageInfo: { name: 'example-package', version: '1.0.0', registry: 'npm' },
    });

    const findings = await runSU001(server);

    expectFinding(findings, 'SU-001', 'CRITICAL');
    expect(findings[0].description).toContain('example-package@1.0.0');
    expect(findings[0].description).toContain('GHSA-1234-abcd-5678');
    expect(findings[0].cveRef).toBe('GHSA-1234-abcd-5678');
    expect(findings[0].confidence).toBe(1.0);
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });

  it('reports no findings when OSV returns empty vulns', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ vulns: [] }),
    }) as unknown as typeof fetch;

    const server = makeServer('some_tool', 'Does something', {
      name: 'safe-server',
      packageInfo: { name: 'safe-package', version: '2.0.0', registry: 'npm' },
    });

    const findings = await runSU001(server);

    expectNoFinding(findings, 'SU-001');
    expect(findings).toHaveLength(0);
  });

  it('reports INFO finding when fetch throws (offline)', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(
      new Error('Network unreachable'),
    ) as unknown as typeof fetch;

    const server = makeServer('some_tool', 'Does something', {
      name: 'offline-server',
      packageInfo: { name: 'some-package', version: '1.0.0', registry: 'npm' },
    });

    const findings = await runSU001(server);

    expectFinding(findings, 'SU-001', 'INFO');
    expect(findings[0].title).toBe('CVE Check Skipped');
    expect(findings[0].evidence).toContain('unreachable');
  });

  it('returns no findings when server has no packageInfo', async () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'no-pkg-server',
    });

    const findings = await runSU001(server);

    expect(findings).toHaveLength(0);
  });

  it('uses PyPI ecosystem for pypi registry', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ vulns: [] }),
    }) as unknown as typeof fetch;

    const server = makeServer('some_tool', 'Does something', {
      name: 'py-server',
      packageInfo: { name: 'requests', version: '2.28.0', registry: 'pypi' },
    });

    await runSU001(server);

    const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(fetchCall[1].body);
    expect(body.package.ecosystem).toBe('PyPI');
  });

  it('maps CVSS scores to correct severity levels', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulns: [
          {
            id: 'CVE-2024-0001',
            severity: [{ type: 'CVSS_V3', score: '5.0' }],
          },
        ],
      }),
    }) as unknown as typeof fetch;

    const server = makeServer('some_tool', 'Does something', {
      name: 'medium-vuln-server',
      packageInfo: { name: 'mid-risk', version: '1.0.0' },
    });

    const findings = await runSU001(server);

    expectFinding(findings, 'SU-001', 'MEDIUM');
  });
});

describe('SU-002: Credential Management', () => {
  it('flags hardcoded GitHub PAT in config env', () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'cred-server',
      config: {
        env: {
          GITHUB_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
        },
      },
    });

    const findings = runSU002(server);

    expectFinding(findings, 'SU-002', 'HIGH');
    expect(findings[0].title).toBe('Hardcoded Credential');
    expect(findings[0].description).toContain('GitHub Personal Access Token');
  });

  it('does not flag process.env reference', () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'env-ref-server',
      config: {
        env: {
          GITHUB_TOKEN: 'process.env.GITHUB_TOKEN',
        },
      },
    });

    const findings = runSU002(server);

    expectNoFinding(findings, 'SU-002');
  });

  it('flags hardcoded OpenAI key in args', () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'openai-server',
      config: {
        args: ['--api-key', 'sk-abcdefghijklmnopqrstuvwxyz12345678'],
      },
    });

    const findings = runSU002(server);

    expectFinding(findings, 'SU-002', 'HIGH');
    expect(findings[0].description).toContain('OpenAI API Key');
  });

  it('flags hardcoded AWS access key in command', () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'aws-server',
      config: {
        command: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE node server.js',
      },
    });

    const findings = runSU002(server);

    expectFinding(findings, 'SU-002', 'HIGH');
    expect(findings[0].description).toContain('AWS Access Key ID');
  });

  it('does not flag env vars that use $ variable references', () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'safe-server',
      config: {
        env: {
          GITHUB_TOKEN: '${GITHUB_TOKEN}',
        },
      },
    });

    const findings = runSU002(server);

    expectNoFinding(findings, 'SU-002');
  });

  it('does not flag server with no config at all', () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'no-config-server',
    });

    const findings = runSU002(server);

    expect(findings).toHaveLength(0);
  });
});

describe('SU-003: Untrusted Content Processing', () => {
  it('flags tool that reads GitHub issues AND has write capabilities', () => {
    const server = makeMultiToolServer(
      [
        makeTool(
          'create_pr_from_issue',
          'Reads GitHub issues and creates pull requests based on their content',
        ),
      ],
      { name: 'github-server' },
    );

    const findings = runSU003(server);

    expectFinding(findings, 'SU-003', 'MEDIUM');
    expect(findings[0].description).toContain('GitHub issues');
    expect(findings[0].description).toContain('write capabilities');
  });

  it('does not flag read-only tool', () => {
    const server = makeMultiToolServer(
      [
        makeTool(
          'list_issues',
          'Lists GitHub issues from a repository in read-only mode',
        ),
      ],
      { name: 'github-reader' },
    );

    const findings = runSU003(server);

    expectNoFinding(findings, 'SU-003');
  });

  it('does not flag when sanitization is mentioned', () => {
    const server = makeMultiToolServer(
      [
        makeTool(
          'process_comments',
          'Reads comments from users and creates a summary. All input is sanitized before processing.',
        ),
      ],
      { name: 'comment-server' },
    );

    const findings = runSU003(server);

    expectNoFinding(findings, 'SU-003');
  });

  it('flags tool processing emails with send capability', () => {
    const server = makeMultiToolServer(
      [
        makeTool(
          'forward_email',
          'Reads incoming emails and sends auto-replies based on content',
        ),
      ],
      { name: 'email-server' },
    );

    const findings = runSU003(server);

    expectFinding(findings, 'SU-003', 'MEDIUM');
    expect(findings[0].description).toContain('emails');
  });

  it('does not flag tool with no untrusted content patterns', () => {
    const server = makeMultiToolServer(
      [
        makeTool(
          'calculate_sum',
          'Calculates the sum of numbers and writes result to a file',
        ),
      ],
      { name: 'calc-server' },
    );

    const findings = runSU003(server);

    expectNoFinding(findings, 'SU-003');
  });
});

describe('runSupplyChainAnalysis (integration)', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('runs all three checks on a server', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        vulns: [
          {
            id: 'CVE-2024-9999',
            summary: 'Critical vulnerability',
            severity: [{ type: 'CVSS_V3', score: '9.0' }],
          },
        ],
      }),
    }) as unknown as typeof fetch;

    const server = makeMultiToolServer(
      [
        makeTool(
          'create_pr_from_issue',
          'Reads GitHub issues and creates pull requests',
        ),
      ],
      {
        name: 'risky-server',
        packageInfo: { name: 'risky-pkg', version: '0.1.0' },
        config: {
          env: {
            GITHUB_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
          },
        },
      },
    );

    const findings = await runSupplyChainAnalysis(server);

    expectFinding(findings, 'SU-001');
    expectFinding(findings, 'SU-002');
    expectFinding(findings, 'SU-003');
  });

  it('skips CVE check when cveCheck is false', async () => {
    globalThis.fetch = vi.fn() as unknown as typeof fetch;

    const server = makeServer('some_tool', 'Does something', {
      name: 'test-server',
      packageInfo: { name: 'test-pkg', version: '1.0.0' },
    });

    const findings = await runSupplyChainAnalysis(server, { cveCheck: false });

    expectNoFinding(findings, 'SU-001');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('respects the ignore list', async () => {
    const server = makeServer('some_tool', 'Does something', {
      name: 'test-server',
      config: {
        env: {
          GITHUB_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
        },
      },
    });

    const findings = await runSupplyChainAnalysis(server, {
      cveCheck: false,
      ignore: ['SU-002', 'SU-003'],
    });

    expect(findings).toHaveLength(0);
  });
});
