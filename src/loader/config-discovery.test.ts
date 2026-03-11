import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}));

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/mock-home'),
}));

import { existsSync, readFileSync } from 'node:fs';
import { discoverConfigs, parseMcpConfig, mergeConfigs } from './config-discovery.js';

const mockExists = existsSync as ReturnType<typeof vi.fn>;
const mockRead = readFileSync as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  mockExists.mockReturnValue(false);
});

const VALID_CONFIG = JSON.stringify({
  mcpServers: {
    github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] },
    filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
  },
});

describe('discoverConfigs', () => {
  it('finds global ~/.claude/claude_desktop_config.json', () => {
    mockExists.mockImplementation((p: string) =>
      p === '/mock-home/.claude/claude_desktop_config.json',
    );
    mockRead.mockReturnValue(VALID_CONFIG);

    const configs = discoverConfigs({ cwd: '/project' });
    expect(configs).toHaveLength(1);
    expect(configs[0].scope).toBe('global');
    expect(configs[0].servers).toHaveLength(2);
  });

  it('finds project .mcp.json', () => {
    mockExists.mockImplementation((p: string) => p === '/project/.mcp.json');
    mockRead.mockReturnValue(VALID_CONFIG);

    const configs = discoverConfigs({ cwd: '/project' });
    expect(configs).toHaveLength(1);
    expect(configs[0].scope).toBe('project');
    expect(configs[0].path).toBe('/project/.mcp.json');
  });

  it('finds .claude/mcp.json', () => {
    mockExists.mockImplementation((p: string) => p === '/project/.claude/mcp.json');
    mockRead.mockReturnValue(VALID_CONFIG);

    const configs = discoverConfigs({ cwd: '/project' });
    expect(configs).toHaveLength(1);
    expect(configs[0].path).toBe('/project/.claude/mcp.json');
  });

  it('finds .vscode/mcp.json', () => {
    mockExists.mockImplementation((p: string) => p === '/project/.vscode/mcp.json');
    mockRead.mockReturnValue(VALID_CONFIG);

    const configs = discoverConfigs({ cwd: '/project' });
    expect(configs).toHaveLength(1);
    expect(configs[0].path).toBe('/project/.vscode/mcp.json');
  });

  it('returns empty array when no configs found', () => {
    const configs = discoverConfigs({ cwd: '/project' });
    expect(configs).toHaveLength(0);
  });

  it('projectOnly: true skips global paths', () => {
    mockExists.mockImplementation((p: string) =>
      p === '/mock-home/.claude/claude_desktop_config.json' || p === '/project/.mcp.json',
    );
    mockRead.mockReturnValue(VALID_CONFIG);

    const configs = discoverConfigs({ cwd: '/project', projectOnly: true });
    expect(configs).toHaveLength(1);
    expect(configs[0].scope).toBe('project');
  });
});

describe('parseMcpConfig', () => {
  it('handles mcpServers format (object keys become server names)', () => {
    mockExists.mockReturnValue(true);
    mockRead.mockReturnValue(
      JSON.stringify({
        mcpServers: {
          myServer: { command: 'node', args: ['server.js'], env: { TOKEN: 'abc' } },
        },
      }),
    );

    const config = parseMcpConfig('/path/config.json', 'project');
    expect(config).not.toBeNull();
    expect(config!.servers).toHaveLength(1);
    expect(config!.servers[0].name).toBe('myServer');
    expect(config!.servers[0].command).toBe('node');
    expect(config!.servers[0].env).toEqual({ TOKEN: 'abc' });
  });

  it('returns null for config without mcpServers key', () => {
    mockExists.mockReturnValue(true);
    mockRead.mockReturnValue(JSON.stringify({ something: 'else' }));

    const config = parseMcpConfig('/path/config.json', 'project');
    expect(config).toBeNull();
  });

  it('throws on invalid JSON', () => {
    mockExists.mockReturnValue(true);
    mockRead.mockReturnValue('not json{{{');

    expect(() => parseMcpConfig('/path/bad.json', 'project')).toThrow(
      'Invalid JSON in MCP config: /path/bad.json',
    );
  });

  it('returns null for non-existent file', () => {
    mockExists.mockReturnValue(false);
    const config = parseMcpConfig('/nonexistent', 'global');
    expect(config).toBeNull();
  });

  it('handles SSE transport servers with url', () => {
    mockExists.mockReturnValue(true);
    mockRead.mockReturnValue(
      JSON.stringify({
        mcpServers: {
          remote: { url: 'https://example.com/mcp' },
        },
      }),
    );

    const config = parseMcpConfig('/path/config.json', 'project');
    expect(config!.servers[0].url).toBe('https://example.com/mcp');
    expect(config!.servers[0].command).toBeUndefined();
  });
});

describe('mergeConfigs', () => {
  it('project scope overrides global for same server name', () => {
    const merged = mergeConfigs([
      {
        path: '/global',
        scope: 'global',
        servers: [{ name: 'github', command: 'npx', args: ['old'] }],
      },
      {
        path: '/project',
        scope: 'project',
        servers: [{ name: 'github', command: 'npx', args: ['new'] }],
      },
    ]);

    expect(merged).toHaveLength(1);
    expect(merged[0].args).toEqual(['new']);
  });

  it('deduplicates same server name across project configs', () => {
    const merged = mergeConfigs([
      {
        path: '/a',
        scope: 'project',
        servers: [{ name: 'fs', command: 'npx', args: ['a'] }],
      },
      {
        path: '/b',
        scope: 'project',
        servers: [{ name: 'fs', command: 'npx', args: ['b'] }],
      },
    ]);

    expect(merged).toHaveLength(1);
    // Last project config wins
    expect(merged[0].args).toEqual(['b']);
  });

  it('keeps servers with different names from multiple configs', () => {
    const merged = mergeConfigs([
      {
        path: '/global',
        scope: 'global',
        servers: [{ name: 'github', command: 'npx' }],
      },
      {
        path: '/project',
        scope: 'project',
        servers: [{ name: 'filesystem', command: 'npx' }],
      },
    ]);

    expect(merged).toHaveLength(2);
    expect(merged.map((s) => s.name).sort()).toEqual(['filesystem', 'github']);
  });
});
