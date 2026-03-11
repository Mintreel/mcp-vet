import { describe, it, expect, vi } from 'vitest';
import {
  mcpEntryToServerDefinition,
  mcpEntryToServerDefinitionLive,
  resolvePackageName,
} from './mcp-config-loader.js';

vi.mock('./live-connector.js', () => ({
  connectAndListTools: vi.fn(),
}));

import { connectAndListTools } from './live-connector.js';

describe('mcpEntryToServerDefinition', () => {
  it('converts command/args/env to ServerDefinition', () => {
    const server = mcpEntryToServerDefinition({
      name: 'github',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-github'],
      env: { GITHUB_TOKEN: 'ghp_abc123' },
    });

    expect(server.name).toBe('github');
    expect(server.version).toBe('0.0.0');
    expect(server.tools).toEqual([]);
    expect(server.config?.command).toBe('npx');
    expect(server.config?.args).toEqual(['-y', '@modelcontextprotocol/server-github']);
    expect(server.config?.env).toEqual({ GITHUB_TOKEN: 'ghp_abc123' });
    expect(server.packageInfo?.name).toBe('@modelcontextprotocol/server-github');
  });

  it('extracts package name from args', () => {
    const server = mcpEntryToServerDefinition({
      name: 'fetch',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-fetch'],
    });

    expect(server.packageInfo?.name).toBe('@modelcontextprotocol/server-fetch');
  });

  it('returns minimal server with empty tools when no package resolution', () => {
    const server = mcpEntryToServerDefinition({
      name: 'custom',
      command: '/usr/local/bin/my-server',
      args: ['--port', '3000'],
    });

    expect(server.name).toBe('custom');
    expect(server.tools).toEqual([]);
    expect(server.packageInfo).toBeUndefined();
  });

  it('env values accessible for SU-002', () => {
    const server = mcpEntryToServerDefinition({
      name: 'test',
      command: 'node',
      env: { API_KEY: 'sk-secret', DB_URL: 'postgres://localhost/db' },
    });

    expect(server.config?.env?.API_KEY).toBe('sk-secret');
    expect(server.config?.env?.DB_URL).toBe('postgres://localhost/db');
  });

  it('handles SSE transport with url', () => {
    const server = mcpEntryToServerDefinition({
      name: 'remote',
      url: 'https://example.com/mcp',
    });

    expect(server.config?.url).toBe('https://example.com/mcp');
    expect(server.config?.command).toBeUndefined();
  });
});

describe('mcpEntryToServerDefinitionLive', () => {
  it('populates tools on successful connection', async () => {
    vi.mocked(connectAndListTools).mockResolvedValue({
      tools: [
        { name: 'read_file', description: 'Read a file', parameters: [] },
      ],
      serverVersion: '1.2.3',
    });

    const server = await mcpEntryToServerDefinitionLive({
      name: 'test',
      command: 'node',
      args: ['server.js'],
    });

    expect(server.tools).toHaveLength(1);
    expect(server.tools[0].name).toBe('read_file');
    expect(server.version).toBe('1.2.3');
    expect(server.connectionError).toBeUndefined();
  });

  it('falls back to empty tools on connection failure', async () => {
    vi.mocked(connectAndListTools).mockResolvedValue({
      tools: [],
      error: 'ENOENT',
    });

    const server = await mcpEntryToServerDefinitionLive({
      name: 'broken',
      command: 'bad-binary',
    });

    expect(server.tools).toEqual([]);
    expect(server.connectionError).toBe('ENOENT');
  });

  it('passes timeout option through', async () => {
    vi.mocked(connectAndListTools).mockResolvedValue({ tools: [] });

    await mcpEntryToServerDefinitionLive(
      { name: 'test', command: 'node' },
      { timeout: 5000 },
    );

    expect(connectAndListTools).toHaveBeenCalledWith(
      expect.anything(),
      { timeout: 5000 },
    );
  });

  it('returns connectionError when no command specified', async () => {
    const server = await mcpEntryToServerDefinitionLive({
      name: 'url-only',
      url: 'http://example.com',
    });

    expect(server.connectionError).toBe('No command specified');
    expect(server.tools).toEqual([]);
  });
});

describe('resolvePackageName', () => {
  it('finds scoped package names', () => {
    expect(resolvePackageName(['-y', '@modelcontextprotocol/server-github'])).toBe(
      '@modelcontextprotocol/server-github',
    );
  });

  it('finds unscoped package names', () => {
    expect(resolvePackageName(['-y', 'mcp-server-fetch'])).toBe('mcp-server-fetch');
  });

  it('returns null for local path commands', () => {
    expect(resolvePackageName(['--port', '3000'])).toBeNull();
  });

  it('ignores flags', () => {
    expect(resolvePackageName(['-y', '--verbose'])).toBeNull();
  });
});
