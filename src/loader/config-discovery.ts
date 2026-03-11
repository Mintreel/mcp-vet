import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { DiscoveredConfig, McpServerEntry } from '../types.js';

const GLOBAL_PATHS = [
  () => join(homedir(), '.claude', 'claude_desktop_config.json'),
  () => join(homedir(), '.claude.json'),
];

const PROJECT_PATHS = [
  (cwd: string) => join(cwd, '.mcp.json'),
  (cwd: string) => join(cwd, '.claude', 'mcp.json'),
  (cwd: string) => join(cwd, 'claude_desktop_config.json'),
  (cwd: string) => join(cwd, '.vscode', 'mcp.json'),
];

export function discoverConfigs(opts: {
  projectOnly?: boolean;
  cwd?: string;
}): DiscoveredConfig[] {
  const cwd = opts.cwd || process.cwd();
  const configs: DiscoveredConfig[] = [];

  if (!opts.projectOnly) {
    for (const pathFn of GLOBAL_PATHS) {
      const filePath = pathFn();
      const config = parseMcpConfig(filePath, 'global');
      if (config) configs.push(config);
    }
  }

  for (const pathFn of PROJECT_PATHS) {
    const filePath = pathFn(cwd);
    const config = parseMcpConfig(filePath, 'project');
    if (config) configs.push(config);
  }

  return configs;
}

export function parseMcpConfig(
  filePath: string,
  scope: 'global' | 'project',
): DiscoveredConfig | null {
  if (!existsSync(filePath)) return null;

  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in MCP config: ${filePath}`);
  }

  if (typeof data !== 'object' || data === null) return null;

  const obj = data as Record<string, unknown>;
  const mcpServers = obj.mcpServers as Record<string, unknown> | undefined;

  if (!mcpServers || typeof mcpServers !== 'object') return null;

  const servers: McpServerEntry[] = [];
  for (const [name, value] of Object.entries(mcpServers)) {
    if (typeof value !== 'object' || value === null) continue;
    const entry = value as Record<string, unknown>;
    servers.push({
      name,
      command: typeof entry.command === 'string' ? entry.command : undefined,
      args: Array.isArray(entry.args) ? (entry.args as string[]) : undefined,
      env:
        typeof entry.env === 'object' && entry.env !== null
          ? (entry.env as Record<string, string>)
          : undefined,
      url: typeof entry.url === 'string' ? entry.url : undefined,
    });
  }

  if (servers.length === 0) return null;

  return { path: filePath, scope, servers };
}

export function mergeConfigs(configs: DiscoveredConfig[]): McpServerEntry[] {
  const serverMap = new Map<string, McpServerEntry>();

  // Process global first, then project — project overrides global
  const sorted = [...configs].sort((a, b) => {
    if (a.scope === 'global' && b.scope === 'project') return -1;
    if (a.scope === 'project' && b.scope === 'global') return 1;
    return 0;
  });

  for (const config of sorted) {
    for (const server of config.servers) {
      serverMap.set(server.name, server);
    }
  }

  return Array.from(serverMap.values());
}
