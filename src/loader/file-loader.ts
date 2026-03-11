import { readFileSync } from 'node:fs';
import type { ServerDefinition, ToolDefinition, ToolParameter } from '../types.js';

export function loadServerFromFile(filePath: string): ServerDefinition {
  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf-8');
  } catch {
    throw new Error(`Cannot read file: ${filePath}`);
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in file: ${filePath}`);
  }

  return parseServerDefinition(data, filePath);
}

function parseServerDefinition(data: unknown, source: string): ServerDefinition {
  if (typeof data !== 'object' || data === null) {
    throw new Error(`Invalid server definition in ${source}: expected an object`);
  }

  const obj = data as Record<string, unknown>;

  const name = typeof obj.name === 'string' ? obj.name : 'unknown';
  const version = typeof obj.version === 'string' ? obj.version : '0.0.0';

  const tools: ToolDefinition[] = [];
  if (Array.isArray(obj.tools)) {
    for (const tool of obj.tools) {
      if (typeof tool === 'object' && tool !== null) {
        const t = tool as Record<string, unknown>;
        const params: ToolParameter[] = [];
        if (Array.isArray(t.parameters)) {
          for (const p of t.parameters) {
            if (typeof p === 'object' && p !== null) {
              const param = p as Record<string, unknown>;
              params.push({
                name: String(param.name ?? ''),
                type: String(param.type ?? 'string'),
                description: typeof param.description === 'string' ? param.description : undefined,
                required: typeof param.required === 'boolean' ? param.required : undefined,
              });
            }
          }
        }
        tools.push({
          name: String(t.name ?? ''),
          description: String(t.description ?? ''),
          parameters: params,
        });
      }
    }
  }

  return {
    name,
    version,
    tools,
    config: typeof obj.config === 'object' && obj.config !== null
      ? (obj.config as ServerDefinition['config'])
      : undefined,
    sourcePath: typeof obj.sourcePath === 'string' ? obj.sourcePath : undefined,
    packageInfo: typeof obj.packageInfo === 'object' && obj.packageInfo !== null
      ? (obj.packageInfo as ServerDefinition['packageInfo'])
      : undefined,
    capabilities: typeof obj.capabilities === 'object' && obj.capabilities !== null
      ? (obj.capabilities as ServerDefinition['capabilities'])
      : undefined,
  };
}
