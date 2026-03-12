import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { McpServerEntry, ToolDefinition, ToolParameter } from '../types.js';

export type ConnectionErrorCategory = 'package_not_found' | 'server_needs_config' | 'no_executable' | 'timeout' | 'unknown';

export interface ConnectionResult {
  tools: ToolDefinition[];
  serverVersion?: string;
  error?: string;
  errorCategory?: ConnectionErrorCategory;
  errorMessage?: string;
}

export function categorizeError(errorMessage: string): ConnectionErrorCategory {
  const msg = errorMessage.toLowerCase();

  if (msg.includes('e404') || msg.includes('not found') || msg.includes('could not resolve')) {
    return 'package_not_found';
  }
  if (msg.includes('could not determine executable') || msg.includes('enoent') || msg.includes('command not found')) {
    return 'no_executable';
  }
  if (msg.includes('timed out')) {
    return 'timeout';
  }
  if (msg.includes('environment variable') || msg.includes('please set') || msg.includes('please provide') || msg.includes('missing required')) {
    return 'server_needs_config';
  }
  return 'unknown';
}

function buildErrorMessage(category: ConnectionErrorCategory, entry: McpServerEntry, error: string, timeoutMs: number): string {
  switch (category) {
    case 'package_not_found':
      return `Package "${entry.name}" not found on npm. Check the package name and try again.`;
    case 'server_needs_config':
      return `Server started but exited — it likely requires environment variables or arguments. Try scanning via your MCP config file instead: npx mcp-vet audit <config-file>`;
    case 'no_executable':
      return `Package found but no executable entry point. This may be a Python server — mcp-vet currently supports stdio-based Node.js servers.`;
    case 'timeout':
      return `Connection timed out after ${timeoutMs}ms. The server may be slow to start or waiting for input.`;
    case 'unknown':
      return `Could not connect: ${error}. The server process may require additional configuration.`;
  }
}

interface SdkTool {
  name: string;
  description?: string;
  inputSchema?: {
    type: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
  };
}

export function sdkToolsToDefinitions(sdkTools: SdkTool[]): ToolDefinition[] {
  return sdkTools.map((tool) => ({
    name: tool.name,
    description: tool.description ?? '',
    parameters: Object.entries(tool.inputSchema?.properties ?? {}).map(
      ([name, schema]): ToolParameter => ({
        name,
        type: schema.type ?? 'string',
        description: schema.description,
        required: (tool.inputSchema?.required ?? []).includes(name),
      }),
    ),
  }));
}

export async function connectAndListTools(
  entry: McpServerEntry,
  options?: { timeout?: number },
): Promise<ConnectionResult> {
  const timeoutMs = options?.timeout ?? 10000;

  if (!entry.command) {
    return { tools: [], error: 'No command specified for server' };
  }

  let transport: StdioClientTransport | undefined;

  try {
    const result = await Promise.race([
      (async () => {
        transport = new StdioClientTransport({
          command: entry.command!,
          args: entry.args,
          env: entry.env
            ? { ...process.env, ...entry.env } as Record<string, string>
            : undefined,
          stderr: 'pipe',
        });

        const client = new Client(
          { name: 'mcp-vet', version: '0.1.0' },
          { capabilities: {} },
        );

        await client.connect(transport);

        const response = await client.listTools();
        const tools = sdkToolsToDefinitions(response.tools);

        const serverVersion = (client as unknown as { serverVersion?: string }).serverVersion;

        await client.close();

        return { tools, serverVersion };
      })(),
      new Promise<ConnectionResult>((_, reject) =>
        setTimeout(() => reject(new Error(`Connection timed out after ${timeoutMs}ms`)), timeoutMs),
      ),
    ]);

    return result;
  } catch (err) {
    const rawError = err instanceof Error ? err.message : String(err);
    const category = categorizeError(rawError);
    const message = buildErrorMessage(category, entry, rawError, timeoutMs);
    return {
      tools: [],
      error: rawError,
      errorCategory: category,
      errorMessage: message,
    };
  } finally {
    try {
      await transport?.close();
    } catch {
      // Ignore close errors
    }
  }
}
