import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { McpServerEntry } from '../types.js';

// Mock the SDK modules
const mockConnect = vi.fn();
const mockListTools = vi.fn();
const mockClientClose = vi.fn();
const mockTransportClose = vi.fn();
let capturedTransportArgs: unknown;

vi.mock('@modelcontextprotocol/sdk/client/index.js', () => {
  return {
    Client: class MockClient {
      connect = mockConnect;
      listTools = mockListTools;
      close = mockClientClose;
    },
  };
});

vi.mock('@modelcontextprotocol/sdk/client/stdio.js', () => {
  return {
    StdioClientTransport: class MockTransport {
      close = mockTransportClose;
      constructor(args: unknown) {
        capturedTransportArgs = args;
      }
    },
  };
});

import { connectAndListTools, sdkToolsToDefinitions, categorizeError } from './live-connector.js';

beforeEach(() => {
  vi.clearAllMocks();
  capturedTransportArgs = undefined;
  mockConnect.mockResolvedValue(undefined);
  mockClientClose.mockResolvedValue(undefined);
  mockTransportClose.mockResolvedValue(undefined);
});

describe('sdkToolsToDefinitions', () => {
  it('converts SDK tools to ToolDefinition array', () => {
    const sdkTools = [
      {
        name: 'read_file',
        description: 'Read a file from disk',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'File path' },
          },
          required: ['path'],
        },
      },
    ];

    const result = sdkToolsToDefinitions(sdkTools);

    expect(result).toEqual([
      {
        name: 'read_file',
        description: 'Read a file from disk',
        parameters: [
          { name: 'path', type: 'string', description: 'File path', required: true },
        ],
      },
    ]);
  });

  it('handles missing description (defaults to empty string)', () => {
    const sdkTools = [
      {
        name: 'tool_no_desc',
        inputSchema: { type: 'object', properties: {} },
      },
    ];

    const result = sdkToolsToDefinitions(sdkTools);
    expect(result[0].description).toBe('');
  });

  it('handles missing inputSchema / no properties', () => {
    const sdkTools = [
      { name: 'simple_tool', description: 'No params' },
    ];

    const result = sdkToolsToDefinitions(sdkTools);
    expect(result[0].parameters).toEqual([]);
  });

  it('handles required fields correctly', () => {
    const sdkTools = [
      {
        name: 'multi_param',
        description: 'Test',
        inputSchema: {
          type: 'object',
          properties: {
            required_field: { type: 'string' },
            optional_field: { type: 'number' },
          },
          required: ['required_field'],
        },
      },
    ];

    const result = sdkToolsToDefinitions(sdkTools);
    expect(result[0].parameters).toHaveLength(2);

    const reqParam = result[0].parameters.find((p) => p.name === 'required_field');
    const optParam = result[0].parameters.find((p) => p.name === 'optional_field');
    expect(reqParam?.required).toBe(true);
    expect(optParam?.required).toBe(false);
  });

  it('defaults parameter type to string when missing', () => {
    const sdkTools = [
      {
        name: 'untyped',
        description: 'Test',
        inputSchema: {
          type: 'object',
          properties: {
            field: { description: 'no type here' },
          },
        },
      },
    ];

    const result = sdkToolsToDefinitions(sdkTools);
    expect(result[0].parameters[0].type).toBe('string');
  });
});

describe('connectAndListTools', () => {
  const entry: McpServerEntry = {
    name: 'test-server',
    command: 'node',
    args: ['server.js'],
    env: { API_KEY: 'test123' },
  };

  it('connects successfully and returns tools', async () => {
    mockListTools.mockResolvedValue({
      tools: [
        {
          name: 'read_file',
          description: 'Read a file',
          inputSchema: {
            type: 'object',
            properties: { path: { type: 'string' } },
            required: ['path'],
          },
        },
      ],
    });

    const result = await connectAndListTools(entry);

    expect(result.error).toBeUndefined();
    expect(result.tools).toHaveLength(1);
    expect(result.tools[0].name).toBe('read_file');
    expect(mockConnect).toHaveBeenCalled();
  });

  it('passes env vars from McpServerEntry to transport', async () => {
    mockListTools.mockResolvedValue({ tools: [] });

    await connectAndListTools(entry);

    expect(capturedTransportArgs).toEqual(
      expect.objectContaining({
        command: 'node',
        args: ['server.js'],
        env: expect.objectContaining({ API_KEY: 'test123' }),
      }),
    );
  });

  it('returns error when no command specified', async () => {
    const noCmd: McpServerEntry = { name: 'no-cmd', url: 'http://example.com' };
    const result = await connectAndListTools(noCmd);

    expect(result.tools).toEqual([]);
    expect(result.error).toBe('No command specified for server');
  });

  it('returns error on connection failure with category', async () => {
    mockConnect.mockRejectedValue(new Error('ENOENT: no such file or directory'));

    const result = await connectAndListTools(entry);

    expect(result.tools).toEqual([]);
    expect(result.error).toBe('ENOENT: no such file or directory');
    expect(result.errorCategory).toBe('no_executable');
    expect(result.errorMessage).toBeDefined();
  });

  it('returns error on timeout with category', async () => {
    mockConnect.mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 5000)),
    );

    const result = await connectAndListTools(entry, { timeout: 50 });

    expect(result.tools).toEqual([]);
    expect(result.error).toContain('timed out');
    expect(result.errorCategory).toBe('timeout');
  }, 10000);

  it('always closes transport even on error', async () => {
    mockConnect.mockRejectedValue(new Error('fail'));

    await connectAndListTools(entry);

    expect(mockTransportClose).toHaveBeenCalled();
  });

  it('handles listTools error', async () => {
    mockListTools.mockRejectedValue(new Error('tools/list failed'));

    const result = await connectAndListTools(entry);

    expect(result.tools).toEqual([]);
    expect(result.error).toBe('tools/list failed');
    expect(result.errorCategory).toBe('unknown');
  });
});

describe('categorizeError', () => {
  it('detects package not found (E404)', () => {
    expect(categorizeError('npm error code E404')).toBe('package_not_found');
  });

  it('detects no executable (ENOENT)', () => {
    expect(categorizeError('ENOENT: no such file')).toBe('no_executable');
  });

  it('detects no executable (could not determine)', () => {
    expect(categorizeError('could not determine executable to run')).toBe('no_executable');
  });

  it('detects timeout', () => {
    expect(categorizeError('Connection timed out after 10000ms')).toBe('timeout');
  });

  it('detects server needs config', () => {
    expect(categorizeError('Please set SLACK_BOT_TOKEN')).toBe('server_needs_config');
  });

  it('returns unknown for unrecognized errors', () => {
    expect(categorizeError('some random error')).toBe('unknown');
  });
});
