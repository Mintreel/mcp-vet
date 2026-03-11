import { expect } from 'vitest';
import type {
  ToolDefinition,
  ToolParameter,
  ServerDefinition,
  Finding,
  Severity,
} from '../src/types.js';

export function makeTool(
  name: string,
  description: string,
  params: Record<string, string> = {},
): ToolDefinition {
  return {
    name,
    description,
    parameters: Object.entries(params).map(
      ([k, v]): ToolParameter => ({ name: k, description: v, type: 'string' }),
    ),
  };
}

export function makeServer(
  toolName: string,
  description: string,
  overrides: Partial<ServerDefinition> = {},
): ServerDefinition {
  return {
    name: 'test-server',
    version: '1.0.0',
    tools: [makeTool(toolName, description)],
    ...overrides,
  };
}

export function makeMultiToolServer(
  tools: ToolDefinition[],
  overrides: Partial<ServerDefinition> = {},
): ServerDefinition {
  return {
    name: 'test-server',
    version: '1.0.0',
    tools,
    ...overrides,
  };
}

export function expectFinding(
  findings: Finding[],
  ruleId: string,
  severity?: Severity,
): void {
  const match = findings.find((f) => f.id === ruleId);
  expect(match, `Expected finding ${ruleId} to be present`).toBeDefined();
  if (severity) {
    expect(match!.severity).toBe(severity);
  }
}

export function expectNoFinding(findings: Finding[], ruleId: string): void {
  const match = findings.find((f) => f.id === ruleId);
  expect(match, `Expected finding ${ruleId} to NOT be present`).toBeUndefined();
}

export function findingById(findings: Finding[], ruleId: string): Finding | undefined {
  return findings.find((f) => f.id === ruleId);
}
