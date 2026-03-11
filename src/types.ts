export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AttackVector =
  | 'PROMPT_INJECTION'
  | 'TOOL_POISONING'
  | 'DATA_EXFILTRATION'
  | 'PRIVILEGE_ESCALATION'
  | 'DENIAL_OF_WALLET'
  | 'CROSS_SERVER_SHADOWING'
  | 'IMPLEMENTATION_VULN'
  | 'SUPPLY_CHAIN';

export interface ToolParameter {
  name: string;
  type: string;
  description?: string;
  required?: boolean;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: ToolParameter[];
}

export interface ServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  rateLimit?: number;
  timeout?: number;
  oauthScopes?: string[];
}

export interface PackageInfo {
  name: string;
  version: string;
  registry?: 'npm' | 'pypi';
}

export interface ServerDefinition {
  name: string;
  version: string;
  tools: ToolDefinition[];
  config?: ServerConfig;
  sourcePath?: string;
  packageInfo?: PackageInfo;
  capabilities?: {
    sampling?: boolean;
    resources?: boolean;
    prompts?: boolean;
  };
}

export interface Finding {
  id: string;
  vector: AttackVector;
  severity: Severity;
  title: string;
  description: string;
  toolName: string;
  evidence: string;
  cveRef?: string;
  recommendation: string;
  confidence: number;
}

export interface TrustScore {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  autoFail: boolean;
  autoFailReasons: string[];
}

export interface RuleDefinition {
  id: string;
  name: string;
  vector: AttackVector;
  severity: Severity;
  description: string;
}

export type RuleFunction = (
  server: ServerDefinition,
  allServers?: ServerDefinition[],
) => Finding[];

export interface McpVetConfig {
  failOn?: Severity[];
  ignore?: string[];
  trustedDomains?: string[];
  trustedServers?: string[];
  snapshotDir?: string;
  sourceAnalysis?: boolean;
  cveCheck?: boolean;
}

export interface PipelineOptions {
  sourceAnalysis?: boolean;
  cveCheck?: boolean;
  ignore?: string[];
}

export interface PipelineResult {
  serverName: string;
  serverVersion: string;
  findings: Finding[];
  score: TrustScore;
  scanTimestamp: string;
  toolCount?: number;
  connectionStatus?: 'connected' | 'failed' | 'skipped';
  connectionError?: string;
  connectionErrorCategory?: 'package_not_found' | 'server_needs_config' | 'no_executable' | 'timeout' | 'unknown';
  connectionErrorMessage?: string;
}

export interface DiscoveredConfig {
  path: string;
  scope: 'global' | 'project';
  servers: McpServerEntry[];
}

export interface McpServerEntry {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

export interface MultiPipelineResult {
  results: PipelineResult[];
  combinedFindings: Finding[];
  combinedScore: TrustScore;
  discoveredConfigs: string[];
  scanTimestamp: string;
}
