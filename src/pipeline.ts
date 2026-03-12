import type {
  PipelineOptions,
  PipelineResult,
  MultiPipelineResult,
  Finding,
  ServerDefinition,
} from './types.js';
import { loadServerFromFile, loadServersFromFile } from './loader/file-loader.js';
import { discoverConfigs, mergeConfigs } from './loader/config-discovery.js';
import {
  mcpEntryToServerDefinition,
  mcpEntryToServerDefinitionLive,
} from './loader/mcp-config-loader.js';
import { runMetadataAnalysis } from './analyzers/metadata/index.js';
import { runCrossServerAnalysis } from './analyzers/cross-server/index.js';
import { runSourceAnalysis } from './analyzers/source/index.js';
import { runSupplyChainAnalysis } from './analyzers/supply-chain/index.js';
import { calculateScore } from './scoring/score-calculator.js';

export async function runPipeline(
  targetPath: string,
  options: PipelineOptions = {},
): Promise<PipelineResult> {
  const allServers = loadServersFromFile(targetPath);
  const findings: Finding[] = [];

  // Run metadata analysis for each server
  for (const s of allServers) {
    const metadataFindings = runMetadataAnalysis(s, options.ignore, allServers);
    findings.push(...metadataFindings);
  }

  // Run cross-server analysis if multiple servers
  if (allServers.length > 1) {
    const crossFindings = runCrossServerAnalysis(allServers, options.ignore);
    findings.push(...crossFindings);
  }

  // Run source code analysis if enabled and source path exists
  if (options.sourceAnalysis !== false) {
    for (const s of allServers) {
      if (s.sourcePath) {
        const sourceFindings = await runSourceAnalysis(s.sourcePath, options.ignore);
        findings.push(...sourceFindings);
      }
    }
  }

  // Run supply chain analysis (use first/primary server for package info)
  const primary = allServers[0];
  const supplyChainFindings = await runSupplyChainAnalysis(primary, {
    cveCheck: options.cveCheck,
    ignore: options.ignore,
  });
  findings.push(...supplyChainFindings);

  const score = calculateScore(findings);

  // Report under the primary server name, or a combined name for multi-server
  const serverName = allServers.length === 1
    ? primary.name
    : allServers.map((s) => s.name).join(' + ');

  return {
    serverName,
    serverVersion: primary.version,
    findings,
    score,
    scanTimestamp: new Date().toISOString(),
  };
}

export async function runPipelineMulti(
  servers: ServerDefinition[],
  options: PipelineOptions = {},
): Promise<PipelineResult> {
  const findings: Finding[] = [];

  for (const s of servers) {
    const metadataFindings = runMetadataAnalysis(s, options.ignore, servers);
    findings.push(...metadataFindings);
  }

  if (servers.length > 1) {
    const crossFindings = runCrossServerAnalysis(servers, options.ignore);
    findings.push(...crossFindings);
  }

  if (options.sourceAnalysis !== false) {
    for (const s of servers) {
      if (s.sourcePath) {
        const sourceFindings = await runSourceAnalysis(s.sourcePath, options.ignore);
        findings.push(...sourceFindings);
      }
    }
  }

  const score = calculateScore(findings);
  const primary = servers[0];

  return {
    serverName: primary.name,
    serverVersion: primary.version,
    findings,
    score,
    scanTimestamp: new Date().toISOString(),
  };
}

export async function runDiscoveryPipeline(
  options: PipelineOptions & {
    projectOnly?: boolean;
    cwd?: string;
    connect?: boolean;
    timeout?: number;
  } = {},
): Promise<MultiPipelineResult> {
  const configs = discoverConfigs({
    projectOnly: options.projectOnly,
    cwd: options.cwd,
  });
  const entries = mergeConfigs(configs);

  const shouldConnect = options.connect !== false;

  let servers: (ServerDefinition & { connectionError?: string; connectionErrorCategory?: PipelineResult['connectionErrorCategory']; connectionErrorMessage?: string })[];

  if (shouldConnect) {
    servers = await Promise.all(
      entries.map((entry) =>
        mcpEntryToServerDefinitionLive(entry, { timeout: options.timeout }),
      ),
    );
  } else {
    servers = entries.map(mcpEntryToServerDefinition);
  }

  const results: PipelineResult[] = [];
  const allFindings: Finding[] = [];

  for (const server of servers) {
    const findings: Finding[] = [];

    const metadataFindings = runMetadataAnalysis(server, options.ignore, servers);
    findings.push(...metadataFindings);

    const supplyChainFindings = await runSupplyChainAnalysis(server, {
      cveCheck: options.cveCheck,
      ignore: options.ignore,
    });
    findings.push(...supplyChainFindings);

    const score = calculateScore(findings);

    let connectionStatus: PipelineResult['connectionStatus'];
    if (!shouldConnect) {
      connectionStatus = 'skipped';
    } else if (server.connectionError) {
      connectionStatus = 'failed';
    } else {
      connectionStatus = 'connected';
    }

    const result: PipelineResult = {
      serverName: server.name,
      serverVersion: server.version,
      findings,
      score,
      scanTimestamp: new Date().toISOString(),
      toolCount: server.tools.length,
      connectionStatus,
      connectionError: server.connectionError,
      connectionErrorCategory: server.connectionErrorCategory,
      connectionErrorMessage: server.connectionErrorMessage,
    };
    results.push(result);
    allFindings.push(...findings);
  }

  // Cross-server analysis
  if (servers.length > 1) {
    const crossFindings = runCrossServerAnalysis(servers, options.ignore);
    allFindings.push(...crossFindings);
  }

  const combinedScore = calculateScore(allFindings);

  return {
    results,
    combinedFindings: allFindings,
    combinedScore,
    discoveredConfigs: configs.map((c) => c.path),
    scanTimestamp: new Date().toISOString(),
  };
}
