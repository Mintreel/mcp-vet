#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Command } from 'commander';
import type { PipelineResult, ServerDefinition } from './types.js';
import { runPipeline, runPipelineMulti, runDiscoveryPipeline } from './pipeline.js';
import { mcpEntryToServerDefinitionLive, resolveSourceDir, installPackageToTemp } from './loader/mcp-config-loader.js';
import { formatTerminalReport, formatMultiServerReport } from './reporters/terminal.js';
import { formatJsonReport } from './reporters/json.js';
import { generateHtmlReport } from './reporters/html.js';
import { generateSarifReport } from './reporters/sarif.js';
import { VERSION } from './version.js';

function resolveEntryPoint(packageRoot: string): string {
  try {
    const pkgJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf-8'));
    const bin = pkgJson.bin;
    if (typeof bin === 'string') return join(packageRoot, bin);
    if (typeof bin === 'object') {
      const first = Object.values(bin)[0] as string;
      if (first) return join(packageRoot, first);
    }
    if (pkgJson.main) return join(packageRoot, pkgJson.main);
  } catch {
    // fall through
  }
  return join(packageRoot, 'index.js');
}

function isPackageName(s: string): boolean {
  // Scoped: @scope/name
  if (/^@[\w-]+\/[\w.-]+$/.test(s)) return true;
  // Unscoped: starts with letter, no path separators
  if (/^[a-zA-Z][\w.-]*$/.test(s) && !s.includes('/')) return true;
  return false;
}

const program = new Command();

program
  .name('mcp-vet')
  .description('MCP security auditor — scans MCP servers for vulnerabilities')
  .version(VERSION);

program
  .command('audit <target>')
  .description('Audit an MCP server config file or npm package')
  .option('--json', 'Output results as JSON')
  .option('--ci', 'CI mode: exit 1 on critical/high findings')
  .option('--report [path]', 'Generate HTML report')
  .option('--sarif <path>', 'Output SARIF 2.1.0 to file')
  .option('--no-source', 'Skip source code analysis')
  .option('--no-cve', 'Skip CVE lookups')
  .option('--timeout <ms>', 'Connection timeout in ms (default: 10000)', parseInt)
  .action(async (target: string, options) => {
    try {
      let result;

      if (existsSync(target)) {
        // Existing behavior: load from file
        result = await runPipeline(target, {
          sourceAnalysis: options.source !== false,
          cveCheck: options.cve !== false,
        });
      } else if (isPackageName(target)) {
        // Install package to temp directory for source analysis
        console.error(`Installing ${target}...`);
        const tempInstall = installPackageToTemp(target);

        try {
          // Use the installed copy for live connection
          const entry = {
            name: target,
            command: 'node',
            args: [resolveEntryPoint(tempInstall.packageRoot)],
          };
          const server = await mcpEntryToServerDefinitionLive(entry, {
            timeout: options.timeout,
          });

          // Source analysis uses the installed source directly
          if (options.source !== false) {
            server.sourcePath = resolveSourceDir(tempInstall.packageRoot);
          }

          const pipelineResult = await runPipelineMulti([server], {
            sourceAnalysis: options.source !== false,
            cveCheck: options.cve !== false,
          });
          const serverAny = server as ServerDefinition & { connectionErrorCategory?: PipelineResult['connectionErrorCategory']; connectionErrorMessage?: string };
          result = {
            ...pipelineResult,
            toolCount: server.tools.length,
            connectionStatus: (server.connectionError ? 'failed' : 'connected') as PipelineResult['connectionStatus'],
            connectionError: server.connectionError,
            connectionErrorCategory: serverAny.connectionErrorCategory,
            connectionErrorMessage: serverAny.connectionErrorMessage,
          };
        } finally {
          tempInstall.cleanup();
        }
      } else {
        console.error(`Error: "${target}" is not a file or known package`);
        process.exit(2);
        return;
      }

      if (options.json) {
        console.log(formatJsonReport(result));
      } else {
        console.log(formatTerminalReport(result));
      }

      if (options.report) {
        const htmlPath =
          typeof options.report === 'string' ? options.report : 'mcp-vet-report.html';
        writeFileSync(htmlPath, generateHtmlReport(result), 'utf-8');
        console.log(`HTML report written to ${htmlPath}`);
      }

      if (options.sarif) {
        writeFileSync(options.sarif, generateSarifReport(result), 'utf-8');
        console.log(`SARIF report written to ${options.sarif}`);
      }

      if (options.ci) {
        const hasCriticalOrHigh = result.findings.some(
          (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
        );
        process.exit(hasCriticalOrHigh ? 1 : 0);
      }
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program
  .command('scan', { isDefault: true })
  .description('Auto-discover and audit MCP server configs')
  .option('--project', 'Only scan project-level MCP configs')
  .option('--no-connect', 'Skip live server connections (config-only analysis)')
  .option('--timeout <ms>', 'Connection timeout in ms (default: 10000)', parseInt)
  .option('--json', 'JSON output')
  .option('--ci', 'CI mode: exit 1 on critical/high findings')
  .action(async (options) => {
    try {
      const { discoverConfigs } = await import('./loader/config-discovery.js');
      const configs = discoverConfigs({ projectOnly: options.project });

      if (configs.length === 0) {
        console.log('');
        console.log(`  mcp-vet v${VERSION} — MCP security auditor`);
        console.log('');
        console.log('  No MCP server configs found.');
        console.log('');
        console.log('  Searched:');
        console.log('    ~/.claude/claude_desktop_config.json');
        console.log('    ~/.claude.json');
        console.log('    .mcp.json');
        console.log('    .claude/mcp.json');
        console.log('    .vscode/mcp.json');
        console.log('');
        console.log('  To scan a specific server config:');
        console.log('    npx mcp-vet audit ./path/to/mcp.json');
        console.log('');
        console.log('  To scan only this project:');
        console.log('    npx mcp-vet --project');
        console.log('');
        console.log('  To list all 30 detection rules:');
        console.log('    npx mcp-vet list-rules');
        console.log('');
        process.exit(0);
        return;
      }

      const result = await runDiscoveryPipeline({
        projectOnly: options.project,
        connect: options.connect,
        timeout: options.timeout,
        cveCheck: false,
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(formatMultiServerReport(result));
      }

      if (options.ci) {
        const hasCriticalOrHigh = result.combinedFindings.some(
          (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
        );
        process.exit(hasCriticalOrHigh ? 1 : 0);
      }
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program
  .command('list-rules')
  .description('List all detection rules')
  .action(async () => {
    const { listRules } = await import('./commands/list-rules.js');
    listRules();
  });

program
  .command('diff <path>')
  .description('Compare current scan vs stored snapshot (rug-pull detection)')
  .action(async (targetPath: string) => {
    try {
      const { runDiff } = await import('./commands/diff.js');
      const { findings, isFirstRun } = runDiff(targetPath);

      if (isFirstRun) {
        console.log('Snapshot created. Run again to detect changes.');
        return;
      }

      if (findings.length === 0) {
        console.log('No changes detected since last snapshot.');
      } else {
        console.log(`${findings.length} change(s) detected:`);
        for (const f of findings) {
          console.log(`  [${f.severity}] ${f.title}: ${f.description}`);
        }
      }
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program
  .command('graph <path>')
  .description('Show toxic flow graph for multi-server config')
  .action(async (targetPath: string) => {
    try {
      const { showGraph } = await import('./commands/graph.js');
      showGraph(targetPath);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program.parse();
