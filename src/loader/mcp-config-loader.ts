import { readdirSync, existsSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { execSync } from 'node:child_process';
import type { McpServerEntry, ServerDefinition } from '../types.js';
import { connectAndListTools, type ConnectionErrorCategory } from './live-connector.js';

export async function mcpEntryToServerDefinitionLive(
  entry: McpServerEntry,
  options?: { timeout?: number },
): Promise<ServerDefinition & { connectionError?: string; connectionErrorCategory?: ConnectionErrorCategory; connectionErrorMessage?: string }> {
  const base = mcpEntryToServerDefinition(entry);

  if (!entry.command) {
    return { ...base, connectionError: 'No command specified' };
  }

  const result = await connectAndListTools(entry, options);

  if (result.error) {
    return {
      ...base,
      connectionError: result.error,
      connectionErrorCategory: result.errorCategory,
      connectionErrorMessage: result.errorMessage,
    };
  }

  return {
    ...base,
    tools: result.tools,
    version: result.serverVersion ?? base.version,
  };
}

export function mcpEntryToServerDefinition(entry: McpServerEntry): ServerDefinition {
  const packageName = resolvePackageName(entry.args || []);

  return {
    name: entry.name,
    version: '0.0.0',
    tools: [],
    config: {
      command: entry.command,
      args: entry.args,
      env: entry.env,
      url: entry.url,
    },
    packageInfo: packageName ? { name: packageName, version: '0.0.0' } : undefined,
  };
}

/**
 * Find an npm package's source directory in the npx cache or local node_modules.
 * Returns the package root directory, or undefined if not found.
 */
export function resolvePackageSourcePath(packageName: string): string | undefined {
  // Check local node_modules first
  const localPath = join(process.cwd(), 'node_modules', packageName);
  if (existsSync(localPath)) return localPath;

  // Search npx cache: ~/.npm/_npx/*/node_modules/<package>
  const npxCacheDir = join(homedir(), '.npm', '_npx');
  try {
    const hashes = readdirSync(npxCacheDir);
    for (const hash of hashes) {
      const candidate = join(npxCacheDir, hash, 'node_modules', packageName);
      if (existsSync(candidate)) {
        return candidate;
      }
    }
  } catch {
    // npx cache not accessible
  }

  return undefined;
}

/**
 * Find the main source directory of a package by examining its package.json.
 * Returns the directory containing the entry point (src/ if available, otherwise the package root).
 */
export function resolveSourceDir(packageRoot: string): string {
  // Prefer src/ directory if it exists
  const srcDir = join(packageRoot, 'src');
  if (existsSync(srcDir)) return srcDir;

  // Try to find entry point from package.json
  try {
    const pkgJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf-8'));
    const entry = pkgJson.main || pkgJson.bin;
    const entryFile = typeof entry === 'string' ? entry : typeof entry === 'object' ? Object.values(entry)[0] as string : undefined;
    if (entryFile) {
      const entryDir = dirname(join(packageRoot, entryFile));
      if (existsSync(entryDir)) return entryDir;
    }
  } catch {
    // Couldn't parse package.json
  }

  return packageRoot;
}

export interface TempInstall {
  /** Root of the installed package (e.g. /tmp/mcp-vet-xxx/node_modules/@scope/pkg) */
  packageRoot: string;
  /** The temp directory to clean up */
  tempDir: string;
  /** Call when done to remove the temp directory */
  cleanup: () => void;
}

/**
 * Install an npm package into a temporary directory and return paths.
 * This ensures source code is available for analysis without requiring
 * the user to run npm install manually.
 */
export function installPackageToTemp(packageName: string): TempInstall {
  const tempDir = mkdtempSync(join(tmpdir(), 'mcp-vet-'));

  try {
    execSync(`npm install --ignore-scripts --no-audit --no-fund ${packageName}`, {
      cwd: tempDir,
      stdio: 'pipe',
      timeout: 60_000,
    });
  } catch (err) {
    // Clean up on install failure
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(
      `Failed to install "${packageName}": ${err instanceof Error ? err.message : err}`,
    );
  }

  const packageRoot = join(tempDir, 'node_modules', packageName);
  if (!existsSync(packageRoot)) {
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Package "${packageName}" installed but not found in node_modules`);
  }

  return {
    packageRoot,
    tempDir,
    cleanup: () => rmSync(tempDir, { recursive: true, force: true }),
  };
}

export function resolvePackageName(args: string[]): string | null {
  for (const arg of args) {
    // Match scoped packages like @modelcontextprotocol/server-github
    if (/^@[\w-]+\/[\w.-]+$/.test(arg)) return arg;
    // Match unscoped packages (not file paths, flags, or pure numbers)
    if (
      /^[a-zA-Z][\w.-]*$/.test(arg) &&
      !arg.startsWith('-') &&
      !arg.includes('/')
    )
      return arg;
  }
  return null;
}
