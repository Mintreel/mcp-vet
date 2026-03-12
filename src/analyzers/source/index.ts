import { readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import type { Finding } from '../../types.js';
import { analyzeTypeScriptFile } from './ts-analyzer.js';
import { analyzePythonFile } from './py-analyzer.js';

const TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
const PY_EXTENSIONS = new Set(['.py']);
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv']);

function collectFiles(dirPath: string, extensions: Set<string>, maxDepth = 5): string[] {
  const files: string[] = [];
  if (maxDepth <= 0) return files;

  try {
    const entries = readdirSync(dirPath);
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue;
      const fullPath = join(dirPath, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          files.push(...collectFiles(fullPath, extensions, maxDepth - 1));
        } else if (extensions.has(extname(entry))) {
          files.push(fullPath);
        }
      } catch {
        // Skip inaccessible files
      }
    }
  } catch {
    // Skip inaccessible directories
  }

  return files;
}

export async function runSourceAnalysis(
  sourcePath: string,
  ignore: string[] = [],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ignoreSet = new Set(ignore);

  // Collect TypeScript/JavaScript files
  const tsFiles = collectFiles(sourcePath, TS_EXTENSIONS);
  for (const file of tsFiles) {
    const fileFindings = analyzeTypeScriptFile(file);
    findings.push(...fileFindings.filter((f) => !ignoreSet.has(f.id)));
  }

  // Collect Python files
  const pyFiles = collectFiles(sourcePath, PY_EXTENSIONS);
  for (const file of pyFiles) {
    const fileFindings = await analyzePythonFile(file);
    findings.push(...fileFindings.filter((f) => !ignoreSet.has(f.id)));
  }

  return findings;
}
