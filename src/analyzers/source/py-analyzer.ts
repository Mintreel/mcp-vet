import { readFileSync } from 'node:fs';
import type { Finding } from '../../types.js';
import { PY_EXEC_SINKS, PY_FETCH_SINKS, PY_FILE_SINKS, PY_QUERY_SINKS } from './sink-functions.js';

interface PatternMatch {
  sink: string;
  line: number;
  lineText: string;
  isDynamic: boolean;
}

function findSinkCalls(
  lines: string[],
  sinks: string[],
): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('#')) continue; // Skip comments

    for (const sink of sinks) {
      const funcName = sink.split('.').pop()!;
      if (!line.includes(funcName + '(')) continue;

      // Check the full sink name (e.g., os.system)
      if (sink.includes('.') && !line.includes(sink)) continue;

      // Determine if argument is dynamic
      const callStart = line.indexOf(funcName + '(');
      const afterParen = line.substring(callStart + funcName.length + 1);

      const isDynamic =
        /f["']/.test(afterParen) || // f-string
        /\+\s*\w/.test(afterParen) || // string concat
        /format\s*\(/.test(afterParen) || // .format()
        /\%\s*\w/.test(afterParen); // % formatting with variable

      const isStatic =
        afterParen.startsWith("'") ||
        afterParen.startsWith('"') ||
        afterParen.startsWith('[');

      matches.push({
        sink,
        line: i + 1,
        lineText: line,
        isDynamic: isDynamic || (!isStatic && /\w+\)?$/.test(afterParen.split(')')[0])),
      });
    }
  }

  return matches;
}

export function analyzePythonFile(filePath: string): Finding[] {
  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const lines = content.split('\n');
  const findings: Finding[] = [];
  const fileName = filePath.split('/').pop() || filePath;

  // SC-001: Command Injection
  const execMatches = findSinkCalls(lines, PY_EXEC_SINKS);
  for (const match of execMatches) {
    if (!match.isDynamic) continue;

    // Check for shell=True for subprocess calls
    if (match.sink.startsWith('subprocess.')) {
      if (!match.lineText.includes('shell=True') && !match.lineText.includes('shell = True')) {
        continue; // subprocess without shell=True is safer
      }
    }

    findings.push({
      id: 'SC-001',
      vector: 'IMPLEMENTATION_VULN',
      severity: 'CRITICAL',
      title: 'Command Injection',
      description: `Dynamic input passed to ${match.sink}()`,
      toolName: fileName,
      evidence: `${match.lineText.substring(0, 100)} at line ${match.line}`,
      recommendation:
        'Use subprocess with list arguments instead of shell=True with string interpolation.',
      confidence: 0.75,
    });
  }

  // SC-002: SSRF
  const fetchMatches = findSinkCalls(lines, PY_FETCH_SINKS);
  for (const match of fetchMatches) {
    if (!match.isDynamic) continue;

    // Check for URL validation
    const surroundingLines = lines.slice(Math.max(0, match.line - 5), match.line + 2).join('\n');
    if (/validate|allowlist|whitelist|is_private|urlparse/i.test(surroundingLines)) {
      continue;
    }

    findings.push({
      id: 'SC-002',
      vector: 'IMPLEMENTATION_VULN',
      severity: 'HIGH',
      title: 'SSRF',
      description: `Unvalidated URL in ${match.sink}()`,
      toolName: fileName,
      evidence: `${match.lineText.substring(0, 100)} at line ${match.line}`,
      recommendation:
        'Validate URLs against an allowlist and block private IP ranges.',
      confidence: 0.6,
    });
  }

  // SC-003: Path Traversal
  const fileMatches = findSinkCalls(lines, PY_FILE_SINKS);
  for (const match of fileMatches) {
    if (!match.isDynamic) continue;

    const surroundingLines = lines.slice(Math.max(0, match.line - 5), match.line + 2).join('\n');
    if (/os\.path\.realpath|os\.path\.abspath.*startswith|pathlib.*resolve/i.test(surroundingLines)) {
      continue;
    }

    findings.push({
      id: 'SC-003',
      vector: 'IMPLEMENTATION_VULN',
      severity: 'HIGH',
      title: 'Path Traversal',
      description: `User-controlled path in ${match.sink}()`,
      toolName: fileName,
      evidence: `${match.lineText.substring(0, 100)} at line ${match.line}`,
      recommendation:
        'Use os.path.realpath() and verify the resolved path is within allowed directories.',
      confidence: 0.6,
    });
  }

  // SC-004: SQL Injection
  const queryMatches = findSinkCalls(lines, PY_QUERY_SINKS);
  for (const match of queryMatches) {
    if (!match.isDynamic) continue;

    // Check for parameterized queries
    if (/\%s|%\(|\?/.test(match.lineText) && /,\s*[\[(]/.test(match.lineText)) {
      continue; // Parameterized
    }

    findings.push({
      id: 'SC-004',
      vector: 'IMPLEMENTATION_VULN',
      severity: 'HIGH',
      title: 'SQL Injection',
      description: `Unparameterized query in ${match.sink}()`,
      toolName: fileName,
      evidence: `${match.lineText.substring(0, 100)} at line ${match.line}`,
      recommendation:
        'Use parameterized queries with placeholders instead of string formatting.',
      confidence: 0.7,
    });
  }

  return findings;
}
