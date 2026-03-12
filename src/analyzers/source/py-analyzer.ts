import { readFileSync } from 'node:fs';
import type { Finding } from '../../types.js';
import { PY_EXEC_SINKS, PY_FETCH_SINKS, PY_FILE_SINKS, PY_QUERY_SINKS } from './sink-functions.js';
import { getPythonParser, parsePython, type SyntaxNode } from './py-tree-sitter.js';
import { tracePyNode, type PyTaintResult } from './py-taint-tracer.js';

/**
 * Extract the dotted function name from a call node's function child.
 * e.g., `os.system(...)` → "os.system", `open(...)` → "open"
 */
function getCallName(callNode: SyntaxNode): string {
  const func = callNode.childForFieldName('function');
  if (!func) return '';
  return func.text;
}

/**
 * Check if a call name matches any sink in the list.
 */
function matchesSink(callName: string, sinks: string[]): boolean {
  return sinks.some((sink) => {
    if (callName === sink) return true;
    // Dotted sinks: match suffix (e.g., "subprocess.run" matches "subprocess.run")
    if (sink.includes('.')) {
      return callName === sink || callName.endsWith('.' + sink);
    }
    // Non-dotted sinks: match exact or as method
    return callName.split('.').pop() === sink;
  });
}

/**
 * Check if a keyword argument is present in a call's argument list.
 */
function hasKeywordArg(callNode: SyntaxNode, name: string, value?: string): boolean {
  const args = callNode.childForFieldName('arguments');
  if (!args) return false;
  for (const child of args.namedChildren) {
    if (child.type === 'keyword_argument') {
      const key = child.childForFieldName('name');
      const val = child.childForFieldName('value');
      if (key?.text === name) {
        if (value === undefined) return true;
        if (val?.text === value) return true;
      }
    }
  }
  return false;
}

/**
 * Get the first positional argument of a call.
 */
function getFirstArg(callNode: SyntaxNode): SyntaxNode | null {
  const args = callNode.childForFieldName('arguments');
  if (!args) return null;
  for (const child of args.namedChildren) {
    if (child.type !== 'keyword_argument') return child;
  }
  return null;
}

/**
 * Get the URL/path argument — first positional arg, or 'url' keyword arg.
 */
function getTargetArg(callNode: SyntaxNode, kwName?: string): SyntaxNode | null {
  const positional = getFirstArg(callNode);
  if (positional) return positional;
  if (!kwName) return null;

  const args = callNode.childForFieldName('arguments');
  if (!args) return null;
  for (const child of args.namedChildren) {
    if (child.type === 'keyword_argument') {
      const key = child.childForFieldName('name');
      if (key?.text === kwName) {
        return child.childForFieldName('value');
      }
    }
  }
  return null;
}

/**
 * Check if the enclosing function body contains validation patterns.
 */
function hasValidationInScope(callNode: SyntaxNode, patterns: RegExp[]): boolean {
  // Walk up to find enclosing function
  let current: SyntaxNode | null = callNode.parent;
  while (current) {
    if (current.type === 'function_definition') {
      const body = current.childForFieldName('body');
      if (body) {
        const text = body.text;
        return patterns.some((p) => p.test(text));
      }
    }
    current = current.parent;
  }
  // Check at module level (surrounding lines)
  return false;
}

/**
 * Check if the file-level text contains a pattern.
 */
function fileContains(rootNode: SyntaxNode, pattern: RegExp): boolean {
  return pattern.test(rootNode.text);
}

function checkSC001(callNode: SyntaxNode, callName: string, fileName: string): Finding | null {
  if (!matchesSink(callName, PY_EXEC_SINKS)) return null;

  // For subprocess calls, require shell=True
  if (callName.startsWith('subprocess.') || callName === 'subprocess.Popen') {
    if (!hasKeywordArg(callNode, 'shell', 'True')) return null;
  }

  const arg = getFirstArg(callNode);
  if (!arg) return null;

  const result = tracePyNode(arg);
  if (result === 'SAFE') return null;

  return {
    id: 'SC-001',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'CRITICAL',
    title: 'Command Injection',
    description: `Dynamic input passed to ${callName}()`,
    toolName: fileName,
    evidence: `${callName}(${arg.text.substring(0, 100)}) at line ${callNode.startPosition.row + 1}`,
    recommendation: 'Use subprocess with list arguments instead of shell=True with string interpolation.',
    confidence: result === 'TAINTED' ? 0.85 : 0.6,
  };
}

function checkSC002(callNode: SyntaxNode, callName: string, fileName: string): Finding | null {
  if (!matchesSink(callName, PY_FETCH_SINKS)) return null;

  const urlArg = getTargetArg(callNode, 'url');
  if (!urlArg) return null;

  const result = tracePyNode(urlArg);
  if (result === 'SAFE') return null;

  // Check for URL validation in scope
  if (hasValidationInScope(callNode, [
    /validate|allowlist|whitelist|is_private|urlparse|is_valid_url/i,
  ])) {
    return null;
  }

  return {
    id: 'SC-002',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'HIGH',
    title: 'SSRF',
    description: `Unvalidated URL in ${callName}()`,
    toolName: fileName,
    evidence: `${callName}(${urlArg.text.substring(0, 100)}) at line ${callNode.startPosition.row + 1}`,
    recommendation: 'Validate URLs against an allowlist and block private IP ranges.',
    confidence: result === 'TAINTED' ? 0.7 : 0.5,
  };
}

function checkSC003(
  callNode: SyntaxNode,
  callName: string,
  fileName: string,
  rootNode: SyntaxNode,
): Finding | null {
  if (!matchesSink(callName, PY_FILE_SINKS)) return null;

  const pathArg = getFirstArg(callNode);
  if (!pathArg) return null;

  const result = tracePyNode(pathArg);
  if (result === 'SAFE') return null;

  // Check path argument variable name for validation indicators
  if (pathArg.type === 'identifier' && /^(valid|resolved|sanitized|normalized|safe|checked)/i.test(pathArg.text)) {
    return null;
  }

  // Check for path validation in scope
  if (hasValidationInScope(callNode, [
    /os\.path\.realpath/,
    /os\.path\.abspath.*startswith/i,
    /pathlib.*resolve/i,
    /validate_path|sanitize_path|check_path/i,
  ])) {
    return null;
  }

  // Check file-level for validate_path function
  if (fileContains(rootNode, /def\s+validate_path|def\s+sanitize_path/)) {
    return null;
  }

  return {
    id: 'SC-003',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'HIGH',
    title: 'Path Traversal',
    description: `User-controlled path in ${callName}()`,
    toolName: fileName,
    evidence: `${callName}(${pathArg.text.substring(0, 100)}) at line ${callNode.startPosition.row + 1}`,
    recommendation: 'Use os.path.realpath() and verify the resolved path is within allowed directories.',
    confidence: result === 'TAINTED' ? 0.75 : 0.5,
  };
}

function checkSC004(callNode: SyntaxNode, callName: string, fileName: string): Finding | null {
  if (!matchesSink(callName, PY_QUERY_SINKS)) return null;

  const queryArg = getFirstArg(callNode);
  if (!queryArg) return null;

  // Check for parameterized queries: second argument present + placeholders
  const args = callNode.childForFieldName('arguments');
  if (args) {
    const positionalArgs = args.namedChildren.filter((c) => c.type !== 'keyword_argument');
    if (positionalArgs.length >= 2) {
      // Has parameters argument — check if query uses placeholders
      const queryText = queryArg.text;
      if (/%s|%\(|:\w+|\?/.test(queryText)) return null;
    }
  }

  const result = tracePyNode(queryArg);
  if (result === 'SAFE') return null;

  return {
    id: 'SC-004',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'HIGH',
    title: 'SQL Injection',
    description: `Unparameterized query in ${callName}()`,
    toolName: fileName,
    evidence: `${callName}(${queryArg.text.substring(0, 100)}) at line ${callNode.startPosition.row + 1}`,
    recommendation: 'Use parameterized queries with placeholders instead of string formatting.',
    confidence: result === 'TAINTED' ? 0.8 : 0.6,
  };
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const grouped = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${f.id}:${f.toolName}`;
    const group = grouped.get(key);
    if (group) group.push(f);
    else grouped.set(key, [f]);
  }

  const result: Finding[] = [];
  for (const [, group] of grouped) {
    const best = group.reduce((a, b) => (b.confidence > a.confidence ? b : a));
    if (group.length > 1) {
      result.push({ ...best, description: `${best.description} (${group.length} instances)` });
    } else {
      result.push(best);
    }
  }
  return result;
}

export async function analyzePythonFile(filePath: string): Promise<Finding[]> {
  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  let parser;
  try {
    parser = await getPythonParser();
  } catch {
    // Fall back: tree-sitter not available, return empty
    return [];
  }

  const rootNode = parsePython(parser, content);
  const fileName = filePath.split('/').pop() || filePath;
  const rawFindings: Finding[] = [];

  // Walk all call nodes
  const calls = rootNode.descendantsOfType('call');
  for (const call of calls) {
    const callName = getCallName(call);
    if (!callName) continue;

    const sc001 = checkSC001(call, callName, fileName);
    if (sc001) rawFindings.push(sc001);

    const sc002 = checkSC002(call, callName, fileName);
    if (sc002) rawFindings.push(sc002);

    const sc003 = checkSC003(call, callName, fileName, rootNode);
    if (sc003) rawFindings.push(sc003);

    const sc004 = checkSC004(call, callName, fileName);
    if (sc004) rawFindings.push(sc004);
  }

  return deduplicateFindings(rawFindings);
}
