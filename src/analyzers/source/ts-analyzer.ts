import { Project, SyntaxKind, type SourceFile, type CallExpression } from 'ts-morph';
import { statSync } from 'node:fs';
import type { Finding } from '../../types.js';
import { traceNode } from './taint-tracer.js';
import { EXEC_SINKS, FETCH_SINKS, FILE_SINKS, QUERY_SINKS } from './sink-functions.js';

function getCallName(call: CallExpression): string {
  const expr = call.getExpression();
  return expr.getText();
}

/**
 * Known bundler eval patterns that are safe — they're tricks used by
 * Webpack/Rollup/esbuild to call require() at runtime without the bundler
 * statically analyzing the call and trying to inline the dependency.
 *
 * e.g. eval("quire".replace(/^\//, "re"))  →  require()
 *      eval(["req","uire"].join(""))        →  require()
 */
const BUNDLER_EVAL_PATTERNS = [
  // eval("quire".replace(..., "re"))  — esbuild / tsup pattern
  /eval\(\s*["']quire["']\.replace\(/,
  // eval([...].join(""))  — webpack join pattern
  /eval\(\s*\[.*\]\.join\(["']["']\)\)/,
  // eval("re"+"quire")  — string concat pattern
  /eval\(\s*["']re["']\s*\+\s*["']quire["']\)/,
  // eval(atob(...))  — only safe if it's a module loader idiom
  // NOTE: atob eval is NOT whitelisted here — it remains flagged as PI-006 handles it
];

function isBundlerEvalCall(call: CallExpression): boolean {
  const callText = call.getText();
  return BUNDLER_EVAL_PATTERNS.some((p) => p.test(callText));
}

/**
 * Heuristic: detect minified/bundled single-file output.
 * Bundled files have very few lines but enormous line lengths.
 * Real source files rarely have lines > 500 chars.
 */
function isBundledFile(sourceFile: SourceFile): boolean {
  const filePath = sourceFile.getFilePath();
  const lineCount = sourceFile.getEndLineNumber();

  // If the file has fewer than 200 lines but is larger than 50 KB,
  // it's almost certainly a minified/bundled file.
  try {
    const bytes = statSync(filePath).size;
    const avgBytesPerLine = bytes / Math.max(lineCount, 1);
    // > 500 bytes/line is a strong signal of bundled/minified code
    if (avgBytesPerLine > 500) return true;
  } catch {
    // ignore stat errors
  }

  // Also flag files named index.js / bundle.js that are very long
  const base = filePath.split('/').pop() ?? '';
  if ((base === 'index.js' || base.includes('bundle') || base.includes('vendor')) && lineCount > 5000) {
    return true;
  }

  return false;
}

// Generic method names that should NOT match via suffix alone
const GENERIC_METHODS = new Set(['get', 'post', 'put', 'delete', 'request', 'run', 'all', 'execute', 'exec']);

function matchesSink(callName: string, sinks: string[]): boolean {
  return sinks.some((sink) => {
    if (callName === sink) return true;
    // Dot-prefix sinks like '.query' — match any object
    if (sink.startsWith('.') && callName.endsWith(sink)) return true;
    // Multi-part sinks like 'axios.get' — match exact or same-suffix object
    if (sink.includes('.')) {
      const method = sink.split('.').pop()!;
      // For generic method names, require the object prefix to match too
      if (GENERIC_METHODS.has(method)) {
        const sinkObj = sink.split('.').slice(0, -1).join('.');
        const callObj = callName.split('.').slice(0, -1).join('.');
        return callObj === sinkObj || callName === sink;
      }
      return callName.endsWith('.' + method);
    }
    return false;
  });
}

function checkCallForSC001(
  call: CallExpression,
  sourceFile: SourceFile,
): Finding | null {
  const callName = getCallName(call);

  if (!matchesSink(callName, EXEC_SINKS)) return null;

  // Skip known-safe bundler eval idioms (e.g. eval("quire".replace(/^/, "re")))
  // These are tricks used by Webpack/Rollup/esbuild/tsup to call require() at
  // runtime without bundlers statically analyzing the import.
  if (callName === 'eval' && isBundlerEvalCall(call)) return null;

  const args = call.getArguments();
  if (args.length === 0) return null;

  const firstArg = args[0];
  const result = traceNode(firstArg, sourceFile);

  if (result === 'SAFE') return null;

  // In bundled files, eval() false-positives are common from embedded deps.
  // Only flag if taint is confirmed (not just UNKNOWN).
  if (callName === 'eval' && isBundledFile(sourceFile) && result !== 'TAINTED') return null;

  return {
    id: 'SC-001',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'CRITICAL',
    title: 'Command Injection',
    description: `Unsanitized input passed to ${callName}()`,
    toolName: sourceFile.getBaseName(),
    evidence: `${callName}(${firstArg.getText().substring(0, 80)}) at line ${call.getStartLineNumber()}`,
    recommendation:
      'Use parameterized execution (e.g., execFile with array args) instead of string interpolation in shell commands.',
    confidence: result === 'TAINTED' ? 0.85 : 0.6,
  };
}

function checkCallForSC002(
  call: CallExpression,
  sourceFile: SourceFile,
): Finding | null {
  const callName = getCallName(call);

  if (!matchesSink(callName, FETCH_SINKS)) return null;

  const args = call.getArguments();
  if (args.length === 0) return null;

  const urlArg = args[0];
  const result = traceNode(urlArg, sourceFile);

  if (result === 'SAFE') return null;

  // Check if there's URL validation nearby
  const funcBody = call.getFirstAncestorByKind(SyntaxKind.Block);
  if (funcBody) {
    const bodyText = funcBody.getText();
    if (
      /isPrivateIP|validateUrl|isValidUrl|allowlist|whitelist|URL\s*\(/i.test(bodyText)
    ) {
      return null; // Validation detected
    }
  }

  return {
    id: 'SC-002',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'HIGH',
    title: 'SSRF',
    description: `URL argument to ${callName}() is not validated`,
    toolName: sourceFile.getBaseName(),
    evidence: `${callName}(${urlArg.getText().substring(0, 80)}) at line ${call.getStartLineNumber()}`,
    recommendation:
      'Validate URLs against an allowlist and block private IP ranges before making requests.',
    confidence: result === 'TAINTED' ? 0.7 : 0.5,
  };
}

function checkCallForSC003(
  call: CallExpression,
  sourceFile: SourceFile,
): Finding | null {
  const callName = getCallName(call);

  if (!matchesSink(callName, FILE_SINKS)) return null;

  const args = call.getArguments();
  if (args.length === 0) return null;

  const pathArg = args[0];
  const result = traceNode(pathArg, sourceFile);

  if (result === 'SAFE') return null;

  // Check if the path argument name indicates prior validation
  const pathArgText = pathArg.getText();
  if (/^(valid|resolved|sanitized|normalized|safe|checked)(Path|File|Dir)/i.test(pathArgText)) {
    return null;
  }

  // Check if the enclosing function name signals a safety wrapper (e.g. readFileSafe, safeRead)
  const enclosingFunc =
    call.getFirstAncestorByKind(SyntaxKind.FunctionDeclaration) ||
    call.getFirstAncestorByKind(SyntaxKind.MethodDeclaration);
  if (enclosingFunc) {
    const funcName = enclosingFunc.getName?.() ?? '';
    if (/safe|validate|sanitize|checked/i.test(funcName)) {
      return null;
    }
  }

  // Check if the file defines a path validation function (cross-function validation pattern)
  const fileText = sourceFile.getText();
  if (/function\s+validatePath|export\s+.*validatePath|const\s+validatePath/i.test(fileText)) {
    return null;
  }

  // Check for proper containment validation — search all ancestor blocks up to function level
  const funcDecl =
    call.getFirstAncestorByKind(SyntaxKind.FunctionDeclaration) ||
    call.getFirstAncestorByKind(SyntaxKind.ArrowFunction) ||
    call.getFirstAncestorByKind(SyntaxKind.MethodDeclaration) ||
    call.getFirstAncestorByKind(SyntaxKind.Block);
  if (funcDecl) {
    const bodyText = funcDecl.getText();

    // validatePath() or similar validation function call present
    if (/validatePath|sanitizePath|normalizePath|checkPath/i.test(bodyText)) {
      return null;
    }

    // path.resolve() + startsWith() = proper containment
    if (/path\.resolve/.test(bodyText) && /startsWith/.test(bodyText)) {
      return null;
    }

    // fs.realpathSync before access
    if (/realpath(Sync)?/.test(bodyText)) {
      return null;
    }

    // startsWith without path.resolve — still vulnerable (prefix bypass)
    if (/startsWith/.test(bodyText) && !/path\.resolve/.test(bodyText)) {
      return {
        id: 'SC-003',
        vector: 'IMPLEMENTATION_VULN',
        severity: 'HIGH',
        title: 'Path Traversal (Prefix Bypass)',
        description: `Path validation uses startsWith() without path.resolve() — vulnerable to prefix bypass`,
        toolName: sourceFile.getBaseName(),
        evidence: `${callName}() with startsWith-only validation at line ${call.getStartLineNumber()}`,
        cveRef: 'CVE-2025-53110',
        recommendation:
          'Use path.resolve() before startsWith() to prevent prefix bypass attacks.',
        confidence: 0.75,
      };
    }
  }

  // TAINTED — confirmed user-controlled input, report HIGH
  if (result === 'TAINTED') {
    return {
      id: 'SC-003',
      vector: 'IMPLEMENTATION_VULN',
      severity: 'HIGH',
      title: 'Path Traversal',
      description: `User-controlled path passed to ${callName}() without containment validation`,
      toolName: sourceFile.getBaseName(),
      evidence: `${callName}(${pathArg.getText().substring(0, 80)}) at line ${call.getStartLineNumber()}`,
      recommendation:
        'Use path.resolve() + startsWith() to ensure paths stay within allowed directories.',
      confidence: 0.75,
    };
  }

  // UNKNOWN — could not fully trace the path; downgrade to MEDIUM/low-confidence
  // so internal helper patterns don't generate HIGH findings.
  // Suppress entirely if the variable name looks like an internal config/cache path.
  // Two-part naming requirement: safe prefix + path-like suffix prevents suppressing
  // dangerous generics like `path` or `file` while catching `fullPath`, `configFile`, etc.
  const INTERNAL_PATH_PREFIXES = /^(cache|cached|config|full|resolved|base|dir|root|start|pkg|dist|bundle|module|template|asset|static|vendor|lib|file)(Path|File|Dir|Folder|Name)/i;
  if (INTERNAL_PATH_PREFIXES.test(pathArgText)) return null;

  return {
    id: 'SC-003',
    vector: 'IMPLEMENTATION_VULN',
    severity: 'MEDIUM',
    title: 'Path Traversal (Unverified)',
    description: `Path argument to ${callName}() could not be fully traced — verify it is not user-controlled`,
    toolName: sourceFile.getBaseName(),
    evidence: `${callName}(${pathArg.getText().substring(0, 80)}) at line ${call.getStartLineNumber()}`,
    recommendation:
      'Ensure paths are validated with path.resolve() + startsWith() against an allowed directory.',
    confidence: 0.35,
  };
}

function checkCallForSC004(
  call: CallExpression,
  sourceFile: SourceFile,
): Finding | null {
  const callName = getCallName(call);

  const isQuerySink = QUERY_SINKS.some((sink) => {
    if (sink.startsWith('.')) {
      return callName.endsWith(sink);
    }
    return callName === sink || callName.endsWith('.' + sink);
  });

  if (!isQuerySink) return null;

  const args = call.getArguments();
  if (args.length === 0) return null;

  const queryArg = args[0];
  const kind = queryArg.getKind();

  // Tagged template literal — safe (parameterized by tag function)
  if (kind === SyntaxKind.TaggedTemplateExpression) {
    return null;
  }

  // String literal with placeholders ($1, ?, %s, :name) + params array = safe
  if (kind === SyntaxKind.StringLiteral) {
    const text = queryArg.getText();
    if (/\$\d|[?]|%s|:\w+/.test(text) && args.length >= 2) {
      return null; // Parameterized query
    }
    return null; // Static query string
  }

  if (kind === SyntaxKind.NoSubstitutionTemplateLiteral) {
    return null; // Static template — safe
  }

  // Template expression with interpolation — dangerous
  if (kind === SyntaxKind.TemplateExpression) {
    return {
      id: 'SC-004',
      vector: 'IMPLEMENTATION_VULN',
      severity: 'HIGH',
      title: 'SQL Injection',
      description: `Unparameterized template literal in ${callName}()`,
      toolName: sourceFile.getBaseName(),
      evidence: `${callName}(${queryArg.getText().substring(0, 80)}) at line ${call.getStartLineNumber()}`,
      recommendation:
        'Use parameterized queries with placeholders ($1, ?) instead of string interpolation.',
      confidence: 0.8,
    };
  }

  // Binary expression (string concat) — dangerous
  if (kind === SyntaxKind.BinaryExpression) {
    const result = traceNode(queryArg, sourceFile);
    if (result !== 'SAFE') {
      return {
        id: 'SC-004',
        vector: 'IMPLEMENTATION_VULN',
        severity: 'HIGH',
        title: 'SQL Injection',
        description: `String concatenation in ${callName}() query argument`,
        toolName: sourceFile.getBaseName(),
        evidence: `${callName}(${queryArg.getText().substring(0, 80)}) at line ${call.getStartLineNumber()}`,
        recommendation:
          'Use parameterized queries instead of string concatenation.',
        confidence: 0.8,
      };
    }
  }

  return null;
}

export function analyzeTypeScriptFile(filePath: string): Finding[] {
  const project = new Project({
    compilerOptions: {
      allowJs: true,
      noEmit: true,
      skipLibCheck: true,
    },
    skipAddingFilesFromTsConfig: true,
  });

  let sourceFile: SourceFile;
  try {
    sourceFile = project.addSourceFileAtPath(filePath);
  } catch {
    return [];
  }

  // For bundled files, only report high-confidence confirmed-taint findings
  // to avoid flooding output with false positives from embedded third-party deps.
  const bundled = isBundledFile(sourceFile);
  const MIN_BUNDLED_CONFIDENCE = 0.8;

  const rawFindings: Finding[] = [];
  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const sc001 = checkCallForSC001(call, sourceFile);
    if (sc001) rawFindings.push(sc001);

    const sc002 = checkCallForSC002(call, sourceFile);
    if (sc002) rawFindings.push(sc002);

    const sc003 = checkCallForSC003(call, sourceFile);
    if (sc003) rawFindings.push(sc003);

    const sc004 = checkCallForSC004(call, sourceFile);
    if (sc004) rawFindings.push(sc004);
  }

  const deduplicated = deduplicateFindings(rawFindings);

  // In bundled files, suppress findings that don't meet the higher confidence bar.
  // SC-001 (eval bundler idiom) is already filtered above; this handles SC-002/SC-003
  // that originate from embedded third-party library code.
  if (bundled) {
    return deduplicated.filter((f) => (f.confidence ?? 0) >= MIN_BUNDLED_CONFIDENCE);
  }

  return deduplicated;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const grouped = new Map<string, Finding[]>();

  for (const f of findings) {
    const key = `${f.id}:${f.toolName}`;
    const group = grouped.get(key);
    if (group) {
      group.push(f);
    } else {
      grouped.set(key, [f]);
    }
  }

  const result: Finding[] = [];
  for (const [, group] of grouped) {
    const best = group.reduce((a, b) => (b.confidence > a.confidence ? b : a));
    if (group.length > 1) {
      result.push({
        ...best,
        description: `${best.description} (${group.length} instances)`,
      });
    } else {
      result.push(best);
    }
  }

  return result;
}
