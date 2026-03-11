import { Project, SyntaxKind, type SourceFile, type CallExpression } from 'ts-morph';
import type { Finding } from '../../types.js';
import { traceNode, type TaintResult } from './taint-tracer.js';
import { EXEC_SINKS, FETCH_SINKS, FILE_SINKS, QUERY_SINKS } from './sink-functions.js';

function getCallName(call: CallExpression): string {
  const expr = call.getExpression();
  return expr.getText();
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

  const args = call.getArguments();
  if (args.length === 0) return null;

  const firstArg = args[0];
  const result = traceNode(firstArg, sourceFile);

  if (result === 'SAFE') return null;

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
    confidence: result === 'TAINTED' ? 0.75 : 0.5,
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

  // Deduplicate: consolidate findings with same rule ID per file
  return deduplicateFindings(rawFindings);
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
