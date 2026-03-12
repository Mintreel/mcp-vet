import type { SyntaxNode } from './py-tree-sitter.js';

export type PyTaintResult = 'SAFE' | 'TAINTED' | 'UNKNOWN';

// Python-specific tainted sources
const TAINTED_ATTRIBUTES = [
  /^request\.args/,
  /^request\.form/,
  /^request\.json/,
  /^request\.data/,
  /^request\.values/,
  /^request\.files/,
  /^sys\.argv/,
];

// Python-specific safe patterns
const SAFE_PATTERNS = [
  /^os\.environ\b/,
  /^os\.environ\.get\b/,
  /^self\.config/,
  /^self\.settings/,
  /^settings\./,
  /^__file__$/,
  /^os\.path\.dirname\(__file__\)/,
  /^os\.path\.abspath\(__file__\)/,
  /^pathlib\.Path\(__file__\)/,
];

const SAFE_CALL_PATTERNS = [
  /^os\.path\.join$/,
  /^os\.path\.dirname$/,
  /^os\.path\.basename$/,
  /^os\.path\.normpath$/,
  /^os\.path\.abspath$/,
  /^os\.path\.realpath$/,
  /^pathlib\.Path$/,
  /^str$/,
  /^int$/,
  /^float$/,
  /^bool$/,
];

/**
 * Trace a Python AST node to determine if it's safe, tainted, or unknown.
 */
export function tracePyNode(node: SyntaxNode, depth = 0): PyTaintResult {
  if (depth > 10) return 'UNKNOWN';

  const type = node.type;

  // f-strings: check if they have interpolation
  if (type === 'string' && node.text.startsWith('f')) {
    // f-string with interpolation is tainted
    return 'TAINTED';
  }

  // Pure String/number/None literals are safe
  if (type === 'string' || type === 'integer' || type === 'float' || type === 'none' || type === 'true' || type === 'false') {
    return 'SAFE';
  }

  // Formatted string (f-string) with expressions
  if (type === 'formatted_string' || type === 'f_string') {
    // Check if there are interpolation expressions
    const interpolations = node.namedChildren.filter(
      (c) => c.type === 'interpolation' || c.type === 'format_expression',
    );
    if (interpolations.length === 0) return 'SAFE';
    // Check if all interpolations are safe
    for (const interp of interpolations) {
      const expr = interp.namedChildren[0];
      if (expr) {
        const result = tracePyNode(expr, depth + 1);
        if (result === 'TAINTED') return 'TAINTED';
        if (result === 'UNKNOWN') return 'TAINTED'; // Conservative
      }
    }
    return 'SAFE';
  }

  // Concatenated string (implicit or +)
  if (type === 'concatenated_string') {
    for (const child of node.namedChildren) {
      const result = tracePyNode(child, depth + 1);
      if (result === 'TAINTED') return 'TAINTED';
    }
    return 'SAFE';
  }

  // Binary operator (e.g., string + variable)
  if (type === 'binary_operator') {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    if (left) {
      const lr = tracePyNode(left, depth + 1);
      if (lr === 'TAINTED') return 'TAINTED';
    }
    if (right) {
      const rr = tracePyNode(right, depth + 1);
      if (rr === 'TAINTED') return 'TAINTED';
    }
    // If either side is an identifier, likely tainted via concat
    const leftType = left?.type;
    const rightType = right?.type;
    if (leftType === 'identifier' || rightType === 'identifier') {
      // Check if the identifier is a parameter
      const id = leftType === 'identifier' ? left! : right!;
      return traceIdentifier(id, depth + 1);
    }
    return 'SAFE';
  }

  // Modulo operator for string formatting (e.g., "SELECT %s" % var)
  if (type === 'binary_operator') {
    const op = node.children.find((c) => c.type === '%');
    if (op) return 'TAINTED';
  }

  // Identifier — trace to definition
  if (type === 'identifier') {
    return traceIdentifier(node, depth);
  }

  // Attribute access (e.g., request.args, os.environ)
  if (type === 'attribute') {
    const text = node.text;
    if (TAINTED_ATTRIBUTES.some((p) => p.test(text))) return 'TAINTED';
    if (SAFE_PATTERNS.some((p) => p.test(text))) return 'SAFE';
    return 'UNKNOWN';
  }

  // Call expression — check if it's a known-safe function
  if (type === 'call') {
    const funcNode = node.childForFieldName('function');
    if (funcNode) {
      const funcText = funcNode.text;
      if (SAFE_CALL_PATTERNS.some((p) => p.test(funcText))) return 'SAFE';
    }
    return 'UNKNOWN';
  }

  // List/dict/tuple/set literals are safe
  if (type === 'list' || type === 'dictionary' || type === 'tuple' || type === 'set') {
    return 'SAFE';
  }

  // Subscript (e.g., os.environ["KEY"]) — check the object
  if (type === 'subscript') {
    const value = node.childForFieldName('value');
    if (value) {
      const text = value.text;
      if (/^os\.environ$/.test(text)) return 'SAFE';
      if (TAINTED_ATTRIBUTES.some((p) => p.test(text))) return 'TAINTED';
    }
    return 'UNKNOWN';
  }

  return 'UNKNOWN';
}

function traceIdentifier(node: SyntaxNode, depth: number): PyTaintResult {
  const name = node.text;

  // Check safe patterns
  if (SAFE_PATTERNS.some((p) => p.test(name))) return 'SAFE';

  // Check if it's a function parameter by walking up to the enclosing function
  const funcDef = findEnclosingFunction(node);
  if (funcDef) {
    const params = funcDef.childForFieldName('parameters');
    if (params) {
      const paramNames = params.namedChildren
        .filter((c) => c.type === 'identifier' || c.type === 'typed_parameter' || c.type === 'default_parameter')
        .map((c) => {
          if (c.type === 'identifier') return c.text;
          // typed_parameter or default_parameter: first child is the name
          const nameNode = c.namedChildren[0];
          return nameNode ? nameNode.text : c.text;
        });
      if (paramNames.includes(name)) return 'TAINTED';
    }

    // Try to trace to assignment within the function body
    const body = funcDef.childForFieldName('body');
    if (body) {
      const result = traceAssignment(name, body, node, depth + 1);
      if (result !== 'UNKNOWN') return result;
    }
  }

  // Variable names that suggest validated input
  if (/^(valid|resolved|sanitized|normalized|safe|checked)/i.test(name)) {
    return 'SAFE';
  }

  return 'UNKNOWN';
}

function findEnclosingFunction(node: SyntaxNode): SyntaxNode | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'function_definition') return current;
    current = current.parent;
  }
  return null;
}

function traceAssignment(
  varName: string,
  body: SyntaxNode,
  usageSite: SyntaxNode,
  depth: number,
): PyTaintResult {
  if (depth > 10) return 'UNKNOWN';

  // Find assignments to this variable that come before the usage
  const assignments = body.descendantsOfType('assignment');
  for (const assign of assignments) {
    const left = assign.childForFieldName('left');
    if (left && left.text === varName && assign.startPosition.row < usageSite.startPosition.row) {
      const right = assign.childForFieldName('right');
      if (right) return tracePyNode(right, depth + 1);
    }
  }

  return 'UNKNOWN';
}
