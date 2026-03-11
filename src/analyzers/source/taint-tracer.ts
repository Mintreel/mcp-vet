import { SyntaxKind, type Node, type SourceFile } from 'ts-morph';

export type TaintResult = 'SAFE' | 'TAINTED' | 'UNKNOWN';

const EXTERNAL_INPUT_PATTERNS = [
  /req\.body/,
  /req\.params/,
  /req\.query/,
  /request\.body/,
  /request\.params/,
  /request\.query/,
  /args\./,
  /input\./,
  /params\./,
  /toolInput/,
];

// Patterns that indicate config/internal state, not user-controlled input
const CONFIG_SAFE_PATTERNS = [
  /^this\.\w*(path|file|dir|config|options|settings)/i,
  /^self\.\w*(path|file|dir|config|options|settings)/i,
  /^config\./,
  /^options\./,
  /^settings\./,
  /^process\.env\./,
  /^__dirname/,
  /^__filename/,
  /^path\.join\(__dirname/,
  /^path\.resolve\(__dirname/,
];

/**
 * Traces a node backward through the AST to determine if it originates
 * from safe (constant) or tainted (user-controlled) input.
 */
export function traceNode(node: Node, _sourceFile: SourceFile, depth = 0): TaintResult {
  if (depth > 10) return 'UNKNOWN';

  const kind = node.getKind();

  // String/number literals are safe
  if (
    kind === SyntaxKind.StringLiteral ||
    kind === SyntaxKind.NumericLiteral ||
    kind === SyntaxKind.NoSubstitutionTemplateLiteral
  ) {
    return 'SAFE';
  }

  // Template expressions with interpolation are tainted
  if (kind === SyntaxKind.TemplateExpression) {
    return 'TAINTED';
  }

  // Binary expression with + (string concat) — check if non-literal parts exist
  if (kind === SyntaxKind.BinaryExpression) {
    const text = node.getText();
    // If it's string concatenation with any non-literal, treat as tainted
    if (text.includes('+')) {
      const children = node.getChildren();
      for (const child of children) {
        const childResult = traceNode(child, _sourceFile, depth + 1);
        if (childResult === 'TAINTED') return 'TAINTED';
      }
      // Check if any operand is an identifier (non-constant)
      const hasIdentifier = children.some(
        (c) =>
          c.getKind() === SyntaxKind.Identifier ||
          c.getKind() === SyntaxKind.PropertyAccessExpression,
      );
      if (hasIdentifier) return 'TAINTED';
    }
    return 'SAFE';
  }

  // Parenthesized expression — unwrap
  if (kind === SyntaxKind.ParenthesizedExpression) {
    const inner = node.getChildAtIndex(1);
    if (inner) return traceNode(inner, _sourceFile, depth + 1);
  }

  // Identifier — trace to declaration
  if (kind === SyntaxKind.Identifier) {
    const text = node.getText();

    // Check if it matches external input patterns
    if (EXTERNAL_INPUT_PATTERNS.some((p) => p.test(text))) {
      return 'TAINTED';
    }

    // Check if it matches config/internal patterns
    if (CONFIG_SAFE_PATTERNS.some((p) => p.test(text))) {
      return 'SAFE';
    }

    // Try to find the declaration
    try {
      const symbol = node.getSymbol();
      if (symbol) {
        const declarations = symbol.getDeclarations();
        if (declarations.length > 0) {
          const decl = declarations[0];

          // If it's a parameter — tainted (external input)
          if (decl.getKind() === SyntaxKind.Parameter) {
            return 'TAINTED';
          }

          // If it's a variable declaration, trace the initializer
          if (decl.getKind() === SyntaxKind.VariableDeclaration) {
            const init = decl.getChildrenOfKind(SyntaxKind.StringLiteral);
            if (init.length > 0) return 'SAFE';

            // Check for other initializers
            const children = decl.getChildren();
            const equalsIdx = children.findIndex(
              (c) => c.getKind() === SyntaxKind.EqualsToken,
            );
            if (equalsIdx >= 0 && equalsIdx + 1 < children.length) {
              return traceNode(children[equalsIdx + 1], _sourceFile, depth + 1);
            }
          }
        }
      }
    } catch {
      // Symbol resolution failed
    }

    return 'UNKNOWN';
  }

  // Property access — check for external input patterns, then config patterns
  if (kind === SyntaxKind.PropertyAccessExpression) {
    const text = node.getText();
    if (EXTERNAL_INPUT_PATTERNS.some((p) => p.test(text))) {
      return 'TAINTED';
    }
    if (CONFIG_SAFE_PATTERNS.some((p) => p.test(text))) {
      return 'SAFE';
    }
    return 'UNKNOWN';
  }

  // Call expression — check if it's a known-safe function
  if (kind === SyntaxKind.CallExpression) {
    const callText = node.getText();
    if (/^(path\.(join|resolve|dirname|basename|normalize)|fileURLToPath|url\.fileURLToPath)\b/.test(callText)) {
      return 'SAFE';
    }
    return 'UNKNOWN';
  }

  // Array/object literals are safe
  if (
    kind === SyntaxKind.ArrayLiteralExpression ||
    kind === SyntaxKind.ObjectLiteralExpression
  ) {
    return 'SAFE';
  }

  return 'UNKNOWN';
}

/**
 * Check if a function call's argument traces back to externally controlled input.
 */
export function isArgumentTainted(
  argNode: Node,
  sourceFile: SourceFile,
): { tainted: boolean; confidence: number } {
  const result = traceNode(argNode, sourceFile);

  switch (result) {
    case 'SAFE':
      return { tainted: false, confidence: 0.9 };
    case 'TAINTED':
      return { tainted: true, confidence: 0.85 };
    case 'UNKNOWN':
      return { tainted: true, confidence: 0.6 };
  }
}
