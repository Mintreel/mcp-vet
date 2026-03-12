import { createRequire } from 'node:module';

// Lazy singleton for tree-sitter parser
let parserPromise: Promise<TreeSitterParser> | null = null;

interface TreeSitterParser {
  parse(source: string): SyntaxTree;
}

interface SyntaxTree {
  rootNode: SyntaxNode;
}

export interface SyntaxNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  children: SyntaxNode[];
  childCount: number;
  namedChildren: SyntaxNode[];
  namedChildCount: number;
  parent: SyntaxNode | null;
  child(index: number): SyntaxNode | null;
  namedChild(index: number): SyntaxNode | null;
  childForFieldName(name: string): SyntaxNode | null;
  descendantsOfType(type: string | string[]): SyntaxNode[];
}

async function initParser(): Promise<TreeSitterParser> {
  const require = createRequire(import.meta.url);

  // Use the explicit .wasm subpath exports — package.json is not in the exports map
  const treeSitterWasm = require.resolve('web-tree-sitter/web-tree-sitter.wasm');
  const pythonWasm = require.resolve('tree-sitter-python/tree-sitter-python.wasm');

  // Dynamic import to avoid issues with ESM/CJS, with fallback for vitest interop
  const rawImport = await import('web-tree-sitter');

  // Depending on environment (node ESM vs vitest interop), exports might be on the 
  // default export or directly on the namespace
  const ParserConstructor = rawImport.Parser || (rawImport.default ? (rawImport.default.Parser ? rawImport.default.Parser : rawImport.default) : rawImport);

  // Fallback check: find init where it exists
  const init = ParserConstructor.init || rawImport.init || rawImport.default?.init;
  if (!init) throw new Error('Could not find web-tree-sitter init function');

  // Same for Language namespace
  const Language = rawImport.Language || rawImport.default?.Language || ParserConstructor.Language;
  if (!Language) throw new Error('Could not find web-tree-sitter Language namespace');

  await init({
    locateFile: () => treeSitterWasm,
  });

  const Python = await Language.load(pythonWasm);
  const parser = new ParserConstructor();
  parser.setLanguage(Python);

  return parser as unknown as TreeSitterParser;
}

export async function getPythonParser(): Promise<TreeSitterParser> {
  if (!parserPromise) {
    parserPromise = initParser();
  }
  return parserPromise;
}

export function parsePython(parser: TreeSitterParser, source: string): SyntaxNode {
  return parser.parse(source).rootNode;
}
