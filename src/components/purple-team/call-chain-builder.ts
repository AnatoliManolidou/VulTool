import * as fs from 'fs';
import * as path from 'path';
import Parser from 'web-tree-sitter';
import { CallChainStep, EntryPoint } from './types';
import { CodeSlice } from '../ast-analyzer';

const MAX_DEPTH = 8;

// ─── Parser ───────────────────────────────────────────────────────────────────

let parser: Parser | null = null;
let jsLanguage: Parser.Language | null = null;

async function initParser(): Promise<void> {
  if (parser) return;
  await Parser.init({ locateFile: (f: string) => path.join(__dirname, f) });
  parser = new Parser();
  jsLanguage = await Parser.Language.load(path.join(__dirname, 'tree-sitter-javascript.wasm'));
}

// ─── File Scanner ─────────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);
const EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.cache',
]);

function findSourceFiles(workspacePath: string): string[] {
  const results: string[] = [];
  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.isDirectory() && !EXCLUDED_DIRS.has(entry.name)) {
        walk(path.join(dir, entry.name));
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        results.push(path.join(dir, entry.name));
      }
    }
  }
  walk(workspacePath);
  return results;
}

// ─── Function Definition Locator ─────────────────────────────────────────────

interface FunctionDef {
  file:       string;
  startLine:  number;
  endLine:    number;
  sourceText: string;
}

// Searches all source files for the first definition of a function with the given name.
// Covers: function declarations, arrow functions, and function expressions assigned to variables.
function findFunctionDef(name: string, files: string[]): FunctionDef | null {
  if (!parser || !jsLanguage) return null;

  for (const file of files) {
    let source: string;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (!source.includes(name)) continue;

    parser.setLanguage(jsLanguage);
    const tree = parser.parse(source);

    for (const node of tree.rootNode.descendantsOfType('function_declaration')) {
      if (node.childForFieldName('name')?.text === name) {
        return { file, startLine: node.startPosition.row + 1, endLine: node.endPosition.row + 1, sourceText: node.text };
      }
    }

    for (const node of tree.rootNode.descendantsOfType('variable_declarator')) {
      const id    = node.childForFieldName('name');
      const value = node.childForFieldName('value');
      if (id?.text !== name || !value) continue;
      if (value.type !== 'arrow_function' && value.type !== 'function_expression') continue;
      return { file, startLine: value.startPosition.row + 1, endLine: value.endPosition.row + 1, sourceText: value.text };
    }
  }

  return null;
}

// ─── Call Extractor ───────────────────────────────────────────────────────────

// Returns the names of all functions called directly within a source fragment.
// Captures both free calls (foo()) and method calls (obj.foo()) — method names
// are included because intermediate functions are often called via a service instance.
function extractCalledNames(source: string): Set<string> {
  if (!parser || !jsLanguage) return new Set();

  parser.setLanguage(jsLanguage);
  const tree = parser.parse(source);

  const called = new Set<string>();
  for (const node of tree.rootNode.descendantsOfType('call_expression')) {
    const fn = node.childForFieldName('function');
    if (fn?.type === 'identifier') {
      called.add(fn.text);
    } else if (fn?.type === 'member_expression') {
      const prop = fn.childForFieldName('property');
      if (prop) called.add(prop.text);
    }
  }
  return called;
}

// ─── BFS Path Finder ─────────────────────────────────────────────────────────

export async function buildCallChain(
  entryPoint: EntryPoint | null,
  codeSlice: CodeSlice,
  workspacePath: string,
): Promise<CallChainStep[]> {
  if (!entryPoint) return [];

  await initParser();

  const callerNames = new Set(codeSlice.callerSlices.map(s => s.functionName));

  // Direct case: the entry point handler itself is one of the EIF callers.
  if (callerNames.has(entryPoint.handlerFunction)) return [];

  const files = findSourceFiles(workspacePath);

  // parent_map tracks how we reached each function — used to reconstruct the path.
  const parentMap = new Map<string, string | null>();
  const defCache  = new Map<string, FunctionDef | null>();

  parentMap.set(entryPoint.handlerFunction, null);

  // Seed the cache with the handler source we already have from Step 3
  // so we don't re-scan for it.
  defCache.set(entryPoint.handlerFunction, {
    file:       entryPoint.handlerFile,
    startLine:  entryPoint.handlerStartLine,
    endLine:    entryPoint.handlerStartLine,
    sourceText: entryPoint.handlerSource,
  });

  const queue: string[] = [entryPoint.handlerFunction];
  let depth = 0;
  let found: string | null = null;

  outer: while (queue.length > 0 && depth < MAX_DEPTH) {
    const levelSize = queue.length;

    for (let i = 0; i < levelSize; i++) {
      const current = queue.shift()!;

      let currentDef = defCache.get(current) ?? null;
      if (currentDef === undefined) {
        currentDef = findFunctionDef(current, files);
        defCache.set(current, currentDef);
      }
      if (!currentDef) continue;

      for (const callee of extractCalledNames(currentDef.sourceText)) {
        if (callerNames.has(callee)) {
          parentMap.set(callee, current);
          found = callee;
          break outer;
        }
        if (!parentMap.has(callee)) {
          parentMap.set(callee, current);
          queue.push(callee);
        }
      }
    }

    depth++;
  }

  if (!found) return [];

  // Collect intermediate function names by walking the parent_map backwards
  // from the found EIF caller up to (but not including) the entry point handler.
  const intermediateNames: string[] = [];
  let cursor: string | null = parentMap.get(found) ?? null;

  while (cursor !== null && cursor !== entryPoint.handlerFunction) {
    intermediateNames.unshift(cursor);
    cursor = parentMap.get(cursor) ?? null;
  }

  // Resolve each intermediate name to a full CallChainStep
  const chain: CallChainStep[] = [];
  for (const name of intermediateNames) {
    const def = defCache.get(name) ?? findFunctionDef(name, files);
    if (!def) continue;
    defCache.set(name, def);
    chain.push({
      functionName: name,
      file:         def.file,
      startLine:    def.startLine,
      endLine:      def.endLine,
      sourceText:   def.sourceText,
    });
  }

  return chain;
}
