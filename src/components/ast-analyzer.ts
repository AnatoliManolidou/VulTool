import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import Parser from 'web-tree-sitter';

// --- Types ---

export interface EIFCallSite {
  file: string;
  line: number;
  callExpression: string;
}

export interface CallerSlice {
  file: string;
  functionName: string;
  sourceText: string;
  startLine: number;
  endLine: number;
}

export interface CodeSlice {
  threatGhsaId: string;
  packageName: string;
  severity: string;
  priorityScore: number;
  affectedFiles: string[];
  eifCallSites: EIFCallSite[];
  callerSlices: CallerSlice[];
}

// --- Parser singleton ---
// tree-sitter.wasm and tree-sitter-javascript.wasm are copied to dist/ by postbuild.
// At runtime __dirname resolves to dist/, so the paths below work correctly.
// We use the JS grammar for all JS/TS/JSX/TSX — imports and call expressions
// are identical syntax in both languages, which is all Phase 2 needs.

let parser: Parser | null = null;
let jsLanguage: Parser.Language | null = null;

async function initParser(): Promise<void> {
  if (parser) return;
  await Parser.init({
    locateFile(scriptName: string) {
      return path.join(__dirname, scriptName);
    },
  });
  parser = new Parser();
  jsLanguage = await Parser.Language.load(
    path.join(__dirname, 'tree-sitter-javascript.wasm')
  );
}

// --- File scanner ---

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);
const EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out',
  'coverage', '.next', '.nuxt', '.cache', '__pycache__',
]);

function findSourceFiles(workspacePath: string): string[] {
  const results: string[] = [];
  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name)) walk(path.join(dir, entry.name));
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        results.push(path.join(dir, entry.name));
      }
    }
  }
  walk(workspacePath);
  return results;
}

// --- Import detection (regex pre-filter) ---
// Quick check before spending time on a full parse.

function fileImportsPackage(source: string, packageName: string): boolean {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    `(?:from\\s+|require\\s*\\(\\s*)['"]${escaped}(?:/[^'"]*)?['"]`
  );
  return pattern.test(source);
}

// --- Step 2a: extract import bindings ---
// Returns the local identifier names that the file bound to the package.
//
// Handles:
//   import express from 'pkg'            → { express }
//   import { Router, static as s } from  → { Router, s }
//   import * as pkg from 'pkg'           → { pkg }
//   const express = require('pkg')       → { express }
//   const { Router } = require('pkg')    → { Router }

function extractImportBindings(tree: Parser.Tree, packageName: string): Set<string> {
  const bindings = new Set<string>();
  const matches = (p: string) => p === packageName || p.startsWith(packageName + '/');

  // ES module import statements
  for (const stmt of tree.rootNode.descendantsOfType('import_statement')) {
    const sourceNode = stmt.childForFieldName('source');
    if (!sourceNode) continue;
    const importPath = sourceNode.text.replace(/^['"]|['"]$/g, '');
    if (!matches(importPath)) continue;

    for (const child of stmt.children) {
      if (child.type !== 'import_clause') continue;
      for (const clauseChild of child.children) {
        if (clauseChild.type === 'identifier') {
          // default import: import express from 'pkg'
          bindings.add(clauseChild.text);
        } else if (clauseChild.type === 'namespace_import') {
          // namespace: import * as express from 'pkg'
          for (const c of clauseChild.children) {
            if (c.type === 'identifier') bindings.add(c.text);
          }
        } else if (clauseChild.type === 'named_imports') {
          // named: import { Router, static as s } from 'pkg'
          for (const specifier of clauseChild.children) {
            if (specifier.type !== 'import_specifier') continue;
            // local name is the alias if present, otherwise the original name
            const local = specifier.childForFieldName('alias') ?? specifier.childForFieldName('name');
            if (local) bindings.add(local.text);
          }
        }
      }
    }
  }

  // CommonJS require() calls
  for (const call of tree.rootNode.descendantsOfType('call_expression')) {
    const fn = call.childForFieldName('function');
    if (!fn || fn.type !== 'identifier' || fn.text !== 'require') continue;
    const args = call.childForFieldName('arguments');
    if (!args) continue;
    const strNode = args.descendantsOfType('string')[0];
    if (!strNode) continue;
    const reqPath = strNode.text.replace(/^['"]|['"]$/g, '');
    if (!matches(reqPath)) continue;

    // Walk up to the variable_declarator that wraps this require call
    let cursor: Parser.SyntaxNode | null = call.parent;
    while (cursor && cursor.type !== 'variable_declarator') cursor = cursor.parent;
    if (!cursor) continue;

    const pattern = cursor.childForFieldName('name');
    if (!pattern) continue;

    if (pattern.type === 'identifier') {
      // const express = require('pkg')
      bindings.add(pattern.text);
    } else if (pattern.type === 'object_pattern') {
      // const { Router, use: u } = require('pkg')
      for (const child of pattern.children) {
        if (child.type === 'shorthand_property_identifier_pattern') {
          bindings.add(child.text);
        } else if (child.type === 'pair_pattern') {
          const val = child.childForFieldName('value');
          if (val?.type === 'identifier') bindings.add(val.text);
        }
      }
    }
  }

  return bindings;
}

// --- Step 2b: find EIF call site nodes ---
// Returns the raw call_expression AST nodes where the callee is (or starts with)
// one of the known package bindings.
//
//   express()              callee is identifier 'express'
//   express.static(...)    callee is member_expression with object 'express'
//   Router()               callee is identifier 'Router'

function findEIFNodes(tree: Parser.Tree, bindings: Set<string>): Parser.SyntaxNode[] {
  const nodes: Parser.SyntaxNode[] = [];

  // Regular call expressions: binding() or binding.method()
  for (const call of tree.rootNode.descendantsOfType('call_expression')) {
    const fn = call.childForFieldName('function');
    if (!fn) continue;
    if (fn.type === 'identifier' && bindings.has(fn.text)) {
      nodes.push(call);
    } else if (fn.type === 'member_expression') {
      const obj = fn.childForFieldName('object');
      if (obj?.type === 'identifier' && bindings.has(obj.text)) nodes.push(call);
    }
  }

  // Constructor calls: new Binding(...) — a distinct node type in the grammar.
  // Instantiating a vulnerable class is itself an EIF (e.g. new Client({ endpoint })
  // triggers the URL validation path where the vulnerability lives).
  for (const newExpr of tree.rootNode.descendantsOfType('new_expression')) {
    const ctor = newExpr.childForFieldName('constructor');
    if (!ctor) continue;
    if (ctor.type === 'identifier' && bindings.has(ctor.text)) {
      nodes.push(newExpr);
    } else if (ctor.type === 'member_expression') {
      const obj = ctor.childForFieldName('object');
      if (obj?.type === 'identifier' && bindings.has(obj.text)) nodes.push(newExpr);
    }
  }

  return nodes;
}

// --- Step 2c: walk up to enclosing function + slice extraction ---

const FUNCTION_NODE_TYPES = new Set([
  'function_declaration',
  'function_expression',
  'arrow_function',
  'method_definition',
  'generator_function_declaration',
  'generator_function',
]);

function getEnclosingFunction(node: Parser.SyntaxNode): Parser.SyntaxNode | null {
  let current = node.parent;
  while (current) {
    if (FUNCTION_NODE_TYPES.has(current.type)) return current;
    current = current.parent;
  }
  return null;
}

function buildCallerSlice(fn: Parser.SyntaxNode, source: string, file: string): CallerSlice {
  // Named function declarations have a 'name' field directly.
  // Arrow functions and function expressions assigned to a variable don't —
  // the name lives on the parent variable_declarator instead.
  const nameNode = fn.childForFieldName('name');
  let functionName = nameNode?.text;
  if (!functionName && fn.parent?.type === 'variable_declarator') {
    functionName = fn.parent.childForFieldName('name')?.text;
  }
  return {
    file,
    functionName: functionName ?? '<anonymous>',
    sourceText:   source.slice(fn.startIndex, fn.endIndex),
    startLine:    fn.startPosition.row + 1,
    endLine:      fn.endPosition.row + 1,
  };
}

// Fallback for EIF calls at module scope (not inside any function).
// Extracts a context window of lines around the call site.
function buildModuleLevelSlice(callNode: Parser.SyntaxNode, source: string, file: string): CallerSlice {
  const CONTEXT = 10;
  const lines = source.split('\n');
  const callLine = callNode.startPosition.row;
  const startLine = Math.max(0, callLine - CONTEXT);
  const endLine   = Math.min(lines.length - 1, callLine + CONTEXT);
  return {
    file,
    functionName: '<module>',
    sourceText:   lines.slice(startLine, endLine + 1).join('\n'),
    startLine:    startLine + 1,
    endLine:      endLine + 1,
  };
}

// --- Main export ---

export async function analyzeCodeUsage(
  npmThreats: any[],
  workspacePath: string
): Promise<CodeSlice[]> {
  core.info('Component 7: Waking up AST Analyzer...');

  await initParser();

  const sourceFiles = findSourceFiles(workspacePath);
  core.info(`Scanning ${sourceFiles.length} source file(s) across the repository.`);

  const results: CodeSlice[] = [];

  for (const threat of npmThreats) {
    core.info(`Analyzing usage of: ${threat.packageName} (${threat.ghsaId})`);

    // Step 1 — narrow to files that import the vulnerable package (fast regex pre-filter)
    const affectedFiles: string[] = [];
    const sourceCaches = new Map<string, string>();

    for (const file of sourceFiles) {
      try {
        const source = fs.readFileSync(file, 'utf8');
        if (fileImportsPackage(source, threat.packageName)) {
          affectedFiles.push(file);
          sourceCaches.set(file, source);
        }
      } catch { /* unreadable — skip */ }
    }

    if (affectedFiles.length === 0) {
      core.info(`  No direct imports of ${threat.packageName} found — skipping.`);
      continue;
    }

    core.info(`  ${affectedFiles.length} file(s) import ${threat.packageName}. Running AST pass...`);

    const eifCallSites: EIFCallSite[] = [];
    const callerSlices: CallerSlice[] = [];

    for (const file of affectedFiles) {
      if (!jsLanguage || !parser) continue;

      const source = sourceCaches.get(file)!;
      parser.setLanguage(jsLanguage);
      const tree = parser.parse(source);
      const relPath = path.relative(workspacePath, file);

      // Step 2a — resolve which local names are bound to this package
      const bindings = extractImportBindings(tree, threat.packageName);
      if (bindings.size === 0) {
        core.info(`  [${relPath}] Import found but bindings unresolved — skipping EIF scan.`);
        continue;
      }

      core.info(`  [${relPath}] Bindings resolved: ${[...bindings].join(', ')}`);

      // Step 2b — find all EIF call site nodes
      const eifNodes = findEIFNodes(tree, bindings);
      core.info(`  [${relPath}] EIF call sites found: ${eifNodes.length}`);

      for (const node of eifNodes) {
        const text = node.text;
        eifCallSites.push({
          file,
          line: node.startPosition.row + 1,
          callExpression: text.length > 120 ? text.slice(0, 120) + '...' : text,
        });
      }

      // Step 2c — extract unique caller slices (deduplicated by enclosing function position)
      // If a call is at module scope (no enclosing function), fall back to a context window.
      const seenFunctions = new Set<string>();
      for (const node of eifNodes) {
        const fn = getEnclosingFunction(node);
        if (fn) {
          const key = `${file}:${fn.startPosition.row}`;
          if (seenFunctions.has(key)) continue;
          seenFunctions.add(key);
          callerSlices.push(buildCallerSlice(fn, source, file));
        } else {
          const key = `${file}:module:${node.startPosition.row}`;
          if (seenFunctions.has(key)) continue;
          seenFunctions.add(key);
          callerSlices.push(buildModuleLevelSlice(node, source, file));
        }
      }
    }

    const funcNames = callerSlices.length > 0
      ? [...new Set(callerSlices.map(s => s.functionName))].join(', ')
      : 'none';
    core.info(`  EIF call sites: ${eifCallSites.length} | Caller functions: ${funcNames}`);

    results.push({
      threatGhsaId:  threat.ghsaId,
      packageName:   threat.packageName,
      severity:      threat.severity,
      priorityScore: threat.priorityScore,
      affectedFiles,
      eifCallSites,
      callerSlices,
    });
  }

  core.info(`AST analysis complete. ${results.length} threat(s) have confirmed code usage.`);
  return results;
}
