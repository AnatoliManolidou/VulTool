import * as fs from 'fs';
import * as path from 'path';
import Parser from 'web-tree-sitter';
import { Threat } from '../types';

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
  isIndirect?: boolean;
  viaPackage?: string;
}

// tree-sitter.wasm and tree-sitter-javascript.wasm are copied to dist/ by postbuild.
// At runtime __dirname resolves to dist/, so the paths below work correctly.
// The JS grammar covers TS/JSX/TSX too — import and call expression syntax is identical.
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

// Regex pre-filter before full parse — avoids parsing files that don't import the package.
function fileImportsPackage(source: string, packageName: string): boolean {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    `(?:from\\s+|require\\s*\\(\\s*)['"]${escaped}(?:/[^'"]*)?['"]`
  );
  return pattern.test(source);
}

// Returns the local identifier names the file bound to the package.
// Handles all import forms:
//   import express from 'pkg'           → { express }
//   import { Router, static as s } from → { Router, s }
//   import * as pkg from 'pkg'          → { pkg }
//   const express = require('pkg')      → { express }
//   const { Router } = require('pkg')   → { Router }
function extractImportBindings(tree: Parser.Tree, packageName: string): Set<string> {
  const bindings = new Set<string>();
  const matches = (p: string) => p === packageName || p.startsWith(packageName + '/');

  for (const stmt of tree.rootNode.descendantsOfType('import_statement')) {
    const sourceNode = stmt.childForFieldName('source');
    if (!sourceNode) continue;
    const importPath = sourceNode.text.replace(/^['"]|['"]$/g, '');
    if (!matches(importPath)) continue;

    for (const child of stmt.children) {
      if (child.type !== 'import_clause') continue;
      for (const clauseChild of child.children) {
        if (clauseChild.type === 'identifier') {
          bindings.add(clauseChild.text);
        } else if (clauseChild.type === 'namespace_import') {
          for (const c of clauseChild.children) {
            if (c.type === 'identifier') bindings.add(c.text);
          }
        } else if (clauseChild.type === 'named_imports') {
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
      bindings.add(pattern.text);
    } else if (pattern.type === 'object_pattern') {
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

function findEIFNodes(tree: Parser.Tree, bindings: Set<string>): Parser.SyntaxNode[] {
  const nodes: Parser.SyntaxNode[] = [];

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

  // new Binding(...) is a separate node type — instantiating a vulnerable class
  // is itself an EIF because the constructor triggers the vulnerable code path.
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
  // Arrow functions and function expressions don't have a 'name' field —
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

// EIF call at module scope (outside any function) — extract a ±10-line context window.
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

function readDirectDependencies(workspacePath: string): Set<string> {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(workspacePath, 'package.json'), 'utf8'));
    return new Set([
      ...Object.keys(pkg.dependencies    ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ]);
  } catch {
    return new Set();
  }
}

function findConsumerPackages(
  vulnerablePackage: string,
  directDeps: Set<string>,
  workspacePath: string,
): string[] {
  const consumers: string[] = [];
  const nodeModulesPath = path.join(workspacePath, 'node_modules');

  for (const dep of directDeps) {
    const pkgJsonPath = path.join(nodeModulesPath, dep, 'package.json');
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      if (pkg.dependencies?.[vulnerablePackage] || pkg.peerDependencies?.[vulnerablePackage]) {
        consumers.push(dep);
      }
    } catch { /* dep not in node_modules — skip */ }
  }

  return consumers;
}

function findIndirectUsage(
  threat: Threat,
  consumers: string[],
  sourceFiles: string[],
  workspacePath: string,
): CodeSlice | null {
  if (!parser || !jsLanguage) return null;

  for (const consumer of consumers) {
    const affectedFiles: string[] = [];
    const sourceCaches = new Map<string, string>();

    for (const file of sourceFiles) {
      try {
        const source = fs.readFileSync(file, 'utf8');
        if (fileImportsPackage(source, consumer)) {
          affectedFiles.push(file);
          sourceCaches.set(file, source);
        }
      } catch { continue; }
    }

    if (affectedFiles.length === 0) continue;

    const eifCallSites: EIFCallSite[] = [];
    const callerSlices: CallerSlice[] = [];

    for (const file of affectedFiles) {
      const source = sourceCaches.get(file)!;
      parser.setLanguage(jsLanguage);
      const tree = parser.parse(source);

      const bindings = extractImportBindings(tree, consumer);
      if (bindings.size === 0) continue;

      const eifNodes = findEIFNodes(tree, bindings);

      for (const node of eifNodes) {
        const text = node.text;
        eifCallSites.push({
          file,
          line: node.startPosition.row + 1,
          callExpression: text.length > 120 ? text.slice(0, 120) + '...' : text,
        });
      }

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

    if (eifCallSites.length > 0) {
      return {
        threatGhsaId:  threat.ghsaId,
        packageName:   threat.packageName,
        severity:      threat.severity,
        priorityScore: threat.priorityScore,
        affectedFiles,
        eifCallSites,
        callerSlices,
        isIndirect:    true,
        viaPackage:    consumer,
      };
    }
  }

  return null;
}

export async function analyzeCodeUsage(
  npmThreats: Threat[],
  workspacePath: string
): Promise<CodeSlice[]> {
  await initParser();

  const sourceFiles  = findSourceFiles(workspacePath);
  const directDeps   = readDirectDependencies(workspacePath);
  const results: CodeSlice[] = [];

  for (const threat of npmThreats) {
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
      const consumers    = findConsumerPackages(threat.packageName, directDeps, workspacePath);
      const indirectSlice = findIndirectUsage(threat, consumers, sourceFiles, workspacePath);
      if (indirectSlice) results.push(indirectSlice);
      continue;
    }

    const eifCallSites: EIFCallSite[] = [];
    const callerSlices: CallerSlice[] = [];

    for (const file of affectedFiles) {
      if (!jsLanguage || !parser) continue;

      const source = sourceCaches.get(file)!;
      parser.setLanguage(jsLanguage);
      const tree = parser.parse(source);
      const relPath = path.relative(workspacePath, file);

      const bindings = extractImportBindings(tree, threat.packageName);
      if (bindings.size === 0) continue;

      const eifNodes = findEIFNodes(tree, bindings);

      for (const node of eifNodes) {
        const text = node.text;
        eifCallSites.push({
          file,
          line: node.startPosition.row + 1,
          callExpression: text.length > 120 ? text.slice(0, 120) + '...' : text,
        });
      }

      // Deduplicated by enclosing function position; module-scope calls fall back to a context window.
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

  return results;
}
