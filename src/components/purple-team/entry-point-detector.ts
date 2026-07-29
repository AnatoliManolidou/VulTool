import * as fs from 'fs';
import * as path from 'path';
import Parser from 'web-tree-sitter';
import { EntryPoint } from './types';
import { CallerSlice } from '../ast-analyzer';

// ─── Parser ───────────────────────────────────────────────────────────────────

let parser: Parser | null = null;
let jsLanguage: Parser.Language | null = null;

async function initParser(): Promise<void> {
  if (parser) return;
  await Parser.init({ locateFile: (f: string) => path.join(__dirname, f) });
  parser = new Parser();
  jsLanguage = await Parser.Language.load(path.join(__dirname, 'tree-sitter-javascript.wasm'));
}

// ─── Framework Detection ──────────────────────────────────────────────────────

function readDependencies(workspacePath: string): Record<string, string> {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(workspacePath, 'package.json'), 'utf8'));
    return { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  } catch {
    return {};
  }
}

function resolveHttpFramework(deps: Record<string, string>): string | null {
  if (deps['express'])        return 'express';
  if (deps['fastify'])        return 'fastify';
  if (deps['koa'])            return 'koa';
  if (deps['@hapi/hapi'])     return 'hapi';
  if (deps['@nestjs/core'])   return 'nestjs';
  return null;
}

function resolveWsFramework(deps: Record<string, string>): string | null {
  if (deps['socket.io']) return 'socket.io';
  if (deps['ws'])        return 'ws';
  return null;
}

function resolveQueueFramework(deps: Record<string, string>): string | null {
  if (deps['bullmq'])  return 'bullmq';
  if (deps['bull'])    return 'bull';
  if (deps['amqplib']) return 'amqplib';
  if (deps['kafkajs']) return 'kafkajs';
  return null;
}

// ─── Pre-filter Regexes ───────────────────────────────────────────────────────

// Each regex is checked against the raw file source before paying the cost of a full parse.
const HTTP_ROUTE_RE   = /\.(get|post|put|delete|patch|use)\s*\(/;
const WS_HANDLER_RE   = /\.on\s*\(\s*['"](?:connection|message|data)/;
const QUEUE_WORKER_RE = /queue\.process|new\s+Worker\s*\(|consumer\.run|channel\.consume/;
const CRON_RE         = /cron\.schedule|agenda\.define|scheduleJob\s*\(/;

// ─── Attackable Surface Extraction ───────────────────────────────────────────

// Scans a handler's source text for every field the handler reads from the incoming
// request. These are the fields the attacker can control.
function extractAttackableSurface(source: string): string[] {
  const patterns = [
    /req\.body(?:\.\w+)*/g,
    /req\.params(?:\.\w+)*/g,
    /req\.query(?:\.\w+)*/g,
    /req\.headers(?:\.\w+)*/g,
    /req\.cookies?(?:\.\w+)*/g,
    /req\.files?(?:\.\w+)*/g,
    /ctx\.request\.body(?:\.\w+)*/g,
    /ctx\.params(?:\.\w+)*/g,
    /ctx\.query(?:\.\w+)*/g,
  ];
  const found = new Set<string>();
  for (const re of patterns) {
    for (const match of source.matchAll(re)) found.add(match[0]);
  }
  return [...found];
}

// ─── HTTP Entry Point ─────────────────────────────────────────────────────────

const HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'use']);

function findHttpEntryPoint(
  callerNames: Set<string>,
  files: string[],
  framework: string | null,
): EntryPoint | null {
  for (const file of files) {
    let source: string;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }

    if (!HTTP_ROUTE_RE.test(source)) continue;
    if (![...callerNames].some(name => source.includes(name))) continue;

    if (!parser || !jsLanguage) continue;
    parser.setLanguage(jsLanguage);
    const tree = parser.parse(source);

    for (const call of tree.rootNode.descendantsOfType('call_expression')) {
      const fn = call.childForFieldName('function');
      if (!fn || fn.type !== 'member_expression') continue;

      const method = fn.childForFieldName('property')?.text?.toLowerCase();
      if (!method || !HTTP_METHODS.has(method)) continue;

      const args = call.childForFieldName('arguments');
      if (!args) continue;

      const argNodes = args.children.filter(
        c => c.type !== ',' && c.type !== '(' && c.type !== ')',
      );

      // First string argument is the route path
      const routePath = argNodes
        .find(n => n.type === 'string')
        ?.text.replace(/^['"`]|['"`]$/g, '') ?? '';

      // Last function argument is the handler (middleware may precede it)
      const handlerNode = [...argNodes].reverse().find(n =>
        n.type === 'arrow_function' ||
        n.type === 'function_expression' ||
        n.type === 'identifier',
      );
      if (!handlerNode) continue;

      const handlerSource = handlerNode.text;

      const matchedCaller = [...callerNames].find(name => handlerSource.includes(name));
      if (!matchedCaller) continue;

      return {
        type:             'http-route',
        identifier:       `${method.toUpperCase()} ${routePath || '/'}`,
        framework:        framework,
        handlerFunction:  matchedCaller,
        handlerFile:      file,
        handlerStartLine: handlerNode.startPosition.row + 1,
        handlerSource,
        attackableSurface: extractAttackableSurface(handlerSource),
      };
    }
  }
  return null;
}

// ─── WebSocket Entry Point ────────────────────────────────────────────────────

function findWsEntryPoint(
  callerNames: Set<string>,
  files: string[],
  framework: string | null,
): EntryPoint | null {
  for (const file of files) {
    let source: string;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }

    if (!WS_HANDLER_RE.test(source)) continue;
    if (![...callerNames].some(name => source.includes(name))) continue;

    if (!parser || !jsLanguage) continue;
    parser.setLanguage(jsLanguage);
    const tree = parser.parse(source);

    for (const call of tree.rootNode.descendantsOfType('call_expression')) {
      const fn = call.childForFieldName('function');
      if (!fn || fn.type !== 'member_expression') continue;
      if (fn.childForFieldName('property')?.text !== 'on') continue;

      const args = call.childForFieldName('arguments');
      if (!args) continue;

      const argNodes = args.children.filter(
        c => c.type !== ',' && c.type !== '(' && c.type !== ')',
      );

      const event = argNodes[0]?.text.replace(/^['"`]|['"`]$/g, '') ?? '';
      if (!['connection', 'message', 'data'].includes(event)) continue;

      const handlerNode = argNodes[1];
      if (!handlerNode) continue;

      const handlerSource = handlerNode.text;
      const matchedCaller = [...callerNames].find(name => handlerSource.includes(name));
      if (!matchedCaller) continue;

      return {
        type:             'websocket',
        identifier:       `ws:${event}`,
        framework:        framework,
        handlerFunction:  matchedCaller,
        handlerFile:      file,
        handlerStartLine: handlerNode.startPosition.row + 1,
        handlerSource,
        // WebSocket payload fields are not standardised — flag both common shapes
        attackableSurface: ['message.data', 'message.payload'],
      };
    }
  }
  return null;
}

// ─── Message Queue Entry Point ────────────────────────────────────────────────

function findQueueEntryPoint(
  callerNames: Set<string>,
  files: string[],
  framework: string | null,
): EntryPoint | null {
  for (const file of files) {
    let source: string;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }

    if (!QUEUE_WORKER_RE.test(source)) continue;

    const matchedCaller = [...callerNames].find(name => source.includes(name));
    if (!matchedCaller) continue;

    // Queue consumer patterns vary significantly across libraries — regex is
    // more reliable here than AST traversal for the initial detection.
    const queueName =
      source.match(/new\s+Worker\s*\(\s*['"`]([^'"`]+)['"`]/)?.[1] ??
      source.match(/queue\.process\s*\(\s*['"`]([^'"`]+)['"`]/)?.[1] ??
      'unknown';

    return {
      type:             'message-queue',
      identifier:       `queue:${queueName}`,
      framework:        framework,
      handlerFunction:  matchedCaller,
      handlerFile:      file,
      handlerStartLine: 0,
      handlerSource:    source,
      attackableSurface: ['job.data', 'message.content'],
    };
  }
  return null;
}

// ─── Cron Entry Point ─────────────────────────────────────────────────────────

function findCronEntryPoint(
  callerNames: Set<string>,
  files: string[],
): EntryPoint | null {
  for (const file of files) {
    let source: string;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }

    if (!CRON_RE.test(source)) continue;

    const matchedCaller = [...callerNames].find(name => source.includes(name));
    if (!matchedCaller) continue;

    const schedule =
      source.match(/cron\.schedule\s*\(\s*['"`]([^'"`]+)['"`]/)?.[1] ??
      source.match(/scheduleJob\s*\(\s*['"`]([^'"`]+)['"`]/)?.[1] ??
      'unknown';

    return {
      type:             'cron-job',
      identifier:       `cron:${schedule}`,
      framework:        null,
      handlerFunction:  matchedCaller,
      handlerFile:      file,
      handlerStartLine: 0,
      handlerSource:    source,
      // Cron jobs are not directly triggerable by an external attacker
      attackableSurface: [],
    };
  }
  return null;
}

// ─── File Scanner ─────────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);
const EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out',
  'coverage', '.next', '.nuxt', '.cache', '__pycache__',
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

// ─── Upstream Caller Discovery ────────────────────────────────────────────────

// Returns names of functions (one hop up) whose body contains a call to any
// name in `callerNames`.  Handles the common pattern where a route handler
// delegates to a service function that then calls the EIF caller — without
// this the entry-point search would miss routes that don't mention the EIF
// caller directly.
function findParentCallers(
  callerNames: Set<string>,
  files: string[],
): Set<string> {
  const parents = new Set<string>();

  if (!parser || !jsLanguage) return parents;

  for (const file of files) {
    let source: string;
    try { source = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (![...callerNames].some(name => source.includes(name))) continue;

    parser.setLanguage(jsLanguage);
    const tree = parser.parse(source);

    for (const fn of tree.rootNode.descendantsOfType('function_declaration')) {
      const fnName = fn.childForFieldName('name')?.text;
      if (!fnName || callerNames.has(fnName)) continue;
      if ([...callerNames].some(name => fn.text.includes(name))) parents.add(fnName);
    }

    for (const decl of tree.rootNode.descendantsOfType('variable_declarator')) {
      const id    = decl.childForFieldName('name');
      const value = decl.childForFieldName('value');
      if (!id || !value) continue;
      if (value.type !== 'arrow_function' && value.type !== 'function_expression') continue;
      const fnName = id.text;
      if (callerNames.has(fnName)) continue;
      if ([...callerNames].some(name => value.text.includes(name))) parents.add(fnName);
    }
  }

  return parents;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export async function detectEntryPoint(
  callerSlices: CallerSlice[],
  workspacePath: string,
): Promise<EntryPoint | null> {
  await initParser();

  // Anonymous and module-level callers have no useful name to search for
  const callerNames = new Set(
    callerSlices
      .map(s => s.functionName)
      .filter(n => n !== '<anonymous>' && n !== '<module>'),
  );

  if (callerNames.size === 0) return null;

  const deps          = readDependencies(workspacePath);
  const httpFramework = resolveHttpFramework(deps);
  const wsFramework   = resolveWsFramework(deps);
  const queueFw       = resolveQueueFramework(deps);
  const files         = findSourceFiles(workspacePath);

  // Expand the search set with functions that call our EIF callers directly —
  // covers the route → service → EIF caller indirection pattern.
  const parentCallers = findParentCallers(callerNames, files);
  const searchNames   = new Set([...callerNames, ...parentCallers]);

  // Priority: HTTP is checked first — it is the most accessible surface
  // for an external attacker and the most common in web applications.
  return (
    findHttpEntryPoint(searchNames, files, httpFramework) ??
    findWsEntryPoint(searchNames, files, wsFramework)     ??
    findQueueEntryPoint(searchNames, files, queueFw)      ??
    findCronEntryPoint(searchNames, files)                ??
    null
  );
}
