import { GuardContext, GuardType, DetectedGuard, EntryPoint, CallChainStep } from './types';
import { CodeSlice } from '../ast-analyzer';

// ─── Guard Patterns ───────────────────────────────────────────────────────────

// One pattern per GuardType. Each regex looks for the most common library calls
// and naming conventions — not exhaustive but covers the dominant patterns in
// npm web apps (Express, Fastify, Koa, NestJS).
const GUARD_PATTERNS: Record<GuardType, RegExp> = {
  'authentication': /passport\.authenticate|jwt\.verify|jsonwebtoken\.verify|req\.isAuthenticated\s*\(\)|verifyToken|authenticateJWT|requireAuth|@UseGuards.*AuthGuard/i,
  'authorization':  /req\.user\.role|hasPermission|checkRole|hasRole|authorize\s*\(|@Roles\s*\(/i,
  'input-validation': /Joi\s*\.|validationResult\s*\(|z\s*\.\s*(parse|safeParse)|\.safeParse\s*\(|yup\s*\.|check\s*\(['"]\w|sanitize/i,
  'rate-limiting':  /rateLimit|rateLimiter|rate[_-]limit|limiter\.consume|checkRateLimit/i,
  'size-limit':     /limits\s*:\s*\{|fileSize|maxFileSize|bodyLimit/i,
  'content-type':   /content[_-]?[Tt]ype|mimetype|fileFilter/i,
};

// ─── Snippet Extractor ────────────────────────────────────────────────────────

// Given a source string and the character index of a regex match, returns
// the matched line text and its 1-based line number within the source fragment.
function extractSnippet(source: string, matchIndex: number): { code: string; line: number } {
  const lines = source.split('\n');
  const lineNumber = source.substring(0, matchIndex).split('\n').length;
  return {
    code: (lines[lineNumber - 1] ?? '').trim(),
    line: lineNumber,
  };
}

// ─── Source Scanner ───────────────────────────────────────────────────────────

// Scans a single source fragment for all guard types.
// `lineOffset` converts fragment-relative line numbers to file-level line numbers.
function scanSource(source: string, file: string, lineOffset: number): DetectedGuard[] {
  const guards: DetectedGuard[] = [];

  for (const [type, pattern] of Object.entries(GUARD_PATTERNS) as [GuardType, RegExp][]) {
    const match = pattern.exec(source);
    if (!match) continue;
    const { code, line } = extractSnippet(source, match.index);
    guards.push({ type, code, file, line: line + lineOffset });
  }

  return guards;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export function detectGuards(
  entryPoint: EntryPoint | null,
  callChain: CallChainStep[],
  codeSlice: CodeSlice,
): GuardContext {
  const raw: DetectedGuard[] = [];

  if (entryPoint) {
    // handlerStartLine is 1-based, so offset = startLine - 1
    raw.push(...scanSource(entryPoint.handlerSource, entryPoint.handlerFile, entryPoint.handlerStartLine - 1));
  }

  for (const step of callChain) {
    raw.push(...scanSource(step.sourceText, step.file, step.startLine - 1));
  }

  for (const caller of codeSlice.callerSlices) {
    raw.push(...scanSource(caller.sourceText, caller.file, caller.startLine - 1));
  }

  // Deduplicate: same guard type at the same location (same file + line) should
  // not be reported twice even if it was found in overlapping source fragments.
  const seen = new Set<string>();
  const guards = raw.filter(g => {
    const key = `${g.type}:${g.file}:${g.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    hasAuthentication:  guards.some(g => g.type === 'authentication' || g.type === 'authorization'),
    hasInputValidation: guards.some(g => g.type === 'input-validation'),
    guards,
  };
}
