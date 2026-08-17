import { Threat } from '../../types';
import { CodeSlice } from '../ast-analyzer';

// ─── Attack Classification ────────────────────────────────────────────────────

// Derived from the advisory's CWE IDs. Falls back to CVSS vector when CWEs are absent.
export type AttackClass =
  | 'rce'
  | 'ssrf'
  | 'sqli'
  | 'xss'
  | 'path-traversal'
  | 'prototype-pollution'
  | 'deserialization'
  | 'redos'
  | 'dos'
  | 'auth-bypass'
  | 'info-disclosure'
  | 'unknown';

// How rich the advisory description is — determines how much the LLM must infer vs. read.
export type AdvisoryRichness = 'rich' | 'moderate' | 'sparse';

// ─── Entry Point ──────────────────────────────────────────────────────────────

export type EntryPointType =
  | 'http-route'    // Express, Fastify, Koa, Hapi, NestJS
  | 'websocket'     // ws, socket.io
  | 'message-queue' // Bull, BullMQ, amqplib, kafkajs
  | 'cron-job'      // node-cron, agenda — not directly triggerable by attacker
  | 'file-trigger'  // chokidar watcher, direct fs.read with user-controlled path
  | 'cli'           // process.argv — requires local execution
  | 'unknown';

export interface EntryPoint {
  type:             EntryPointType;
  // Human-readable identifier — e.g. "POST /api/upload", "ws:message", "queue:jobs"
  identifier:       string;
  framework:        string | null;  // "express", "fastify", "socket.io", "bullmq", etc.
  handlerFunction:  string;
  handlerFile:      string;
  handlerStartLine: number;
  handlerSource:    string;
  // Request fields that carry attacker-controlled data — e.g. ["req.body.content", "req.params.id"]
  attackableSurface: string[];
}

// ─── Call Chain ───────────────────────────────────────────────────────────────

// One function in the chain between the entry point handler and the EIF caller.
export interface CallChainStep {
  functionName: string;
  file:         string;
  startLine:    number;
  endLine:      number;
  sourceText:   string;
}

// ─── Guards ───────────────────────────────────────────────────────────────────

export type GuardType =
  | 'authentication'
  | 'authorization'
  | 'input-validation'
  | 'rate-limiting'
  | 'size-limit'
  | 'content-type';

export interface DetectedGuard {
  type: GuardType;
  code: string;
  file: string;
  line: number;
}

export interface GuardContext {
  hasAuthentication:  boolean;
  hasInputValidation: boolean;
  guards:             DetectedGuard[];
}

// ─── Exploit Context ─────────────────────────────────────────────────────────

// Everything assembled by C8 steps 3–5 before the LLM call.
export interface ExploitContext {
  threat:           Threat;
  codeSlice:        CodeSlice;
  attackClass:      AttackClass;
  advisoryRichness: AdvisoryRichness;
  entryPoint:       EntryPoint | null;  // null when no reachable entry point is found
  callChain:        CallChainStep[];    // ordered from entry point handler down to EIF caller
  guards:           GuardContext;
}

