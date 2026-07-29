import { Threat } from '../../types';
import { CodeSlice } from '../ast-analyzer';
import { EntryPoint, CallChainStep, GuardContext } from './types';
import { AttackClass, AdvisoryRichness, ExploitContext } from './types';

// ─── Attack Class Classifier ──────────────────────────────────────────────────

// CWE ID → AttackClass mapping. When multiple CWEs are present the first match wins.
// CVSS vector is used as a fallback when no CWE matches.
const CWE_TO_ATTACK_CLASS: Record<string, AttackClass> = {
  'CWE-78':   'rce',              // OS Command Injection
  'CWE-94':   'rce',              // Code Injection
  'CWE-77':   'rce',              // Command Injection
  'CWE-502':  'deserialization',
  'CWE-918':  'ssrf',
  'CWE-89':   'sqli',
  'CWE-79':   'xss',
  'CWE-22':   'path-traversal',
  'CWE-23':   'path-traversal',
  'CWE-1321': 'prototype-pollution',
  'CWE-915':  'prototype-pollution',
  'CWE-400':  'dos',
  'CWE-770':  'dos',
  'CWE-20':   'dos',
  'CWE-287':  'auth-bypass',
  'CWE-306':  'auth-bypass',
  'CWE-862':  'auth-bypass',
  'CWE-200':  'info-disclosure',
  'CWE-209':  'info-disclosure',
  'CWE-117':  'redos',
  'CWE-1333': 'redos',
};

function classifyAttackClass(threat: Threat): AttackClass {
  for (const cwe of threat.cwes) {
    const match = CWE_TO_ATTACK_CLASS[cwe.cweId];
    if (match) return match;
  }

  // CVSS vector fallback — AV:N/AC:L is a strong signal for network-reachable attacks
  const vector = threat.cvss?.vectorString ?? '';
  if (vector.includes('C:H') && vector.includes('I:H')) return 'rce';
  if (vector.includes('CWE-89') || threat.summary.toLowerCase().includes('sql injection')) return 'sqli';
  if (threat.summary.toLowerCase().includes('prototype pollution')) return 'prototype-pollution';
  if (threat.summary.toLowerCase().includes('path traversal'))      return 'path-traversal';
  if (threat.summary.toLowerCase().includes('ssrf'))                return 'ssrf';
  if (threat.summary.toLowerCase().includes('denial of service') || threat.summary.toLowerCase().includes(' dos')) return 'dos';

  return 'unknown';
}

// ─── Advisory Richness Scorer ─────────────────────────────────────────────────

// Estimates how much useful information the advisory text provides to the LLM.
// Rich advisories have PoC details, function names, or step-by-step descriptions.
// Sparse ones are just a one-liner with no technical depth.
function scoreAdvisoryRichness(threat: Threat): AdvisoryRichness {
  const desc = (threat.description ?? '').toLowerCase();
  const wordCount = desc.split(/\s+/).filter(Boolean).length;

  if (wordCount < 30) return 'sparse';

  const richSignals = [
    /proof.of.concept|poc|exploit|payload/i,
    /step.by.step|\d+\.\s/,
    /function|method|parameter|argument|input/i,
    /curl|http|fetch|request/i,
    /`[^`]+`/,        // inline code
    /```[\s\S]+```/,  // code block
  ];

  const richScore = richSignals.filter(re => re.test(desc)).length;

  if (richScore >= 3 || wordCount > 200) return 'rich';
  if (richScore >= 1 || wordCount > 80)  return 'moderate';
  return 'sparse';
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export function assembleContext(
  threat:     Threat,
  codeSlice:  CodeSlice,
  entryPoint: EntryPoint | null,
  callChain:  CallChainStep[],
  guards:     GuardContext,
): ExploitContext {
  return {
    threat,
    codeSlice,
    attackClass:      classifyAttackClass(threat),
    advisoryRichness: scoreAdvisoryRichness(threat),
    entryPoint,
    callChain,
    guards,
  };
}
