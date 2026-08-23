import { ExploitContext } from './types';

export function buildExploitPrompt(ctx: ExploitContext): string {
  const { threat, codeSlice, entryPoint, callChain, guards, attackClass, advisoryRichness } = ctx;

  const attackPath = entryPoint
    ? [
        entryPoint.identifier,
        entryPoint.handlerFunction,
        ...callChain.map(s => s.functionName),
        ...codeSlice.callerSlices.map(s => s.functionName),
        threat.packageName,
      ].join(' → ')
    : 'entry point not traced';

  const callerCode = codeSlice.callerSlices
    .map(s => `// ${s.functionName} (${s.file}:${s.startLine})\n${s.sourceText}`)
    .join('\n\n');

  const guardSummary = guards.guards.length === 0
    ? 'None detected — the attack path has no authentication, input validation, or rate-limiting guards.'
    : guards.guards.map(g => `${g.type} at ${g.file}:${g.line} — \`${g.code}\``).join('\n');

  const indirectNote = codeSlice.isIndirect
    ? `\nINDIRECT PATH: The user's code does not import ${threat.packageName} directly. ` +
      `It imports "${codeSlice.viaPackage}", which depends on ${threat.packageName} internally. ` +
      `The call sites below show calls to "${codeSlice.viaPackage}" — assess whether ` +
      `attacker-controlled data flowing through those calls can trigger the underlying ` +
      `${threat.packageName} vulnerability.`
    : '';

  const cwes = threat.cwes.map(c => `${c.cweId} (${c.name})`).join(', ') || 'none';
  const cvss = threat.cvss ? `${threat.cvss.score} — ${threat.cvss.vectorString}` : 'not available';
  const patchedIn = threat.firstPatchedVersion ?? 'no patch available';

  return `
You are a senior application security engineer performing a red-team exploit analysis. Your job is to determine whether this vulnerability is actually exploitable in this specific codebase, and if so, exactly how an attacker would do it.

═══════════════════════════════════════════════
VULNERABILITY FINDING
═══════════════════════════════════════════════
Package        : ${threat.packageName}
Advisory       : ${threat.ghsaId}
Summary        : ${threat.summary}
Severity       : ${threat.severity}
CWEs           : ${cwes}
CVSS           : ${cvss}
Affected range : ${threat.vulnerableVersionRange ?? 'unknown'}
Patched in     : ${patchedIn}
Attack class   : ${attackClass}
Advisory depth : ${advisoryRichness}

${threat.description ? `Advisory description:\n${threat.description}\n` : ''}
═══════════════════════════════════════════════
CODE ANALYSIS
═══════════════════════════════════════════════
Attack path    : ${attackPath}
Attack surface : ${entryPoint?.attackableSurface.join(', ') || 'unknown'}
Guards         : ${guardSummary}${indirectNote}

EIF call sites (where this codebase calls into the ${codeSlice.isIndirect ? `"${codeSlice.viaPackage}" consumer package` : 'vulnerable package'}):
${codeSlice.eifCallSites.map(s => `  ${s.callExpression} (line ${s.line})`).join('\n')}

Caller function source code:
\`\`\`javascript
${callerCode}
\`\`\`

═══════════════════════════════════════════════
TASK
═══════════════════════════════════════════════
Produce an exploit analysis report with exactly these four sections:

## Exploit Feasibility
In 2–3 sentences: is this vulnerability exploitable in this specific codebase given the attack path and guards above? Reference the actual route and input surface. Be direct — do not repeat the advisory summary.

## Attack Scenario
A concrete, step-by-step description of how an attacker would exploit this: what they send, how it reaches the vulnerable function, and what the impact is. Reference the real function names and call chain.

## Proof of Concept
A ready-to-run exploit payload targeting this specific endpoint and input surface. Use the real route, method, and field names from the code analysis above. Format as an HTTP request or curl command. Label it clearly as LLM-generated and note what observable effect confirms it worked (e.g. server hang, error response, timeout).

## Risk Verdict
A single line in this exact format:
VERDICT: <EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|NOT_EXPLOITABLE> — <one sentence justification>
`.trim();
}
