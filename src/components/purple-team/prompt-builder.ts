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
    ? 'None detected — the code path has no authentication, input validation, or rate-limiting guards.'
    : guards.guards.map(g => `${g.type} at ${g.file}:${g.line} — \`${g.code}\``).join('\n');

  const indirectNote = codeSlice.isIndirect
    ? `\nINDIRECT PATH: The user's code does not import ${threat.packageName} directly. ` +
      `It imports "${codeSlice.viaPackage}", which depends on ${threat.packageName} internally. ` +
      `The call sites below show calls to "${codeSlice.viaPackage}" — assess whether ` +
      `user-controlled data flowing through those calls can trigger the underlying ` +
      `${threat.packageName} vulnerability.`
    : '';

  const cwes = threat.cwes.map(c => `${c.cweId} (${c.name})`).join(', ') || 'none';
  const cvss = threat.cvss ? `${threat.cvss.score} — ${threat.cvss.vectorString}` : 'not available';
  const patchedIn = threat.firstPatchedVersion ?? 'no patch available';

  return `
You are a software security engineer performing an authorized code review to assess whether a known library vulnerability is reachable in this codebase. The development team needs to prioritize patching — your job is to determine whether this issue requires immediate action.

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
Vulnerability class : ${attackClass}
Advisory depth : ${advisoryRichness}

${threat.description ? `Advisory description:\n${threat.description}\n` : ''}
═══════════════════════════════════════════════
CODE ANALYSIS
═══════════════════════════════════════════════
Code path      : ${attackPath}
Input surface  : ${entryPoint?.attackableSurface.join(', ') || 'unknown'}
Guards         : ${guardSummary}${indirectNote}

Call sites (where this codebase calls into the ${codeSlice.isIndirect ? `"${codeSlice.viaPackage}" consumer package` : 'vulnerable package'}):
${codeSlice.eifCallSites.map(s => `  ${s.callExpression} (line ${s.line})`).join('\n')}

Caller function source code:
\`\`\`javascript
${callerCode}
\`\`\`

═══════════════════════════════════════════════
TASK
═══════════════════════════════════════════════
Produce a vulnerability reachability report with exactly these sections:

## Reachability Assessment
In 2–3 sentences: is this vulnerability reachable and triggerable in this specific codebase given the code path and guards above? Reference the actual route and input surface. Be direct — do not repeat the advisory summary.

## Trigger Conditions
A concrete, step-by-step description of how this vulnerability could be triggered: what input causes it, how it flows through the call chain to the vulnerable function, and what the impact would be. Reference the real function names.

## Verification Steps
A concrete test case a developer can use to confirm whether the vulnerability is reachable. Use the real route, method, and field names from the code analysis above. Format as an HTTP request or curl command. Label it clearly as LLM-generated and note what observable effect confirms the vulnerability is present (e.g. server hang, error response, timeout).

## Risk Verdict
A single line in this exact format:
VERDICT: <EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|NOT_EXPLOITABLE> — <one sentence justification>

## Adjacent Risks
While reviewing the code path above, identify any other security weaknesses in the *application's own code* — such as SSRF, injection flaws, missing authentication, open redirects, or insecure deserialization — that are distinct from the library advisory under review.

For each finding, one line in this exact format:
ADJACENT_RISK: <vulnerability type> — <one sentence: what the application code does wrong and how it could be triggered>

If you observed no adjacent risks in the code above, write exactly:
ADJACENT_RISK: none
`.trim();
}
