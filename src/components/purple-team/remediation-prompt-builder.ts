import { ExploitContext } from './types';

export function buildRemediationPrompt(
  ctx: ExploitContext,
  verdict: string,
  llmReport: string,
): string {
  const { threat, codeSlice, entryPoint, callChain, guards } = ctx;

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
    ? 'None — no authentication, input validation, or rate-limiting guards detected.'
    : guards.guards.map(g => `${g.type} at ${g.file}:${g.line} — \`${g.code}\``).join('\n');

  const reachabilitySection = extractSection(llmReport, 'Reachability Assessment');
  const triggerSection      = extractSection(llmReport, 'Trigger Conditions');

  return `
You are a software security engineer. A known library vulnerability has been confirmed as reachable in this codebase. Your task is to propose a code-level fix in the application's own source code to mitigate the risk.

IMPORTANT CONSTRAINTS:
- Do NOT suggest upgrading or replacing the library.
- Do NOT suggest removing the feature.
- Fix only the application code shown below.

═══════════════════════════════════════════════
VULNERABILITY
═══════════════════════════════════════════════
Package     : ${threat.packageName}
Advisory    : ${threat.ghsaId}
Summary     : ${threat.summary}
Severity    : ${threat.severity}
Type        : ${ctx.attackClass}
Verdict     : ${verdict}

═══════════════════════════════════════════════
CONFIRMED REACHABILITY
═══════════════════════════════════════════════
${reachabilitySection ? reachabilitySection : '(see trigger conditions below)'}

${triggerSection ? `Trigger Conditions:\n${triggerSection}` : ''}

═══════════════════════════════════════════════
VULNERABLE CODE
═══════════════════════════════════════════════
Code path   : ${attackPath}
Input surface: ${entryPoint?.attackableSurface.join(', ') || 'unknown'}
Guards      : ${guardSummary}

Call sites into the vulnerable library:
${codeSlice.eifCallSites.map(s => `  ${s.callExpression} (line ${s.line})`).join('\n')}

Caller source code:
\`\`\`javascript
${callerCode}
\`\`\`

═══════════════════════════════════════════════
TASK
═══════════════════════════════════════════════
Propose a minimal code-level fix for the application code above that mitigates this specific vulnerability. The fix must:
- Address the exact trigger conditions identified above
- Be written in the same language and style as the original code
- Change as little as possible — do not refactor unrelated logic

Produce your response with exactly these sections:

## Fixed Code
The complete corrected version of each modified function. Preserve the original function signatures and file structure.

## What Changed
A concise bullet list: what was added or modified, and why each change mitigates the vulnerability.

## Residual Risk
Any remaining exposure after this fix is applied, or conditions under which the fix would be insufficient.
`.trim();
}

function extractSection(report: string, heading: string): string {
  const re = new RegExp(`##\\s*${heading}\\s*\\n([\\s\\S]*?)(?=\\n##|$)`, 'i');
  const m = report.match(re);
  return m ? m[1].trim() : '';
}
