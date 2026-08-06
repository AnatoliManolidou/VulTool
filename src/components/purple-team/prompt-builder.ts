import { ExploitContext } from './types';

export function buildRemediationPrompt(ctx: ExploitContext): string {
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

  const cwes = threat.cwes.map(c => `${c.cweId} (${c.name})`).join(', ') || 'none';
  const cvss = threat.cvss ? `${threat.cvss.score} — ${threat.cvss.vectorString}` : 'not available';
  const patchedIn = threat.firstPatchedVersion ?? 'no patch available';

  return `
You are a senior application security engineer. Analyse the following vulnerability finding and produce a structured remediation report.

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
Guards         : ${guardSummary}

EIF call sites (where your code calls into the vulnerable package):
${codeSlice.eifCallSites.map(s => `  ${s.callExpression} (line ${s.line})`).join('\n')}

Caller function source code:
\`\`\`javascript
${callerCode}
\`\`\`

═══════════════════════════════════════════════
TASK
═══════════════════════════════════════════════
Produce a remediation report with exactly these two sections:

## Risk Assessment
In 3–5 sentences: explain how exploitable this vulnerability is given the specific attack path and guard context above. Reference the actual route, the input field the attacker controls, and whether any guards are present. Be concrete — do not repeat the advisory summary.

## Remediation Steps
A numbered list of concrete actions, starting with the package upgrade and followed by any code-level hardening that is appropriate given the attack class and the caller code above. Each step should be specific to this codebase — reference actual function names, file paths, and field names where relevant. Include the exact npm command for the upgrade.
`.trim();
}
