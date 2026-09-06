import { ExploitContext } from './types';

export function buildVerificationPrompt(
  ctx: ExploitContext,
  originalCode: string,
  fixedCode: string,
  exploitReport: string,
): string {
  const triggerConditions = extractSection(exploitReport, 'Trigger Conditions');

  return `
You are a software security engineer. You previously confirmed this vulnerability is reachable in this codebase.

Package      : ${ctx.threat.packageName}
Advisory     : ${ctx.threat.ghsaId}
Vulnerability: ${ctx.threat.summary}
Type         : ${ctx.attackClass}

ORIGINAL VULNERABLE CODE:
\`\`\`javascript
${originalCode}
\`\`\`

PROPOSED APPLICATION-LEVEL FIX:
\`\`\`javascript
${fixedCode}
\`\`\`

ORIGINAL TRIGGER CONDITIONS:
${triggerConditions || ctx.threat.summary}

Does the proposed fix prevent the vulnerability from being triggered through the original code path? Evaluate only the application-level code change — do not factor in library upgrades.

Answer with exactly one line in this format:
VERIFICATION: <YES|NO> — <one sentence explaining whether the fix eliminates the vulnerability>
`.trim();
}

function extractSection(report: string, heading: string): string {
  const re = new RegExp(`##\\s*${heading}\\s*\\n([\\s\\S]*?)(?=\\n##|$)`, 'i');
  const m = report.match(re);
  return m ? m[1].trim() : '';
}
