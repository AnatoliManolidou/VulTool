import { ExploitContext } from './types';

export function buildVerificationPrompt(
  ctx: ExploitContext,
  originalCode: string,
  fixedCode: string,
  exploitReport: string,
): string {
  const triggerConditions = extractSection(exploitReport, 'Trigger Conditions');

  return `
You are a software security engineer performing adversarial review of a proposed security fix. Your job is to determine whether the fix actually stops the attack — not whether it looks correct at a glance.

Package      : ${ctx.threat.packageName}
Advisory     : ${ctx.threat.ghsaId}
Vulnerability: ${ctx.threat.summary}
Type         : ${ctx.attackClass}

ORIGINAL VULNERABLE CODE:
\`\`\`javascript
${originalCode}
\`\`\`

PROPOSED FIX:
\`\`\`javascript
${fixedCode}
\`\`\`

ORIGINAL TRIGGER CONDITIONS (the exact attack that was confirmed exploitable):
${triggerConditions || ctx.threat.summary}

═══════════════════════════════════════════════
TASK — answer in order, do not skip steps
═══════════════════════════════════════════════

## Step 1: Simulate the attack against the fixed code
Trace the execution of the original attack payload through the fixed code, line by line. State exactly which line in the fix intercepts or rejects the malicious input.

## Step 2: Check for bypass paths
Answer each question explicitly (yes/no + reason):
- Can the security check throw an exception that is caught and silently ignored, allowing execution to continue to the vulnerable call?
- Is there any code path (branch, early return, exception handler) that reaches the vulnerable function call despite the fix being present?
- Does the fix cover all input representations of the attack (e.g. different encodings, formats, or types)?

## Step 3: Verdict
A single line in this exact format:
VERIFICATION: <YES|NO> — <one sentence: what specifically stops the attack, or what specific bypass makes the fix insufficient>
`.trim();
}

function extractSection(report: string, heading: string): string {
  const re = new RegExp(`##\\s*${heading}\\s*\\n([\\s\\S]*?)(?=\\n##|$)`, 'i');
  const m = report.match(re);
  return m ? m[1].trim() : '';
}
