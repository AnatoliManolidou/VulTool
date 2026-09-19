import * as core from '@actions/core';
import * as cache from '@actions/cache';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { detectEcosystems } from './components/ecosystem-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';
import { getRepositoryDependencies } from './components/dependency-mapper';
import { filterAdvisories } from './components/vulnerability-filter';
import { classifyDeploymentContext } from './components/deployment-classifier';
import { prioritizeThreats } from './components/threat-prioritizer';
import { analyzeCodeUsage, CodeSlice } from './components/ast-analyzer';
import { detectEntryPoint } from './components/purple-team/entry-point-detector';
import { buildCallChain } from './components/purple-team/call-chain-builder';
import { detectGuards } from './components/purple-team/guard-detector';
import { assembleContext } from './components/purple-team/context-assembler';
import { buildExploitPrompt } from './components/purple-team/prompt-builder';
import { buildRemediationPrompt, buildRetryRemediationPrompt } from './components/purple-team/remediation-prompt-builder';
import { buildVerificationPrompt } from './components/purple-team/verification-prompt-builder';
import { extractFixedCode, applyFixToFile, revertFile } from './components/purple-team/fix-applier';
import { callLLM } from './components/purple-team/llm-client';
import { ExploitContext } from './components/purple-team/types';
import { Advisory, Threat } from './types';

const STATE_FILE = '/tmp/vultool-advisory-state.json';
const CACHE_KEY  = `vultool-advisory-state-${process.env.GITHUB_REPOSITORY ?? 'local'}`;

async function loadLastSeenGhsaIds(): Promise<Set<string>> {
  try {
    await cache.restoreCache([STATE_FILE], CACHE_KEY);
    if (fs.existsSync(STATE_FILE)) {
      const stored = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      return new Set<string>(stored.ghsaIds ?? []);
    }
  } catch { /* first run or cache miss — treat as empty */ }
  return new Set<string>();
}

async function saveSeenGhsaIds(ids: Set<string>): Promise<void> {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify({ ghsaIds: [...ids] }));
    await cache.saveCache([STATE_FILE], CACHE_KEY);
  } catch (err) {
    core.warning(`Could not save advisory state to cache: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function buildAttackPathString(ctx: ExploitContext): string {
  if (!ctx.entryPoint) return 'entry point not traced';
  const eifFnName = ctx.codeSlice.eifCallSites[0]?.callExpression.split('(')[0]?.trim() ?? ctx.threat.packageName;
  const sortedEifCallers = [...ctx.codeSlice.callerSlices]
    .sort((a, b) => {
      if (a.sourceText.includes(b.functionName)) return -1;
      if (b.sourceText.includes(a.functionName)) return 1;
      return 0;
    })
    .map(s => s.functionName);
  const chain = [
    ctx.entryPoint.handlerFunction,
    ...ctx.callChain.map(s => s.functionName),
    ...sortedEifCallers,
    `${eifFnName} (${ctx.threat.packageName})`,
  ];
  return `${ctx.entryPoint.identifier} → ${chain.join(' → ')}`;
}

async function sendDiscordNotification(webhookUrl: string, payload: object): Promise<void> {
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch { /* notification failure must never crash the pipeline */ }
}

const DC_RED    = 0xC0392B; // exploit confirmed, patch failed, pipeline error
const DC_ORANGE = 0xE67E22; // conditional exploit, unverified fix, refused, inconclusive
const DC_GREEN  = 0x27AE60; // not exploitable, patch confirmed
const DC_BLUE   = 0x2980B9; // informational — no threats, no advisories, no ecosystems
const DC_GREY   = 0x95A5A6; // threats detected but no code usage / no LLM analysis

function discordEmbed(
  title: string,
  description: string,
  color: number,
  fields: object[],
  repoName: string,
): object {
  const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;
  return {
    embeds: [{
      title, description, color, fields,
      url: runUrl,
      timestamp: new Date().toISOString(),
      footer: { text: 'VulTool CTI Scanner' },
    }],
  };
}

function discordNoEcosystems(repoName: string): object {
  return discordEmbed(
    'No Package Ecosystem Detected',
    'No supported package manager files were found. Verify the action is configured against the correct repository.',
    DC_BLUE,
    [{ name: 'Repository', value: repoName, inline: true }],
    repoName,
  );
}

function discordNoAdvisories(repoName: string): object {
  return discordEmbed(
    'No Advisories in CTI Feed',
    'The advisory feed returned no entries for the detected ecosystems. The feed will be checked again on the next scheduled run.',
    DC_BLUE,
    [{ name: 'Repository', value: repoName, inline: true }],
    repoName,
  );
}

function discordDependencyMapperFailed(repoName: string): object {
  return discordEmbed(
    'Dependency Mapper Failed',
    'The GitHub SBOM API timed out or returned an error. Verify that the Dependency Graph is enabled in repository settings.',
    DC_ORANGE,
    [{ name: 'Repository', value: repoName, inline: true }],
    repoName,
  );
}

function discordNoThreats(repoName: string, fetched: number, skipped: number): object {
  return discordEmbed(
    'No Matching Vulnerabilities',
    `${fetched} advisor${fetched === 1 ? 'y' : 'ies'} fetched, ${skipped} filtered out — none matched the installed dependency set at the configured severity threshold.`,
    DC_GREEN,
    [{ name: 'Repository', value: repoName, inline: true }],
    repoName,
  );
}

function discordAnalysisComplete(
  repoName: string,
  sortedThreats: Threat[],
  exploitContexts: ExploitContext[],
  llmReports: Map<string, string>,
  fixBranches: Map<string, string>,
  verificationResults: Map<string, boolean>,
): object {
  const verdicts       = [...llmReports.values()].map(parseVerdict).filter(Boolean) as string[];
  const exploitable    = verdicts.filter(v => v === 'EXPLOITABLE').length;
  const conditional    = verdicts.filter(v => v === 'CONDITIONALLY_EXPLOITABLE').length;
  const notExploitable = verdicts.filter(v => v === 'NOT_EXPLOITABLE').length;
  const refused        = verdicts.filter(v => v === 'REFUSED').length;
  const hasVerifiedFix = [...fixBranches.keys()].some(id => verificationResults.get(id) === true);

  let title: string;
  let description: string;
  let color: number;

  if (exploitable > 0 && hasVerifiedFix) {
    title       = 'Exploit Confirmed — Automated Fix Generated';
    description = `${exploitable} exploitable threat(s) confirmed. An automated fix was generated and internally verified. A patch verification rescan has been triggered — a GitHub Issue will be opened once the rescan verdict is known.`;
    color       = DC_ORANGE;
  } else if (exploitable > 0) {
    title       = 'Exploit Confirmed — Manual Remediation Required';
    description = `${exploitable} exploitable threat(s) confirmed. No automated fix was generated. A GitHub Issue has been opened with the full analysis.`;
    color       = DC_RED;
  } else if (conditional > 0) {
    title       = 'Conditional Exploit Confirmed';
    description = `${conditional} conditionally exploitable threat(s) detected. Exploitability depends on runtime configuration or deployment context.`;
    color       = DC_ORANGE;
  } else if (refused > 0 && refused === llmReports.size) {
    title       = 'Model Refused Analysis';
    description = 'The model declined to analyze the detected threats. Switch to a security-capable model for full exploit analysis.';
    color       = DC_ORANGE;
  } else if (notExploitable > 0) {
    title       = 'Threats Analyzed — Not Exploitable';
    description = `${sortedThreats.length} threat(s) confirmed in the dependency set. LLM exploit analysis determined none are reachable in the current codebase.`;
    color       = DC_GREEN;
  } else if (exploitContexts.length === 0) {
    title       = 'Threats Detected — No Direct Code Usage';
    description = `${sortedThreats.length} threat(s) confirmed in the dependency set but no direct code usage was found. These represent static risk only.`;
    color       = DC_GREY;
  } else {
    title       = 'Analysis Complete';
    description = `${sortedThreats.length} threat(s) processed. No LLM analysis was performed — provide an API key to enable exploit analysis.`;
    color       = DC_GREY;
  }

  const fields: object[] = [
    { name: 'Repository',       value: repoName,                      inline: true },
    { name: 'Threats confirmed', value: String(sortedThreats.length),  inline: true },
  ];

  if (verdicts.length > 0) {
    const parts: string[] = [];
    if (exploitable > 0)    parts.push(`Exploitable: ${exploitable}`);
    if (conditional > 0)    parts.push(`Conditional: ${conditional}`);
    if (notExploitable > 0) parts.push(`Not exploitable: ${notExploitable}`);
    if (refused > 0)        parts.push(`Refused: ${refused}`);
    fields.push({ name: 'Verdicts', value: parts.join(' | '), inline: false });
  }

  for (const ctx of exploitContexts.slice(0, 3)) {
    const report   = llmReports.get(ctx.threat.ghsaId);
    const verdict  = report ? parseVerdict(report) : null;
    const branch   = fixBranches.get(ctx.threat.ghsaId);
    const verified = verificationResults.get(ctx.threat.ghsaId);
    const lines: string[] = [
      `${ctx.threat.severity}  |  ${ctx.threat.ghsaId}`,
      buildAttackPathString(ctx),
    ];
    if (verdict)                  lines.push(`Verdict: ${verdict}`);
    if (branch && verified)       lines.push(`Fix branch: \`${branch}\` (verified — rescan pending)`);
    else if (branch && !verified) lines.push(`Fix branch: \`${branch}\` (verification failed)`);
    fields.push({ name: ctx.threat.packageName, value: lines.join('\n'), inline: false });
  }

  return discordEmbed(title, description, color, fields, repoName);
}

function discordRescanComplete(
  repoName: string,
  ghsaId: string,
  patchVerdict: 'PATCH_CONFIRMED' | 'PATCH_FAILED' | 'PATCH_INCONCLUSIVE',
  packageName: string,
): object {
  const configs = {
    PATCH_CONFIRMED: {
      title:       'Patch Verified — Vulnerability No Longer Reachable',
      description: 'The automated fix was applied and the rescan confirmed the vulnerability is no longer reachable in the patched code. A GitHub Issue has been opened with instructions to review and merge the fix branch.',
      color:       DC_GREEN,
    },
    PATCH_FAILED: {
      title:       'Patch Failed — Vulnerability Still Reachable',
      description: 'The automated fix was applied but the rescan determined the vulnerability remains exploitable in the patched code. A GitHub Issue has been opened — manual remediation is required.',
      color:       DC_RED,
    },
    PATCH_INCONCLUSIVE: {
      title:       'Patch Verification Inconclusive',
      description: 'The rescan ran but did not produce a definitive exploit verdict. Manual review of the fix branch is recommended.',
      color:       DC_ORANGE,
    },
  };
  const { title, description, color } = configs[patchVerdict];
  return discordEmbed(title, description, color, [
    { name: 'Repository', value: repoName,   inline: true },
    { name: 'Advisory',   value: ghsaId,     inline: true },
    { name: 'Package',    value: packageName, inline: true },
  ], repoName);
}

function discordPipelineError(repoName: string, message: string): object {
  return discordEmbed(
    'Pipeline Error',
    message,
    DC_RED,
    [{ name: 'Repository', value: repoName, inline: true }],
    repoName,
  );
}

function parseAdjacentRisks(report: string | null | undefined): string[] {
  if (!report) return [];
  const risks: string[] = [];
  for (const line of report.split('\n')) {
    const m = line.match(/ADJACENT_RISK:\s*(.+)/);
    if (m && m[1].trim().toLowerCase() !== 'none') risks.push(m[1].trim());
  }
  return risks;
}

function parseVerdict(report: string | null | undefined): string | null {
  if (!report) return null;
  const m = report.match(/VERDICT:\s*(EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|NOT_EXPLOITABLE)/);
  if (m) return m[1];
  if (/I(?:'m| am) (?:sorry|unable|not able)|I can(?:'t|not) (?:help|assist)/i.test(report)) {
    return 'REFUSED';
  }
  return null;
}

function parseVerification(response: string): boolean {
  return /VERIFICATION:\s*YES/i.test(response);
}

function parseVerificationReason(response: string): string {
  const m = response.match(/VERIFICATION:\s*(?:YES|NO)\s*[—-]\s*(.+)/i);
  return m ? m[1].trim() : 'insufficient fix — see verification output';
}

function createFixBranch(
  ghsaId: string,
  packageName: string,
  modifiedFiles: string[],
  workspacePath: string,
): string {
  const branch = `vultool/fix-${ghsaId.toLowerCase()}`;
  const git = (args: string[]) =>
    execSync(['git', ...args.map(a => JSON.stringify(a))].join(' '), {
      cwd: workspacePath,
      stdio: 'pipe',
    });

  git(['config', 'user.email', 'vultool@github-actions']);
  git(['config', 'user.name', 'VulTool']);

  try { git(['branch', '-D', branch]); } catch { /* ok if it doesn't exist */ }
  git(['checkout', '-b', branch]);

  for (const f of modifiedFiles) git(['add', f]);

  git(['commit', '-m', `fix(security): address ${ghsaId} in ${packageName} — VulTool automated fix`]);
  git(['push', '-f', 'origin', branch]);
  git(['checkout', '-']);

  return branch;
}

async function createGithubIssue(token: string, title: string, body: string): Promise<void> {
  const octokit = github.getOctokit(token);
  const [owner, repo] = (process.env.GITHUB_REPOSITORY ?? '').split('/');
  try {
    await octokit.rest.issues.create({ owner, repo, title, body, labels: ['security'] });
  } catch {
    // 'security' label may not exist in the target repo — retry without labels
    try {
      await octokit.rest.issues.create({ owner, repo, title, body });
    } catch (err) {
      core.warning(`Failed to create GitHub Issue: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

async function triggerRescan(token: string, ghsaId: string, fixBranch: string): Promise<void> {
  const octokit = github.getOctokit(token);
  const [owner, repo] = (process.env.GITHUB_REPOSITORY ?? '').split('/');
  const ref = process.env.GITHUB_REF_NAME ?? 'main';
  await octokit.rest.actions.createWorkflowDispatch({
    owner,
    repo,
    workflow_id: 'rescan.yml',
    ref,
    inputs: { ghsa_id: ghsaId, fix_branch: fixBranch },
  });
}

async function main() {
  try {
    const token          = core.getInput('github_token', { required: true });
    const threshold      = core.getInput('severity_threshold');
    const watchedGhsaRaw = core.getInput('watched_ghsa_ids');
    const watchedGhsaIds = watchedGhsaRaw
      ? watchedGhsaRaw.split(',').map(s => s.trim()).filter(Boolean)
      : [];
    const llmApiKey      = core.getInput('llm_api_key');
    const discordWebhook = core.getInput('discord_webhook_url');
    const demoMode       = core.getInput('demo_mode') === 'true';
    const rescanMode        = core.getInput('rescan_mode') === 'true';
    const rescanGhsaId      = core.getInput('rescan_ghsa_id') || undefined;
    const includeAdjacentRisks = core.getInput('adjacent_risks') === 'true';
    const createIssue          = core.getInput('create_issue') === 'true';
    core.setSecret(token);

    const repoName      = process.env.GITHUB_REPOSITORY ?? 'unknown/unknown';
    const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

    const HEAVY = '━'.repeat(60);
    const LIGHT = '─'.repeat(60);

    core.info(HEAVY);
    if (rescanMode) {
      core.info('  PATCH VERIFICATION SCAN');
      core.info(`  ${repoName}  |  Advisory: ${rescanGhsaId ?? 'unknown'}`);
    } else {
      core.info('  CTI VULNERABILITY SCANNER');
      core.info(`  ${repoName}  |  Threshold: ${threshold}${demoMode ? '  |  Demo Mode' : ''}`);
    }
    core.info(HEAVY);
    core.info('');

    // --- C1: ECOSYSTEM DETECTOR ---
    const { ecosystems: detectedEcosystems } = detectEcosystems(workspacePath);
    core.info(`  [C1] Ecosystem Detector     → ${detectedEcosystems.length > 0 ? detectedEcosystems.join(', ') : 'none'}`);
    if (detectedEcosystems.length === 0) {
      core.info('');
      core.info('  No package manager files found — nothing to scan.');
      core.info(HEAVY);
      if (discordWebhook) await sendDiscordNotification(discordWebhook, discordNoEcosystems(repoName));
      return;
    }

    // --- C2: ALERT FETCHER ---
    const rawAdvisories: Advisory[] = await fetchRecentAdvisories(token, detectedEcosystems, watchedGhsaIds, demoMode, rescanGhsaId);
    core.info(`  [C2] Alert Fetcher          → ${rawAdvisories.length} advisor${rawAdvisories.length === 1 ? 'y' : 'ies'} ${rescanMode ? 'loaded' : 'fetched'}`);
    if (rawAdvisories.length === 0) {
      core.info('');
      core.info('  No recent advisories from the CTI feed.');
      core.info(HEAVY);
      if (discordWebhook) await sendDiscordNotification(discordWebhook, discordNoAdvisories(repoName));
      return;
    }

    // Advisory skip check — bypassed in demo mode so every run exercises the full pipeline
    const lastSeenIds = await loadLastSeenGhsaIds();
    const currentIds  = new Set<string>(rawAdvisories.map(a => a.ghsaId));
    const newIds      = [...currentIds].filter(id => !lastSeenIds.has(id));
    if (!demoMode && lastSeenIds.size > 0 && newIds.length === 0) {
      core.info('       No new advisories since last scan — pipeline skipped.');
      core.info('');
      core.info(HEAVY);
      return;
    }
    if (!demoMode && lastSeenIds.size > 0 && newIds.length < rawAdvisories.length) {
      core.info(`       ↳ ${newIds.length} new since last scan`);
    }

    // --- C3: DEPENDENCY MAPPER ---
    const installedPackages = await getRepositoryDependencies(token, workspacePath);
    if (installedPackages === null) {
      core.info(`  [C3] Dependency Mapper      → FAILED`);
      core.info('');
      core.info('  Dependency Mapper failed — verify the GitHub Dependency Graph is enabled.');
      core.info(HEAVY);
      if (discordWebhook) await sendDiscordNotification(discordWebhook, discordDependencyMapperFailed(repoName));
      return;
    }
    core.info(`  [C3] Dependency Mapper      → ${installedPackages.size} packages mapped`);

    // --- C4: VULNERABILITY FILTER ---
    const { confirmed: confirmedAdvisories, versionSkips } = filterAdvisories(rawAdvisories, threshold, installedPackages);
    const skippedCount = rawAdvisories.length - confirmedAdvisories.length;
    core.info(`  [C4] Vulnerability Filter   → ${confirmedAdvisories.length} confirmed  (${skippedCount} skipped)`);
    for (const s of versionSkips) {
      core.info(`       ↳ ${s.packageName}@${s.installedVersion} — patched (not in range ${s.advisoryRange})`);
    }
    if (confirmedAdvisories.length === 0) {
      core.info('');
      core.info('  No matching vulnerabilities found in this repository.');
      await saveSeenGhsaIds(currentIds);
      core.info(HEAVY);
      if (discordWebhook) await sendDiscordNotification(discordWebhook, discordNoThreats(repoName, rawAdvisories.length, skippedCount));
      return;
    }

    // --- C5: DEPLOYMENT CLASSIFIER ---
    const contextualizedThreats: Threat[] = classifyDeploymentContext(confirmedAdvisories, workspacePath, detectedEcosystems);
    core.info(`  [C5] Deployment Classifier  → ${contextualizedThreats.length} threats classified`);

    // --- C6: THREAT PRIORITIZER ---
    const sortedThreats: Threat[] = prioritizeThreats(contextualizedThreats);
    core.info(`  [C6] Threat Prioritizer     → ${sortedThreats.length} threats queued`);

    // --- C7: AST ANALYZER ---
    const npmThreats: Threat[] = sortedThreats.filter(t => t.ecosystem === 'npm');
    let codeSlices: CodeSlice[] = [];
    if (npmThreats.length > 0) {
      codeSlices = await analyzeCodeUsage(npmThreats, workspacePath);
    }
    const directSlices   = codeSlices.filter(s => !s.isIndirect);
    const indirectSlices = codeSlices.filter(s =>  s.isIndirect);
    const c7Status = npmThreats.length === 0
      ? 'no npm threats — skipped'
      : directSlices.length > 0 && indirectSlices.length > 0
        ? `${directSlices.length} direct + ${indirectSlices.length} indirect usage(s) traced`
        : directSlices.length > 0
          ? `${directSlices.length} threat(s) with confirmed direct usage`
          : indirectSlices.length > 0
            ? `${indirectSlices.length} indirect usage(s) via transitive dep`
            : 'no code usage found';
    core.info(`  [C7] AST Analyzer           → ${c7Status}`);

    // --- C8: PURPLE TEAM CONTEXT ---
    const exploitContexts: ExploitContext[] = [];
    if (codeSlices.length > 0) {
      for (const slice of codeSlices) {
        const threat = sortedThreats.find(t => t.ghsaId === slice.threatGhsaId);
        if (!threat) continue;
        const entryPoint = await detectEntryPoint(slice.callerSlices, workspacePath);
        const callChain  = await buildCallChain(entryPoint, slice, workspacePath);
        const guards     = detectGuards(entryPoint, callChain, slice);
        exploitContexts.push(assembleContext(threat, slice, entryPoint, callChain, guards));
      }
    }
    core.info(`  [C8] Purple Team            → ${exploitContexts.length > 0 ? `${exploitContexts.length} exploit context(s) assembled` : 'skipped — no confirmed code usage'}`);

    // --- C9: LLM EXPLOIT ANALYZER ---
    const llmReports = new Map<string, string>();
    if (exploitContexts.length === 0) {
      core.info(`  [C9] LLM Exploit Analyzer   → skipped — no exploit contexts`);
    } else if (!llmApiKey) {
      core.info(`  [C9] LLM Exploit Analyzer   → skipped — no API key provided`);
    } else {
      for (const ctx of exploitContexts) {
        try {
          const report = await callLLM(llmApiKey, buildExploitPrompt(ctx, includeAdjacentRisks));
          llmReports.set(ctx.threat.ghsaId, report);
        } catch (err) {
          core.warning(`  LLM call failed for ${ctx.threat.packageName}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      core.info(`  [C9] LLM Exploit Analyzer   → ${llmReports.size} analysis complete`);
    }

    // --- C10: CODE REMEDIATION ---
    const remediationReports  = new Map<string, string>();
    const verificationResults = new Map<string, boolean>();
    const fixBranches         = new Map<string, string>();
    const rescanTriggered     = new Set<string>();
    const actionableVerdicts  = new Set(['EXPLOITABLE', 'CONDITIONALLY_EXPLOITABLE']);
    const remediationTargets  = exploitContexts.filter(ctx => {
      const v = parseVerdict(llmReports.get(ctx.threat.ghsaId) ?? '');
      return v && actionableVerdicts.has(v);
    });

    if (rescanMode) {
      core.info(`  [C10] Remediation Engine     → skipped — patch verification scan`);
    } else if (remediationTargets.length === 0 || !llmApiKey) {
      core.info(`  [C10] Remediation Engine     → ${!llmApiKey ? 'skipped — no API key' : 'skipped — no actionable verdicts'}`);
    } else {
      const FIX_MAX_ATTEMPTS = 2;

      for (const ctx of remediationTargets) {
        const exploitReport = llmReports.get(ctx.threat.ghsaId)!;
        const verdict       = parseVerdict(exploitReport)!;
        const primarySlice  = ctx.codeSlice.callerSlices[0];
        if (!primarySlice) continue;

        const targetFile = path.isAbsolute(primarySlice.file)
          ? primarySlice.file
          : path.resolve(workspacePath, primarySlice.file);

        let latestFixReport: string | null = null;
        let previousFix:     string | null = null;
        let verificationFailureReason      = '';

        for (let attempt = 1; attempt <= FIX_MAX_ATTEMPTS; attempt++) {
          // Step 1: generate (or retry) fix
          const prompt = attempt === 1
            ? buildRemediationPrompt(ctx, verdict, exploitReport)
            : buildRetryRemediationPrompt(ctx, primarySlice.sourceText, previousFix!, verificationFailureReason);

          let fixReport: string;
          try {
            fixReport = await callLLM(llmApiKey, prompt);
          } catch (err) {
            core.warning(`  Remediation call failed (attempt ${attempt}) for ${ctx.threat.packageName}: ${err instanceof Error ? err.message : String(err)}`);
            if (previousFix && !remediationReports.has(ctx.threat.ghsaId)) {
              // preserve attempt 1 fix so output still shows something
              remediationReports.set(ctx.threat.ghsaId, latestFixReport ?? '');
            }
            break;
          }

          // Step 2: extract and apply fix
          const fixedCode = extractFixedCode(fixReport);
          if (!fixedCode) {
            core.warning(`  Could not parse fixed code (attempt ${attempt}) for ${ctx.threat.packageName}`);
            break;
          }

          const { applied, originalContent } = applyFixToFile(targetFile, primarySlice.sourceText, fixedCode);
          if (!applied) {
            core.warning(`  Could not apply fix (attempt ${attempt}) for ${ctx.threat.packageName}`);
            break;
          }

          // Step 3: verify
          let verificationReport: string;
          try {
            verificationReport = await callLLM(
              llmApiKey,
              buildVerificationPrompt(ctx, primarySlice.sourceText, fixedCode, exploitReport),
            );
          } catch (err) {
            revertFile(targetFile, originalContent);
            core.warning(`  Verification call failed (attempt ${attempt}) for ${ctx.threat.packageName}: ${err instanceof Error ? err.message : String(err)}`);
            break;
          }

          latestFixReport = fixReport;
          remediationReports.set(ctx.threat.ghsaId, fixReport); // always keep latest fix
          const verified  = parseVerification(verificationReport);
          verificationResults.set(ctx.threat.ghsaId, verified);

          if (verified) {
            // Step 4: create fix branch
            try {
              const branch = createFixBranch(ctx.threat.ghsaId, ctx.threat.packageName, [targetFile], workspacePath);
              fixBranches.set(ctx.threat.ghsaId, branch);
              // Step 5: trigger patch verification re-scan on the fix branch
              try {
                await triggerRescan(token, ctx.threat.ghsaId, branch);
                rescanTriggered.add(ctx.threat.ghsaId);
              } catch (err) {
                core.warning(`  Re-scan dispatch failed for ${ctx.threat.ghsaId}: ${err instanceof Error ? err.message : String(err)}`);
              }
            } catch (err) {
              revertFile(targetFile, originalContent);
              core.warning(`  Branch creation failed for ${ctx.threat.packageName}: ${err instanceof Error ? err.message : String(err)}`);
            }
            break;
          } else {
            verificationFailureReason = parseVerificationReason(verificationReport);
            revertFile(targetFile, originalContent);
            previousFix = fixedCode;
            if (attempt < FIX_MAX_ATTEMPTS) {
              core.info(`  [C10] Attempt ${attempt} not verified — retrying with feedback`);
            } else {
              remediationReports.set(ctx.threat.ghsaId, fixReport);
              core.warning(`  Fix for ${ctx.threat.packageName} (${ctx.threat.ghsaId}) not verified after ${FIX_MAX_ATTEMPTS} attempts`);
            }
          }
        }
      }

      const branchCount = fixBranches.size;
      const fixCount    = remediationReports.size;
      core.info(`  [C10] Remediation Engine     → ${fixCount} fix(es) generated, ${branchCount} branch(es) created`);
    }

    // --- GITHUB ISSUE REPORTER (main run) ---
    // Only open issues for exploitable findings where no fix branch was created —
    // findings with a fix branch will be handled by the rescan after verdict is known.
    if (createIssue && !rescanMode) {
      const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;
      const unfixedTargets = remediationTargets.filter(ctx => !fixBranches.has(ctx.threat.ghsaId));
      for (const ctx of unfixedTargets) {
        const report  = llmReports.get(ctx.threat.ghsaId) ?? '';
        const verdict = parseVerdict(report) ?? 'unknown';

        const issueBody = [
          `## Vulnerability Confirmed Exploitable — No Automated Fix Generated`,
          ``,
          `| | |`,
          `|---|---|`,
          `| **Package** | \`${ctx.threat.packageName}\` |`,
          `| **Advisory** | [${ctx.threat.ghsaId}](https://github.com/advisories/${ctx.threat.ghsaId}) |`,
          `| **Severity** | ${ctx.threat.severity} |`,
          `| **Verdict** | ${verdict} |`,
          `| **Attack path** | \`${buildAttackPathString(ctx)}\` |`,
          ``,
          `---`,
          ``,
          `### Exploit Analysis`,
          ``,
          report,
          ``,
          `---`,
          ``,
          `### Remediation Required`,
          ``,
          `No automated fix was generated for this finding. Manual remediation is required.`,
          `See the [advisory](https://github.com/advisories/${ctx.threat.ghsaId}) for patch guidance.`,
          ``,
          `---`,
          ``,
          `> *Opened automatically by VulTool · [Run ${process.env.GITHUB_RUN_ID ?? ''}](${runUrl})*`,
        ].join('\n');

        const issueTitle = `[VulTool] ${ctx.threat.severity} · ${ctx.threat.packageName} (${ctx.threat.ghsaId}) confirmed exploitable`;
        await createGithubIssue(token, issueTitle, issueBody);
      }
      if (unfixedTargets.length > 0) {
        core.info(`  Issues opened for ${unfixedTargets.length} exploitable threat(s) without automated fix`);
      }
    }

    await saveSeenGhsaIds(currentIds);

    // ── THREAT QUEUE ──────────────────────────────────────────────────────────
    core.info('');
    core.info(LIGHT);
    core.info('  THREAT QUEUE');
    core.info(LIGHT);
    core.info('');

    for (let i = 0; i < sortedThreats.length; i++) {
      const t   = sortedThreats[i];
      const ctx = exploitContexts.find(c => c.threat.ghsaId === t.ghsaId);

      core.info(`  #${i + 1}  ${t.packageName.padEnd(22)} ${t.severity.padEnd(10)} ${t.ghsaId}`);
      core.info(`       ${t.summary}`);
      core.info(`       Vulnerable : ${t.vulnerableVersionRange ?? 'unknown'}   →   Fix: ${t.firstPatchedVersion ?? 'no patch available'}`);
      core.info(`       Risk       : ${t.isDevDependency ? 'Dev dependency' : 'Production'}`);

      if (ctx) {
        const guardStr  = ctx.guards.guards.length === 0
          ? 'none'
          : ctx.guards.guards.map(g => g.type).join(', ');
        const pathLabel = ctx.codeSlice.isIndirect
          ? `Indirect path: ${buildAttackPathString(ctx)}  (via ${ctx.codeSlice.viaPackage})`
          : `Attack path: ${buildAttackPathString(ctx)}`;
        core.info(`       ${pathLabel}`);
        core.info(`       Guards     : ${guardStr}`);
      } else {
        core.info(`       Code usage : not confirmed — static risk only`);
      }

      core.info('');
    }

    // ── EXPLOIT ANALYSIS ─────────────────────────────────────────────────────
    if (llmReports.size > 0) {
      for (const ctx of exploitContexts) {
        const report = llmReports.get(ctx.threat.ghsaId);
        if (!report) continue;

        core.info(LIGHT);
        core.info(`  EXPLOIT ANALYSIS  —  ${ctx.threat.packageName}  (${ctx.threat.ghsaId})`);
        core.info(LIGHT);
        core.info('');
        if (parseVerdict(report) === 'REFUSED') {
          core.info(`  [!] Model refused to analyze this advisory.`);
          core.info(`      Switch to a security-capable model for full exploit analysis.`);
        } else {
          for (const line of report.split('\n')) {
            core.info(`  ${line}`);
          }
        }
        core.info('');
      }
    }

    // ── REMEDIATION ───────────────────────────────────────────────────────────
    if (remediationReports.size > 0) {
      for (const ctx of remediationTargets) {
        const fix = remediationReports.get(ctx.threat.ghsaId);
        if (!fix) continue;

        const verified = verificationResults.get(ctx.threat.ghsaId);
        const branch   = fixBranches.get(ctx.threat.ghsaId);

        core.info(LIGHT);
        core.info(`  CODE FIX  —  ${ctx.threat.packageName}  (${ctx.threat.ghsaId})`);
        core.info(LIGHT);
        core.info('');
        for (const line of fix.split('\n')) {
          core.info(`  ${line}`);
        }
        core.info('');
        if (verified === true && branch) {
          core.info(`  Verification : CONFIRMED — fix eliminates the vulnerability`);
          core.info(`  Branch       : ${branch}`);
          if (rescanTriggered.has(ctx.threat.ghsaId)) {
            core.info(`  Re-scan      : triggered — patch verification queued on ${branch}`);
          }
        } else if (verified === true && !branch) {
          core.info(`  Verification : CONFIRMED — branch creation failed; apply the fix above manually`);
        } else if (verified === false) {
          core.info(`  Verification : NOT CONFIRMED — fix may be incomplete; review manually`);
        } else {
          core.info(`  Verification : NOT RUN — see warnings above`);
        }
        core.info('');
      }
    }

    // ── FOOTER ────────────────────────────────────────────────────────────────
    const verdicts        = [...llmReports.values()].map(parseVerdict).filter(Boolean) as string[];
    const exploitable     = verdicts.filter(v => v === 'EXPLOITABLE').length;
    const conditional     = verdicts.filter(v => v === 'CONDITIONALLY_EXPLOITABLE').length;
    const notExploitable  = verdicts.filter(v => v === 'NOT_EXPLOITABLE').length;
    const refused         = verdicts.filter(v => v === 'REFUSED').length;
    const adjacentRisks   = includeAdjacentRisks ? [...llmReports.values()].flatMap(parseAdjacentRisks) : [];

    core.info(HEAVY);
    if (rescanMode) {
      core.info('  PATCH VERIFICATION COMPLETE');
      const patchVerdict = notExploitable > 0
        ? `PATCH_CONFIRMED — vulnerability no longer reachable`
        : exploitable > 0
          ? `PATCH_FAILED — vulnerability still reachable after fix`
          : `PATCH_INCONCLUSIVE — no exploit verdict produced`;
      core.info(`  ${rescanGhsaId} → ${patchVerdict}`);

      // PATCH_CONFIRMED — fix is verified; open an issue so the team knows to review and merge
      if (createIssue && notExploitable > 0 && exploitContexts.length > 0) {
        const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;
        const ctx    = exploitContexts[0];
        const fixBranch = `vultool/fix-${rescanGhsaId?.toLowerCase() ?? ''}`;

        const issueBody = [
          `## Automated Fix Verified — Ready to Review and Merge`,
          ``,
          `| | |`,
          `|---|---|`,
          `| **Package** | \`${ctx.threat.packageName}\` |`,
          `| **Advisory** | [${rescanGhsaId}](https://github.com/advisories/${rescanGhsaId}) |`,
          `| **Severity** | ${ctx.threat.severity} |`,
          `| **Patch verdict** | PATCH_CONFIRMED ✓ |`,
          `| **Fix branch** | [\`${fixBranch}\`](../../tree/${fixBranch}) |`,
          ``,
          `---`,
          ``,
          `### What Happened`,
          ``,
          `VulTool detected this vulnerability as exploitable, generated an application-level fix,`,
          `and confirmed via independent rescan that the patched code is no longer reachable.`,
          ``,
          `### Next Steps`,
          ``,
          `1. Review the changes on [\`${fixBranch}\`](../../compare/${fixBranch})`,
          `2. Open a pull request and merge after approval`,
          `3. Close this issue once merged`,
          ``,
          `---`,
          ``,
          `> *Opened automatically by VulTool (patch verification scan) · [Run ${process.env.GITHUB_RUN_ID ?? ''}](${runUrl})*`,
        ].join('\n');

        const issueTitle = `[VulTool] PATCH CONFIRMED · ${ctx.threat.packageName} (${rescanGhsaId}) — fix ready to merge`;
        await createGithubIssue(token, issueTitle, issueBody);
        core.info(`  Issue opened for verified fix on ${rescanGhsaId}`);
      }

      // PATCH_FAILED — open an issue because the automated fix was insufficient
      if (createIssue && exploitable > 0 && exploitContexts.length > 0) {
        const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;
        const ctx    = exploitContexts[0];
        const report = llmReports.get(ctx.threat.ghsaId) ?? '';

        const issueBody = [
          `## Automated Fix Failed — Vulnerability Still Reachable`,
          ``,
          `| | |`,
          `|---|---|`,
          `| **Package** | \`${ctx.threat.packageName}\` |`,
          `| **Advisory** | [${rescanGhsaId}](https://github.com/advisories/${rescanGhsaId}) |`,
          `| **Severity** | ${ctx.threat.severity} |`,
          `| **Patch verdict** | PATCH_FAILED |`,
          `| **Attack path** | \`${buildAttackPathString(ctx)}\` |`,
          ``,
          `---`,
          ``,
          `### Why the Fix Failed`,
          ``,
          `The automated patch was applied and a rescan was triggered. The rescan determined the vulnerability remains exploitable. Rescan exploit analysis:`,
          ``,
          report,
          ``,
          `---`,
          ``,
          `### Remediation Required`,
          ``,
          `The automated fix was insufficient. Manual review and remediation are required.`,
          `See the [advisory](https://github.com/advisories/${rescanGhsaId}) for patch guidance.`,
          ``,
          `---`,
          ``,
          `> *Opened automatically by VulTool (patch verification scan) · [Run ${process.env.GITHUB_RUN_ID ?? ''}](${runUrl})*`,
        ].join('\n');

        const issueTitle = `[VulTool] PATCH FAILED · ${ctx.threat.packageName} (${rescanGhsaId}) — vulnerability still reachable after automated fix`;
        await createGithubIssue(token, issueTitle, issueBody);
        core.info(`  Issue opened for patch failure on ${rescanGhsaId}`);
      }
    } else {
      core.info('  PIPELINE COMPLETE');
      const parts = [
        `${sortedThreats.length} threat(s) confirmed`,
        `${codeSlices.length} with active code usage`,
      ];
      if (verdicts.length > 0) {
        const vParts: string[] = [];
        if (exploitable > 0)    vParts.push(`EXPLOITABLE: ${exploitable}`);
        if (conditional > 0)    vParts.push(`CONDITIONAL: ${conditional}`);
        if (notExploitable > 0) vParts.push(`NOT EXPLOITABLE: ${notExploitable}`);
        if (refused > 0)        vParts.push(`REFUSED: ${refused}`);
        parts.push(vParts.join('  '));
      }
      if (adjacentRisks.length > 0) parts.push(`ADJACENT RISKS: ${adjacentRisks.length}`);
      if (fixBranches.size > 0)     parts.push(`FIX BRANCHES: ${fixBranches.size}`);
      core.info(`  ${parts.join('  |  ')}`);
    }
    core.info(HEAVY);

    // ── WRITE RUN RESULT ────────────────────────────────────────────────────────
    try {
      const runResult = rescanMode
        ? {
            mode: 'rescan',
            timestamp: new Date().toISOString(),
            repo: process.env.GITHUB_REPOSITORY ?? 'unknown',
            runId: process.env.GITHUB_RUN_ID ?? 'unknown',
            ghsaId: rescanGhsaId ?? null,
            patchVerdict: notExploitable > 0 ? 'PATCH_CONFIRMED'
              : exploitable > 0 ? 'PATCH_FAILED' : 'PATCH_INCONCLUSIVE',
          }
        : {
            mode: 'main',
            timestamp: new Date().toISOString(),
            repo: process.env.GITHUB_REPOSITORY ?? 'unknown',
            runId: process.env.GITHUB_RUN_ID ?? 'unknown',
            threats: sortedThreats.map(t => ({
              package:         t.packageName,
              ghsaId:          t.ghsaId,
              severity:        t.severity,
              hasDirectUsage:  codeSlices.some(s => s.threatGhsaId === t.ghsaId),
              analyzedByLLM:   llmReports.has(t.ghsaId),
              verdict:         parseVerdict(llmReports.get(t.ghsaId) ?? '') ?? null,
              patchAttempted:  verificationResults.has(t.ghsaId),
              patchConfirmed:  verificationResults.get(t.ghsaId) ?? null,
              fixBranch:       fixBranches.get(t.ghsaId) ?? null,
              rescanTriggered: rescanTriggered.has(t.ghsaId),
            })),
          };
      fs.writeFileSync('/tmp/vultool-run-result.json', JSON.stringify(runResult, null, 2));
    } catch (err) {
      core.warning(`Failed to write run result: ${err instanceof Error ? err.message : String(err)}`);
    }

    if (discordWebhook) {
      if (rescanMode) {
        const patchVerdict = notExploitable > 0 ? 'PATCH_CONFIRMED'
          : exploitable > 0 ? 'PATCH_FAILED' : 'PATCH_INCONCLUSIVE';
        const pkgName = exploitContexts[0]?.threat.packageName ?? rescanGhsaId ?? '';
        await sendDiscordNotification(discordWebhook, discordRescanComplete(repoName, rescanGhsaId ?? '', patchVerdict, pkgName));
      } else {
        await sendDiscordNotification(discordWebhook, discordAnalysisComplete(repoName, sortedThreats, exploitContexts, llmReports, fixBranches, verificationResults));
      }
    }

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
      const discordWebhook = core.getInput('discord_webhook_url');
      if (discordWebhook) {
        const repoName = process.env.GITHUB_REPOSITORY ?? 'unknown/unknown';
        await sendDiscordNotification(discordWebhook, discordPipelineError(repoName, error.message));
      }
    }
  }
}

main();
