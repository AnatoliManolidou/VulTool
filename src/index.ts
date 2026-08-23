import * as core from '@actions/core';
import * as cache from '@actions/cache';
import * as fs from 'fs';
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

function buildDiscordPayload(
  repoName: string,
  sortedThreats: Threat[],
  exploitContexts: ExploitContext[],
  llmReports: Map<string, string>,
  verdicts: string[],
): object {
  const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;

  const exploitable    = verdicts.filter(v => v === 'EXPLOITABLE').length;
  const conditional    = verdicts.filter(v => v === 'CONDITIONALLY_EXPLOITABLE').length;
  const notExploitable = verdicts.filter(v => v === 'NOT_EXPLOITABLE').length;

  let color: number;
  let title: string;
  if (exploitable > 0) {
    color = 15158332; title = '🚨 EXPLOITABLE THREAT DETECTED';
  } else if (conditional > 0) {
    color = 15105570; title = '⚠️ Conditional Exploit Confirmed';
  } else if (llmReports.size > 0) {
    color = 3066993;  title = '✅ Threats Analyzed — Not Exploitable';
  } else {
    color = 3447003;  title = '🔵 Threats Confirmed — No Exploit Analysis';
  }

  const fields: object[] = [
    { name: 'Repository', value: repoName, inline: true },
    { name: 'Threats',    value: `${sortedThreats.length} confirmed`, inline: true },
  ];

  if (verdicts.length > 0) {
    const parts: string[] = [];
    if (exploitable > 0)    parts.push(`EXPLOITABLE: ${exploitable}`);
    if (conditional > 0)    parts.push(`CONDITIONAL: ${conditional}`);
    if (notExploitable > 0) parts.push(`NOT EXPLOITABLE: ${notExploitable}`);
    fields.push({ name: 'Verdicts', value: parts.join(' | '), inline: false });
  }

  for (const t of sortedThreats.slice(0, 3)) {
    const report  = llmReports.get(t.ghsaId);
    const verdict = report ? parseVerdict(report) : null;
    const ctx     = exploitContexts.find(c => c.threat.ghsaId === t.ghsaId);

    const lines: string[] = [
      `${t.severity}  |  ${t.ghsaId}`,
      t.firstPatchedVersion ? `Fix: upgrade to ${t.firstPatchedVersion}` : 'No patch available',
    ];
    if (ctx)     lines.push(buildAttackPathString(ctx));
    if (verdict) lines.push(`**${verdict}**`);

    fields.push({ name: t.packageName, value: lines.join('\n'), inline: false });
  }

  return {
    embeds: [{
      title,
      color,
      fields,
      url: runUrl,
      timestamp: new Date().toISOString(),
      footer: { text: 'VulTool CTI Scanner' },
    }],
  };
}

function buildDiscordCleanPayload(repoName: string, scanned: number, skipped: number): object {
  const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;
  return {
    embeds: [{
      title:  '✅ Clean Scan — No Threats Confirmed',
      color:  3066993,
      fields: [
        { name: 'Repository', value: repoName,           inline: true },
        { name: 'Scanned',    value: `${scanned} advisories from CTI feed`, inline: true },
        { name: 'Result',     value: `${skipped} filtered — none match your stack`, inline: false },
      ],
      url:       runUrl,
      timestamp: new Date().toISOString(),
      footer:    { text: 'VulTool CTI Scanner' },
    }],
  };
}

function buildDiscordErrorPayload(repoName: string, message: string): object {
  const runUrl = `https://github.com/${repoName}/actions/runs/${process.env.GITHUB_RUN_ID ?? ''}`;
  return {
    embeds: [{
      title:       '❌ VulTool Pipeline Error',
      description: message,
      color:       15158332,
      url:         runUrl,
      timestamp:   new Date().toISOString(),
      footer:      { text: 'VulTool CTI Scanner' },
    }],
  };
}

function parseVerdict(report: string): string | null {
  const m = report.match(/VERDICT:\s*(EXPLOITABLE|CONDITIONALLY_EXPLOITABLE|NOT_EXPLOITABLE)/);
  return m ? m[1] : null;
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
    core.setSecret(token);

    const repoName      = process.env.GITHUB_REPOSITORY ?? 'unknown/unknown';
    const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

    const HEAVY = '━'.repeat(60);
    const LIGHT = '─'.repeat(60);

    core.info(HEAVY);
    core.info('  CTI VULNERABILITY SCANNER');
    core.info(`  ${repoName}  |  Threshold: ${threshold}`);
    core.info(HEAVY);
    core.info('');

    // --- C1: ECOSYSTEM DETECTOR ---
    const { ecosystems: detectedEcosystems } = detectEcosystems(workspacePath);
    core.info(`  [C1] Ecosystem Detector     → ${detectedEcosystems.length > 0 ? detectedEcosystems.join(', ') : 'none'}`);
    if (detectedEcosystems.length === 0) {
      core.info('');
      core.info('  No package manager files found — nothing to scan.');
      core.info(HEAVY);
      return;
    }

    // --- C2: ALERT FETCHER ---
    const rawAdvisories: Advisory[] = await fetchRecentAdvisories(token, detectedEcosystems, watchedGhsaIds);
    core.info(`  [C2] Alert Fetcher          → ${rawAdvisories.length} advisories fetched`);
    if (rawAdvisories.length === 0) {
      core.info('');
      core.info('  No recent advisories from the CTI feed.');
      core.info(HEAVY);
      return;
    }

    // Advisory skip check
    const lastSeenIds = await loadLastSeenGhsaIds();
    const currentIds  = new Set<string>(rawAdvisories.map(a => a.ghsaId));
    const newIds      = [...currentIds].filter(id => !lastSeenIds.has(id));
    if (lastSeenIds.size > 0 && newIds.length === 0) {
      core.info('       No new advisories since last scan — pipeline skipped.');
      core.info('');
      core.info(HEAVY);
      return;
    }
    if (lastSeenIds.size > 0 && newIds.length < rawAdvisories.length) {
      core.info(`       ↳ ${newIds.length} new since last scan`);
    }

    // --- C3: DEPENDENCY MAPPER ---
    const installedPackages = await getRepositoryDependencies(token, workspacePath);
    if (installedPackages === null) {
      core.info(`  [C3] Dependency Mapper      → FAILED`);
      core.info('');
      core.info('  Dependency Mapper failed — verify the GitHub Dependency Graph is enabled.');
      core.info(HEAVY);
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
      if (discordWebhook) {
        await sendDiscordNotification(
          discordWebhook,
          buildDiscordCleanPayload(repoName, rawAdvisories.length, skippedCount),
        );
      }
      return;
    }

    // --- C5: DEPLOYMENT CLASSIFIER ---
    const contextualizedThreats: Threat[] = classifyDeploymentContext(confirmedAdvisories, workspacePath, detectedEcosystems);
    core.info(`  [C5] Deployment Classifier  → ${contextualizedThreats.length} threats classified`);

    // --- C6: REMEDIATION QUEUE ---
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
          const report = await callLLM(llmApiKey, buildExploitPrompt(ctx));
          llmReports.set(ctx.threat.ghsaId, report);
        } catch (err) {
          core.warning(`  LLM call failed for ${ctx.threat.packageName}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      core.info(`  [C9] LLM Exploit Analyzer   → ${llmReports.size} analysis complete`);
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
        for (const line of report.split('\n')) {
          core.info(`  ${line}`);
        }
        core.info('');
      }
    }

    // ── FOOTER ────────────────────────────────────────────────────────────────
    const verdicts        = [...llmReports.values()].map(parseVerdict).filter(Boolean) as string[];
    const exploitable     = verdicts.filter(v => v === 'EXPLOITABLE').length;
    const conditional     = verdicts.filter(v => v === 'CONDITIONALLY_EXPLOITABLE').length;
    const notExploitable  = verdicts.filter(v => v === 'NOT_EXPLOITABLE').length;

    if (discordWebhook) {
      await sendDiscordNotification(
        discordWebhook,
        buildDiscordPayload(repoName, sortedThreats, exploitContexts, llmReports, verdicts),
      );
    }

    core.info(HEAVY);
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
      parts.push(vParts.join('  '));
    }
    core.info(`  ${parts.join('  |  ')}`);
    core.info(HEAVY);

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
      const discordWebhook = core.getInput('discord_webhook_url');
      if (discordWebhook) {
        const repoName = process.env.GITHUB_REPOSITORY ?? 'unknown/unknown';
        await sendDiscordNotification(discordWebhook, buildDiscordErrorPayload(repoName, error.message));
      }
    }
  }
}

main();
