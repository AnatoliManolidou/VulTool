import * as core from '@actions/core';
import * as cache from '@actions/cache';
import * as fs from 'fs';
import { detectEcosystems } from './components/ecosystem-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';
import { getRepositoryDependencies } from './components/dependency-mapper';
import { filterAdvisories } from './components/vulnerability-filter';
import { classifyDeploymentContext } from './components/deployment-classifier';
import { generateRemediationQueue } from './components/remediation-queue';
import { analyzeCodeUsage, CodeSlice } from './components/ast-analyzer';
import { detectEntryPoint } from './components/purple-team/entry-point-detector';
import { buildCallChain } from './components/purple-team/call-chain-builder';
import { detectGuards } from './components/purple-team/guard-detector';
import { assembleContext } from './components/purple-team/context-assembler';
import { buildExploitPrompt } from './components/purple-team/prompt-builder';
import { callLLM } from './components/purple-team/llm-client';
import { ExploitContext } from './components/purple-team/types';
import { Advisory, Threat } from './types';

// Advisory IDs are cached between runs — skip the pipeline when the feed has not
// changed since the last hourly scan.
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

async function main() {
  try {
    const token          = core.getInput('github_token', { required: true });
    const threshold      = core.getInput('severity_threshold');
    const watchedGhsaRaw = core.getInput('watched_ghsa_ids');
    const watchedGhsaIds = watchedGhsaRaw
      ? watchedGhsaRaw.split(',').map(s => s.trim()).filter(Boolean)
      : [];
    core.setSecret(token);

    const repoName      = process.env.GITHUB_REPOSITORY ?? 'unknown/unknown';
    const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

    core.info('=========================================');
    core.info('      CTI VULNERABILITY SCANNER          ');
    core.info('=========================================');
    core.info(`  Repository : ${repoName}`);
    core.info(`  Threshold  : ${threshold}`);
    core.info('');

    // --- COMPONENT 1: ECOSYSTEM DETECTOR ---
    const { ecosystems: detectedEcosystems } = detectEcosystems(workspacePath);
    if (detectedEcosystems.length === 0) {
      core.info('No ecosystems detected. Exiting successfully.');
      return;
    }

    // --- COMPONENT 2: ALERT FETCHER ---
    core.info('');
    const rawAdvisories: Advisory[] = await fetchRecentAdvisories(token, detectedEcosystems, watchedGhsaIds);
    if (rawAdvisories.length === 0) {
      core.info('No recent advisories found. Exiting successfully.');
      return;
    }

    // --- ADVISORY SKIP CHECK ---
    const lastSeenIds = await loadLastSeenGhsaIds();
    const currentIds  = new Set<string>(rawAdvisories.map(a => a.ghsaId));
    const hasNewIds   = lastSeenIds.size === 0 || [...currentIds].some(id => !lastSeenIds.has(id));

    if (!hasNewIds) {
      core.info('');
      core.info('No new advisories since last scan — pipeline skipped. Next check in ~1 hour.');
      return;
    }

    const newCount = [...currentIds].filter(id => !lastSeenIds.has(id)).length;
    core.info(`  ${newCount} new advisory ID(s) since last scan — proceeding with full pipeline.`);

    // --- COMPONENT 3: DEPENDENCY MAPPER ---
    core.info('');
    const installedPackages = await getRepositoryDependencies(token, workspacePath);
    if (installedPackages === null) {
      core.error('CRITICAL PIPELINE HALT: Dependency Mapper failed. Check that the GitHub Dependency Graph is enabled for this repository.');
      return;
    }

    // --- COMPONENT 4: VULNERABILITY FILTER ---
    core.info('');
    const confirmedAdvisories: Advisory[] = filterAdvisories(rawAdvisories, threshold, installedPackages);
    if (confirmedAdvisories.length === 0) {
      core.info('No matching vulnerabilities found in this repository.');
      await saveSeenGhsaIds(currentIds);
      return;
    }

    // --- COMPONENT 5: DEPLOYMENT CLASSIFIER ---
    core.info('');
    const contextualizedThreats: Threat[] = classifyDeploymentContext(confirmedAdvisories, workspacePath, detectedEcosystems);

    // --- COMPONENT 6: REMEDIATION QUEUE ---
    core.info('');
    const sortedThreats: Threat[] = generateRemediationQueue(contextualizedThreats);

    // --- COMPONENT 7: AST ANALYZER (npm threats only) ---
    core.info('');
    const npmThreats: Threat[] = sortedThreats.filter(t => t.ecosystem === 'npm');
    let codeSlices: CodeSlice[] = [];

    if (npmThreats.length > 0) {
      codeSlices = await analyzeCodeUsage(npmThreats, workspacePath);
    } else {
      core.info('Component 7: No npm threats in queue — AST analysis skipped.');
    }

    // --- COMPONENT 8: PURPLE TEAM CONTEXT (tree-sitter) ---
    core.info('');
    // Populated by C8; consumed by C9 Prompt Builder → LLM Call → Risk Scorer (not yet implemented)
    const exploitContexts: ExploitContext[] = [];

    if (codeSlices.length > 0) {
      core.info('Component 8: Waking up Purple Team Context Analyzer (tree-sitter)...');
      for (const slice of codeSlices) {
        const threat = sortedThreats.find(t => t.ghsaId === slice.threatGhsaId);
        if (!threat) {
          core.warning(`No threat found for code slice ${slice.threatGhsaId} — skipping.`);
          continue;
        }
        core.info(`  Analyzing: ${slice.packageName}`);

        const entryPoint = await detectEntryPoint(slice.callerSlices, workspacePath);
        core.info(`  Entry point   : ${entryPoint ? entryPoint.identifier : 'not found'}`);
        if (entryPoint) {
          core.info(`  Framework     : ${entryPoint.framework ?? 'unknown'}`);
          core.info(`  Handler fn    : ${entryPoint.handlerFunction}`);
          core.info(`  Attack surface: ${entryPoint.attackableSurface.join(', ') || 'none detected'}`);
        }

        const callChain = await buildCallChain(entryPoint, slice, workspacePath);
        core.info(`  Call chain    : ${callChain.length === 0 ? 'direct (no intermediates)' : callChain.map(s => s.functionName).join(' → ')}`);

        const guards = detectGuards(entryPoint, callChain, slice);
        core.info(`  Guards found  : ${guards.guards.length === 0 ? 'none' : guards.guards.map(g => g.type).join(', ')}`);
        core.info(`  Has auth      : ${guards.hasAuthentication}`);
        core.info(`  Has validation: ${guards.hasInputValidation}`);

        const ctx = assembleContext(threat, slice, entryPoint, callChain, guards);
        exploitContexts.push(ctx);

        core.info(`  Attack class  : ${ctx.attackClass}`);
        core.info(`  Advisory info : ${ctx.advisoryRichness}`);
        core.info('');
        core.info('  ── Assembled Exploit Context ───────────────────────');
        core.info(`  Package       : ${ctx.threat.packageName} (installed: ${ctx.codeSlice.affectedFiles.length} file(s))`);
        core.info(`  Advisory      : ${ctx.threat.ghsaId} — ${ctx.threat.summary}`);
        core.info(`  CWEs          : ${ctx.threat.cwes.map(c => `${c.cweId} (${c.name})`).join(', ') || 'none'}`);
        core.info(`  CVSS          : ${ctx.threat.cvss ? `${ctx.threat.cvss.score} — ${ctx.threat.cvss.vectorString}` : 'n/a'}`);
        core.info(`  Affected range: ${ctx.threat.vulnerableVersionRange ?? 'unknown'}`);
        core.info(`  EIF caller(s) : ${ctx.codeSlice.callerSlices.map(c => `${c.functionName} (${c.file}:${c.startLine})`).join(', ')}`);
        core.info(`  EIF call site : ${ctx.codeSlice.eifCallSites.map(s => `${s.callExpression} (line ${s.line})`).join(', ')}`);
        if (ctx.entryPoint) {
          const eifFnName = ctx.codeSlice.eifCallSites[0]?.callExpression.split('(')[0]?.trim() ?? ctx.threat.packageName;
          // Sort EIF callers so that a caller whose body contains another caller's name
          // comes first — this reconstructs the correct topological call order.
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
          core.info(`  Attack path   : ${ctx.entryPoint.identifier} → ${chain.join(' → ')}`);
          core.info(`  Attack surface: ${ctx.entryPoint.attackableSurface.join(', ')}`);
        } else {
          core.info('  Attack path   : entry point not found — no direct attack path traced');
        }
        core.info(`  Guards        : ${ctx.guards.guards.length === 0 ? 'none' : ctx.guards.guards.map(g => `${g.type} (${g.file}:${g.line})`).join(', ')}`);
        core.info('  ────────────────────────────────────────────────────');
      }
    } else {
      core.info('Component 8: No code slices to analyze — purple team skipped.');
    }

    // --- COMPONENT 9: LLM REMEDIATION GENERATOR ---
    core.info('');
    const llmApiKey = core.getInput('llm_api_key');

    if (exploitContexts.length === 0) {
      core.info('Component 9: No exploit contexts to analyse — LLM step skipped.');
    } else if (!llmApiKey) {
      core.info('Component 9: No LLM API key provided — skipping exploit analysis.');
      core.info('  Add llm_api_key to your workflow to enable AI-powered exploit analysis.');
    } else {
      core.info('Component 9: Waking up LLM Exploit Analyzer...');
      for (const ctx of exploitContexts) {
        core.info(`  Analyzing exploitability for: ${ctx.threat.packageName}`);
        try {
          const prompt = buildExploitPrompt(ctx);
          const report = await callLLM(llmApiKey, prompt);
          core.info('');
          core.info('  ── LLM Exploit Analysis ────────────────────────────');
          core.info(`  Package : ${ctx.threat.packageName} (${ctx.threat.ghsaId})`);
          core.info('');
          report.split('\n').forEach(line => core.info(`  ${line}`));
          core.info('  ────────────────────────────────────────────────────');
        } catch (err) {
          core.warning(`  LLM call failed for ${ctx.threat.packageName}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    await saveSeenGhsaIds(currentIds);

    core.info('');
    core.info('=========================================');
    core.info('           PIPELINE COMPLETE             ');
    core.info('=========================================');
    core.info(`  Threats confirmed : ${sortedThreats.length}`);
    core.info(`  Active code usage : ${codeSlices.length} threat(s) with confirmed call sites`);
    core.info('');

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
    }
  }
}

main();
