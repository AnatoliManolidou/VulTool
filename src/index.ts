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
    const token     = core.getInput('github_token', { required: true });
    const threshold = core.getInput('severity_threshold');
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
    const rawAdvisories: Advisory[] = await fetchRecentAdvisories(token, detectedEcosystems);
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
    const installedPackages = await getRepositoryDependencies(token);
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
    if (codeSlices.length > 0) {
      core.info('Component 8: Waking up Purple Team Context Analyzer (tree-sitter)...');
      for (const slice of codeSlices) {
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
      }
    } else {
      core.info('Component 8: No code slices to analyze — purple team skipped.');
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
