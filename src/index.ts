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

// Advisory state is cached between runs — skip the pipeline when the global
// advisory feed has not changed since the last hourly scan.
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
    const { ecosystems: detectedEcosystems } = await detectEcosystems(workspacePath);
    if (detectedEcosystems.length === 0) {
      core.info('No ecosystems detected. Exiting successfully.');
      return;
    }

    // --- COMPONENT 2: ALERT FETCHER ---
    core.info('');
    const rawAdvisories = await fetchRecentAdvisories(token, detectedEcosystems);
    if (rawAdvisories.length === 0) {
      core.info('No recent advisories found. Exiting successfully.');
      return;
    }

    // --- ADVISORY SKIP CHECK ---
    // If the GHSA ID set is identical to the last run, no new advisories have
    // been published — skip the heavy pipeline and wait for the next hourly scan.
    const lastSeenIds = await loadLastSeenGhsaIds();
    const currentIds  = new Set<string>(rawAdvisories.map((a: any) => a.ghsaId));
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
    const finalThreats = filterAdvisories(rawAdvisories, threshold, installedPackages);
    if (finalThreats.length === 0) {
      core.info('No matching vulnerabilities found in this repository.');
      await saveSeenGhsaIds(currentIds);
      return;
    }

    // --- COMPONENT 5: DEPLOYMENT CLASSIFIER ---
    core.info('');
    const contextualizedThreats = classifyDeploymentContext(finalThreats, workspacePath, detectedEcosystems);

    // --- COMPONENT 6: REMEDIATION QUEUE ---
    core.info('');
    const sortedThreats = generateRemediationQueue(contextualizedThreats);

    // --- COMPONENT 7: AST ANALYZER (npm threats only) ---
    core.info('');
    const npmThreats = sortedThreats.filter((t: any) => t.ecosystem === 'npm');
    let codeSlices: CodeSlice[] = [];

    if (npmThreats.length > 0) {
      codeSlices = await analyzeCodeUsage(npmThreats, workspacePath);
    } else {
      core.info('Component 7: No npm threats in queue — AST analysis skipped.');
    }

    // Persist the current advisory set so the next hourly run can compare against it.
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
