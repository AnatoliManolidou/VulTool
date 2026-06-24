import * as core from '@actions/core';
import * as cache from '@actions/cache';
import * as fs from 'fs';
import * as path from 'path';
import { detectEcosystems } from './components/ecosystem-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';
import { getRepositoryDependencies } from './components/dependency-mapper';
import { filterAdvisories } from './components/vulnerability-filter';
import { classifyDeploymentContext } from './components/deployment-classifier';
import { generateRemediationQueue } from './components/remediation-queue';
import { analyzeCodeUsage } from './components/ast-analyzer';

// Advisory state is cached between runs to skip the pipeline when nothing new
// has been published since the last scan.
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
    core.info('CTI Vulnerability Scanner Waking Up...');

    const token = core.getInput('github_token', { required: true });
    const threshold = core.getInput('severity_threshold');
    core.setSecret(token);

    core.info(`Target Threshold: ${threshold}\n`);

    const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

    // --- COMPONENT 1: ECOSYSTEM DETECTOR ---
    const { ecosystems: detectedEcosystems, hasSbom } = await detectEcosystems(workspacePath);
    if (detectedEcosystems.length === 0) {
      core.info('No ecosystems to analyze. Exiting successfully.');
      return;
    }

    // --- COMPONENT 2: ALERT FETCHER ---
    // Fetches the 10 most recently updated advisories per detected ecosystem.
    const rawAdvisories = await fetchRecentAdvisories(token, detectedEcosystems);
    if (rawAdvisories.length === 0) {
      core.info('No recent advisories found. Exiting successfully.');
      return;
    }

    // --- ADVISORY SKIP CHECK ---
    // Compare the fetched GHSA IDs against what we saw last run.
    // If the set is identical, no new advisories have been published — skip the rest.
    const lastSeenIds  = await loadLastSeenGhsaIds();
    const currentIds   = new Set<string>(rawAdvisories.map((a: any) => a.ghsaId));
    const hasNewIds    = lastSeenIds.size === 0 || [...currentIds].some(id => !lastSeenIds.has(id));

    if (!hasNewIds) {
      core.info('No new advisories since last scan. Pipeline skipped — next check in 1 hour.');
      return;
    }

    const newCount = [...currentIds].filter(id => !lastSeenIds.has(id)).length;
    core.info(`${newCount} new advisory ID(s) detected since last scan. Proceeding with pipeline.`);

    // --- COMPONENT 3: DEPENDENCY MAPPER ---
    const localDependencies = await getRepositoryDependencies(token, hasSbom, workspacePath);
    if (localDependencies === null) {
      core.error('CRITICAL PIPELINE HALT: Dependency Mapper failed. Check that the GitHub Dependency Graph is enabled for this repository.');
      return;
    }

    // --- COMPONENT 4: VULNERABILITY FILTER ---
    const finalThreats = filterAdvisories(rawAdvisories, threshold, localDependencies, workspacePath);
    if (finalThreats.length === 0) {
      core.info('No matching vulnerabilities found in your dependencies.');
      await saveSeenGhsaIds(currentIds);
      return;
    }

    // --- COMPONENT 5: DEPLOYMENT CLASSIFIER ---
    const contextualizedThreats = classifyDeploymentContext(finalThreats, workspacePath, detectedEcosystems);

    // --- COMPONENT 6: REMEDIATION QUEUE ---
    const sortedThreats = generateRemediationQueue(contextualizedThreats);

    // --- COMPONENT 7: AST ANALYZER (npm threats only) ---
    const npmThreats = sortedThreats.filter((t: any) => t.ecosystem === 'npm');
    if (npmThreats.length > 0) {
      core.info(`${npmThreats.length} npm threat(s) routed to deep AST analysis.`);
      await analyzeCodeUsage(npmThreats, workspacePath);
    } else {
      core.info('No npm threats in queue. Skipping AST analysis.');
    }

    // Save the current advisory set so the next hourly run can compare against it.
    await saveSeenGhsaIds(currentIds);

    core.info('Pipeline finished successfully.');

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
    }
  }
}

main();
