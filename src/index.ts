import * as core from '@actions/core';
import { detectEcosystems } from './components/language-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';
import { getRepositoryDependencies } from './components/dependency-mapper';
import { filterAdvisories } from './components/vulnerability-filter';
import { assessContextualRisk } from './components/contextual-risk-solver';
import { generateRemediationQueue } from './components/remediation-queue';

async function main() {
  try {
    core.info('CTI Vulnerability Scanner Waking Up...');

    const token = core.getInput('github_token', { required: true });
    const threshold = core.getInput('severity_threshold');
    core.setSecret(token);

    core.info(`Target Threshold: ${threshold}`);

    const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

    // --- COMPONENT 1: LANGUAGE & SBOM DETECTOR ---
    const { ecosystems: detectedEcosystems, hasSbom } = await detectEcosystems(workspacePath);
    if (detectedEcosystems.length === 0) {
      core.info('No ecosystems to analyze. Exiting successfully.');
      return; 
    }

    // --- COMPONENT 2: ALERT FETCHER ---
    const rawAdvisories = await fetchRecentAdvisories(token, detectedEcosystems);
    if (rawAdvisories.length === 0) {
      core.info('No recent advisories found. Exiting successfully.');
      return;
    }

    // --- COMPONENT 3: DEPENDENCY MAPPER ---
    const localDependencies = await getRepositoryDependencies(token);

    // --- COMPONENT 4: VULNERABILITY FILTER ---
    const finalThreats = filterAdvisories(rawAdvisories, threshold, localDependencies);
    if (finalThreats.length === 0) {
      core.info('No matching vulnerabilities found in your dependencies. Your codebase is safe!');
      return;
    }

    // --- COMPONENT 5: CONTEXTUAL RISK SOLVER ---
    const contextualizedThreats = assessContextualRisk(finalThreats, workspacePath, detectedEcosystems);

    // --- COMPONENT 6: REMEDIATION QUEUE ---
    generateRemediationQueue(contextualizedThreats);
    core.info('Component 6 finished successfully.');

    core.info('Pipeline finished successfully.');

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
    }
  }
}

main();