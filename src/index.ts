import * as core from '@actions/core';
import { detectEcosystems } from './components/language-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';
import { getRepositoryDependencies } from './components/dependency-mapper';
import { filterAdvisories } from './components/vulnerability-filter';
import { assessContextualRisk } from './components/contextual-risk-solver';
import { generateRemediationQueue } from './components/remediation-queue';
import { analyzeCodeUsage } from './components/ast-analyzer';

async function main() {
  try {
    core.info('CTI Vulnerability Scanner Waking Up...');

    const token = core.getInput('github_token', { required: true });
    const threshold = core.getInput('severity_threshold');
    core.setSecret(token);

    core.info(`Target Threshold: ${threshold}\n`);

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
    const localDependencies = await getRepositoryDependencies(token, hasSbom, workspacePath);
    
    // Check for API timeout/failure handler
    if (localDependencies === null) {
      core.error('CRITICAL PIPELINE HALT: Dependency Mapper failed to retrieve your local repository map due to an upstream API timeout or configuration error.');
      core.info('Action Plan: Check if GitHub Dependency Graph is enabled in your repository settings or retry the run.');
      return; 
    }

    // --- COMPONENT 4: VULNERABILITY FILTER ---
    const finalThreats = filterAdvisories(rawAdvisories, threshold, localDependencies);
    if (finalThreats.length === 0) {
      core.info('No matching vulnerabilities found in your dependencies.');
      return;
    }

    // --- COMPONENT 5: CONTEXTUAL RISK SOLVER ---
    const contextualizedThreats = assessContextualRisk(finalThreats, workspacePath, detectedEcosystems);

    // --- COMPONENT 6: REMEDIATION QUEUE ---
    const sortedThreats = generateRemediationQueue(contextualizedThreats);

    // --- COMPONENT 7: AST ANALYZER (npm threats only) ---
    const npmThreats = sortedThreats.filter((t: any) => t.ecosystem === 'npm');
    if (npmThreats.length > 0) {
      core.info(`${npmThreats.length} npm threat(s) routed to deep AST analysis.`);
      await analyzeCodeUsage(npmThreats, workspacePath);
      // Phase 3 (Red Team) will consume the code slices returned here
    } else {
      core.info('No npm threats in queue. Skipping AST analysis.');
    }

    core.info('Pipeline finished successfully.');

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
    }
  }
}

main();