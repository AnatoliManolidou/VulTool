import * as core from '@actions/core';
import { detectEcosystems } from './components/language-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';
import { getRepositoryDependencies } from './components/dependency-mapper';
import { filterAdvisories } from './components/vulnerability-filter';
import { assessContextualRisk } from './components/contextual-risk-solver';
import { generateRemediationQueue } from './components/remediation-queue';
import { analyzeReachability } from './components/ast-analyzer';

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
    generateRemediationQueue(contextualizedThreats);
    core.info('Component 6 finished successfully.');

    // --- COMPONENT 7: AST REACHABILITY ANALYZER ---
    const activeImports = analyzeReachability(workspacePath, detectedEcosystems);
    core.info(`Active source code imports: ${JSON.stringify(activeImports)}`);

    const reachableThreats = finalThreats.filter(threat => 
      activeImports.includes(threat.packageName.toLowerCase())
    );

    if (reachableThreats.length > 0) {
      core.warning(`REACHABILITY ALERT: ${reachableThreats.length} vulnerabilities are actively imported in your code execution path!`);
      core.info(`Top reachable threat: ${reachableThreats[0].packageName}`);
    } else {
      core.info('REACHABILITY NOTICE: Verified threats are installed in manifests but unreferenced in code execution blocks.');
    }
    core.info('Component 7 finished successfully.');
    core.info('Pipeline finished successfully.');

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
    }
  }
}

main();