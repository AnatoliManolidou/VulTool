import * as core from '@actions/core';
import { detectEcosystems } from './components/language-detector';
import { fetchRecentAdvisories } from './components/alert-fetcher';

async function main() {
  try {
    core.info('CTI Vulnerability Scanner Waking Up...');

    // Read inputs passed from the test repo workflow
    const token = core.getInput('github_token', { required: true });
    const threshold = core.getInput('severity_threshold');
    core.setSecret(token); // Safely mask the token

    core.info(`Target Threshold: ${threshold}`);

    // Locate where the test repo's code is checked out
    const workspacePath = process.env.GITHUB_WORKSPACE || process.cwd();

    // --- COMPONENT 1: LANGUAGE DETECTOR ---
    const detectedEcosystems = await detectEcosystems(workspacePath);
    core.info(`Active Ecosystems: ${JSON.stringify(detectedEcosystems)}`);

    // Stop sign
    if (detectedEcosystems.length === 0) {
        core.info('No ecosystems to analyze. Exiting successfully.');
        return; // This immediately stops the Orchestrator.
    }

    core.info('Component 1 finished successfully.');

    // --- COMPONENT 2: ALERT FETCHER ---
    const rawAdvisories = await fetchRecentAdvisories(token, detectedEcosystems);
    
    // Just printing the very first threat to prove we got the data
    if (rawAdvisories.length > 0) {
        core.info(`Sample Threat Fetched: ${rawAdvisories[0].summary} (Severity: ${rawAdvisories[0].severity})`);
    } else {
        core.info('No recent advisories found.');
    }

    core.info('Component 2 finished successfully.');
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Pipeline crashed: ${error.message}`);
    }
  }
}

main();