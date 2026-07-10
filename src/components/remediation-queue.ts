import * as core from '@actions/core';
import { Threat } from '../types';

export function generateRemediationQueue(threats: Threat[]): Threat[] {
  core.info('Component 6: Waking up Remediation Queue...');

  if (threats.length === 0) {
    core.info('Queue empty. No remediation required.');
    return [];
  }

  const sortedThreats = [...threats].sort((a, b) => b.priorityScore - a.priorityScore);

  core.info('=========================================');
  core.info('         FINAL REMEDIATION QUEUE         ');
  core.info('=========================================');

  sortedThreats.forEach((threat, index) => {
    core.info(`[Priority ${index + 1}] ${threat.packageName}`);
    core.info(`    Identifier:    ${threat.ghsaId}`);
    core.info(`    Ecosystem:     ${threat.ecosystem}`);
    core.info(`    Severity:      ${threat.severity}`);
    core.info(`    Context:       ${threat.contextualRisk}`);
    core.info(`    Priority Score: ${threat.priorityScore}`);
    core.info(`    Affected:      ${threat.vulnerableVersionRange}`);
    core.info(`    Patched In:    ${threat.firstPatchedVersion ?? 'no patch available'}`);
    core.info(`    Summary:       ${threat.summary}`);
    core.info('-----------------------------------------');
  });

  return sortedThreats;
}
