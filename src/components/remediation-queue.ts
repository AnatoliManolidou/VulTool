import * as core from '@actions/core';

export function generateRemediationQueue(assessedThreats: any[]): any[] {
  core.info('Component 6: Waking up Remediation Queue...');

  if (assessedThreats.length === 0) {
    core.info('Queue empty. No remediation required.');
    return [];
  }

  // Sort descending by priorityScore (set by contextual-risk-solver).
  // Severity is the primary key; prod/dev is the tiebreaker within the same severity.
  const sortedThreats = [...assessedThreats].sort((a, b) => b.priorityScore - a.priorityScore);

  core.info('=========================================');
  core.info('         FINAL REMEDIATION QUEUE         ');
  core.info('=========================================');

  sortedThreats.forEach((threat, index) => {
    core.info(`[Priority ${index + 1}] Package: ${threat.packageName}`);
    core.info(`    Identifier:    ${threat.ghsaId}`);
    core.info(`    Ecosystem:     ${threat.ecosystem}`);
    core.info(`    Base Severity: ${threat.severity}`);
    core.info(`    Context:       ${threat.contextualRisk}`);
    core.info(`    Priority Score:${threat.priorityScore}`);
    core.info(`    Versions:      ${threat.vulnerableVersionRange}`);
    core.info(`    Details:       ${threat.summary}`);
    core.info('-----------------------------------------');
  });

  return sortedThreats;
}
