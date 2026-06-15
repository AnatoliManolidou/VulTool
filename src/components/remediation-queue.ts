import * as core from '@actions/core';

export function generateRemediationQueue(assessedThreats: any[]) {
  core.info('Component 6: Waking up Remediation Queue...');

  if (assessedThreats.length === 0) {
    core.info('Queue empty. No remediation required.');
    return;
  }

  // Sort the queue: Production risks (isDevDependency: false) first, Dev risks last
  const sortedThreats = assessedThreats.sort((a, b) => {
    if (a.isDevDependency === b.isDevDependency) return 0;
    return a.isDevDependency ? 1 : -1; 
  });

  core.info('=========================================');
  core.info('         FINAL REMEDIATION QUEUE         ');
  core.info('=========================================');
  
  sortedThreats.forEach((threat, index) => {
    core.info(`[Priority ${index + 1}] Package: ${threat.packageName}`);
    core.info(`    Base Severity: ${threat.severity}`);
    core.info(`    Context:       ${threat.contextualRisk}`);
    core.info(`    Details:       ${threat.summary}`);
    core.info('-----------------------------------------');
  });
}