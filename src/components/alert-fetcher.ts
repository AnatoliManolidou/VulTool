import * as core from '@actions/core';
import * as github from '@actions/github';

export async function fetchRecentAdvisories(token: string, ecosystems: string[]) {
  const octokit = github.getOctokit(token);
  const allAdvisories: any[] = [];

  // Map our simple ecosystem strings to GitHub's exact GraphQL Enums
  const ecosystemMap: Record<string, string> = {
    'npm':      'NPM',
    'pip':      'PIP',
    'rubygems': 'RUBYGEMS',
    'go':       'GO',
    'crates':   'RUST',
    'maven':    'MAVEN',
    'nuget':    'NUGET',
    'composer': 'COMPOSER',
    'swift':    'SWIFT',
    'pub':      'PUB',
    'erlang':   'ERLANG',
    'actions':  'ACTIONS',
  };

  try {
    core.info('Component 2: Waking up Alert Fetcher...');

    for (const eco of ecosystems) {
      const graphqlEnum = ecosystemMap[eco];
      if (!graphqlEnum) {
        core.warning(`Unknown ecosystem for GraphQL: ${eco}`);
        continue;
      }

      core.info(`Fetching latest threat intel for ecosystem: ${graphqlEnum}...`);

      // Querying 'securityVulnerabilities'
      const query = `
        query($ecosystem: SecurityAdvisoryEcosystem) {
          securityVulnerabilities(first: 50, ecosystem: $ecosystem, orderBy: {field: UPDATED_AT, direction: DESC}) {
            nodes {
              severity
              package { name }
              vulnerableVersionRange
              advisory {
                ghsaId
                summary
              }
            }
          }
        }
      `;

      const response: any = await octokit.graphql(query, { ecosystem: graphqlEnum });
      const vulnerabilities = response.securityVulnerabilities.nodes;
      
      core.info(`Pulled ${vulnerabilities.length} raw vulnerabilities for ${graphqlEnum}.`);
      
      //Print a single real-time sample from the global threat database ---
      if (vulnerabilities.length > 0) {
        const sample = vulnerabilities[0];
        core.info(`Sample Threat Fetched: ${sample.package.name}: ${sample.advisory.summary} (Severity: ${sample.severity})`);
      }
      
      // Map the nested GraphQL response into a clean, flat object for our pipeline
      const formattedData = vulnerabilities.map((v: any) => ({
        ghsaId: v.advisory.ghsaId,
        summary: v.advisory.summary,
        severity: v.severity,
        packageName: v.package.name,
        vulnerableVersionRange: v.vulnerableVersionRange
      }));

      allAdvisories.push(...formattedData);
    }

    return allAdvisories;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Alert Fetcher crashed: ${error.message}`);
    }
    return [];
  }
}