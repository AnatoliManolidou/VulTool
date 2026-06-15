import * as core from '@actions/core';
import * as github from '@actions/github';

export async function fetchRecentAdvisories(token: string, ecosystems: string[]) {
  const octokit = github.getOctokit(token);
  const allAdvisories: any[] = [];

  // Map our simple ecosystem strings to GitHub's exact GraphQL Enums
  const ecosystemMap: Record<string, string> = {
    'npm': 'NPM',
    'pip': 'PIP',
    'rubygems': 'RUBYGEMS',
    'go': 'GO',
    'crates': 'RUST'
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

      // GraphQL Query asking for the 50 most recent vulnerabilities
      const query = `
        query($ecosystem: SecurityAdvisoryEcosystem) {
          securityAdvisories(first: 50, ecosystem: $ecosystem, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
            nodes {
              ghsaId
              summary
              cvss { score }
              severity
              vulnerabilities(first: 10) {
                nodes {
                  package { name }
                  vulnerableVersionRange
                }
              }
            }
          }
        }
      `;

      const response: any = await octokit.graphql(query, { ecosystem: graphqlEnum });
      const advisories = response.securityAdvisories.nodes;
      
      core.info(`Pulled ${advisories.length} raw advisories for ${graphqlEnum}.`);
      allAdvisories.push(...advisories);
    }

    return allAdvisories;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Alert Fetcher crashed: ${error.message}`);
    }
    return [];
  }
}