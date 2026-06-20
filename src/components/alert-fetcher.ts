import * as core from '@actions/core';
import * as github from '@actions/github';

export async function fetchRecentAdvisories(token: string, ecosystems: string[]): Promise<any[]> {
  const octokit = github.getOctokit(token);
  const allAdvisories: any[] = [];

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

      core.info(`Fetching latest 10 advisories for ecosystem: ${graphqlEnum}...`);

      const query = `
        query($ecosystem: SecurityAdvisoryEcosystem) {
          securityVulnerabilities(first: 10, ecosystem: $ecosystem, orderBy: {field: UPDATED_AT, direction: DESC}) {
            nodes {
              severity
              vulnerableVersionRange
              firstPatchedVersion { identifier }
              package { name }
              advisory { ghsaId summary description }
            }
          }
        }
      `;

      const response: any = await octokit.graphql(query, { ecosystem: graphqlEnum });
      const nodes = response.securityVulnerabilities.nodes as any[];

      core.info(`Pulled ${nodes.length} advisories from the CTI feed for ${graphqlEnum}.`);

      nodes.forEach((v: any, i: number) => {
        core.info(`  [${i + 1}] ${v.package.name} ${v.vulnerableVersionRange} — ${v.advisory.summary} (${v.severity})`);
      });

      const formatted = nodes.map((v: any) => ({
        ghsaId:                 v.advisory.ghsaId,
        summary:                v.advisory.summary,
        description:            v.advisory.description,
        severity:               v.severity,
        packageName:            v.package.name,
        vulnerableVersionRange: v.vulnerableVersionRange,
        firstPatchedVersion:    v.firstPatchedVersion?.identifier ?? null,
        ecosystem:              eco,
      }));

      allAdvisories.push(...formatted);
    }

    return allAdvisories;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Alert Fetcher crashed: ${error.message}`);
    }
    return [];
  }
}
