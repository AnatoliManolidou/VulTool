import * as core from '@actions/core';
import * as github from '@actions/github';
import { Advisory, Ecosystem, Severity } from '../types';

export async function fetchRecentAdvisories(token: string, ecosystems: string[]): Promise<Advisory[]> {
  const octokit = github.getOctokit(token);
  const allAdvisories: Advisory[] = [];

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
              advisory {
                ghsaId
                summary
                description
                cwes(first: 10) { nodes { cweId name } }
                cvss { score vectorString }
              }
            }
          }
        }
      `;

      const response: any = await octokit.graphql(query, { ecosystem: graphqlEnum });
      const nodes = response.securityVulnerabilities.nodes as any[];

      core.info(`Pulled ${nodes.length} advisories from the CTI feed for ${graphqlEnum}.`);

      nodes.forEach((v: any, i: number) => {
        const cwes    = (v.advisory.cwes?.nodes ?? []) as Array<{ cweId: string }>;
        const cweStr  = cwes.length > 0 ? cwes.map(c => c.cweId).join(', ') : 'no CWE';
        const cvssStr = v.advisory.cvss ? `CVSS ${(v.advisory.cvss.score as number).toFixed(1)}` : 'no CVSS';
        core.info(`  [${i + 1}] ${v.package.name} ${v.vulnerableVersionRange} — ${v.advisory.summary} (${v.severity}) [${cweStr}] [${cvssStr}]`);
      });

      const formatted: Advisory[] = nodes.map((v: any): Advisory => ({
        ghsaId:                 v.advisory.ghsaId,
        summary:                v.advisory.summary,
        description:            v.advisory.description ?? null,
        cwes:                   v.advisory.cwes?.nodes ?? [],
        cvss:                   v.advisory.cvss ?? null,
        severity:               v.severity as Severity,
        packageName:            v.package.name,
        vulnerableVersionRange: v.vulnerableVersionRange ?? null,
        firstPatchedVersion:    v.firstPatchedVersion?.identifier ?? null,
        ecosystem:              eco as Ecosystem,
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
