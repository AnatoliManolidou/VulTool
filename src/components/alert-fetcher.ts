import * as core from '@actions/core';
import * as github from '@actions/github';
import { Advisory, Ecosystem, Severity } from '../types';

const ECOSYSTEM_MAP: Record<string, string> = {
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

// ─── Live Feed ────────────────────────────────────────────────────────────────

async function fetchFeedAdvisories(
  octokit: ReturnType<typeof github.getOctokit>,
  ecosystems: string[],
): Promise<Advisory[]> {
  const results: Advisory[] = [];

  for (const eco of ecosystems) {
    const graphqlEnum = ECOSYSTEM_MAP[eco];
    if (!graphqlEnum) {
      core.warning(`Unknown ecosystem for GraphQL: ${eco}`);
      continue;
    }

    core.info(`Fetching latest 25 advisories for ecosystem: ${graphqlEnum}...`);

    const query = `
      query($ecosystem: SecurityAdvisoryEcosystem) {
        securityVulnerabilities(first: 25, ecosystem: $ecosystem, orderBy: {field: UPDATED_AT, direction: DESC}) {
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

    results.push(...nodes.map((v: any): Advisory => ({
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
    })));
  }

  return results;
}

// ─── Watched Advisories ───────────────────────────────────────────────────────

// Fetches specific advisories by GHSA ID — used for packages the team knows
// are in their stack and wants checked on every run regardless of feed position.
async function fetchWatchedAdvisories(
  octokit: ReturnType<typeof github.getOctokit>,
  ghsaIds: string[],
): Promise<Advisory[]> {
  if (ghsaIds.length === 0) return [];

  core.info(`Fetching ${ghsaIds.length} watched advisory ID(s)...`);

  const results: Advisory[] = [];

  for (const ghsaId of ghsaIds) {
    const query = `
      query($ghsaId: String!) {
        securityAdvisory(ghsaId: $ghsaId) {
          ghsaId
          summary
          description
          cwes(first: 10) { nodes { cweId name } }
          cvss { score vectorString }
          vulnerabilities(first: 10) {
            nodes {
              severity
              vulnerableVersionRange
              firstPatchedVersion { identifier }
              package { name ecosystem }
            }
          }
        }
      }
    `;

    try {
      const response: any = await octokit.graphql(query, { ghsaId });
      const advisory = response.securityAdvisory;
      if (!advisory) {
        core.warning(`  Watched advisory not found: ${ghsaId}`);
        continue;
      }

      for (const vuln of advisory.vulnerabilities.nodes as any[]) {
        const eco = (vuln.package.ecosystem as string).toLowerCase();
        results.push({
          ghsaId:                 advisory.ghsaId,
          summary:                advisory.summary,
          description:            advisory.description ?? null,
          cwes:                   advisory.cwes?.nodes ?? [],
          cvss:                   advisory.cvss ?? null,
          severity:               vuln.severity as Severity,
          packageName:            vuln.package.name,
          vulnerableVersionRange: vuln.vulnerableVersionRange ?? null,
          firstPatchedVersion:    vuln.firstPatchedVersion?.identifier ?? null,
          ecosystem:              eco as Ecosystem,
        });
        core.info(`  [watched] ${vuln.package.name} ${vuln.vulnerableVersionRange} — ${advisory.summary} (${vuln.severity})`);
      }
    } catch (err) {
      core.warning(`  Failed to fetch watched advisory ${ghsaId}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return results;
}

// ─── Demo Feed ────────────────────────────────────────────────────────────────

// Loads the bundled advisory-feed.json and returns a random sample of size n.
function fetchDemoAdvisories(sampleSize: number): Advisory[] {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodes: any[] = require('../data/advisory-feed.json');

  // Fisher-Yates shuffle, take first sampleSize
  for (let i = nodes.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [nodes[i], nodes[j]] = [nodes[j], nodes[i]];
  }
  const sample = nodes.slice(0, Math.min(sampleSize, nodes.length));

  // Apply the same node→Advisory mapping as the live feed path
  const advisories: Advisory[] = sample.map((v: any): Advisory => ({
    ghsaId:                 v.advisory.ghsaId,
    summary:                v.advisory.summary,
    description:            v.advisory.description ?? null,
    cwes:                   v.advisory.cwes?.nodes ?? [],
    cvss:                   v.advisory.cvss ?? null,
    severity:               v.severity as Severity,
    packageName:            v.package.name,
    vulnerableVersionRange: v.vulnerableVersionRange ?? null,
    firstPatchedVersion:    v.firstPatchedVersion?.identifier ?? null,
    ecosystem:              (v.package.ecosystem as string).toLowerCase() as Ecosystem,
  }));

  return advisories;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export async function fetchRecentAdvisories(
  token: string,
  ecosystems: string[],
  watchedGhsaIds: string[] = [],
  demoMode: boolean = false,
): Promise<Advisory[]> {
  if (demoMode) {
    return fetchDemoAdvisories(8);
  }

  const octokit = github.getOctokit(token);

  try {
    const [feedAdvisories, watchedAdvisories] = await Promise.all([
      fetchFeedAdvisories(octokit, ecosystems),
      fetchWatchedAdvisories(octokit, watchedGhsaIds),
    ]);

    // Merge: watched advisories fill in anything the live feed missed.
    // Deduplicate by GHSA ID + package name so a watched advisory already
    // in the feed isn't reported twice.
    const seen = new Set(feedAdvisories.map(a => `${a.ghsaId}:${a.packageName}`));
    const merged = [
      ...feedAdvisories,
      ...watchedAdvisories.filter(a => !seen.has(`${a.ghsaId}:${a.packageName}`)),
    ];

    return merged;

  } catch (error) {
    if (error instanceof Error) core.error(`Alert Fetcher crashed: ${error.message}`);
    return [];
  }
}
