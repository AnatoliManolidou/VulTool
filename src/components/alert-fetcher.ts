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

function mapFeedNode(v: any): Advisory {
  return {
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
  };
}

// Exact (ghsaId, packageName, vulnerableVersionRange) triples for feed entries that are
// genuinely installed at a vulnerable version AND reachable via direct source usage in
// the Dummy repo (reaches C7/C8/C9). Deliberately includes both GT-exploitable packages
// and reachable-but-NOT_EXPLOITABLE ones (node-fetch) — "reachable" is about whether the
// entry triggers LLM analysis, independent of the eventual verdict.
//
// Composite-key matching (not just ghsaId or packageName alone) is required because
// several GHSAs have multiple feed entries sharing a package name where only ONE range
// matches what's installed — e.g. GHSA-pfrx-2q88-qq97 has both "got < 11.8.5" (matches
// our 11.8.3) and "got >= 12.0.0, < 12.1.0" (does not); matching by name alone can select
// either one at random, which previously caused "0 confirmed" when the wrong one was drawn.
interface ReachableEntry { ghsaId: string; packageName: string; range: string; }
const REACHABLE_ENTRIES: ReachableEntry[] = [
  { ghsaId: 'GHSA-36jr-mh4h-2g58', packageName: 'd3-color',     range: '>= 1.0.2, < 3.1.0' },
  { ghsaId: 'GHSA-f2jv-r9rf-7988', packageName: 'handlebars',   range: '< 4.7.7' },
  { ghsaId: 'GHSA-phwq-j96m-2c2q', packageName: 'ejs',          range: '< 3.1.7' },
  { ghsaId: 'GHSA-hjrf-2m68-5959', packageName: 'jsonwebtoken', range: '<= 8.5.1' },
  { ghsaId: 'GHSA-wc9g-mqfw-jrwm', packageName: 'multer',       range: '>= 1.4.4-lts.1, < 2.3.0' },
  { ghsaId: 'GHSA-535w-7cp7-47q4', packageName: 'multer',       range: '>= 1.4.4-lts.1, < 2.3.0' },
  { ghsaId: 'GHSA-qfvm-cv95-jqjf', packageName: 'multer',       range: '= 2.2.0' },
  { ghsaId: 'GHSA-2x7j-588g-ccc2', packageName: 'nodemailer',   range: '< 9.1.0' },
  { ghsaId: 'GHSA-wmmp-3585-3rmp', packageName: 'nodemailer',   range: '< 9.1.0' },
  { ghsaId: 'GHSA-cc9r-2j5m-2m83', packageName: 'nodemailer',   range: '>= 6.9.16, < 9.1.0' },
  { ghsaId: 'GHSA-2883-xcg3-v3hh', packageName: 'js-yaml',      range: '>= 4.0.0, < 4.3.2' },
  { ghsaId: 'GHSA-jxfw-x594-9x9m', packageName: 'morgan',       range: '< 1.12.0' },
  { ghsaId: 'GHSA-7w5x-hrqm-74c2', packageName: 'smol-toml',    range: '<= 1.7.0' },
  { ghsaId: 'GHSA-rgj7-g3m4-5g8c', packageName: 'sharp',        range: '< 0.35.4' },
  { ghsaId: 'GHSA-j95f-988m-3j2f', packageName: '@tiptap/core', range: '>= 3.7.0, < 3.30.5' },
  { ghsaId: 'GHSA-pfrx-2q88-qq97', packageName: 'got',          range: '< 11.8.5' },
  { ghsaId: 'GHSA-9c47-m6qq-7p4h', packageName: 'json5',        range: '>= 2.0.0, < 2.2.2' },
  { ghsaId: 'GHSA-x5rq-j2xg-h7qm', packageName: 'lodash',       range: '>= 4.7.0, < 4.17.11' },
  { ghsaId: 'GHSA-72xf-g2v4-qvf3', packageName: 'tough-cookie', range: '< 4.1.3' },
  { ghsaId: 'GHSA-cf4h-3jhx-xvhq', packageName: 'underscore',   range: '>= 1.3.2, < 1.12.1' },
  { ghsaId: 'GHSA-r683-j2x4-v87g', packageName: 'node-fetch',   range: '< 2.6.7' }, // reachable, GT = NOT_EXPLOITABLE
];
const REACHABLE_GHSA_IDS = new Set(REACHABLE_ENTRIES.map(e => e.ghsaId));

function fisherYates<T>(arr: T[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
}

// Loads the bundled advisory-feed.json. In rescan mode returns only the entry
// matching ghsaIdFilter; otherwise returns a stratified sample:
//   • exactly 2 distinct-GHSA entries drawn from REACHABLE_ENTRIES (guaranteed to reach C9)
//   • (sampleSize - 2) filler entries — any feed entry whose GHSA is not in the reachable
//     pool, which is therefore guaranteed to be rejected by C4 (not installed / out of
//     range) or confirmed-but-unreachable by C7 (no source usage, e.g. semver, hono)
function fetchDemoAdvisories(sampleSize: number, ghsaIdFilter?: string): Advisory[] {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodes: any[] = require('../data/advisory-feed.json');

  if (ghsaIdFilter) {
    return nodes
      .filter((n: any) => n.advisory.ghsaId === ghsaIdFilter)
      .map(mapFeedNode);
  }

  // Resolve each allowlisted entry to its exact feed node — exact ghsaId + packageName +
  // vulnerableVersionRange match, never just "a node with this ghsaId".
  const reachableNodes = REACHABLE_ENTRIES
    .map(e => nodes.find((n: any) =>
      n.advisory.ghsaId === e.ghsaId &&
      n.package.name === e.packageName &&
      n.vulnerableVersionRange === e.range
    ))
    .filter((n: any) => n != null);

  const fillerPool = nodes.filter((n: any) => !REACHABLE_GHSA_IDS.has(n.advisory.ghsaId));

  fisherYates(reachableNodes);
  fisherYates(fillerPool);

  // Pick exactly 2 entries from distinct reachable GHSAs
  const picked: any[] = [];
  const seenGhsas = new Set<string>();
  for (const entry of reachableNodes) {
    if (seenGhsas.has(entry.advisory.ghsaId)) continue;
    seenGhsas.add(entry.advisory.ghsaId);
    picked.push(entry);
    if (picked.length >= 2) break;
  }

  const fill = fillerPool.slice(0, sampleSize - picked.length);
  return [...picked, ...fill].map(mapFeedNode);
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export async function fetchRecentAdvisories(
  token: string,
  ecosystems: string[],
  watchedGhsaIds: string[] = [],
  demoMode: boolean = false,
  rescanGhsaId?: string,
): Promise<Advisory[]> {
  if (demoMode) {
    return fetchDemoAdvisories(25, rescanGhsaId);
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
