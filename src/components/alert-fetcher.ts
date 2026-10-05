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

// GHSAs confirmed exploitable in the Dummy test environment (GT = True).
// Used to build the "guaranteed" portion of every demo sample.
const EXPLOITABLE_GHSAS = new Set([
  'GHSA-f2jv-r9rf-7988', // handlebars
  'GHSA-phwq-j96m-2c2q', // ejs
  'GHSA-36jr-mh4h-2g58', // d3-color
  'GHSA-hjrf-2m68-5959', // jsonwebtoken
  'GHSA-wc9g-mqfw-jrwm', // multer
  'GHSA-535w-7cp7-47q4', // multer (second advisory)
  'GHSA-qfvm-cv95-jqjf', // multer (third advisory)
  'GHSA-2x7j-588g-ccc2', // nodemailer
  'GHSA-wmmp-3585-3rmp', // nodemailer (second)
  'GHSA-cc9r-2j5m-2m83', // nodemailer (third)
  'GHSA-2883-xcg3-v3hh', // js-yaml
  'GHSA-rgj7-g3m4-5g8c', // sharp
  'GHSA-7w5x-hrqm-74c2', // smol-toml
  'GHSA-j95f-988m-3j2f', // @tiptap/core
  'GHSA-jxfw-x594-9x9m', // morgan
  'GHSA-pfrx-2q88-qq97', // got
  'GHSA-9c47-m6qq-7p4h', // json5
  'GHSA-x5rq-j2xg-h7qm', // lodash
  'GHSA-72xf-g2v4-qvf3', // tough-cookie
  'GHSA-cf4h-3jhx-xvhq', // underscore
]);

// Package names installed in Dummy at a vulnerable version with direct source usage.
// Paired with EXPLOITABLE_GHSAS to exclude variant entries (lodash-rails, org.webjars,
// got >= 12.x, json5 < 1.0.2) that share the same GHSA but don't match the installed pkg.
const INSTALLED_EXPLOITABLE_PACKAGES = new Set([
  'd3-color', 'handlebars', 'ejs', 'jsonwebtoken', 'lodash', 'tough-cookie',
  'underscore', 'got', 'json5', 'multer', 'nodemailer', 'js-yaml',
  'morgan', 'smol-toml', 'sharp', '@tiptap/core',
]);

// Package names whose feed entries will always be rejected by C4 in the Dummy repo
// (not installed, or installed at a version outside every advisory range).
// These are safe filler: they add sample cardinality without triggering C7/C8/C9.
const FILLER_PACKAGES = new Set([
  'ansi-regex',           // transitive @6.2.2 — outside all 3.x/4.x/5.x/6.0.x ranges
  'Moment.js',            // not installed (dep is 'moment', not 'Moment.js')
  'moment',               // 2.29.3 installed — outside < 2.29.2
  'lodash-rails',         // not installed
  'lodash-amd',           // not installed
  'lodash-es',            // not installed
  'lodash.updatewith',    // not installed
  'lodash.update',        // not installed
  'lodash.setwith',       // not installed
  'lodash.set',           // not installed
  'minimist',             // transitive @1.2.8 — outside < 0.2.4 and < 1.2.6
  'decode-uri-component', // not installed
  'follow-redirects',     // transitive @1.16.0 — outside <= 1.15.5 and < 1.15.4
  'cross-spawn',          // transitive @7.0.6 — outside < 6.0.6 and >= 7.0.0, < 7.0.5
  'serialize-javascript', // 3.0.0 installed — outside < 2.1.1
  'astro',                // not installed
  'omniroute',            // not installed
]);

function fisherYates<T>(arr: T[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
}

// Loads the bundled advisory-feed.json. In rescan mode returns only the entry
// matching ghsaIdFilter; otherwise returns a stratified sample:
//   • exactly 2 distinct-GHSA entries from the exploitable pool (guaranteed C7/C8/C9 candidates)
//   • (sampleSize - 2) entries from the filler pool (guaranteed C4 rejects — no LLM analysis)
function fetchDemoAdvisories(sampleSize: number, ghsaIdFilter?: string): Advisory[] {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodes: any[] = require('../data/advisory-feed.json');

  if (ghsaIdFilter) {
    return nodes
      .filter((n: any) => n.advisory.ghsaId === ghsaIdFilter)
      .map(mapFeedNode);
  }

  const exploitPool = nodes.filter((n: any) =>
    EXPLOITABLE_GHSAS.has(n.advisory.ghsaId) &&
    INSTALLED_EXPLOITABLE_PACKAGES.has(n.package.name)
  );
  const fillerPool = nodes.filter((n: any) => FILLER_PACKAGES.has(n.package.name));

  fisherYates(exploitPool);
  fisherYates(fillerPool);

  // Pick exactly 2 entries from distinct exploitable GHSAs
  const picked: any[] = [];
  const seenGhsas = new Set<string>();
  for (const entry of exploitPool) {
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
