/**
 * One-time script to populate src/data/advisory-feed.json with real GitHub
 * advisory data in the exact format the alert-fetcher expects.
 *
 * Usage:
 *   GITHUB_TOKEN=ghp_xxx npx ts-node scripts/fetch-demo-advisories.ts
 */

import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';

const GITHUB_GHSA_IDS = [
  'GHSA-36jr-mh4h-2g58', // d3-color        — ReDoS
  'GHSA-c2qf-rxjj-qqgw', // semver          — ReDoS
  'GHSA-93q8-gq69-wqmw', // ansi-regex      — ReDoS
  'GHSA-8hfj-j24r-96c4', // moment          — ReDoS
  'GHSA-x5rq-j2xg-h7qm', // marked          — ReDoS
  'GHSA-p6mc-m468-83gw', // lodash          — Prototype Pollution
  'GHSA-xvch-5gv4-984h', // minimist        — Prototype Pollution
  'GHSA-72xf-g2v4-qvf3', // tough-cookie    — Prototype Pollution
  'GHSA-f2jv-r9rf-7988', // handlebars      — Prototype Pollution / RCE
  'GHSA-cf4h-3jhx-xvhq', // underscore      — Arbitrary Code Execution
  'GHSA-phwq-j96m-2c2q', // ejs             — Template Injection (RCE)
  'GHSA-hjrf-2m68-5959', // jsonwebtoken    — Signature Bypass
  'GHSA-w573-4hg7-7wgq', // node-forge      — Signature Bypass
  'GHSA-r683-j2x4-v87g', // node-fetch      — SSRF
  'GHSA-cxjh-pqwp-8mfp', // axios           — SSRF
  'GHSA-pfrx-2q88-qq97', // got             — SSRF
  'GHSA-jchw-25xp-jwwc', // follow-redirects — Header Exposure
  'GHSA-3xgq-45jj-v275', // cross-fetch     — Header Exposure
  'GHSA-9c47-m6qq-7p4h', // tar             — Path Traversal
  'GHSA-h9rv-jmmf-4pgx', // serialize-javascript — XSS
];

const QUERY = `
  query($ghsaId: String!) {
    securityAdvisory(ghsaId: $ghsaId) {
      ghsaId
      summary
      description
      cwes(first: 10) { nodes { cweId name } }
      cvss { score vectorString }
      vulnerabilities(first: 5) {
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

function graphql(token: string, ghsaId: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ query: QUERY, variables: { ghsaId } });
    const req = https.request(
      {
        hostname: 'api.github.com',
        path: '/graphql',
        method: 'POST',
        headers: {
          'Authorization': `bearer ${token}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'VulTool-demo-feed-populator',
        },
      },
      res => {
        let data = '';
        res.on('data', chunk => (data += chunk));
        res.on('end', () => resolve(JSON.parse(data)));
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.error('Error: GITHUB_TOKEN environment variable is required.');
    process.exit(1);
  }

  const nodes: any[] = [];

  for (const ghsaId of GITHUB_GHSA_IDS) {
    process.stdout.write(`  Fetching ${ghsaId}... `);
    try {
      const res = await graphql(token, ghsaId);
      const advisory = res.data?.securityAdvisory;
      if (!advisory) {
        console.log(`NOT FOUND — skipping`);
        continue;
      }

      for (const vuln of advisory.vulnerabilities.nodes) {
        nodes.push({
          severity: vuln.severity,
          vulnerableVersionRange: vuln.vulnerableVersionRange,
          firstPatchedVersion: vuln.firstPatchedVersion,
          package: { name: vuln.package.name, ecosystem: vuln.package.ecosystem },
          advisory: {
            ghsaId: advisory.ghsaId,
            summary: advisory.summary,
            description: advisory.description,
            cwes: { nodes: advisory.cwes.nodes },
            cvss: advisory.cvss,
          },
        });
      }
      console.log(`OK (${advisory.vulnerabilities.nodes.length} package(s))`);
    } catch (err) {
      console.log(`ERROR — ${err instanceof Error ? err.message : String(err)}`);
    }

    // Avoid hitting GitHub's rate limit
    await new Promise(r => setTimeout(r, 300));
  }

  const outPath = path.join(__dirname, '..', 'src', 'data', 'advisory-feed.json');
  fs.writeFileSync(outPath, JSON.stringify(nodes, null, 2));
  console.log(`\nWrote ${nodes.length} node(s) to ${outPath}`);
}

main();
