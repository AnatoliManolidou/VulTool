/**
 * Prints the current top-N most recently updated advisories for a given ecosystem.
 * Use this to find a package to add to Dummy for pipeline testing.
 *
 * Usage:
 *   node scripts/check-top-advisories.js <GITHUB_TOKEN> [ecosystem] [count]
 *
 * Examples:
 *   node scripts/check-top-advisories.js ghp_xxx
 *   node scripts/check-top-advisories.js ghp_xxx NPM 10
 *   node scripts/check-top-advisories.js ghp_xxx PIP 5
 */

const [,, token, ecosystem = 'NPM', countStr = '10'] = process.argv;

if (!token) {
  console.error('Usage: node scripts/check-top-advisories.js <GITHUB_TOKEN> [ecosystem] [count]');
  process.exit(1);
}

const count = parseInt(countStr, 10);

async function query(body) {
  const res = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      Authorization: `bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: body }),
  });
  const json = await res.json();
  if (json.errors) throw new Error(JSON.stringify(json.errors, null, 2));
  return json.data;
}

(async () => {
  const data = await query(`
    {
      securityVulnerabilities(
        first: ${count},
        ecosystem: ${ecosystem},
        orderBy: { field: UPDATED_AT, direction: DESC }
      ) {
        nodes {
          severity
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          package { name }
          advisory { ghsaId summary publishedAt }
        }
      }
    }
  `);

  const nodes = data.securityVulnerabilities.nodes;
  console.log(`\nTop ${nodes.length} most recently updated ${ecosystem} advisories:\n`);
  nodes.forEach((v, i) => {
    console.log(`[${i + 1}] ${v.package.name}`);
    console.log(`    GHSA:      ${v.advisory.ghsaId}`);
    console.log(`    Severity:  ${v.severity}`);
    console.log(`    Range:     ${v.vulnerableVersionRange}`);
    console.log(`    Fixed in:  ${v.firstPatchedVersion?.identifier ?? 'no fix yet'}`);
    console.log(`    Published: ${v.advisory.publishedAt}`);
    console.log(`    Summary:   ${v.advisory.summary}`);
    console.log();
  });
})().catch(e => { console.error(e.message); process.exit(1); });
