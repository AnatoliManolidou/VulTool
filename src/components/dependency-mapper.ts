import * as core from '@actions/core';
import * as github from '@actions/github';

const PURL_TYPE_MAP: Record<string, string> = {
  npm:      'npm',
  pypi:     'pip',
  gem:      'rubygems',
  cargo:    'crates',
  golang:   'go',
  maven:    'maven',
  composer: 'composer',
  swift:    'swift',
  pub:      'pub',
  hex:      'erlang',
  nuget:    'nuget',
};

// PURL format: pkg:type/[namespace/]name@version
// Scoped npm packages are URL-encoded: pkg:npm/%40scope%2Fpkg@1.0.0 → @scope/pkg
// Maven: groupId/artifactId in PURL becomes groupId:artifactId to match advisory format
function parsePurl(purl: string): { name: string; version: string } | null {
  if (!purl.startsWith('pkg:')) return null;

  const firstSlash = purl.indexOf('/');
  const lastAt     = purl.lastIndexOf('@');
  if (firstSlash === -1 || lastAt === -1 || lastAt <= firstSlash) return null;

  const purlType    = purl.slice(4, firstSlash).toLowerCase();
  const rawNamePath = purl.slice(firstSlash + 1, lastAt);
  const version     = purl.slice(lastAt + 1);

  if (!version || !PURL_TYPE_MAP[purlType]) return null;

  let name = decodeURIComponent(rawNamePath);

  // Maven advisories use "groupId:artifactId"; PURLs use "groupId/artifactId".
  if (purlType === 'maven' && name.includes('/')) {
    name = name.replace('/', ':');
  }

  return { name: name.toLowerCase(), version };
}

// Uses the SBOM endpoint instead of the GraphQL Dependency Graph: the GraphQL preview
// API caps results at 100 packages per manifest with no pagination path (manifest
// objects omit node IDs in the preview schema, making cursor-based pagination impossible).
// Returns null on failure — the pipeline halts rather than producing false negatives.
// ⚠ This sync endpoint is deprecated and scheduled for removal on 2026-11-13.
export async function getRepositoryDependencies(
  token: string
): Promise<Map<string, string> | null> {
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  try {
    core.info(`Component 3: Waking up Dependency Mapper for ${owner}/${repo}...`);
    core.info('  Source: GitHub Dependency Graph SBOM export');

    const response = await octokit.request(
      'GET /repos/{owner}/{repo}/dependency-graph/sbom',
      {
        owner,
        repo,
        headers: { 'X-GitHub-Api-Version': '2022-11-28' },
      }
    );

    const packages: any[] = (response.data as any).sbom?.packages ?? [];
    const installedPackages = new Map<string, string>();

    for (const pkg of packages) {
      // Each real dependency has at least one PURL in its externalRefs.
      // The root entry (the repository itself) has no PURL and is skipped.
      const purl = pkg.externalRefs?.find(
        (ref: any) => ref.referenceType === 'purl'
      )?.referenceLocator as string | undefined;

      if (!purl) continue;

      const parsed = parsePurl(purl);
      if (!parsed) continue;

      installedPackages.set(parsed.name, parsed.version);
    }

    core.info(`  Mapped ${installedPackages.size} installed package(s) across all ecosystems.`);
    return installedPackages;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Dependency Mapper failed: ${error.message}`);
    }
    return null;
  }
}
