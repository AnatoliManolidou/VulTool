import * as core from '@actions/core';
import * as github from '@actions/github';

// Maps PURL ecosystem type identifiers to our internal ecosystem names.
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

/**
 * Parses a Package URL (PURL) and returns the normalized package name and
 * installed version.
 *
 * PURL format: pkg:type/[namespace/]name@version
 *
 * Examples:
 *   pkg:npm/lodash@4.17.21
 *     → { name: "lodash", version: "4.17.21" }
 *   pkg:npm/%40merill%2Flokka@2.0.0
 *     → { name: "@merill/lokka", version: "2.0.0" }
 *   pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0
 *     → { name: "com.fasterxml.jackson.core:jackson-databind", version: "2.14.0" }
 */
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

/**
 * Exports the GitHub-generated SBOM for the repository and returns a map of
 * lowercased package name → installed version.
 *
 * GitHub generates the SBOM on demand from the same dependency graph data as
 * the GraphQL preview API, but returns every installed package across all
 * manifests with no per-manifest truncation. This replaces the previous
 * GraphQL approach which was hard-capped at 100 deps per manifest and had no
 * pagination path due to the preview API omitting node IDs on manifest objects.
 *
 * Requires the GitHub Dependency Graph to be enabled for the repository.
 * Returns null on hard failure so the pipeline halts rather than producing
 * false negatives.
 */
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
