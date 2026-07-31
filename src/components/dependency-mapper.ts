import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';

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

// Parses package-lock.json from the workspace to catch npm packages that are on the
// current branch but not yet reflected in the GitHub Dependency Graph (which always
// reads the default branch). Supports lockfile v1 (dependencies) and v2/v3 (packages).
function parseLocalNpmPackages(workspacePath: string): Map<string, string> {
  const result: Map<string, string> = new Map();
  const lockfilePath = path.join(workspacePath, 'package-lock.json');

  if (!fs.existsSync(lockfilePath)) return result;

  try {
    const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));

    if (lockfile.packages) {
      for (const [key, value] of Object.entries(lockfile.packages as Record<string, any>)) {
        if (key === '') continue;
        // Strip leading "node_modules/" segments (handles nested hoisting paths)
        const name = key.replace(/^(?:.*node_modules\/)/, '').toLowerCase();
        if (value.version) result.set(name, value.version as string);
      }
    } else if (lockfile.dependencies) {
      for (const [name, value] of Object.entries(lockfile.dependencies as Record<string, any>)) {
        if ((value as any).version) result.set(name.toLowerCase(), (value as any).version as string);
      }
    }
  } catch { /* malformed lockfile — skip */ }

  return result;
}

// Uses the SBOM endpoint instead of the GraphQL Dependency Graph: the GraphQL preview
// API caps results at 100 packages per manifest with no pagination path (manifest
// objects omit node IDs in the preview schema, making cursor-based pagination impossible).
// Returns null on failure — the pipeline halts rather than producing false negatives.
// ⚠ This sync endpoint is deprecated and scheduled for removal on 2026-11-13.
export async function getRepositoryDependencies(
  token: string,
  workspacePath: string,
): Promise<Map<string, string> | null> {
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  try {
    core.info(`Component 3: Waking up Dependency Mapper for ${owner}/${repo}...`);
    core.info('  Source: GitHub Dependency Graph SBOM (cross-ecosystem) + local workspace lockfiles (current branch)');

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

    // Merge local lockfile — covers npm packages on the current branch that the
    // SBOM hasn't indexed yet (SBOM always reflects the default branch).
    const localPackages = parseLocalNpmPackages(workspacePath);
    let localOnly = 0;
    for (const [name, version] of localPackages) {
      if (!installedPackages.has(name)) localOnly++;
      installedPackages.set(name, version);
    }

    core.info(`  Mapped ${installedPackages.size} installed package(s) (${localOnly} npm package(s) added from local workspace lockfile).`);
    return installedPackages;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Dependency Mapper failed: ${error.message}`);
    }
    return null;
  }
}
