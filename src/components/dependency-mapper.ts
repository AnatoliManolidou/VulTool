import * as core from '@actions/core';
import * as github from '@actions/github';

/**
 * Returns a lowercased list of every package in the repository's dependency
 * graph, sourced exclusively from the GitHub Dependency Graph API.
 *
 * Manifests are fully paginated — there is no cap on how many manifest files
 * are processed. Each manifest returns up to 100 dependencies per page.
 * The GitHub preview API does not expose node IDs on manifest objects, so
 * per-manifest dep pagination beyond 100 is not possible without a separate
 * API (e.g. the SBOM export endpoint). In practice this limit is only hit by
 * very large lock files in monorepos; for all standard repos the full dep
 * list is returned.
 *
 * Returns null on hard failure so the pipeline halts rather than producing
 * false negatives.
 */
export async function getRepositoryDependencies(token: string): Promise<string[] | null> {
  const packageNames = new Set<string>();
  const octokit     = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  const HEADERS = { accept: 'application/vnd.github.hawkgirl-preview+json' };

  try {
    core.info(`Component 3: Waking up Dependency Mapper for ${owner}/${repo}...`);

    let manifestCursor: string | null = null;
    let hasMoreManifests              = true;
    let manifestCount                 = 0;

    while (hasMoreManifests) {
      const res: any = await octokit.graphql(
        `query($owner: String!, $repo: String!, $after: String) {
          repository(owner: $owner, name: $repo) {
            dependencyGraphManifests(first: 50, after: $after) {
              pageInfo { hasNextPage endCursor }
              nodes {
                filename
                dependencies(first: 100) {
                  pageInfo { hasNextPage }
                  nodes { packageName }
                }
              }
            }
          }
        }`,
        { owner, repo, after: manifestCursor, headers: HEADERS }
      );

      const page = res.repository.dependencyGraphManifests;

      for (const manifest of page.nodes) {
        manifestCount++;
        const deps = manifest.dependencies;

        for (const dep of deps?.nodes ?? []) {
          if (dep.packageName) packageNames.add(dep.packageName.toLowerCase());
        }

        if (deps?.pageInfo?.hasNextPage) {
          core.warning(
            `  ${manifest.filename} has more than 100 dependencies — additional entries truncated. ` +
            `Consider generating a repo SBOM for complete coverage on large monorepos.`
          );
        }
      }

      hasMoreManifests = page.pageInfo.hasNextPage;
      manifestCursor   = page.pageInfo.endCursor;
    }

    const depsArray = Array.from(packageNames);
    core.info(`Mapped ${depsArray.length} unique dependencies across ${manifestCount} manifest(s).`);
    return depsArray;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Dependency Mapper failed: ${error.message}`);
    }
    return null;
  }
}
