import * as core from '@actions/core';
import * as github from '@actions/github';

/**
 * Returns a lowercased list of every package name in the repository's
 * dependency graph, sourced exclusively from the GitHub Dependency Graph API.
 *
 * Both manifests and per-manifest dependencies are fully paginated — there is
 * no cap on the number of dependencies returned.
 *
 * Returns null on hard failure (API down, Dependency Graph disabled) so the
 * pipeline can halt rather than producing false negatives.
 */
export async function getRepositoryDependencies(token: string): Promise<string[] | null> {
  const packageNames = new Set<string>();
  const octokit     = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  try {
    core.info(`Component 3: Waking up Dependency Mapper for ${owner}/${repo}...`);

    // --- Pass 1: fetch all manifests (paginated) + first 100 deps per manifest ---
    // We also collect the manifest node ID and dep cursor for any manifest that
    // has more than 100 deps, so we can page through the rest in Pass 2.

    const MANIFEST_QUERY = `
      query($owner: String!, $repo: String!, $after: String) {
        repository(owner: $owner, name: $repo) {
          dependencyGraphManifests(first: 50, after: $after) {
            pageInfo { hasNextPage endCursor }
            nodes {
              id
              filename
              dependencies(first: 100) {
                pageInfo { hasNextPage endCursor }
                nodes { packageName }
              }
            }
          }
        }
      }
    `;

    // manifests that need further dep pagination: { id, depCursor }
    const overflow: Array<{ id: string; depCursor: string }> = [];

    let manifestCursor: string | null = null;
    let hasMoreManifests = true;

    while (hasMoreManifests) {
      const res: any = await octokit.graphql(MANIFEST_QUERY, {
        owner, repo,
        after: manifestCursor,
        headers: { accept: 'application/vnd.github.hawkgirl-preview+json' },
      });

      const page = res.repository.dependencyGraphManifests;

      for (const manifest of page.nodes) {
        for (const dep of manifest.dependencies?.nodes ?? []) {
          if (dep.packageName) packageNames.add(dep.packageName.toLowerCase());
        }

        if (manifest.dependencies?.pageInfo?.hasNextPage) {
          overflow.push({
            id:        manifest.id,
            depCursor: manifest.dependencies.pageInfo.endCursor,
          });
        }
      }

      hasMoreManifests = page.pageInfo.hasNextPage;
      manifestCursor   = page.pageInfo.endCursor;
    }

    // --- Pass 2: page through remaining deps for any oversized manifests ---
    if (overflow.length > 0) {
      core.info(`  ${overflow.length} manifest(s) have >100 deps — paginating the remainder...`);

      const DEP_QUERY = `
        query($id: ID!, $after: String) {
          node(id: $id) {
            ... on DependencyGraphManifest {
              dependencies(first: 100, after: $after) {
                pageInfo { hasNextPage endCursor }
                nodes { packageName }
              }
            }
          }
        }
      `;

      for (const { id, depCursor: firstCursor } of overflow) {
        let depCursor: string | null = firstCursor;

        while (depCursor) {
          const res: any = await octokit.graphql(DEP_QUERY, { id, after: depCursor });
          const depPage  = res.node?.dependencies;

          for (const dep of depPage?.nodes ?? []) {
            if (dep.packageName) packageNames.add(dep.packageName.toLowerCase());
          }

          depCursor = depPage?.pageInfo?.hasNextPage ? depPage.pageInfo.endCursor : null;
        }
      }
    }

    const depsArray = Array.from(packageNames);
    core.info(`Mapped ${depsArray.length} unique dependencies from GitHub Dependency Graph.`);
    return depsArray;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Dependency Mapper failed: ${error.message}`);
    }
    return null;
  }
}
