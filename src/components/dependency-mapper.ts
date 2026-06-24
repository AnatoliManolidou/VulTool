import * as core from '@actions/core';
import * as github from '@actions/github';

/**
 * Returns a lowercased list of every package name in the repository's
 * dependency graph, sourced exclusively from the GitHub Dependency Graph API.
 *
 * Returns null on hard failure (API down, Dependency Graph disabled) so the
 * pipeline can halt rather than producing false negatives.
 */
export async function getRepositoryDependencies(
  token: string,
  workspacePath: string
): Promise<string[] | null> {
  const packageNames = new Set<string>();
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;

  try {
    core.info(`Component 3: Waking up Dependency Mapper for ${owner}/${repo}...`);

    const query = `
      query($owner: String!, $repo: String!) {
        repository(owner: $owner, name: $repo) {
          dependencyGraphManifests(first: 50) {
            nodes {
              filename
              dependencies(first: 100) {
                nodes { packageName }
              }
            }
          }
        }
      }
    `;

    const response: any = await octokit.graphql(query, {
      owner,
      repo,
      headers: { accept: 'application/vnd.github.hawkgirl-preview+json' },
    });

    const manifests = response.repository?.dependencyGraphManifests?.nodes ?? [];
    for (const manifest of manifests) {
      for (const dep of manifest.dependencies?.nodes ?? []) {
        if (dep.packageName) packageNames.add(dep.packageName.toLowerCase());
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
