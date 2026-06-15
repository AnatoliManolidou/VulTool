import * as core from '@actions/core';
import * as github from '@actions/github';

export async function getRepositoryDependencies(token: string): Promise<string[]> {
  const octokit = github.getOctokit(token);
  // github.context automatically knows exactly which repo the action is running inside!
  const { owner, repo } = github.context.repo; 
  const packageNames = new Set<string>(); // A Set automatically prevents duplicates

  try {
    core.info(`Component 3: Waking up Dependency Mapper for ${owner}/${repo}...`);

    // GraphQL query to fetch the repository's native Dependency Graph
    const query = `
      query($owner: String!, $repo: String!) {
        repository(owner: $owner, name: $repo) {
          dependencyGraphManifests(first: 50) {
            nodes {
              filename
              dependencies(first: 100) {
                nodes {
                  packageName
                }
              }
            }
          }
        }
      }
    `;

    const response: any = await octokit.graphql(query, {
      owner,
      repo,
      headers: {
        accept: 'application/vnd.github.hawkgirl-preview+json' // Required header for this specific API
      }
    });

    const manifests = response.repository?.dependencyGraphManifests?.nodes || [];

    // Loop through files like package.json and extract the package names
    for (const manifest of manifests) {
      if (manifest.dependencies && manifest.dependencies.nodes) {
        for (const dep of manifest.dependencies.nodes) {
          packageNames.add(dep.packageName.toLowerCase());
        }
      }
    }

    const depsArray = Array.from(packageNames);
    core.info(`Mapped ${depsArray.length} unique dependencies natively from GitHub.`);
    return depsArray;

  } catch (error) {
    if (error instanceof Error) {
      core.warning(`Dependency Mapper couldn't read the graph: ${error.message}`);
      core.warning(`Note: Ensure "Dependency Graph" is enabled in your dummy repo's Settings > Code Security.`);
    }
    return [];
  }
}