import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';
import * as github from '@actions/github';

export async function getRepositoryDependencies(
  token: string, 
  hasSbom: boolean, 
  workspacePath: string
): Promise<string[] | null> { // <-- UPDATED TYPE: Can now return null
  const packageNames = new Set<string>();

  // STRATEGY A: Local SBOM Parsing
  if (hasSbom) {
    core.info('Component 3: Local SBOM detected. Parsing local file for dependency mapping...');
    try {
      const sbomFiles = ['sbom.json', 'cyclonedx.json', 'spdx.json', 'bom.json'];
      let sbomData: any = null;

      for (const file of sbomFiles) {
        const fullPath = path.join(workspacePath, file);
        if (fs.existsSync(fullPath)) {
          core.info(`Reading SBOM target: ${file}`);
          sbomData = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
          break;
        }
      }

      if (sbomData) {
        if (sbomData.components && Array.isArray(sbomData.components)) {
          sbomData.components.forEach((comp: any) => {
            if (comp.name) packageNames.add(comp.name.toLowerCase());
          });
        } 
        else if (sbomData.packages && Array.isArray(sbomData.packages)) {
          sbomData.packages.forEach((pkg: any) => {
            if (pkg.name) packageNames.add(pkg.name.toLowerCase());
          });
        }
        
        const depsArray = Array.from(packageNames);
        core.info(`Mapped ${depsArray.length} unique dependencies directly from local SBOM.`);
        return depsArray;
      }
    } catch (error) {
      if (error instanceof Error) {
        core.warning(`Failed to parse local SBOM: ${error.message}. Falling back to GitHub API.`);
      }
    }
  }

  // STRATEGY B: Fallback to GitHub Dependency Graph API
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo; 

  try {
    core.info(`Component 3: Waking up Dependency Mapper API fallback for ${owner}/${repo}...`);

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
        accept: 'application/vnd.github.hawkgirl-preview+json'
      }
    });

    const manifests = response.repository?.dependencyGraphManifests?.nodes || [];

    for (const manifest of manifests) {
      if (manifest.dependencies && manifest.dependencies.nodes) {
        for (const dep of manifest.dependencies.nodes) {
          packageNames.add(dep.packageName.toLowerCase());
        }
      }
    }

    const depsArray = Array.from(packageNames);
    core.info(`Mapped ${depsArray.length} unique dependencies natively from GitHub API.`);
    return depsArray;

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Dependency Mapper API Error: ${error.message}`);
    }
    return null; //Return null to flag a critical fallback failure
  }
}