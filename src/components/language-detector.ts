import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export async function detectEcosystems(workspacePath: string): Promise<{ ecosystems: string[], hasSbom: boolean }> {
  const ecosystems: string[] = [];
  let hasSbom = false;

  try {
    core.info(`Component 1: Scanning workspace: ${workspacePath}`);

    // SBOM detection
    const sbomSignatures = ['sbom.json', 'bom.xml', 'cyclonedx.json', 'spdx.json', 'spdx.yaml', 'bom.json'];
    for (const sbom of sbomSignatures) {
      if (fs.existsSync(path.join(workspacePath, sbom))) {
        core.info(`Found SBOM file: ${sbom}`);
        hasSbom = true;
        break;
      }
    }

    if (!hasSbom) {
      core.info('No local SBOM file detected. Pipeline will rely entirely on GitHub Dependency Graph.');
    }

    // Fixed-filename ecosystem signatures
    const signatures = [
      // npm / Node.js
      { file: 'package.json',       ecosystem: 'npm'      },
      // Python
      { file: 'requirements.txt',   ecosystem: 'pip'      },
      { file: 'Pipfile',            ecosystem: 'pip'      },
      { file: 'poetry.lock',        ecosystem: 'pip'      },
      { file: 'pyproject.toml',     ecosystem: 'pip'      },
      // Ruby
      { file: 'Gemfile',            ecosystem: 'rubygems' },
      // Rust
      { file: 'Cargo.toml',         ecosystem: 'crates'   },
      // Go
      { file: 'go.mod',             ecosystem: 'go'       },
      // Java / Maven
      { file: 'pom.xml',            ecosystem: 'maven'    },
      { file: 'build.gradle',       ecosystem: 'maven'    },
      { file: 'build.gradle.kts',   ecosystem: 'maven'    },
      // PHP / Composer
      { file: 'composer.json',      ecosystem: 'composer' },
      // Swift
      { file: 'Package.swift',      ecosystem: 'swift'    },
      // Dart / Flutter
      { file: 'pubspec.yaml',       ecosystem: 'pub'      },
      // Elixir / Erlang
      { file: 'mix.exs',            ecosystem: 'erlang'   },
      { file: 'rebar.config',       ecosystem: 'erlang'   },
      // NuGet (packages.config — fixed filename variant)
      { file: 'packages.config',    ecosystem: 'nuget'    },
    ];

    for (const sig of signatures) {
      const fullPath = path.join(workspacePath, sig.file);
      if (fs.existsSync(fullPath)) {
        core.info(`Found signature file: ${sig.file} -> Target Ecosystem: ${sig.ecosystem}`);
        if (!ecosystems.includes(sig.ecosystem)) {
          ecosystems.push(sig.ecosystem);
        }
      }
    }

    // NuGet: also scan root for *.csproj (no fixed filename)
    if (!ecosystems.includes('nuget')) {
      try {
        const rootEntries = fs.readdirSync(workspacePath);
        if (rootEntries.some(f => f.endsWith('.csproj'))) {
          core.info('Found .csproj file -> Target Ecosystem: nuget');
          ecosystems.push('nuget');
        }
      } catch { /* non-critical */ }
    }

    // Actions: detect if the repo has any GitHub Actions workflow files
    const workflowsDir = path.join(workspacePath, '.github', 'workflows');
    if (fs.existsSync(workflowsDir)) {
      try {
        const workflowFiles = fs.readdirSync(workflowsDir);
        if (workflowFiles.some(f => f.endsWith('.yml') || f.endsWith('.yaml'))) {
          core.info('Found GitHub Actions workflow files -> Target Ecosystem: actions');
          ecosystems.push('actions');
        }
      } catch { /* non-critical */ }
    }

    if (ecosystems.length === 0) {
      core.notice('No recognizable package manager files found. Pipeline halting safely.');
    }

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Language detection failed: ${error.message}`);
    }
  }

  return { ecosystems, hasSbom };
}
