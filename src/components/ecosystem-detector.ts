import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export function detectEcosystems(workspacePath: string): { ecosystems: string[] } {
  const ecosystems: string[] = [];

  try {
    core.info('Component 1: Waking up Ecosystem Detector...');
    core.info(`Scanning workspace: ${workspacePath}`);

    const signatures = [
      { file: 'package.json',     ecosystem: 'npm'      },
      { file: 'requirements.txt', ecosystem: 'pip'      },
      { file: 'Pipfile',          ecosystem: 'pip'      },
      { file: 'poetry.lock',      ecosystem: 'pip'      },
      { file: 'pyproject.toml',   ecosystem: 'pip'      },
      { file: 'Gemfile',          ecosystem: 'rubygems' },
      { file: 'Cargo.toml',       ecosystem: 'crates'   },
      { file: 'go.mod',           ecosystem: 'go'       },
      { file: 'pom.xml',          ecosystem: 'maven'    },
      { file: 'build.gradle',     ecosystem: 'maven'    },
      { file: 'build.gradle.kts', ecosystem: 'maven'    },
      { file: 'composer.json',    ecosystem: 'composer' },
      { file: 'Package.swift',    ecosystem: 'swift'    },
      { file: 'pubspec.yaml',     ecosystem: 'pub'      },
      { file: 'mix.exs',          ecosystem: 'erlang'   },
      { file: 'rebar.config',     ecosystem: 'erlang'   },
      { file: 'packages.config',  ecosystem: 'nuget'    },
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

    // .csproj has no fixed filename — scan root directory for any .csproj file
    if (!ecosystems.includes('nuget')) {
      try {
        const rootEntries = fs.readdirSync(workspacePath);
        if (rootEntries.some(f => f.endsWith('.csproj'))) {
          core.info('Found .csproj file -> Target Ecosystem: nuget');
          ecosystems.push('nuget');
        }
      } catch { /* non-critical */ }
    }

    if (ecosystems.length === 0) {
      core.notice('No recognizable package manager files found. Pipeline halting safely.');
    }

  } catch (error) {
    if (error instanceof Error) {
      core.error(`Ecosystem detection failed: ${error.message}`);
    }
  }

  return { ecosystems };
}
