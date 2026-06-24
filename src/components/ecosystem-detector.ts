import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export async function detectEcosystems(workspacePath: string): Promise<{ ecosystems: string[] }> {
  const ecosystems: string[] = [];

  try {
    core.info(`Component 1: Waking up Ecosystem Detector...`);
    core.info(`Scanning workspace: ${workspacePath}`);

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
