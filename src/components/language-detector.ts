import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

// We updated the return type to an object containing both the ecosystems array AND the SBOM status
export async function detectEcosystems(workspacePath: string): Promise<{ ecosystems: string[], hasSbom: boolean }> {
  const ecosystems: string[] = [];
  let hasSbom = false;
  
  try {
    core.info(`Scanning workspace: ${workspacePath}`);

    // --- NEW: SBOM DETECTION ---
    const sbomSignatures = ['sbom.json', 'bom.xml', 'cyclonedx.json', 'spdx.json', 'spdx.yaml', 'bom.json'];
    for (const sbom of sbomSignatures) {
      if (fs.existsSync(path.join(workspacePath, sbom))) {
        core.info(`Found SBOM file: ${sbom}`);
        hasSbom = true;
        break; // Stop looking once we find one
      }
    }

    if (!hasSbom) {
      core.info('No local SBOM file detected. Pipeline will rely entirely on GitHub Dependency Graph.');
    }

    // --- EXISTING: ECOSYSTEM DETECTION ---
    const signatures = [
      { file: 'package.json', ecosystem: 'npm' },
      { file: 'requirements.txt', ecosystem: 'pip' },
      { file: 'Pipfile', ecosystem: 'pip' },
      { file: 'poetry.lock', ecosystem: 'pip' },
      { file: 'Gemfile', ecosystem: 'rubygems' },
      { file: 'Cargo.toml', ecosystem: 'crates' },
      { file: 'go.mod', ecosystem: 'go' }
    ];

    for (const sig of signatures) {
      const fullPath = path.join(workspacePath, sig.file);
      if (fs.existsSync(fullPath)) {
        core.info(`Found signature file: ${sig.file} ➔ Target Ecosystem: ${sig.ecosystem}`);
        if (!ecosystems.includes(sig.ecosystem)) {
          ecosystems.push(sig.ecosystem);
        }
      }
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