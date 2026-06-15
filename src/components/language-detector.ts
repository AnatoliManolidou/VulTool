import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export async function detectEcosystems(workspacePath: string): Promise<string[]> {
  const ecosystems: string[] = [];
  
  try {
    core.info(`Scanning workspace: ${workspacePath}`);

    // The universal list of ecosystem signatures
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
        
        // Prevent duplicates (e.g., if both requirements.txt and Pipfile exist)
        if (!ecosystems.includes(sig.ecosystem)) {
          ecosystems.push(sig.ecosystem);
        }
      }
    }

    if (ecosystems.length === 0) {
      core.notice('No recognizable package manager files found in root directory. Pipeline halting safely.');
      // We return the empty array. The Orchestrator will see this and stop.
    }
    
  } catch (error) {
    if (error instanceof Error) {
      core.error(`Language detection failed: ${error.message}`);
    }
    // Safe fallback to keep the pipeline alive
    ecosystems.push('npm');
  }
  
  return ecosystems;
}