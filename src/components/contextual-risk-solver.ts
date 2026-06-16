import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

export function assessContextualRisk(threats: any[], workspacePath: string, ecosystems: string[]): any[] {
  core.info('Component 5: Waking up Contextual Risk Solver...');

  const devDependencies = new Set<string>();

  try {
    // Dynamically parse dev dependencies based on the ecosystems detected in Component 1
    if (ecosystems.includes('npm')) {
      const pkgPath = path.join(workspacePath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        Object.keys(pkg.devDependencies || {}).forEach(dep => devDependencies.add(dep.toLowerCase()));
      }
    }

    if (ecosystems.includes('pip')) {
      // Python typically separates dev tools into requirements-dev.txt
      const reqDevPath = path.join(workspacePath, 'requirements-dev.txt');
      if (fs.existsSync(reqDevPath)) {
        const content = fs.readFileSync(reqDevPath, 'utf8');
        content.split('\n').forEach(line => {
          const cleanName = line.split(/[=<>~]/)[0].trim().toLowerCase();
          if (cleanName) devDependencies.add(cleanName);
        });
      }
    }
    
    // As you expand to Go, Rust, etc., you just add their specific parser blocks here.

  } catch (e) {
    core.warning('Could not parse local manifests for context assessment. Defaulting to HIGH risk for all threats.\n');
  }

  const assessedThreats = threats.map(threat => {
    const isDev = devDependencies.has(threat.packageName.toLowerCase());
    
    // If we can prove it is a dev dependency, reduce the risk. Otherwise, assume it is in production.
    const contextTag = isDev ? 'REDUCED RISK (Dev Environment)' : 'HIGH RISK (Production Environment)';
    
    return {
      ...threat,
      contextualRisk: contextTag,
      isDevDependency: isDev
    };
  });

  core.info(`Assessed context for ${assessedThreats.length} verified threats.`);
  
  // Print the first assessed threat to prove it worked
  if (assessedThreats.length > 0) {
      core.info(`Context Result: ${assessedThreats[0].packageName} ➔ ${assessedThreats[0].contextualRisk}\n`);
  }

  return assessedThreats;
}