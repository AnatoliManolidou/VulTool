import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

/**
 * Reads package-lock.json and returns a map of lowercased package name → resolved version.
 * Supports lockfile v1 (npm 6) and v2/v3 (npm 7+).
 * Returns an empty map if no lockfile is found or parsing fails.
 */
export function readNpmInstalledVersions(workspacePath: string): Map<string, string> {
  const versions = new Map<string, string>();
  const lockfilePath = path.join(workspacePath, 'package-lock.json');

  if (!fs.existsSync(lockfilePath)) {
    core.info('  No package-lock.json found — version range check skipped for npm.');
    return versions;
  }

  try {
    const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));

    if (lockfile.packages) {
      // v2 / v3: keys are "node_modules/pkg" or "node_modules/@scope/pkg"
      for (const [key, pkg] of Object.entries(lockfile.packages as Record<string, any>)) {
        if (!key || !pkg?.version) continue;
        const name = key.replace(/^node_modules\//, '');
        versions.set(name.toLowerCase(), pkg.version);
      }
    } else if (lockfile.dependencies) {
      // v1: keys are plain package names
      for (const [name, pkg] of Object.entries(lockfile.dependencies as Record<string, any>)) {
        if (pkg?.version) versions.set(name.toLowerCase(), pkg.version);
      }
    }

    core.info(`  Lockfile parsed: ${versions.size} resolved npm versions loaded.`);
  } catch (err) {
    core.warning(`  Failed to parse package-lock.json: ${err instanceof Error ? err.message : String(err)}`);
  }

  return versions;
}
