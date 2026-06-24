import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

const SEVERITY_WEIGHTS: Record<string, number> = {
  'LOW':      1,
  'MODERATE': 2,
  'HIGH':     3,
  'CRITICAL': 4,
};

// Each extractor adds known dev-only package names (lowercase) to the set.
// Failures are isolated — one broken manifest doesn't affect others.

function extractNpmDevDeps(workspacePath: string, devDeps: Set<string>): void {
  const pkgPath = path.join(workspacePath, 'package.json');
  if (!fs.existsSync(pkgPath)) return;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    for (const dep of Object.keys(pkg.devDependencies || {})) {
      devDeps.add(dep.toLowerCase());
    }
  } catch { /* malformed JSON — skip */ }
}

function extractPipDevDeps(workspacePath: string, devDeps: Set<string>): void {
  // Requirements files: several naming conventions are in common use
  const devFiles = [
    'requirements-dev.txt',
    'dev-requirements.txt',
    path.join('requirements', 'dev.txt'),
    path.join('requirements', 'development.txt'),
    path.join('requirements', 'test.txt'),
  ];

  for (const rel of devFiles) {
    const fullPath = path.join(workspacePath, rel);
    if (!fs.existsSync(fullPath)) continue;
    try {
      for (const line of fs.readFileSync(fullPath, 'utf8').split('\n')) {
        const clean = line.split(/[=<>~!;]/)[0].trim().toLowerCase();
        if (clean && !clean.startsWith('#') && !clean.startsWith('-')) {
          devDeps.add(clean);
        }
      }
    } catch { /* skip */ }
  }

  // pyproject.toml — Poetry dev-dependencies (both old and new group syntax)
  const pyprojectPath = path.join(workspacePath, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const lines = fs.readFileSync(pyprojectPath, 'utf8').split('\n');
      let inDevSection = false;
      for (const line of lines) {
        const trimmed = line.trim();
        if (
          trimmed === '[tool.poetry.dev-dependencies]' ||
          trimmed === '[tool.poetry.group.dev.dependencies]'
        ) {
          inDevSection = true;
          continue;
        }
        if (inDevSection && trimmed.startsWith('[')) {
          inDevSection = false;
        }
        if (inDevSection && trimmed.includes('=')) {
          const name = trimmed.split('=')[0].trim().toLowerCase();
          if (name && !name.startsWith('#')) devDeps.add(name);
        }
      }
    } catch { /* skip */ }
  }
}

function extractRubyDevDeps(workspacePath: string, devDeps: Set<string>): void {
  const gemfilePath = path.join(workspacePath, 'Gemfile');
  if (!fs.existsSync(gemfilePath)) return;
  try {
    const lines = fs.readFileSync(gemfilePath, 'utf8').split('\n');
    let inDevGroup = false;
    let depth = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      // Detect group :development or group :test (may include both)
      if (/^group\s+.*(:(development|test))/.test(trimmed) && trimmed.endsWith('do')) {
        inDevGroup = true;
        depth = 1;
        continue;
      }
      if (inDevGroup) {
        if (trimmed.endsWith('do')) depth++;
        if (trimmed === 'end') {
          depth--;
          if (depth === 0) { inDevGroup = false; continue; }
        }
        const match = trimmed.match(/^gem\s+['"]([^'"]+)['"]/);
        if (match) devDeps.add(match[1].toLowerCase());
      }
    }
  } catch { /* skip */ }
}

function extractCargoDevDeps(workspacePath: string, devDeps: Set<string>): void {
  const cargoPath = path.join(workspacePath, 'Cargo.toml');
  if (!fs.existsSync(cargoPath)) return;
  try {
    const lines = fs.readFileSync(cargoPath, 'utf8').split('\n');
    let inDevDeps = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[dev-dependencies]') { inDevDeps = true; continue; }
      if (inDevDeps && trimmed.startsWith('[')) { inDevDeps = false; }
      if (inDevDeps && trimmed.includes('=')) {
        const name = trimmed.split('=')[0].trim().toLowerCase();
        if (name && !name.startsWith('#')) devDeps.add(name);
      }
    }
  } catch { /* skip */ }
}

function extractMavenDevDeps(workspacePath: string, devDeps: Set<string>): void {
  const pomPath = path.join(workspacePath, 'pom.xml');
  if (!fs.existsSync(pomPath)) return;
  try {
    const content = fs.readFileSync(pomPath, 'utf8');
    // Match <dependency> blocks that contain <scope>test</scope>
    const depBlockRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match: RegExpExecArray | null;
    while ((match = depBlockRegex.exec(content)) !== null) {
      const block = match[1];
      if (!/<scope>\s*test\s*<\/scope>/i.test(block)) continue;
      const artifactMatch = block.match(/<artifactId>\s*([^<]+)\s*<\/artifactId>/);
      const groupMatch    = block.match(/<groupId>\s*([^<]+)\s*<\/groupId>/);
      if (artifactMatch) {
        const artifact = artifactMatch[1].trim().toLowerCase();
        devDeps.add(artifact);
        if (groupMatch) {
          // Advisory package names for Maven use groupId:artifactId format
          devDeps.add(`${groupMatch[1].trim().toLowerCase()}:${artifact}`);
        }
      }
    }
  } catch { /* skip */ }
}

function extractComposerDevDeps(workspacePath: string, devDeps: Set<string>): void {
  const composerPath = path.join(workspacePath, 'composer.json');
  if (!fs.existsSync(composerPath)) return;
  try {
    const pkg = JSON.parse(fs.readFileSync(composerPath, 'utf8'));
    for (const dep of Object.keys(pkg['require-dev'] || {})) {
      devDeps.add(dep.toLowerCase());
    }
  } catch { /* skip */ }
}

function extractNuGetDevDeps(workspacePath: string, devDeps: Set<string>): void {
  // packages.config: developmentDependency="true"
  const pkgConfigPath = path.join(workspacePath, 'packages.config');
  if (fs.existsSync(pkgConfigPath)) {
    try {
      const content = fs.readFileSync(pkgConfigPath, 'utf8');
      const regex = /<package\s[^>]*id="([^"]+)"[^>]*developmentDependency="true"[^>]*\/>/gi;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(content)) !== null) devDeps.add(m[1].toLowerCase());
    } catch { /* skip */ }
  }

  // .csproj files: PackageReference with <PrivateAssets>all</PrivateAssets>
  try {
    const rootEntries = fs.readdirSync(workspacePath);
    for (const entry of rootEntries) {
      if (!entry.endsWith('.csproj')) continue;
      try {
        const content = fs.readFileSync(path.join(workspacePath, entry), 'utf8');
        // Multi-line form
        const multiLine = /<PackageReference\s+Include="([^"]+)"[^>]*>([\s\S]*?)<\/PackageReference>/g;
        let m: RegExpExecArray | null;
        while ((m = multiLine.exec(content)) !== null) {
          if (/<PrivateAssets>\s*[Aa]ll\s*<\/PrivateAssets>/.test(m[2])) {
            devDeps.add(m[1].toLowerCase());
          }
        }
        // Self-closing form with PrivateAssets attribute
        const selfClosing = /<PackageReference\s+Include="([^"]+)"[^/]*PrivateAssets="[Aa]ll"[^/]*\/>/g;
        while ((m = selfClosing.exec(content)) !== null) devDeps.add(m[1].toLowerCase());
      } catch { /* skip this file */ }
    }
  } catch { /* skip */ }
}

function extractPubDevDeps(workspacePath: string, devDeps: Set<string>): void {
  const pubspecPath = path.join(workspacePath, 'pubspec.yaml');
  if (!fs.existsSync(pubspecPath)) return;
  try {
    const lines = fs.readFileSync(pubspecPath, 'utf8').split('\n');
    let inDevDeps = false;
    for (const line of lines) {
      if (line.startsWith('dev_dependencies:')) { inDevDeps = true; continue; }
      // Any non-indented line starts a new top-level key
      if (inDevDeps && line.length > 0 && !/^\s/.test(line)) { inDevDeps = false; }
      if (inDevDeps) {
        const match = line.match(/^\s+([\w-]+)\s*:/);
        if (match) devDeps.add(match[1].toLowerCase());
      }
    }
  } catch { /* skip */ }
}

function extractErlangDevDeps(workspacePath: string, devDeps: Set<string>): void {
  // mix.exs uses {: atom syntax to declare deps.
  // Dev/test deps are marked with `only: :test`, `only: [:dev]`, `only: [:dev, :test]` etc.
  const mixPath = path.join(workspacePath, 'mix.exs');
  if (!fs.existsSync(mixPath)) return;
  try {
    const lines = fs.readFileSync(mixPath, 'utf8').split('\n');
    for (const line of lines) {
      if (!line.includes('only:')) continue;
      const onlyMatch = line.match(/only:\s*(?:\[([^\]]+)\]|(:[\w]+))/);
      if (!onlyMatch) continue;
      const onlyValue = (onlyMatch[1] ?? onlyMatch[2] ?? '').toLowerCase();
      if (!onlyValue.includes(':dev') && !onlyValue.includes(':test')) continue;
      const nameMatch = line.match(/\{:(\w+)/);
      if (nameMatch) devDeps.add(nameMatch[1].toLowerCase());
    }
  } catch { /* skip */ }
}

export function classifyDeploymentContext(threats: any[], workspacePath: string, ecosystems: string[]): any[] {
  core.info('Component 5: Waking up Deployment Classifier...');

  const devDependencies = new Set<string>();

  // Each extractor is individually guarded — one failure doesn't block the others.
  if (ecosystems.includes('npm'))      extractNpmDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('pip'))      extractPipDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('rubygems')) extractRubyDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('crates'))   extractCargoDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('maven'))    extractMavenDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('composer')) extractComposerDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('nuget'))    extractNuGetDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('pub'))      extractPubDevDeps(workspacePath, devDependencies);
  if (ecosystems.includes('erlang'))   extractErlangDevDeps(workspacePath, devDependencies);
  // Go and Swift have no dev-dependency distinction — all deps treated as production

  core.info(`Identified ${devDependencies.size} dev-only packages across all ecosystems.`);

  const assessedThreats = threats.map(threat => {
    const isDev = devDependencies.has(threat.packageName?.toLowerCase());
    const contextTag = isDev
      ? 'REDUCED RISK (Dev Environment)'
      : 'HIGH RISK (Production Environment)';

    // Priority score: severity is the primary key, prod/dev is the tiebreaker.
    // CRITICAL prod = 45, CRITICAL dev = 40, HIGH prod = 35, HIGH dev = 30, ...
    const severityWeight = SEVERITY_WEIGHTS[threat.severity?.toUpperCase()] || 0;
    const priorityScore  = severityWeight * 10 + (isDev ? 0 : 5);

    return {
      ...threat,
      contextualRisk: contextTag,
      isDevDependency: isDev,
      priorityScore,
    };
  });

  core.info(`Assessed context for ${assessedThreats.length} verified threats.`);

  if (assessedThreats.length > 0) {
    core.info(`Top threat: ${assessedThreats[0].packageName} -> ${assessedThreats[0].contextualRisk}`);
  }

  return assessedThreats;
}
