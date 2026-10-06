import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { parseLocalNpmPackages } from '../src/components/dependency-mapper';

function makeTempWorkspace(files: Record<string, string>): { dir: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'depmap-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

describe('parseLocalNpmPackages', () => {
  test('lockfile v2/v3 format: top-level package resolves to its own version', () => {
    const lockfile = {
      lockfileVersion: 3,
      packages: {
        '':                      { name: 'app' },
        'node_modules/js-yaml':  { version: '4.1.0' },
      },
    };
    const { dir, cleanup } = makeTempWorkspace({
      'package-lock.json': JSON.stringify(lockfile),
    });
    try {
      const result = parseLocalNpmPackages(dir);
      expect(result.get('js-yaml')).toBe('4.1.0');
    } finally { cleanup(); }
  });

  // Regression test for the actual bug found in Dummy's real package-lock.json: js-yaml
  // resolved to 3.15.2 instead of the direct dependency's 4.1.0, because two dev-tooling
  // packages (bundled under @istanbuljs and svgo) carry their own nested copy at an older
  // version, and "svgo" sorts alphabetically after the top-level "node_modules/js-yaml" key
  // — so naive last-write-wins iteration picked the nested copy over the direct dependency.
  test('nested copy at a different version does not override the top-level resolution', () => {
    const lockfile = {
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/@eslint/eslintrc/node_modules/js-yaml':         { version: '4.2.0' },
        'node_modules/@istanbuljs/load-nyc-config/node_modules/js-yaml': { version: '3.15.2' },
        'node_modules/eslint/node_modules/js-yaml':                    { version: '4.2.0' },
        'node_modules/js-yaml':                                        { version: '4.1.0' },
        'node_modules/svgo/node_modules/js-yaml':                      { version: '3.15.2' },
      },
    };
    const { dir, cleanup } = makeTempWorkspace({
      'package-lock.json': JSON.stringify(lockfile),
    });
    try {
      const result = parseLocalNpmPackages(dir);
      expect(result.get('js-yaml')).toBe('4.1.0');
    } finally { cleanup(); }
  });

  test('package with no top-level resolution falls back to the shallowest nested one', () => {
    const lockfile = {
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/parent-a/node_modules/leftpad':               { version: '1.0.0' },
        'node_modules/parent-b/node_modules/nested/node_modules/leftpad': { version: '2.0.0' },
      },
    };
    const { dir, cleanup } = makeTempWorkspace({
      'package-lock.json': JSON.stringify(lockfile),
    });
    try {
      const result = parseLocalNpmPackages(dir);
      // depth 2 (parent-a/.../leftpad) is shallower than depth 3 (parent-b/.../nested/.../leftpad)
      expect(result.get('leftpad')).toBe('1.0.0');
    } finally { cleanup(); }
  });

  test('lockfile v1 format: dependencies object', () => {
    const lockfile = {
      lockfileVersion: 1,
      dependencies: {
        'js-yaml': { version: '4.1.0' },
      },
    };
    const { dir, cleanup } = makeTempWorkspace({
      'package-lock.json': JSON.stringify(lockfile),
    });
    try {
      const result = parseLocalNpmPackages(dir);
      expect(result.get('js-yaml')).toBe('4.1.0');
    } finally { cleanup(); }
  });

  test('missing lockfile returns an empty map, does not throw', () => {
    const { dir, cleanup } = makeTempWorkspace({});
    try {
      expect(() => parseLocalNpmPackages(dir)).not.toThrow();
      expect(parseLocalNpmPackages(dir).size).toBe(0);
    } finally { cleanup(); }
  });

  test('malformed lockfile returns an empty map, does not throw', () => {
    const { dir, cleanup } = makeTempWorkspace({
      'package-lock.json': '{ not valid json',
    });
    try {
      expect(() => parseLocalNpmPackages(dir)).not.toThrow();
      expect(parseLocalNpmPackages(dir).size).toBe(0);
    } finally { cleanup(); }
  });
});
