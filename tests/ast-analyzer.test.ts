import * as fs   from 'fs';
import * as os   from 'os';
import * as path from 'path';

import {
  analyzeCodeUsage,
  findSourceFiles,
  SOURCE_EXTENSIONS,
  EXCLUDED_DIRS,
  CodeSlice,
} from '../src/components/ast-analyzer';
import { Threat } from '../src/types';

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeTempWorkspace(files: Record<string, string>): { dir: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ast-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function makeThreat(packageName: string, overrides: Partial<Threat> = {}): Threat {
  return {
    ghsaId:                 'GHSA-test-xxxx-1234',
    summary:                `Test vulnerability in ${packageName}`,
    description:            null,
    cwes:                   [],
    cvss:                   null,
    severity:               'HIGH',
    packageName,
    vulnerableVersionRange: '< 1.0.0',
    firstPatchedVersion:    '1.0.0',
    ecosystem:              'npm',
    contextualRisk:         'production',
    isDevDependency:        false,
    priorityScore:          30,
    ...overrides,
  };
}

// ─── Section 1: findSourceFiles ──────────────────────────────────────────────

describe('findSourceFiles', () => {
  test('SOURCE_EXTENSIONS contains exactly the supported extensions', () => {
    const expected = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'];
    for (const ext of expected) expect(SOURCE_EXTENSIONS.has(ext)).toBe(true);
    expect(SOURCE_EXTENSIONS.size).toBe(expected.length);
  });

  test('EXCLUDED_DIRS contains all expected directories', () => {
    const expected = [
      'node_modules', '.git', 'dist', 'build', 'out',
      'coverage', '.next', '.nuxt', '.cache', '__pycache__',
    ];
    for (const d of expected) expect(EXCLUDED_DIRS.has(d)).toBe(true);
  });

  test('finds .js, .ts, .jsx, .tsx, .mjs, .cjs files recursively', () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/index.ts':    '// ts',
      'src/app.js':      '// js',
      'src/comp.jsx':    '// jsx',
      'src/comp.tsx':    '// tsx',
      'src/worker.mjs':  '// mjs',
      'src/loader.cjs':  '// cjs',
    });
    try {
      const files = findSourceFiles(dir);
      const names = files.map(f => path.basename(f));
      expect(names).toContain('index.ts');
      expect(names).toContain('app.js');
      expect(names).toContain('comp.jsx');
      expect(names).toContain('comp.tsx');
      expect(names).toContain('worker.mjs');
      expect(names).toContain('loader.cjs');
      expect(files).toHaveLength(6);
    } finally { cleanup(); }
  });

  test('ignores non-source extensions (.json, .md, .css, .py)', () => {
    const { dir, cleanup } = makeTempWorkspace({
      'package.json':  '{}',
      'README.md':     '# readme',
      'styles.css':    'body{}',
      'script.py':     'print()',
      'main.ts':       '// ts',
    });
    try {
      const files = findSourceFiles(dir);
      expect(files).toHaveLength(1);
      expect(path.basename(files[0])).toBe('main.ts');
    } finally { cleanup(); }
  });

  test('does not recurse into excluded directories', () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/real.ts':                   '// real',
      'node_modules/pkg/index.js':     '// node_modules',
      '.git/hooks/pre-commit.js':      '// git',
      'dist/bundle.js':                '// dist',
      'build/output.ts':               '// build',
      'out/compiled.js':               '// out',
      'coverage/report.js':            '// coverage',
      '.next/cache.js':                '// next',
      '.nuxt/gen.ts':                  '// nuxt',
      '.cache/loader.js':              '// cache',
      '__pycache__/compiled.js':       '// pycache',
    });
    try {
      const files = findSourceFiles(dir);
      expect(files).toHaveLength(1);
      expect(path.basename(files[0])).toBe('real.ts');
    } finally { cleanup(); }
  });

  test('returns empty array for an empty workspace', () => {
    const { dir, cleanup } = makeTempWorkspace({});
    try {
      expect(findSourceFiles(dir)).toEqual([]);
    } finally { cleanup(); }
  });

  test('returns empty array for a nonexistent path (does not throw)', () => {
    expect(() => findSourceFiles('/tmp/this-does-not-exist-xyz')).not.toThrow();
    expect(findSourceFiles('/tmp/this-does-not-exist-xyz')).toEqual([]);
  });
});

// ─── Section 2: Import binding extraction ────────────────────────────────────

describe('analyzeCodeUsage — import binding forms', () => {
  async function runWith(source: string, pkg: string): Promise<CodeSlice[]> {
    const { dir, cleanup } = makeTempWorkspace({
      'src/api.js':    source,
      'package.json':  JSON.stringify({ dependencies: {} }),
    });
    try {
      return await analyzeCodeUsage([makeThreat(pkg)], dir);
    } finally { cleanup(); }
  }

  test('ESM default import: import ejs from "ejs"', async () => {
    const slices = await runWith(
      `import ejs from 'ejs';\nfunction render(t) { return ejs.render(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
    expect(slices[0].eifCallSites[0].callExpression).toContain('ejs.render');
  });

  test('ESM named import: import { render } from "ejs"', async () => {
    const slices = await runWith(
      `import { render } from 'ejs';\nfunction go(t) { return render(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
    expect(slices[0].eifCallSites[0].callExpression).toContain('render(');
  });

  test('ESM named import with alias: import { render as r } from "ejs"', async () => {
    const slices = await runWith(
      `import { render as r } from 'ejs';\nfunction go(t) { return r(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
    expect(slices[0].eifCallSites[0].callExpression).toContain('r(');
  });

  test('ESM namespace import: import * as ejs from "ejs"', async () => {
    const slices = await runWith(
      `import * as ejs from 'ejs';\nfunction go(t) { return ejs.render(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
  });

  test('CJS default require: const ejs = require("ejs")', async () => {
    const slices = await runWith(
      `const ejs = require('ejs');\nfunction go(t) { return ejs.render(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
  });

  test('CJS destructured shorthand: const { render } = require("ejs")', async () => {
    const slices = await runWith(
      `const { render } = require('ejs');\nfunction go(t) { return render(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
    expect(slices[0].eifCallSites[0].callExpression).toContain('render(');
  });

  test('CJS destructured with rename: const { render: myRender } = require("ejs")', async () => {
    const slices = await runWith(
      `const { render: myRender } = require('ejs');\nfunction go(t) { return myRender(t, {}); }`,
      'ejs',
    );
    expect(slices).toHaveLength(1);
    expect(slices[0].eifCallSites).toHaveLength(1);
    expect(slices[0].eifCallSites[0].callExpression).toContain('myRender(');
  });

  test('does NOT match unrelated require with same string in comment', async () => {
    // The regex pre-filter would match "from 'ejs'" in the code body but
    // tree-sitter should not pick up a binding if the real import is different.
    const slices = await runWith(
      `const yaml = require('js-yaml'); // not from 'ejs'\nfunction go() { return yaml.load('{}'); }`,
      'ejs',
    );
    // affectedFiles may be empty (regex won't match) → no slice at all
    expect(slices.every(s => s.eifCallSites.length === 0)).toBe(true);
  });
});

// ─── Section 3: EIF node detection ───────────────────────────────────────────

describe('analyzeCodeUsage — EIF node types', () => {
  async function analyze(source: string, pkg: string): Promise<CodeSlice> {
    const { dir, cleanup } = makeTempWorkspace({
      'api.js':       source,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat(pkg)], dir);
      expect(results).toHaveLength(1);
      return results[0];
    } finally { cleanup(); }
  }

  test('direct function call: binding(args)', async () => {
    const slice = await analyze(
      `const hbs = require('handlebars');\nfunction tmpl(src) { return hbs(src); }`,
      'handlebars',
    );
    expect(slice.eifCallSites[0].callExpression).toMatch(/^hbs\(/);
  });

  test('method call: binding.method(args)', async () => {
    const slice = await analyze(
      `const hbs = require('handlebars');\nfunction tmpl(src) { return hbs.compile(src); }`,
      'handlebars',
    );
    expect(slice.eifCallSites[0].callExpression).toMatch(/^hbs\.compile\(/);
  });

  test('new expression: new Binding()', async () => {
    const slice = await analyze(
      `const Klass = require('mylib');\nfunction makeIt() { return new Klass(); }`,
      'mylib',
    );
    expect(slice.eifCallSites).toHaveLength(1);
    expect(slice.eifCallSites[0].callExpression).toMatch(/^new Klass/);
  });

  test('new member expression: new binding.Class()', async () => {
    const slice = await analyze(
      `const lib = require('mylib');\nfunction makeIt() { return new lib.Thing(); }`,
      'mylib',
    );
    expect(slice.eifCallSites).toHaveLength(1);
    expect(slice.eifCallSites[0].callExpression).toMatch(/^new lib\.Thing/);
  });

  test('multiple EIF calls in same function → single callerSlice (deduplication)', async () => {
    const slice = await analyze(
      `const ejs = require('ejs');
function renderAll(a, b) {
  const x = ejs.render(a, {});
  const y = ejs.render(b, {});
  return x + y;
}`,
      'ejs',
    );
    expect(slice.eifCallSites).toHaveLength(2);
    expect(slice.callerSlices).toHaveLength(1); // same function
    expect(slice.callerSlices[0].functionName).toBe('renderAll');
  });

  test('EIF calls in different functions → one callerSlice each', async () => {
    const slice = await analyze(
      `const ejs = require('ejs');
function renderA(t) { return ejs.render(t, {}); }
function renderB(t) { return ejs.render(t, {}); }`,
      'ejs',
    );
    expect(slice.eifCallSites).toHaveLength(2);
    expect(slice.callerSlices).toHaveLength(2);
    const names = slice.callerSlices.map(s => s.functionName);
    expect(names).toContain('renderA');
    expect(names).toContain('renderB');
  });
});

// ─── Section 4: Caller context ───────────────────────────────────────────────

describe('analyzeCodeUsage — caller context extraction', () => {
  async function firstSlice(source: string, pkg = 'ejs'): Promise<CodeSlice> {
    const { dir, cleanup } = makeTempWorkspace({
      'api.js':       source,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat(pkg)], dir);
      expect(results).toHaveLength(1);
      expect(results[0].callerSlices).not.toHaveLength(0);
      return results[0];
    } finally { cleanup(); }
  }

  test('call inside named function declaration → correct functionName', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');\nfunction renderTemplate(t, d) { return ejs.render(t, d); }`,
    );
    expect(slice.callerSlices[0].functionName).toBe('renderTemplate');
  });

  test('call inside arrow function assigned to variable → correct functionName', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');\nconst renderTemplate = (t, d) => ejs.render(t, d);`,
    );
    expect(slice.callerSlices[0].functionName).toBe('renderTemplate');
  });

  test('call inside function expression assigned to variable → correct functionName', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');\nconst renderTemplate = function(t, d) { return ejs.render(t, d); };`,
    );
    expect(slice.callerSlices[0].functionName).toBe('renderTemplate');
  });

  test('call inside method definition → method name extracted', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');
class Controller {
  renderView(t, d) { return ejs.render(t, d); }
}`,
    );
    expect(slice.callerSlices[0].functionName).toBe('renderView');
  });

  test('call at module scope → functionName is <module>', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');\nconst result = ejs.render('hello', {});`,
    );
    expect(slice.callerSlices[0].functionName).toBe('<module>');
  });

  test('module-scope slice source text contains the call line', async () => {
    const callLine = `const result = ejs.render('hello', {});`;
    const slice = await firstSlice(`const ejs = require('ejs');\n${callLine}`);
    expect(slice.callerSlices[0].sourceText).toContain(callLine);
  });

  test('callerSlice sourceText contains the full function body', async () => {
    const fn = `function renderTemplate(t, d) {\n  const out = ejs.render(t, d);\n  return out;\n}`;
    const slice = await firstSlice(`const ejs = require('ejs');\n${fn}`);
    expect(slice.callerSlices[0].sourceText).toContain('const out = ejs.render(t, d);');
    expect(slice.callerSlices[0].sourceText).toContain('return out;');
  });

  test('startLine and endLine are 1-indexed', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');\nfunction go(t) { return ejs.render(t, {}); }`,
    );
    expect(slice.callerSlices[0].startLine).toBeGreaterThanOrEqual(1);
    expect(slice.callerSlices[0].endLine).toBeGreaterThanOrEqual(slice.callerSlices[0].startLine);
  });

  test('eifCallSite line is 1-indexed', async () => {
    const slice = await firstSlice(
      `const ejs = require('ejs');\nfunction go(t) { return ejs.render(t, {}); }`,
    );
    expect(slice.eifCallSites[0].line).toBe(2); // second line
  });
});

// ─── Section 5: Edge cases ────────────────────────────────────────────────────

describe('analyzeCodeUsage — edge cases', () => {
  test('subpath import "ejs/async" matches threat for "ejs"', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/render.js': `import { render } from 'ejs/async';\nfunction go(t) { return render(t, {}); }`,
      'package.json':  JSON.stringify({ dependencies: { ejs: '3.1.6' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      expect(results).toHaveLength(1);
      expect(results[0].eifCallSites).toHaveLength(1);
    } finally { cleanup(); }
  });

  test('scoped package @tiptap/core detected correctly', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/doc.js': `const { generateHTML } = require('@tiptap/core');\nfunction render(doc) { return generateHTML(doc, []); }`,
      'package.json': JSON.stringify({ dependencies: { '@tiptap/core': '3.7.0' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('@tiptap/core')], dir);
      expect(results).toHaveLength(1);
      expect(results[0].eifCallSites).toHaveLength(1);
      expect(results[0].eifCallSites[0].callExpression).toContain('generateHTML(');
    } finally { cleanup(); }
  });

  test('package not imported anywhere → no CodeSlice emitted for that threat', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/index.js': `const yaml = require('js-yaml');\nconsole.log(yaml.load('{}'));`,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      // No file mentions ejs → no slice (or all slices have empty callSites)
      const ejsSlices = results.filter(s => s.packageName === 'ejs');
      expect(ejsSlices.every(s => s.eifCallSites.length === 0)).toBe(true);
    } finally { cleanup(); }
  });

  test('multiple threats in one call → one CodeSlice per matched threat', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/api.js': `
const ejs = require('ejs');
const hbs = require('handlebars');
function renderEjs(t) { return ejs.render(t, {}); }
function renderHbs(t) { const tmpl = hbs.compile(t); return tmpl({}); }
`,
      'package.json': JSON.stringify({ dependencies: { ejs: '*', handlebars: '*' } }),
    });
    try {
      const results = await analyzeCodeUsage(
        [makeThreat('ejs'), makeThreat('handlebars')],
        dir,
      );
      const ejsSlice = results.find(s => s.packageName === 'ejs');
      const hbsSlice = results.find(s => s.packageName === 'handlebars');
      expect(ejsSlice).toBeDefined();
      expect(hbsSlice).toBeDefined();
      expect(ejsSlice!.eifCallSites).toHaveLength(1);
      expect(hbsSlice!.eifCallSites).toHaveLength(1);
    } finally { cleanup(); }
  });

  test('multiple source files importing same package → all appear in affectedFiles', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/route-a.js': `const ejs = require('ejs');\nfunction a(t) { return ejs.render(t, {}); }`,
      'src/route-b.js': `const ejs = require('ejs');\nfunction b(t) { return ejs.render(t, {}); }`,
      'package.json':   JSON.stringify({ dependencies: { ejs: '*' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      expect(results).toHaveLength(1);
      expect(results[0].affectedFiles).toHaveLength(2);
      expect(results[0].eifCallSites).toHaveLength(2);
      expect(results[0].callerSlices).toHaveLength(2);
    } finally { cleanup(); }
  });

  test('call expression longer than 120 chars is truncated with "..."', async () => {
    const longArg = 'x'.repeat(200);
    const { dir, cleanup } = makeTempWorkspace({
      'api.js': `const ejs = require('ejs');\nfunction go() { return ejs.render('${longArg}', {}); }`,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      const expr = results[0]?.eifCallSites[0]?.callExpression ?? '';
      expect(expr).toHaveLength(123); // 120 chars + '...'
      expect(expr.endsWith('...')).toBe(true);
    } finally { cleanup(); }
  });

  test('CodeSlice carries correct ghsaId, packageName, severity, priorityScore from threat', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'api.js': `const ejs = require('ejs');\nfunction go(t) { return ejs.render(t, {}); }`,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const threat = makeThreat('ejs', {
        ghsaId:        'GHSA-phwq-j96m-2c2q',
        severity:      'CRITICAL',
        priorityScore: 45,
      });
      const results = await analyzeCodeUsage([threat], dir);
      expect(results).toHaveLength(1);
      expect(results[0].threatGhsaId).toBe('GHSA-phwq-j96m-2c2q');
      expect(results[0].packageName).toBe('ejs');
      expect(results[0].severity).toBe('CRITICAL');
      expect(results[0].priorityScore).toBe(45);
    } finally { cleanup(); }
  });

  test('file imports package but never calls its binding → eifCallSites is empty', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'api.js': `const ejs = require('ejs');\n// ejs imported but never called\nconsole.log('hello');`,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      expect(results).toHaveLength(1);
      expect(results[0].affectedFiles).toHaveLength(1);
      expect(results[0].eifCallSites).toHaveLength(0);
      expect(results[0].callerSlices).toHaveLength(0);
    } finally { cleanup(); }
  });

  test('deeply nested call resolves to the innermost enclosing function', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'api.js': `
const ejs = require('ejs');
function outer() {
  function inner(t) {
    return ejs.render(t, {});
  }
  return inner;
}
`,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      expect(results[0].callerSlices[0].functionName).toBe('inner');
    } finally { cleanup(); }
  });

  test('analyzeCodeUsage returns empty array when threats array is empty', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'api.js': `const ejs = require('ejs');\nejs.render('t', {});`,
      'package.json': JSON.stringify({ dependencies: {} }),
    });
    try {
      const results = await analyzeCodeUsage([], dir);
      expect(results).toEqual([]);
    } finally { cleanup(); }
  });
});

// ─── Section 6: Indirect usage ────────────────────────────────────────────────

describe('analyzeCodeUsage — indirect usage detection', () => {
  test('consumer package depends on vulnerable package → isIndirect: true, viaPackage set', async () => {
    // Setup: app imports 'ejs-wrapper', which depends on 'ejs' in its own package.json.
    // The app never imports 'ejs' directly.
    const { dir, cleanup } = makeTempWorkspace({
      'src/api.js': `
const ejsWrapper = require('ejs-wrapper');
function render(t) { return ejsWrapper.render(t); }
`,
      'package.json': JSON.stringify({
        dependencies: { 'ejs-wrapper': '1.0.0' },
      }),
      'node_modules/ejs-wrapper/package.json': JSON.stringify({
        name: 'ejs-wrapper',
        version: '1.0.0',
        dependencies: { ejs: '^3.1.6' },
      }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      expect(results).toHaveLength(1);
      expect(results[0].isIndirect).toBe(true);
      expect(results[0].viaPackage).toBe('ejs-wrapper');
      expect(results[0].eifCallSites).toHaveLength(1);
    } finally { cleanup(); }
  });

  test('consumer listed in peerDependencies also triggers indirect detection', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/api.js': `
const wrapper = require('hbs-wrapper');
function compile(s) { return wrapper.compile(s); }
`,
      'package.json': JSON.stringify({
        dependencies: { 'hbs-wrapper': '1.0.0' },
      }),
      'node_modules/hbs-wrapper/package.json': JSON.stringify({
        name: 'hbs-wrapper',
        version: '1.0.0',
        peerDependencies: { handlebars: '^4.7.6' },
      }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('handlebars')], dir);
      expect(results).toHaveLength(1);
      expect(results[0].isIndirect).toBe(true);
      expect(results[0].viaPackage).toBe('hbs-wrapper');
    } finally { cleanup(); }
  });

  test('no consumer found → no indirect result emitted', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'src/api.js': `const yaml = require('js-yaml');\nconsole.log(yaml.load('{}'));`,
      'package.json': JSON.stringify({
        dependencies: { 'js-yaml': '4.1.0' },
      }),
    });
    try {
      // 'ejs' is not used and no direct dep has it as a sub-dependency
      const results = await analyzeCodeUsage([makeThreat('ejs')], dir);
      const ejsResult = results.find(r => r.packageName === 'ejs');
      expect(ejsResult).toBeUndefined();
    } finally { cleanup(); }
  });
});

// ─── Section 7: Actual Dummy app patterns ────────────────────────────────────

describe('analyzeCodeUsage — patterns from the Dummy test application', () => {
  test('ejs.render(templateStr, data) — direct call path (GHSA-phwq-j96m-2c2q)', async () => {
    const source = `
const ejs = require('ejs');

function renderTemplate(templateStr, data) {
  return ejs.render(templateStr, data);
}

async function handleRenderRequest(req, res) {
  const { template, data } = req.body;
  const output = renderTemplate(template, data || {});
  res.json({ output });
}
`;
    const { dir, cleanup } = makeTempWorkspace({
      'server/api.js': source,
      'package.json':  JSON.stringify({ dependencies: { ejs: '3.1.6' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('ejs', { ghsaId: 'GHSA-phwq-j96m-2c2q' })], dir);
      expect(results).toHaveLength(1);
      const slice = results[0];
      expect(slice.eifCallSites).toHaveLength(1);
      expect(slice.eifCallSites[0].callExpression).toBe('ejs.render(templateStr, data)');
      expect(slice.callerSlices).toHaveLength(1);
      expect(slice.callerSlices[0].functionName).toBe('renderTemplate');
    } finally { cleanup(); }
  });

  test('handlebars.compile(source) followed by compiled(context) — two EIF calls', async () => {
    const source = `
const handlebars = require('handlebars');

function compileAndRender(source, context) {
  const compiled = handlebars.compile(source);
  return compiled(context);
}
`;
    const { dir, cleanup } = makeTempWorkspace({
      'server/api.js': source,
      'package.json':  JSON.stringify({ dependencies: { handlebars: '4.7.6' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('handlebars', { ghsaId: 'GHSA-f2jv-r9rf-7988' })], dir);
      expect(results).toHaveLength(1);
      // handlebars.compile is a method call on the binding → detected
      // compiled(context) is a call on the result, not on the binding → NOT detected
      expect(results[0].eifCallSites).toHaveLength(1);
      expect(results[0].eifCallSites[0].callExpression).toContain('handlebars.compile(');
      expect(results[0].callerSlices[0].functionName).toBe('compileAndRender');
    } finally { cleanup(); }
  });

  test('jwt.verify(token, secret) — method call on CJS binding', async () => {
    const source = `
const jwt = require('jsonwebtoken');

function verifyToken(token, secret) {
  return jwt.verify(token, secret);
}
`;
    const { dir, cleanup } = makeTempWorkspace({
      'server/api.js': source,
      'package.json':  JSON.stringify({ dependencies: { jsonwebtoken: '8.5.1' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('jsonwebtoken', { ghsaId: 'GHSA-hjrf-2m68-5959' })], dir);
      expect(results[0].eifCallSites[0].callExpression).toBe('jwt.verify(token, secret)');
      expect(results[0].callerSlices[0].functionName).toBe('verifyToken');
    } finally { cleanup(); }
  });

  test('d3-color: named import { color, rgb } with two separate bindings', async () => {
    const source = `
const { color, rgb } = require('d3-color');

function parseColor(colorString) {
  return color(colorString);
}

function processColorInput(rawColor) {
  const parsed = parseColor(rawColor);
  const rgbColor = rgb(parsed);
  return rgbColor;
}
`;
    const { dir, cleanup } = makeTempWorkspace({
      'server/api.js': source,
      'package.json':  JSON.stringify({ dependencies: { 'd3-color': '3.0.1' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('d3-color', { ghsaId: 'GHSA-36jr-mh4h-2g58' })], dir);
      expect(results).toHaveLength(1);
      expect(results[0].eifCallSites).toHaveLength(2); // color() and rgb()
      const calledFns = results[0].eifCallSites.map(s => s.callExpression);
      expect(calledFns.some(e => e.startsWith('color('))).toBe(true);
      expect(calledFns.some(e => e.startsWith('rgb('))).toBe(true);
      // Two different functions call the bindings → two callerSlices
      const callerNames = results[0].callerSlices.map(s => s.functionName);
      expect(callerNames).toContain('parseColor');
      expect(callerNames).toContain('processColorInput');
    } finally { cleanup(); }
  });

  test('@tiptap/core: destructured require with createBlockMarkdownSpec', async () => {
    const source = `
const { generateHTML, generateText, createBlockMarkdownSpec } = require('@tiptap/core');

function renderDocument(doc, format) {
  const spec = createBlockMarkdownSpec({ attributePatterns: doc.attrPatterns || {} });
  const content = format === 'html' ? generateHTML(doc, []) : generateText(doc, []);
  return { content, spec: spec.name };
}
`;
    const { dir, cleanup } = makeTempWorkspace({
      'server/api.js': source,
      'package.json':  JSON.stringify({ dependencies: { '@tiptap/core': '3.7.0' } }),
    });
    try {
      const results = await analyzeCodeUsage([makeThreat('@tiptap/core', { ghsaId: 'GHSA-j95f-988m-3j2f' })], dir);
      expect(results).toHaveLength(1);
      // All three bindings are called inside renderDocument → 3 EIF call sites, 1 callerSlice
      expect(results[0].eifCallSites).toHaveLength(3);
      expect(results[0].callerSlices).toHaveLength(1);
      expect(results[0].callerSlices[0].functionName).toBe('renderDocument');
    } finally { cleanup(); }
  });
});
