import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { detectEntryPoint } from '../src/components/purple-team/entry-point-detector';
import { CallerSlice } from '../src/components/ast-analyzer';

function makeTempWorkspace(files: Record<string, string>): { dir: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epd-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function slice(functionName: string, sourceText: string, overrides: Partial<CallerSlice> = {}): CallerSlice {
  return { file: 'server/api.js', functionName, sourceText, startLine: 1, endLine: 1, ...overrides };
}

describe('detectEntryPoint', () => {
  test('named-function caller referenced by name inside a route handler resolves to that route', async () => {
    // Reproduces the @tiptap/core case from Dummy: the EIF calls live inside a named
    // function, and that function is called by name from the route handler body.
    // findHttpEntryPoint matches on the handler's source text containing the caller name.
    const { dir, cleanup } = makeTempWorkspace({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
      'server/api.js': `
function renderDocument(doc, format) {
  return createBlockMarkdownSpec(doc);
}
app.post('/api/render-doc', (req, res) => {
  const { doc, format } = req.body;
  const result = renderDocument(doc, format || 'text');
  res.json(result);
});
`,
    });
    try {
      const ep = await detectEntryPoint(
        [slice('renderDocument', 'function renderDocument(doc, format) { return createBlockMarkdownSpec(doc); }')],
        dir,
      );
      expect(ep).not.toBeNull();
      expect(ep!.type).toBe('http-route');
      expect(ep!.identifier).toBe('POST /api/render-doc');
      expect(ep!.handlerFunction).toBe('renderDocument');
      expect(ep!.framework).toBe('express');
    } finally { cleanup(); }
  });

  test('module-scope caller (functionName "<module>") is filtered out — returns null', async () => {
    // Reproduces the multer/morgan case: an EIF called at module scope (e.g. as a
    // middleware-registration argument) has no useful name for the route search to
    // match against, so detectEntryPoint returns null rather than guessing.
    const { dir, cleanup } = makeTempWorkspace({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
      'server/api.js': `
const upload = multer({ dest: '/tmp' });
app.post('/api/upload', upload.any(), (req, res) => { res.json({}); });
`,
    });
    try {
      const ep = await detectEntryPoint(
        [slice('<module>', "app.post('/api/upload', upload.any(), (req, res) => { res.json({}); });")],
        dir,
      );
      expect(ep).toBeNull();
    } finally { cleanup(); }
  });

  test('anonymous caller (functionName "<anonymous>") is also filtered out', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
      'server/api.js': `app.get('/', (req, res) => res.send('ok'));`,
    });
    try {
      const ep = await detectEntryPoint([slice('<anonymous>', 'some code')], dir);
      expect(ep).toBeNull();
    } finally { cleanup(); }
  });

  test('empty callerSlices array returns null immediately', async () => {
    const { dir, cleanup } = makeTempWorkspace({ 'package.json': '{}' });
    try {
      const ep = await detectEntryPoint([], dir);
      expect(ep).toBeNull();
    } finally { cleanup(); }
  });

  test('named caller that matches no route anywhere returns null', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
      'server/api.js': `
function orphanFunction() { return 1; }
app.get('/unrelated', (req, res) => res.send('ok'));
`,
    });
    try {
      const ep = await detectEntryPoint([slice('orphanFunction', 'function orphanFunction() { return 1; }')], dir);
      expect(ep).toBeNull();
    } finally { cleanup(); }
  });

  test('extracts attackable surface (req.body/params/query) from the handler', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
      'server/api.js': `
function verifyToken(token, secret) { return jwt.verify(token, secret); }
app.post('/api/auth/verify', (req, res) => {
  const { token, secret } = req.body;
  const decoded = verifyToken(token, secret);
  res.json({ decoded });
});
`,
    });
    try {
      const ep = await detectEntryPoint(
        [slice('verifyToken', 'function verifyToken(token, secret) { return jwt.verify(token, secret); }')],
        dir,
      );
      expect(ep).not.toBeNull();
      expect(ep!.attackableSurface).toContain('req.body');
    } finally { cleanup(); }
  });

  test('resolves through one level of indirection: route → wrapper function → EIF caller', async () => {
    const { dir, cleanup } = makeTempWorkspace({
      'package.json': JSON.stringify({ dependencies: { express: '^4.18.2' } }),
      'server/api.js': `
function eifCaller(x) { return doVulnerableThing(x); }
function wrapper(req) { return eifCaller(req.body.x); }
app.post('/api/wrapped', (req, res) => {
  const result = wrapper(req);
  res.json(result);
});
`,
    });
    try {
      const ep = await detectEntryPoint(
        [slice('eifCaller', 'function eifCaller(x) { return doVulnerableThing(x); }')],
        dir,
      );
      expect(ep).not.toBeNull();
      expect(ep!.identifier).toBe('POST /api/wrapped');
    } finally { cleanup(); }
  });
});
