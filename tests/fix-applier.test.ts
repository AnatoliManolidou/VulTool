import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { extractFixedCode, applyFixToFile, revertFile } from '../src/components/purple-team/fix-applier';

function makeTempFile(content: string): { file: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fixapplier-test-'));
  const file = path.join(dir, 'api.js');
  fs.writeFileSync(file, content, 'utf8');
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

describe('extractFixedCode', () => {
  test('extracts code from a standard "## Fixed Code" block with a javascript tag', () => {
    const response = `## Fixed Code\n\`\`\`javascript\nfunction foo() { return 1; }\n\`\`\`\n\n## What Changed\n- bullet`;
    expect(extractFixedCode(response)).toBe('function foo() { return 1; }');
  });

  test('matches heading case-insensitively', () => {
    const response = `## fixed code\n\`\`\`js\nconst x = 1;\n\`\`\``;
    expect(extractFixedCode(response)).toBe('const x = 1;');
  });

  test('accepts js, ts, typescript, javascript, or no language tag', () => {
    for (const tag of ['js', 'ts', 'typescript', 'javascript', '']) {
      const response = `## Fixed Code\n\`\`\`${tag}\nconst y = 2;\n\`\`\``;
      expect(extractFixedCode(response)).toBe('const y = 2;');
    }
  });

  test('trims leading/trailing whitespace from the extracted code', () => {
    const response = `## Fixed Code\n\`\`\`javascript\n\n  const z = 3;\n\n\`\`\``;
    expect(extractFixedCode(response)).toBe('const z = 3;');
  });

  test('returns null when there is no "## Fixed Code" heading at all', () => {
    const response = `\`\`\`javascript\nconst a = 1;\n\`\`\``;
    expect(extractFixedCode(response)).toBeNull();
  });

  test('returns null when the heading exists but has no code block', () => {
    const response = `## Fixed Code\nNo code block here, just prose.`;
    expect(extractFixedCode(response)).toBeNull();
  });

  test('picks the first code block after the heading when multiple exist in the response', () => {
    const response =
      `## Fixed Code\n\`\`\`javascript\nconst first = 1;\n\`\`\`\n\n` +
      `## Residual Risk\n\`\`\`javascript\nconst second = 2;\n\`\`\``;
    expect(extractFixedCode(response)).toBe('const first = 1;');
  });
});

describe('applyFixToFile', () => {
  test('replaces the matched slice and writes the new content to disk', () => {
    const original = `const a = 1;\nfunction vulnerable() {\n  return a;\n}\nconst b = 2;`;
    const { file, cleanup } = makeTempFile(original);
    try {
      const vulnerableSlice = `function vulnerable() {\n  return a;\n}`;
      const fixedCode       = `function vulnerable() {\n  return sanitize(a);\n}`;
      const result = applyFixToFile(file, vulnerableSlice, fixedCode);

      expect(result.applied).toBe(true);
      expect(result.originalContent).toBe(original); // snapshot of pre-fix content, for revert

      const onDisk = fs.readFileSync(file, 'utf8');
      expect(onDisk).toBe(`const a = 1;\nfunction vulnerable() {\n  return sanitize(a);\n}\nconst b = 2;`);
      expect(onDisk).toContain('const a = 1;');   // untouched prefix preserved
      expect(onDisk).toContain('const b = 2;');   // untouched suffix preserved
    } finally { cleanup(); }
  });

  test('tolerates leading/trailing whitespace differences in the slice being searched for', () => {
    const original = `function f() {\n  return 1;\n}\n`;
    const { file, cleanup } = makeTempFile(original);
    try {
      // Caller passes the slice with extra surrounding whitespace, as an LLM-sourced
      // caller slice sometimes would — applyFixToFile trims before searching.
      const sliceWithWhitespace = `\n  function f() {\n  return 1;\n}\n  \n`;
      const result = applyFixToFile(file, sliceWithWhitespace, 'function f() { return 2; }');
      expect(result.applied).toBe(true);
      expect(fs.readFileSync(file, 'utf8')).toBe('function f() { return 2; }\n');
    } finally { cleanup(); }
  });

  test('returns applied:false and does not touch the file when the slice is not found', () => {
    const original = `function f() { return 1; }`;
    const { file, cleanup } = makeTempFile(original);
    try {
      const result = applyFixToFile(file, 'function thisDoesNotExist() {}', 'function g() {}');
      expect(result.applied).toBe(false);
      expect(result.originalContent).toBe(original);
      expect(fs.readFileSync(file, 'utf8')).toBe(original); // file genuinely untouched
    } finally { cleanup(); }
  });

  test('when the slice text appears more than once, only the first occurrence is replaced', () => {
    const original = `const dup = 1;\nconst dup = 1;\n`;
    const { file, cleanup } = makeTempFile(original);
    try {
      const result = applyFixToFile(file, 'const dup = 1;', 'const dup = 2;');
      expect(result.applied).toBe(true);
      expect(fs.readFileSync(file, 'utf8')).toBe('const dup = 2;\nconst dup = 1;\n');
    } finally { cleanup(); }
  });
});

describe('revertFile', () => {
  test('restores the file to the given content, overwriting whatever is currently there', () => {
    const { file, cleanup } = makeTempFile('modified content');
    try {
      revertFile(file, 'original content');
      expect(fs.readFileSync(file, 'utf8')).toBe('original content');
    } finally { cleanup(); }
  });

  test('round-trip: apply then revert restores the exact original file', () => {
    const original = `function f() {\n  return 1;\n}\n`;
    const { file, cleanup } = makeTempFile(original);
    try {
      const { applied, originalContent } = applyFixToFile(file, 'function f() {\n  return 1;\n}', 'function f() { return 2; }');
      expect(applied).toBe(true);
      expect(fs.readFileSync(file, 'utf8')).not.toBe(original);

      revertFile(file, originalContent);
      expect(fs.readFileSync(file, 'utf8')).toBe(original);
    } finally { cleanup(); }
  });
});
