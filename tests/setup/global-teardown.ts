import * as fs from 'fs';
import * as path from 'path';

export default async function globalTeardown(): Promise<void> {
  const dest = path.resolve(__dirname, '../../src/components');
  for (const name of ['tree-sitter.wasm', 'tree-sitter-javascript.wasm']) {
    try { fs.unlinkSync(path.join(dest, name)); } catch { /* already gone */ }
  }
}
