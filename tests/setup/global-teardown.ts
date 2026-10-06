import * as fs from 'fs';
import * as path from 'path';

export default async function globalTeardown(): Promise<void> {
  const dests = [
    path.resolve(__dirname, '../../src/components'),
    path.resolve(__dirname, '../../src/components/purple-team'),
  ];
  for (const dest of dests) {
    for (const name of ['tree-sitter.wasm', 'tree-sitter-javascript.wasm']) {
      try { fs.unlinkSync(path.join(dest, name)); } catch { /* already gone */ }
    }
  }
}
