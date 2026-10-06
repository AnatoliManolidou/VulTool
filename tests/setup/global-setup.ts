import * as fs from 'fs';
import * as path from 'path';

// Copy WASM files to every src/components/** directory with its own initParser()/
// __dirname-relative resolution, so ts-jest running source directly can find them.
// ast-analyzer.ts resolves from src/components/; entry-point-detector.ts (and the
// rest of purple-team/) resolves from src/components/purple-team/ — each needs its
// own copy since __dirname differs per module.
export default async function globalSetup(): Promise<void> {
  const wasmSrc = path.resolve(__dirname, '../../node_modules/web-tree-sitter/tree-sitter.wasm');
  const jsSrc   = path.resolve(__dirname, '../../wasm/tree-sitter-javascript.wasm');
  const dests = [
    path.resolve(__dirname, '../../src/components'),
    path.resolve(__dirname, '../../src/components/purple-team'),
  ];
  for (const dest of dests) {
    fs.copyFileSync(wasmSrc, path.join(dest, 'tree-sitter.wasm'));
    fs.copyFileSync(jsSrc,   path.join(dest, 'tree-sitter-javascript.wasm'));
  }
}
