import * as fs from 'fs';
import * as path from 'path';

// Copy WASM files to src/components/ so initParser()'s __dirname-relative
// path resolution finds them when ts-jest runs the source directly.
export default async function globalSetup(): Promise<void> {
  const dest    = path.resolve(__dirname, '../../src/components');
  const wasmSrc = path.resolve(__dirname, '../../node_modules/web-tree-sitter/tree-sitter.wasm');
  const jsSrc   = path.resolve(__dirname, '../../wasm/tree-sitter-javascript.wasm');

  fs.copyFileSync(wasmSrc, path.join(dest, 'tree-sitter.wasm'));
  fs.copyFileSync(jsSrc,   path.join(dest, 'tree-sitter-javascript.wasm'));
}
