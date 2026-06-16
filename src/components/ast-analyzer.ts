import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';
import Parser from 'tree-sitter';

// Dynamic loading of tree-sitter language grammars
const Grammars: Record<string, any> = {
  'npm': require('tree-sitter-typescript').typescript,
  'pip': require('tree-sitter-python'),
  'go': require('tree-sitter-go')
};

// Target file extensions associated with each ecosystem
const Extensions: Record<string, string[]> = {
  'npm': ['.js', '.ts', '.jsx', '.tsx'],
  'pip': ['.py'],
  'go': ['.go']
};

// Language-specific S-expression patterns mapping universally to @import_target
const QueryPatterns: Record<string, string> = {
  'npm': `
    (import_statement source: (string) @import_target)
    (call_expression 
      function: (identifier) @func_name 
      arguments: (arguments (string) @import_target)
      (#eq? @func_name "require")
    )
  `,
  'pip': `
    (import_statement name: (dotted_name) @import_target)
    (import_from_statement module_name: (dotted_name) @import_target)
  `,
  'go': `
    (import_spec path: (string) @import_target)
  `
};

// Fully generic directory crawler filtering by applicable extensions
function locateSourceFiles(dirPath: string, allowedExtensions: string[]): string[] {
  let results: string[] = [];
  if (!fs.existsSync(dirPath)) return results;

  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'vendor' && !entry.name.startsWith('.')) {
        results = results.concat(locateSourceFiles(fullPath, allowedExtensions));
      }
    } else if (entry.isFile()) {
      if (allowedExtensions.includes(path.extname(entry.name))) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

export function analyzeReachability(workspacePath: string, ecosystems: string[]): string[] {
  core.info('Component 7: Waking up AST Reachability Analyzer...');
  const importedPackages = new Set<string>();

  for (const eco of ecosystems) {
    const languageGrammar = Grammars[eco];
    const allowedExtensions = Extensions[eco];
    const pattern = QueryPatterns[eco];

    if (!languageGrammar || !allowedExtensions || !pattern) {
      core.warning(`AST Analyzer: Ecosystem ${eco} is not yet supported for AST parsing. Skipping.`);
      continue;
    }

    core.info(`AST Analyzer: Initializing abstract syntax tree parsing for ${eco}...`);

    try {
      const parser = new Parser();
      parser.setLanguage(languageGrammar);
      const query = new Parser.Query(languageGrammar, pattern);

      const sourceFiles = locateSourceFiles(workspacePath, allowedExtensions);
      core.info(`AST Analyzer: Found ${sourceFiles.length} source files matching ecosystem ${eco}.`);

      for (const file of sourceFiles) {
        const sourceCode = fs.readFileSync(file, 'utf8');
        const tree = parser.parse(sourceCode);
        const matches = query.matches(tree.rootNode);

        for (const match of matches) {
          for (const capture of match.captures) {
            if (capture.name === 'import_target') {
              // Strip quotes/whitespace and normalize package target strings
              let rawText = capture.node.text.replace(/['"`]/g, '').trim();
              
              if (eco === 'npm') {
                if (rawText.startsWith('@')) {
                  const parts = rawText.split('/');
                  if (parts.length >= 2) importedPackages.add(`${parts[0]}/${parts[1]}`.toLowerCase());
                } else {
                  importedPackages.add(rawText.split('/')[0].toLowerCase());
                }
              } else {
                // For Python and Go, take the base root module name
                importedPackages.add(rawText.split('.')[0].split('/')[0].toLowerCase());
              }
            }
          }
        }
      }
    } catch (error) {
      if (error instanceof Error) {
        core.error(`AST Analyzer failed for ecosystem ${eco}: ${error.message}`);
      }
    }
  }

  const resultList = Array.from(importedPackages);
  core.info(`AST Analyzer: Total unique active modules detected across source code: ${resultList.length}`);
  return resultList;
}