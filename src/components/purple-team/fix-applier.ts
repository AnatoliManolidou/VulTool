import * as fs from 'fs';

export function extractFixedCode(response: string): string | null {
  const m = response.match(/##\s*Fixed Code[\s\S]*?```(?:javascript|js|typescript|ts)?\n([\s\S]*?)```/i);
  return m ? m[1].trim() : null;
}

export function applyFixToFile(
  filePath: string,
  originalSource: string,
  fixedCode: string,
): { applied: boolean; originalContent: string } {
  const originalContent = fs.readFileSync(filePath, 'utf8');
  const idx = originalContent.indexOf(originalSource.trim());
  if (idx === -1) return { applied: false, originalContent };
  const newContent =
    originalContent.slice(0, idx) +
    fixedCode +
    originalContent.slice(idx + originalSource.trim().length);
  fs.writeFileSync(filePath, newContent, 'utf8');
  return { applied: true, originalContent };
}

export function revertFile(filePath: string, originalContent: string): void {
  fs.writeFileSync(filePath, originalContent, 'utf8');
}
