import * as fs from 'fs';
import * as path from 'path';

// Edge case: path.resolve + startsWith — proper containment, should NOT trigger
export function readContained(userInput: string) {
  const base = '/app/data';
  const resolved = path.resolve(base, userInput);
  if (resolved.startsWith(base)) {
    return fs.readFileSync(resolved, 'utf-8');
  }
  throw new Error('Access denied');
}
