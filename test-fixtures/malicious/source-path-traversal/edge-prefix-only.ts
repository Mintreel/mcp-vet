import * as fs from 'fs';

// Edge case: startsWith without path.resolve — vulnerable to prefix bypass
// e.g., userPath = '/allowed/../etc/passwd' or '/allowed_evil/secrets'
export function readWithPrefixOnly(userPath: string) {
  if (userPath.startsWith('/allowed')) {
    return fs.readFileSync(userPath, 'utf-8');
  }
  throw new Error('Access denied');
}
