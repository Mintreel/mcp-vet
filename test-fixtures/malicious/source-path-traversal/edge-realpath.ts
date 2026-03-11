import * as fs from 'fs';

// Edge case: realpathSync before access — should NOT trigger
export function readWithRealpath(userPath: string) {
  const real = fs.realpathSync(userPath);
  const base = '/app/data';
  if (real.startsWith(base)) {
    return fs.readFileSync(real, 'utf-8');
  }
  throw new Error('Access denied');
}
