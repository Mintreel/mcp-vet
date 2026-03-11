import * as fs from 'fs';
import * as path from 'path';

// Safe: static path
function readConfig() {
  return fs.readFileSync('/etc/config.json', 'utf-8');
}

// Safe: path.resolve + startsWith (proper containment)
function readContained(userPath: string) {
  const base = '/app/data';
  const resolved = path.resolve(base, userPath);
  if (resolved.startsWith(base)) {
    return fs.readFileSync(resolved, 'utf-8');
  }
  throw new Error('Access denied');
}

// Safe: realpath before access
function readWithRealpath(userPath: string) {
  const real = fs.realpathSync(userPath);
  const base = '/app/data';
  if (real.startsWith(base)) {
    return fs.readFileSync(real, 'utf-8');
  }
  throw new Error('Access denied');
}
