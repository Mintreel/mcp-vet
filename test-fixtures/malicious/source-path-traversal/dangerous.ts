import * as fs from 'fs';
import * as path from 'path';

// Dangerous: no path validation
function readUserFile(filePath: string) {
  return fs.readFileSync(filePath, 'utf-8');
}

// Dangerous: startsWith without path.resolve (prefix bypass vulnerability)
function readWithBadValidation(userPath: string) {
  const allowedDir = '/private/tmp/allow_dir';
  if (userPath.startsWith(allowedDir)) {
    return fs.readFileSync(userPath, 'utf-8');
  }
  throw new Error('Access denied');
}
