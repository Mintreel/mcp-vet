import { execFile, execSync } from 'child_process';

// Safe: static string
function listFiles() {
  execSync('ls -la');
}

// Safe: execFile with array args (not exec)
function cloneRepo() {
  execFile('git', ['clone', 'https://github.com/example/repo.git']);
}

// Safe: variable assigned from static string
function runStatic() {
  const cmd = 'echo hello';
  execSync(cmd);
}
