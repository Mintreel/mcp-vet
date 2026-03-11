import { exec, execSync } from 'child_process';

// Dangerous: template literal with interpolation
function cloneRepo(url: string) {
  exec(`git clone ${url}`);
}

// Dangerous: string concatenation
function runCommand(cmd: string) {
  execSync('git ' + cmd);
}

// Dangerous: variable from parameter
function executeUserInput(userInput: string) {
  exec(userInput);
}
