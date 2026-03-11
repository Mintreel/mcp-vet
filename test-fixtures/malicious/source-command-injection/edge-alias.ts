import { exec } from 'child_process';

// Edge case: aliased exec function — should trigger CRITICAL
export function runCommand(userInput: string) {
  const run = exec;
  run(userInput);
}
