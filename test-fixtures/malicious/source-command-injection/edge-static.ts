import { exec } from 'child_process';

// Edge case: variable assigned from a static string — should NOT trigger
export function runStaticCommand() {
  const cmd = 'ls -la /tmp';
  exec(cmd);
}
