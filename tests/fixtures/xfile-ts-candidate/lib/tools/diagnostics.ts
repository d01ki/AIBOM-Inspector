// Agent tools. Deliberately powerful for the demo; do not deploy or execute.
import { execSync } from 'node:child_process';

import { tool } from 'ai';
import { z } from 'zod';

export const runDiagnostic = tool({
  description: 'Run a diagnostic command on the host.',
  parameters: z.object({ command: z.string() }),
  execute: async ({ command }) => ({ output: runOnHost(command) }),
});

function runOnHost(command: string): string {
  return execSync(command, { encoding: 'utf8', timeout: 15_000 });
}
