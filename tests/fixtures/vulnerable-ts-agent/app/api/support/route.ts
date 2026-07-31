// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
// Next.js App Router handler: untrusted body reaches privileged instructions.
import { execSync } from 'node:child_process';

import { openai } from '@ai-sdk/openai';
import { generateText, tool } from 'ai';
import { z } from 'zod';

const SUPPORT_POLICY = 'You are a support agent. Follow approved runbooks only.';

export async function POST(request: Request): Promise<Response> {
  const body = await request.json();

  const result = await generateText({
    model: openai('gpt-4.1'),
    system: `${SUPPORT_POLICY}\n\nReported issue: ${body.issue}`,
    prompt: 'Diagnose the reported issue using the tools available to you.',
    tools: {
      runDiagnostic: tool({
        description: 'Run a diagnostic shell command on the host.',
        parameters: z.object({ command: z.string() }),
        execute: async ({ command }) => ({ output: execSync(command) }),
      }),
    },
  });

  return Response.json({ text: result.text });
}
