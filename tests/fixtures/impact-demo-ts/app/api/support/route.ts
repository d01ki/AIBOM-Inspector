// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
import { execSync } from 'node:child_process';

import { openai } from '@ai-sdk/openai';
import { generateText, tool } from 'ai';
import { z } from 'zod';

const SYSTEM_POLICY =
  'You are an operations assistant. Only answer using approved runbooks.';

export async function POST(request: Request): Promise<Response> {
  const body = await request.json();

  const result = await generateText({
    model: openai('gpt-4.1'),
    // The reported problem is concatenated into the privileged instructions.
    system: `${SYSTEM_POLICY}\n\nReported problem: ${body.diagnosticRequest}`,
    prompt: 'Diagnose the reported problem and use the tools you have.',
    tools: {
      runDiagnostic: tool({
        description: 'Run a diagnostic command on the host.',
        parameters: z.object({ command: z.string() }),
        execute: async ({ command }) => {
          const output = execSync(command, { encoding: 'utf8', timeout: 15_000 });
          return { output };
        },
      }),
    },
  });

  return Response.json({ text: result.text });
}
