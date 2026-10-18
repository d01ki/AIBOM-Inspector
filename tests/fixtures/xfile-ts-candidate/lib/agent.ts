import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

import { buildInstructions } from './prompts';
import { runDiagnostic } from './tools/diagnostics';

export async function runSupportAgent(problem: string): Promise<string> {
  const result = await generateText({
    model: openai('gpt-4.1'),
    system: buildInstructions(problem),
    prompt: problem,
    tools: { runDiagnostic },
  });
  return result.text;
}
