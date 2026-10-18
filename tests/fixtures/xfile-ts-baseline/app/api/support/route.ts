// HTTP layer of the cross-file demo; static fixture only, never executed.
import { runSupportAgent } from '@/lib/agent';

export async function POST(request: Request): Promise<Response> {
  const body = await request.json();
  const text = await runSupportAgent(body.problem);
  return Response.json({ text });
}
