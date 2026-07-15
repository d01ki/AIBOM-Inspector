import Anthropic from "@anthropic-ai/sdk";
const client = new Anthropic();
const MODEL = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5";
export async function ask(q: string) {
  return client.messages.create({ model: MODEL, messages: [{ role: "user", content: q }] });
}
