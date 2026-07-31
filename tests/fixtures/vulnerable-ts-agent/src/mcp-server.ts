// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
// MCP server whose tool input reaches an OpenAI system prompt.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import OpenAI from 'openai';

const client = new OpenAI();
const server = new McpServer({ name: 'notes', version: '1.0.0' });

const SUMMARY_POLICY = 'Summarize the note faithfully and never invent facts.';

server.tool('summarize', {}, async ({ note }) => {
  const completion = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: `${SUMMARY_POLICY} Note: ${note}` },
      { role: 'user', content: 'Summarize it.' },
    ],
  });
  return completion.choices[0].message;
});

export default server;
