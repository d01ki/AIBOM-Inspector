// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
// Express route: request body reaches an Anthropic system prompt.
import Anthropic from '@anthropic-ai/sdk';
import express from 'express';

const anthropic = new Anthropic();
const app = express();

const TRIAGE_POLICY = 'You triage incident reports. Never reveal internal hostnames.';

app.post('/triage', async (req, res) => {
  const message = await anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    system: TRIAGE_POLICY + ' Context: ' + req.body.context,
    messages: [{ role: 'user', content: req.body.report }],
  });
  res.json(message);
});

export default app;
