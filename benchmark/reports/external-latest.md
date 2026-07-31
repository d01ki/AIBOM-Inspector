# AIBOM Inspector benchmark

Repositories evaluated: 6

| Category | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 1.0000 | 0.8462 | 0.9167 | 33 | 0 | 6 |
| Models | 1.0000 | 0.2857 | 0.4444 | 2 | 0 | 5 |
| Services | 1.0000 | 0.5000 | 0.6667 | 1 | 0 | 1 |
| Prompts | 1.0000 | 1.0000 | 1.0000 | 25 | 0 | 0 |
| Agents | N/A | N/A | N/A | 0 | 0 | 0 |
| Tools | N/A | N/A | N/A | 0 | 0 | 0 |
| Mcp | N/A | N/A | N/A | 0 | 0 | 0 |
| Datasets | N/A | N/A | N/A | 0 | 0 | 0 |
| Model Files | N/A | N/A | N/A | 0 | 0 | 0 |
| Ai Packages | 1.0000 | 1.0000 | 1.0000 | 5 | 0 | 0 |

## By language

| Language | Repos | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| python | 4 | 1.0000 | 1.0000 | 1.0000 | 11 | 0 | 0 |
| typescript | 2 | 1.0000 | 0.7857 | 0.8800 | 22 | 0 | 6 |

## Errors

- False negative: `vercel/ai-chatbot` models `moonshotai/kimi-k2.5` at `lib/ai/models.ts:6`
- False negative: `vercel/ai-chatbot` models `deepseek/deepseek-v3.2` at `lib/ai/models.ts:30`
- False negative: `vercel/ai-chatbot` models `openai/gpt-oss-20b` at `lib/ai/models.ts:44`
- False negative: `vercel/ai-chatbot` models `openai/gpt-oss-120b` at `lib/ai/models.ts:52`
- False negative: `vercel/ai-chatbot` models `xai/grok-4.1-fast-non-reasoning` at `lib/ai/models.ts:60`
- False negative: `vercel/ai-chatbot` services `vercel-ai-gateway` at `lib/ai/providers.ts:25`
