# AIBOM Inspector benchmark — 20 repositories, first run on unseen cases (frozen 2026-10-18)

Repositories evaluated: 20

| Category | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 0.9130 | 0.6614 | 0.7671 | 84 | 8 | 43 |
| Models | 0.7619 | 0.5926 | 0.6667 | 16 | 5 | 11 |
| Services | 1.0000 | 1.0000 | 1.0000 | 9 | 0 | 0 |
| Prompts | 1.0000 | 0.5932 | 0.7447 | 35 | 0 | 24 |
| Agents | N/A | N/A | N/A | 0 | 0 | 0 |
| Tools | N/A | N/A | N/A | 0 | 0 | 0 |
| Mcp | 0.7500 | 0.5000 | 0.6000 | 3 | 1 | 3 |
| Datasets | N/A | N/A | N/A | 0 | 0 | 0 |
| Model Files | N/A | N/A | N/A | 0 | 0 | 0 |
| Ai Packages | 0.9130 | 0.8077 | 0.8571 | 21 | 2 | 5 |

## By language

| Language | Repos | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| go | 1 | N/A | N/A | N/A | 0 | 0 | 0 |
| mixed | 1 | 0.7778 | 0.6667 | 0.7179 | 14 | 4 | 7 |
| python | 9 | 0.7647 | 0.4333 | 0.5532 | 13 | 4 | 17 |
| typescript | 9 | 1.0000 | 0.7500 | 0.8571 | 57 | 0 | 19 |

## Errors

- False negative: `vercel-labs/gemini-chatbot` models `gemini-2.5-pro` at `ai/index.ts:7`
- False negative: `vercel-labs/gemini-chatbot` models `gemini-2.5-flash` at `ai/index.ts:12`
- False positive: `simonw/llm-claude-3` models `claude-3-5-sonnet-20241022` at `tests/cassettes/test_claude_3/test_image_prompt.yaml:50`
- False positive: `simonw/llm-claude-3` models `claude-3-5-sonnet-latest` at `tests/cassettes/test_claude_3/test_image_prompt.yaml:5`
- False positive: `simonw/llm-claude-3` models `claude-3-opus-20240229` at `tests/cassettes/test_claude_3/test_async_prompt.yaml:47`
- False positive: `simonw/llm-claude-3` models `claude-3-opus-latest` at `tests/cassettes/test_claude_3/test_async_prompt.yaml:4`
- False negative: `simonw/llm-claude-3` ai_packages `llm` at `pyproject.toml:12`
- False negative: `simonw/llm-claude-3` models `claude-3-opus-20240229` at `llm_claude_3.py:11`
- False negative: `simonw/llm-claude-3` models `claude-3-opus-latest` at `llm_claude_3.py:15`
- False negative: `simonw/llm-claude-3` models `claude-3-sonnet-20240229` at `llm_claude_3.py:20`
- False negative: `simonw/llm-claude-3` models `claude-3-haiku-20240307` at `llm_claude_3.py:25`
- False negative: `simonw/llm-claude-3` models `claude-3-5-sonnet-20240620` at `llm_claude_3.py:31`
- False negative: `simonw/llm-claude-3` models `claude-3-5-sonnet-20241022` at `llm_claude_3.py:35`
- False negative: `simonw/llm-claude-3` models `claude-3-5-sonnet-latest` at `llm_claude_3.py:39`
- False negative: `simonw/llm-claude-3` models `claude-3-5-haiku-latest` at `llm_claude_3.py:44`
- False negative: `simonw/llm-claude-3` prompts `system-prompt@llm_claude_3.py:251` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `template-prompt@llm_claude_3.py:251` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `system-prompt@llm_claude_3.py:257` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `template-prompt@llm_claude_3.py:257` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `system-prompt@llm_claude_3.py:273` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `template-prompt@llm_claude_3.py:273` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `system-prompt@llm_claude_3.py:278` at `llm_claude_3.py`
- False negative: `simonw/llm-claude-3` prompts `template-prompt@llm_claude_3.py:278` at `llm_claude_3.py`
- False negative: `openai/openai-assistants-quickstart` prompts `system-prompt@app/api/assistants/route.ts:8` at `app/api/assistants/route.ts`
- False negative: `openai/openai-assistants-quickstart` prompts `user-prompt@app/api/assistants/threads/[threadId]/messages/route.ts:10` at `app/api/assistants/threads/[threadId]/messages/route.ts`
- False negative: `openai/openai-realtime-agents` ai_packages `@openai/agents` at `package.json:12`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/chatSupervisor/index.ts:7` at `src/app/agentConfigs/chatSupervisor/index.ts`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/customerServiceRetail/authentication.ts:9` at `src/app/agentConfigs/customerServiceRetail/authentication.ts`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/customerServiceRetail/returns.ts:9` at `src/app/agentConfigs/customerServiceRetail/returns.ts`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/customerServiceRetail/sales.ts:9` at `src/app/agentConfigs/customerServiceRetail/sales.ts`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/customerServiceRetail/simulatedHuman.ts:8` at `src/app/agentConfigs/customerServiceRetail/simulatedHuman.ts`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/simpleHandoff.ts:8` at `src/app/agentConfigs/simpleHandoff.ts`
- False negative: `openai/openai-realtime-agents` prompts `system-prompt@src/app/agentConfigs/simpleHandoff.ts:18` at `src/app/agentConfigs/simpleHandoff.ts`
- False negative: `openai/openai-realtime-agents` prompts `template-prompt@src/app/api/responses/route.ts:19` at `src/app/api/responses/route.ts`
- False negative: `openai/openai-realtime-agents` prompts `template-prompt@src/app/api/responses/route.ts:33` at `src/app/api/responses/route.ts`
- False negative: `openai/openai-structured-outputs-samples` prompts `template-prompt@conversational-assistant/app/api/turn_response/route.ts:19` at `conversational-assistant/app/api/turn_response/route.ts`
- False negative: `openai/openai-structured-outputs-samples` prompts `system-prompt@generative-ui/app/api/generate_ui/route.ts:35` at `generative-ui/app/api/generate_ui/route.ts`
- False negative: `openai/openai-structured-outputs-samples` prompts `user-prompt@generative-ui/app/api/generate_ui/route.ts:39:1` at `generative-ui/app/api/generate_ui/route.ts`
- False negative: `openai/openai-structured-outputs-samples` prompts `system-prompt@resume-extraction/app/api/extract_resume/route.ts:18` at `resume-extraction/app/api/extract_resume/route.ts`
- False negative: `openai/openai-structured-outputs-samples` prompts `user-prompt@resume-extraction/app/api/extract_resume/route.ts:19:1` at `resume-extraction/app/api/extract_resume/route.ts`
- False positive: `modelcontextprotocol/quickstart-resources` ai_packages `mcp` at `mcp-client-python/pyproject.toml:2`
- False positive: `modelcontextprotocol/quickstart-resources` ai_packages `rmcp` at `mcp-client-rust/Cargo.toml:9`
- False positive: `modelcontextprotocol/quickstart-resources` mcp `mcp-server@mcp-client-python/client.py` at `mcp-client-python/client.py:8`
- False positive: `modelcontextprotocol/quickstart-resources` models `claude-sonnet-5` at `mcp-client-python/client.py:76`
- False negative: `modelcontextprotocol/quickstart-resources` ai_packages `mcp` at `mcp-client-python/pyproject.toml:9`
- False negative: `modelcontextprotocol/quickstart-resources` ai_packages `mcp-types` at `mcp-client-python/pyproject.toml:11`
- False negative: `modelcontextprotocol/quickstart-resources` ai_packages `rmcp` at `mcp-client-rust/Cargo.toml:10`
- False negative: `modelcontextprotocol/quickstart-resources` models `claude-sonnet-5` at `mcp-client-python/client.py:13`
- False negative: `modelcontextprotocol/quickstart-resources` mcp `mcp-server@weather-server-go/main.go` at `weather-server-go/main.go`
- False negative: `modelcontextprotocol/quickstart-resources` mcp `mcp-server@weather-server-ruby/weather.rb` at `weather-server-ruby/weather.rb`
- False negative: `modelcontextprotocol/quickstart-resources` mcp `mcp-server@weather-server-rust/src/main.rs` at `weather-server-rust/src/main.rs`
