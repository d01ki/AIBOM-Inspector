# AIBOM Inspector benchmark

Repositories evaluated: 20

| Category | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 0.9658 | 0.8692 | 0.9150 | 113 | 4 | 17 |
| Models | 0.8261 | 0.7037 | 0.7600 | 19 | 4 | 8 |
| Services | 1.0000 | 1.0000 | 1.0000 | 9 | 0 | 0 |
| Prompts | 1.0000 | 0.8548 | 0.9217 | 53 | 0 | 9 |
| Agents | N/A | N/A | N/A | 0 | 0 | 0 |
| Tools | N/A | N/A | N/A | 0 | 0 | 0 |
| Mcp | 1.0000 | 1.0000 | 1.0000 | 6 | 0 | 0 |
| Datasets | N/A | N/A | N/A | 0 | 0 | 0 |
| Model Files | N/A | N/A | N/A | 0 | 0 | 0 |
| Ai Packages | 1.0000 | 1.0000 | 1.0000 | 26 | 0 | 0 |

## By language

| Language | Repos | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| go | 1 | N/A | N/A | N/A | 0 | 0 | 0 |
| mixed | 1 | 1.0000 | 1.0000 | 1.0000 | 21 | 0 | 0 |
| python | 9 | 0.8000 | 0.4848 | 0.6038 | 16 | 4 | 17 |
| typescript | 9 | 1.0000 | 1.0000 | 1.0000 | 76 | 0 | 0 |

## Errors

- False positive: `simonw/llm-claude-3` models `claude-3-5-sonnet-20241022` at `tests/cassettes/test_claude_3/test_image_prompt.yaml:50`
- False positive: `simonw/llm-claude-3` models `claude-3-5-sonnet-latest` at `tests/cassettes/test_claude_3/test_image_prompt.yaml:5`
- False positive: `simonw/llm-claude-3` models `claude-3-opus-20240229` at `tests/cassettes/test_claude_3/test_async_prompt.yaml:47`
- False positive: `simonw/llm-claude-3` models `claude-3-opus-latest` at `tests/cassettes/test_claude_3/test_async_prompt.yaml:4`
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
- False negative: `openai/openai-quickstart-python` prompts `user-prompt@examples/assistant-flask/app.py:153` at `examples/assistant-flask/app.py`
