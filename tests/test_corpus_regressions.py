"""Regressions for defects the 20-repository corpus exposed (first run 2026-10-18).

Each test is a minimal reproduction written from the corpus finding, so the
fix is pinned without needing the external checkouts.
"""

from __future__ import annotations

from pathlib import Path

from aibom.inventory import Inventory
from aibom.models.entities import Model, Package, Prompt, Service
from aibom.service import run_scan


def _scan(root: Path, files: dict[str, str]) -> Inventory:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return run_scan(root, lockfiles=False).inventory


def _prompt_names(inventory: Inventory) -> set[str]:
    return {e.name for e in inventory.entities if isinstance(e, Prompt)}


def _mcp_servers(inventory: Inventory) -> set[str]:
    return {e.name for e in inventory.entities if isinstance(e, Service) and e.kind == "mcp"}


# -- manifests (quickstart-resources) -------------------------------------------


def test_package_line_is_the_dependency_not_a_substring_or_comment(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "pyproject.toml": (
                '[project]\nname = "mcp-client"\ndependencies = [\n'
                '    # mcp is pinned below\n    "mcp>=2.3.0",\n]\n'
            ),
            "Cargo.toml": (
                '[package]\nname = "x"\n[dependencies]\n'
                "# Only the client half of rmcp is needed.\n"
                'rmcp = { version = "3.4" }\n'
            ),
        },
    )
    lines = {
        e.name: {item.line_start for item in e.source_evidence}
        for e in inventory.entities
        if isinstance(e, Package)
    }
    assert lines["mcp"] == {5}
    assert lines["rmcp"] == {5}


# -- MCP servers vs clients (quickstart-resources) -------------------------------


def test_mcp_clients_are_not_servers(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "client.py": "from mcp import Client, StdioServerParameters\n",
            "client.ts": "import { Client } from '@modelcontextprotocol/client';\n",
            "sdk_client.ts": (
                "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n"
            ),
        },
    )
    assert _mcp_servers(inventory) == set()


def test_mcp_servers_in_every_sdk_language(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "server.py": "from mcp.server import MCPServer\nmcp = MCPServer('w')\n",
            "server.ts": "import { McpServer } from '@modelcontextprotocol/server';\n",
            "main.go": "package main\nfunc main() { server := mcp.NewServer(nil, nil) }\n",
            "weather.rb": "server = MCP::Server.new(name: 'weather')\n",
            "main.rs": "impl ServerHandler for Weather {}\n",
        },
    )
    assert _mcp_servers(inventory) == {
        f"mcp-server@{name}"
        for name in ("server.py", "server.ts", "main.go", "weather.rb", "main.rs")
    }


# -- OpenAI call shapes (structured-outputs, assistants, realtime) ---------------


def test_chat_completions_stream_and_parse_are_prompt_sinks(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "app.py": (
                "from openai import OpenAI\nclient = OpenAI()\n"
                "client.beta.chat.completions.parse(model='gpt-4o', messages=["
                "{'role': 'system', 'content': 'Extract.'}])\n"
            ),
            "route.ts": (
                "import OpenAI from 'openai';\nconst openai = new OpenAI();\n"
                "openai.beta.chat.completions.stream({ model: 'gpt-4o', messages: [\n"
                "  { role: 'system', content: 'Extract.' },\n]});\n"
            ),
        },
    )
    names = _prompt_names(inventory)
    assert "system-prompt@app.py:3" in names
    assert "system-prompt@route.ts:4" in names


def test_client_imported_from_a_project_module_is_recognized(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "app/openai.ts": "import OpenAI from 'openai';\nexport const openai = new OpenAI();\n",
            "app/route.ts": (
                "import { openai } from './openai';\n"
                "export async function POST() {\n"
                "  return openai.beta.assistants.create({ instructions: 'Be brief.', "
                "model: 'gpt-4o' });\n}\n"
            ),
            "clients.py": "import anthropic\nclient = anthropic.Anthropic()\n",
            "use.py": (
                "from clients import client\n"
                "client.messages.create(model='claude-sonnet-5', system='Be brief.', "
                "messages=[])\n"
            ),
        },
    )
    names = _prompt_names(inventory)
    assert "system-prompt@app/route.ts:3" in names
    assert "system-prompt@use.py:2" in names


def test_realtime_agent_instructions_are_prompts(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "agent.ts": (
                "import { RealtimeAgent } from '@openai/agents/realtime';\n"
                "export const a = new RealtimeAgent({\n  name: 'a',\n"
                "  instructions: 'Greet.',\n});\n"
            )
        },
    )
    assert "system-prompt@agent.ts:4" in _prompt_names(inventory)


def test_spread_request_body_is_a_template_prompt(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "route.ts": (
                "import OpenAI from 'openai';\n"
                "export async function POST(req: Request) {\n"
                "  const body = await req.json();\n  const openai = new OpenAI();\n"
                "  return openai.responses.create({\n    ...body,\n    stream: false,\n  });\n}\n"
            )
        },
    )
    [prompt] = [e for e in inventory.entities if isinstance(e, Prompt)]
    assert prompt.kind == "template"
    assert prompt.user_controlled is True  # the request body, forwarded


# -- models (gemini-chatbot, quickstart-resources) -------------------------------


def test_ai_sdk_provider_factory_models(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "ai/index.ts": (
                "import { google } from '@ai-sdk/google';\n"
                "import { openai } from '@ai-sdk/openai';\n"
                "import { createUI } from '@ai-sdk/react';\n"
                "export const pro = google('gemini-2.5-pro');\n"
                "export const chat = openai.chat('gpt-4.1');\n"
                "export const ui = createUI('not-a-model');\n"
            )
        },
    )
    models = {e.name: e for e in inventory.entities if isinstance(e, Model)}
    assert models["gemini-2.5-pro"].provider == "google"
    assert "gpt-4.1" in models
    assert "not-a-model" not in models


def test_python_model_keeps_its_declaration_line(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "client.py": (
                "import anthropic\nMODEL = 'claude-sonnet-5'\nclient = anthropic.Anthropic()\n"
                "client.messages.create(model=MODEL, max_tokens=1, messages=[])\n"
            )
        },
    )
    [model] = [e for e in inventory.entities if isinstance(e, Model)]
    assert {item.line_start for item in model.source_evidence} >= {2, 4}


def test_allowlist_gaps_from_the_corpus(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "pyproject.toml": (
                '[project]\nname = "x"\ndependencies = ["llm>=0.19", "mcp-types>=2.2"]\n'
            ),
            "package.json": '{"dependencies": {"@openai/agents": "^0.0.5"}}',
        },
    )
    ai = {e.name for e in inventory.entities if isinstance(e, Package) and e.ai}
    assert {"llm", "mcp-types", "@openai/agents"} <= ai


def test_assistants_thread_message_is_a_prompt(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "route.ts": (
                "import OpenAI from 'openai';\nconst openai = new OpenAI();\n"
                "export async function POST(request) {\n"
                "  const { content } = await request.json();\n"
                "  await openai.beta.threads.messages.create('t', {\n"
                "    role: 'user',\n    content: content,\n  });\n}\n"
            ),
            "app.py": (
                "from openai import OpenAI\nclient = OpenAI()\n"
                "client.beta.threads.messages.create(thread_id='t', role='user', content='hi')\n"
            ),
        },
    )
    prompts = {e.name: e for e in inventory.entities if isinstance(e, Prompt)}
    assert prompts["user-prompt@route.ts:7"].user_controlled is True
    assert "user-prompt@app.py:3" in prompts


def test_semicolon_free_imports_and_type_casts_parse(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        {
            "route.ts": (
                "import { MODEL } from './constants'\n"
                "import OpenAI from 'openai'\n"
                "const openai = new OpenAI()\n"
                "export async function POST(request: Request) {\n"
                "  const { input } = await request.json()\n"
                "  const messages = [\n"
                "    { role: 'system', content: 'Classify.' },\n"
                "    { role: 'user', content: input },\n"
                "  ] as Message[]\n"
                "  return openai.chat.completions.create({ model: MODEL, messages })\n"
                "}\n"
            ),
        },
    )
    assert {"system-prompt@route.ts:7", "user-prompt@route.ts:8:1"} <= _prompt_names(inventory)
