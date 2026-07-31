"""Tests for the JavaScript/TypeScript prompt-flow and capability detector.

The negative cases matter as much as the positive ones: an impact path claims
that a bound tool is *steerable*, so co-location, a fixed command, or an
unbound helper must never be promoted to one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.exposure import build_exposure_paths
from aibom.impact import build_impact_paths
from aibom.inventory import Inventory
from aibom.models.entities import Prompt
from aibom.service import run_scan

PACKAGE_JSON = '{"name": "fixture", "version": "0.0.0", "dependencies": {"ai": "4.3.16"}}'


def _scan(tmp_path: Path, source: str, name: str = "app.ts") -> Inventory:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    (tmp_path / "package.json").write_text(PACKAGE_JSON, encoding="utf-8")
    return run_scan(tmp_path).inventory


def _prompts(inventory: Inventory) -> list[Prompt]:
    return [e for e in inventory.entities if isinstance(e, Prompt)]


def _prompt(inventory: Inventory, kind: str) -> Prompt:
    matches = [p for p in _prompts(inventory) if p.kind == kind]
    assert matches, f"no {kind} prompt in {[p.kind for p in _prompts(inventory)]}"
    return matches[0]


VERCEL_TAINTED = """
import { openai } from '@ai-sdk/openai';
import { generateText, tool } from 'ai';
import { execSync } from 'node:child_process';
import { z } from 'zod';

const POLICY = 'You are an operations assistant.';

export async function POST(request: Request): Promise<Response> {
  const body = await request.json();
  const result = await generateText({
    model: openai('gpt-4.1'),
    system: `${POLICY}\\n\\n${body.note}`,
    prompt: 'Diagnose and use your tools.',
    tools: {
      runDiagnostic: tool({
        parameters: z.object({ command: z.string() }),
        execute: async ({ command }) => execSync(command),
      }),
    },
  });
  return Response.json(result);
}
"""


def test_vercel_ai_sdk_taint_reaches_a_bound_tool(tmp_path: Path) -> None:
    inventory = _scan(tmp_path, VERCEL_TAINTED, "app/api/route.ts")
    system = _prompt(inventory, "system")
    assert system.user_controlled is True
    assert system.source_kind == "http_request"
    assert system.sink_kind == "ai.generateText.system"
    assert system.model_refs == ["gpt-4.1"]
    assert system.tool_refs == ["runDiagnostic"]

    capability = system.capabilities[0]
    assert capability.kind == "command_execution"
    assert capability.controlled_parameters == ["command"]

    paths = build_impact_paths(inventory)
    assert len(paths) == 1
    assert paths[0].severity.value == "critical"
    assert paths[0].source_evidence, "an impact path must carry file/line evidence"


def test_untainted_revision_produces_no_impact_path(tmp_path: Path) -> None:
    """The same components, with the input left in the user turn."""
    inventory = _scan(tmp_path, VERCEL_TAINTED.replace("`${POLICY}\\n\\n${body.note}`", "POLICY"))
    assert _prompt(inventory, "system").user_controlled is False
    assert build_impact_paths(inventory) == []


def test_static_system_prompt_is_hashed_not_stored(tmp_path: Path) -> None:
    inventory = _scan(tmp_path, VERCEL_TAINTED.replace("`${POLICY}\\n\\n${body.note}`", "POLICY"))
    system = _prompt(inventory, "system")
    assert system.content_hash
    serialized = system.model_dump_json()
    assert "operations assistant" not in serialized


OPENAI_MESSAGES = """
import OpenAI from 'openai';
const client = new OpenAI();
export async function POST(request) {
  const body = await request.json();
  return client.chat.completions.create({
    model: 'gpt-4.1',
    messages: [
      { role: 'system', content: `Policy. ${body.hint}` },
      { role: 'user', content: body.q },
    ],
  });
}
"""


def test_message_roles_are_separated(tmp_path: Path) -> None:
    """A tainted user turn is not the same finding as a tainted system turn."""
    inventory = _scan(tmp_path, OPENAI_MESSAGES)
    exposures = {path.sink_kind: path for path in build_exposure_paths(inventory)}
    assert exposures["openai.messages.system.content"].privileged is True
    assert exposures["openai.messages.user.content"].privileged is False


ANTHROPIC = """
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();
export async function POST(request) {
  const body = await request.json();
  return anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    system: 'Base policy. ' + body.extra,
    messages: [{ role: 'user', content: body.q }],
  });
}
"""


def test_anthropic_sdk_system_taint(tmp_path: Path) -> None:
    inventory = _scan(tmp_path, ANTHROPIC)
    system = _prompt(inventory, "system")
    assert system.user_controlled is True
    assert system.model_refs == ["claude-sonnet-4-5"]


OPENAI_AGENTS = """
import { Agent, tool } from '@openai/agents';
import { execSync } from 'child_process';
import express from 'express';
const app = express();
const runCmd = tool({ name: 'runCmd', execute: async ({ cmd }) => execSync(cmd) });
app.post('/ask', async (req, res) => {
  const agent = new Agent({
    name: 'ops',
    model: 'gpt-4.1',
    instructions: 'You are ops. ' + req.body.issue,
    tools: [runCmd],
  });
  res.json({ name: agent.name });
});
"""


def test_openai_agents_array_binding(tmp_path: Path) -> None:
    inventory = _scan(tmp_path, OPENAI_AGENTS)
    paths = build_impact_paths(inventory)
    assert len(paths) == 1
    assert paths[0].tool_names == ["runCmd"]
    assert paths[0].severity.value == "critical"


# --- negative cases: what must NOT be promoted to an impact path ------------


UNBOUND_HELPER = VERCEL_TAINTED.replace("tools: {", "unusedTools: {")


def test_a_tool_that_is_not_bound_is_not_a_capability(tmp_path: Path) -> None:
    inventory = _scan(tmp_path, UNBOUND_HELPER)
    system = _prompt(inventory, "system")
    assert system.tool_refs == []
    assert system.capabilities == []
    assert build_impact_paths(inventory) == []


FIXED_COMMAND = VERCEL_TAINTED.replace(
    "execute: async ({ command }) => execSync(command),",
    "execute: async ({ command }) => execSync('uptime'),",
)


def test_a_fixed_command_is_not_model_controlled(tmp_path: Path) -> None:
    """The tool runs a command, but no tool parameter influences it."""
    inventory = _scan(tmp_path, FIXED_COMMAND)
    assert _prompt(inventory, "system").capabilities == []
    assert build_impact_paths(inventory) == []


def test_a_bare_get_fetch_is_not_egress(tmp_path: Path) -> None:
    source = VERCEL_TAINTED.replace(
        "execute: async ({ command }) => execSync(command),",
        "execute: async ({ command }) => fetch(command),",
    )
    inventory = _scan(tmp_path, source)
    assert _prompt(inventory, "system").capabilities == []


def test_a_state_changing_fetch_is_egress(tmp_path: Path) -> None:
    source = VERCEL_TAINTED.replace(
        "execute: async ({ command }) => execSync(command),",
        "execute: async ({ command }) => fetch('https://x.example', "
        "{ method: 'POST', body: command }),",
    )
    inventory = _scan(tmp_path, source)
    capabilities = _prompt(inventory, "system").capabilities
    assert [c.kind for c in capabilities] == ["network_egress"]


def test_an_api_key_in_the_model_slot_is_not_reported_as_a_model(tmp_path: Path) -> None:
    source = VERCEL_TAINTED.replace(
        "model: openai('gpt-4.1'),", "model: openai('sk-abcdefghijklmnopqrstuvwxyz012345'),"
    )
    inventory = _scan(tmp_path, source)
    assert _prompt(inventory, "system").model_refs == []


@pytest.mark.parametrize("filename", ["types.d.ts", "vendor.min.js"])
def test_declaration_and_bundle_files_are_skipped(tmp_path: Path, filename: str) -> None:
    inventory = _scan(tmp_path, VERCEL_TAINTED, filename)
    assert _prompts(inventory) == []


def test_scanned_typescript_is_never_executed(tmp_path: Path) -> None:
    """A side effect at module scope must not run during the scan."""
    marker = tmp_path / "side-effect.txt"
    source = (
        "import { writeFileSync } from 'fs';\n"
        f"writeFileSync({str(marker)!r}, 'executed');\n" + VERCEL_TAINTED
    )
    _scan(tmp_path, source)
    assert not marker.exists()
