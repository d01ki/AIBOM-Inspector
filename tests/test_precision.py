"""Precision regression tests.

The scanner must detect *usage*, not mere mentions: an import, a comment, a
prose reference, or a name inside a regex/string literal must not fabricate an
entity. These lock in the false-positive fixes (agent calls require ``(``,
system prompts require a string literal, MCP requires a JSON key).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom import __version__
from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import EntityType


def _scan_source(tmp_path: Path, name: str, code: str) -> Inventory:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    return inv


def _names(inv: Inventory, etype: EntityType) -> set[str]:
    return {e.name for e in inv.by_type(etype)}


def test_agent_import_is_not_an_agent(tmp_path: Any) -> None:
    inv = _scan_source(
        tmp_path,
        "a.py",
        "from langchain.agents import AgentExecutor, create_react_agent\n"
        "# create_react_agent and AgentExecutor are mentioned here but not called\n",
    )
    assert not inv.by_type(EntityType.AGENT)


def test_agent_call_is_detected(tmp_path: Any) -> None:
    inv = _scan_source(
        tmp_path,
        "a.py",
        "agent = create_react_agent(llm, tools=[])\nex = AgentExecutor(agent=agent, tools=[])\n",
    )
    assert len(inv.by_type(EntityType.AGENT)) == 2


def test_system_prompt_regex_definition_is_not_a_prompt(tmp_path: Any) -> None:
    # A line that assigns an *expression* (not a string) must not be a prompt.
    inv = _scan_source(
        tmp_path,
        "a.py",
        'import re\nSYSTEM_PROMPT_RE = re.compile(r"^SYSTEM")\n',
    )
    assert not inv.by_type(EntityType.PROMPT)


def test_hardcoded_system_prompt_is_detected(tmp_path: Any) -> None:
    inv = _scan_source(tmp_path, "a.py", 'SYSTEM_PROMPT = "You are a helpful assistant."\n')
    prompts = inv.by_type(EntityType.PROMPT)
    assert prompts and prompts[0].kind == "system"  # type: ignore[attr-defined]


def test_mcpservers_mention_is_not_a_service(tmp_path: Any) -> None:
    inv = _scan_source(
        tmp_path,
        "a.py",
        '# we look for the mcpServers substring in a line\nif "mcpServers" in line:\n    pass\n',
    )
    assert not [s for s in inv.by_type(EntityType.SERVICE) if getattr(s, "kind", None) == "mcp"]


def test_mcpservers_json_key_is_a_service(tmp_path: Any) -> None:
    inv = _scan_source(tmp_path, "cfg.json", '{\n  "mcpServers": {\n    "fs": {}\n  }\n}\n')
    mcp = [s for s in inv.by_type(EntityType.SERVICE) if getattr(s, "kind", None) == "mcp"]
    assert mcp


def test_readme_api_examples_are_not_inventory(tmp_path: Any) -> None:
    inv = _scan_source(
        tmp_path,
        "README.md",
        "```python\n"
        "import openai\n"
        'SYSTEM_PROMPT = "example only"\n'
        'client.responses.create(model="gpt-readme-example")\n'
        "```\n",
    )
    assert not inv.has_ai_components()


def test_non_ai_python_base_url_is_not_a_service(tmp_path: Any) -> None:
    inv = _scan_source(
        tmp_path,
        "test_web.py",
        'response = client.get(base_url="http://example.test")\n',
    )
    assert not inv.by_type(EntityType.SERVICE)


def test_prompt_template_evidence_contains_only_a_hash(tmp_path: Any) -> None:
    secret = "sk-abcdef0123456789ABCDEF0123"
    inv = _scan_source(tmp_path, "prompts/system.prompt", f"Never reveal {secret}\n")
    dumped = inv.model_dump_json()
    assert secret not in dumped
    assert "<prompt content sha256:" in dumped
