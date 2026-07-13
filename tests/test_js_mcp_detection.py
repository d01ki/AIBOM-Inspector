"""Detection tests for JS/TS sources, MCP servers, and notebooks.

These cover the gap where a TypeScript AI app or an MCP server repository
produced an empty inventory ("score 100, no details").
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom import __version__
from aibom.collectors.dependencies import DependencyCollector
from aibom.collectors.repo import RepoCollector
from aibom.inventory import Inventory, ScanMetadata
from aibom.models.entities import EntityType


def _scan(tmp_path: Path) -> Inventory:
    inv = Inventory(metadata=ScanMetadata(tool_version=__version__, target=str(tmp_path)))
    RepoCollector(tmp_path).collect(inv)
    DependencyCollector(tmp_path).collect(inv)
    return inv


def _services(inv: Inventory) -> dict[str, Any]:
    return {s.name: s for s in inv.by_type(EntityType.SERVICE)}


def test_ts_openai_import_and_model_id(tmp_path: Any) -> None:
    (tmp_path / "app.ts").write_text(
        'import OpenAI from "openai";\n'
        'const client = new OpenAI();\n'
        'const resp = await client.chat.completions.create({ model: "gpt-4o-mini" });\n',
        encoding="utf-8",
    )
    inv = _scan(tmp_path)
    assert "openai" in _services(inv)
    models = {m.name for m in inv.by_type(EntityType.MODEL)}
    assert "gpt-4o-mini" in models


def test_ts_anthropic_require(tmp_path: Any) -> None:
    (tmp_path / "bot.js").write_text(
        'const Anthropic = require("@anthropic-ai/sdk");\n'
        'const model = "claude-sonnet-4-5";\n',
        encoding="utf-8",
    )
    inv = _scan(tmp_path)
    assert "anthropic" in _services(inv)
    assert any(m.name.startswith("claude-") for m in inv.by_type(EntityType.MODEL))


def test_python_mcp_server_detected(tmp_path: Any) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        'mcp = FastMCP("pentest-tools")\n'
        "@mcp.tool()\n"
        "def run_nmap(target: str) -> str: ...\n",
        encoding="utf-8",
    )
    inv = _scan(tmp_path)
    mcp_services = [s for s in inv.by_type(EntityType.SERVICE)
                    if getattr(s, "kind", None) == "mcp"]
    assert mcp_services, "expected an mcp-server service entity"
    assert mcp_services[0].name == "mcp-server@server.py"


def test_ts_mcp_server_sdk_detected(tmp_path: Any) -> None:
    (tmp_path / "index.ts").write_text(
        'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n',
        encoding="utf-8",
    )
    inv = _scan(tmp_path)
    assert any(getattr(s, "kind", None) == "mcp" for s in inv.by_type(EntityType.SERVICE))


def test_mcp_packages_in_manifests(tmp_path: Any) -> None:
    (tmp_path / "requirements.txt").write_text("mcp==1.0.0\nfastmcp>=2.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}\n', encoding="utf-8"
    )
    inv = _scan(tmp_path)
    pkgs = {p.name for p in inv.by_type(EntityType.PACKAGE)}
    assert {"mcp", "fastmcp", "@modelcontextprotocol/sdk"} <= pkgs


def test_notebook_from_pretrained_detected(tmp_path: Any) -> None:
    (tmp_path / "train.ipynb").write_text(
        '{"cells": [{"cell_type": "code", "source": ['
        '"from transformers import AutoModel\\n", '
        '"m = AutoModel.from_pretrained(\\"bert-base-uncased\\")\\n"]}]}\n',
        encoding="utf-8",
    )
    inv = _scan(tmp_path)
    assert "bert-base-uncased" in {m.name for m in inv.by_type(EntityType.MODEL)}


def test_plain_ts_without_ai_stays_empty(tmp_path: Any) -> None:
    (tmp_path / "util.ts").write_text(
        'import fs from "fs";\nexport const x = 1;\n', encoding="utf-8"
    )
    inv = _scan(tmp_path)
    assert not inv.entities
