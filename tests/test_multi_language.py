"""Phase 1 coverage: languages read by the pattern layer only.

Go, Java, Rust, Ruby, C# and PHP get inventory-level detection — models,
provider SDKs, prompt constants, secrets and dependencies. They deliberately do
**not** get prompt-flow or blast-radius analysis: those claims require a syntax
tree, which only Python and JS/TS have.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.collectors.repo import _RE_SYSTEM_PROMPT_VAR
from aibom.impact import build_impact_paths
from aibom.inventory import Inventory
from aibom.models.entities import EntityType
from aibom.service import run_scan

FIXTURE = Path(__file__).parent / "fixtures" / "multi-language-agent"


@pytest.fixture(scope="module")
def inventory() -> Inventory:
    return run_scan(FIXTURE).inventory


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        ("github.com/sashabaranov/go-openai", "Go"),
        ("async-openai", "crates.io"),
        ("com.openai:openai-java", "Maven"),
        ("ruby-openai", "RubyGems"),
        ("openai-php/client", "Packagist"),
        ("OpenAI", "NuGet"),
    ],
)
def test_ai_dependency_found_per_ecosystem(
    inventory: Inventory, name: str, ecosystem: str
) -> None:
    packages = {p.name: p for p in inventory.by_type(EntityType.PACKAGE)}
    assert packages[name].ecosystem == ecosystem
    assert packages[name].ai is True
    assert packages[name].purl


@pytest.mark.parametrize(
    "name", ["github.com/gin-gonic/gin", "tokio", "org.slf4j:slf4j-api", "rails",
             "monolog/monolog", "Newtonsoft.Json"]
)
def test_ordinary_dependency_is_inventoried_but_not_flagged(
    inventory: Inventory, name: str
) -> None:
    packages = {p.name: p for p in inventory.by_type(EntityType.PACKAGE)}
    assert name in packages, "a complete BOM must still list ordinary dependencies"
    assert packages[name].ai is False


@pytest.mark.parametrize("model", ["gpt-4.1", "gpt-4o-mini", "claude-sonnet-4-5"])
def test_model_ids_found_in_go_rust_and_java(inventory: Inventory, model: str) -> None:
    assert model in {m.name for m in inventory.by_type(EntityType.MODEL)}


def test_prompt_constants_found_in_go_rust_and_java(inventory: Inventory) -> None:
    files = {
        e.source_evidence[0].file
        for e in inventory.by_type(EntityType.PROMPT)
        if e.source_evidence
    }
    assert {"main.go", "agent.rs", "Agent.java"} <= files


def test_no_behavioral_claims_for_pattern_only_languages(inventory: Inventory) -> None:
    """Impact paths need a syntax tree; the regex layer must not fabricate one."""
    assert build_impact_paths(inventory) == []
    assert all(
        prompt.user_controlled is not True
        for prompt in inventory.by_type(EntityType.PROMPT)
    )


@pytest.mark.parametrize(
    "line",
    [
        'SYSTEM_PROMPT = "You are ops."',
        '    static final String SYSTEM_PROMPT = "You are ops.";',
        'const SYSTEM_PROMPT: &str = "You are ops.";',
        '  systemPrompt := "You are ops."',
        'const string SystemPrompt = "You are ops.";',
        'AGENT_SYSTEM_PROMPT = "hi"',
    ],
)
def test_prompt_constant_shape_is_recognized(line: str) -> None:
    assert _RE_SYSTEM_PROMPT_VAR.search(line)


@pytest.mark.parametrize(
    "line",
    [
        'ecosystem = "npm"',
        'filesystem_path = "/tmp"',
        'operating_system = "linux"',
        'subsystem = "a"',
        'self.ecosystem = "npm"',
        'SYSTEM_PROMPT = re.compile(r"x")',
    ],
)
def test_words_containing_system_are_not_prompts(line: str) -> None:
    """'system' as a substring is the obvious false-positive trap here."""
    assert not _RE_SYSTEM_PROMPT_VAR.search(line)
