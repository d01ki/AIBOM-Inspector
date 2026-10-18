"""Bounded cross-file prompt flow and tool binding for TypeScript.

Mirrors ``test_cross_file_python``: a Next.js route, a prompt builder, an agent
module and a tool module.  Import shapes covered: relative specifiers,
``tsconfig`` path aliases, barrels (``export * from`` / ``export { } from``),
namespace imports.  Anything else must stay unresolved rather than be guessed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from aibom.impact import build_impact_paths
from aibom.inventory import Inventory
from aibom.models.analysis import Reachability
from aibom.models.entities import Prompt
from aibom.service import run_scan

FIXTURES = Path(__file__).parent / "fixtures"
CANDIDATE = FIXTURES / "xfile-ts-candidate"


def _copy(tmp_path: Path) -> Path:
    target = tmp_path / "app"
    shutil.copytree(CANDIDATE, target)
    return target


def _edit(root: Path, name: str, old: str, new: str) -> None:
    path = root / name
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{old!r} not in {name}"
    path.write_text(text.replace(old, new), encoding="utf-8")


def _system(inventory: Inventory) -> Prompt:
    prompts = [e for e in inventory.entities if isinstance(e, Prompt) and e.kind == "system"]
    assert len(prompts) == 1, [p.name for p in prompts]
    return prompts[0]


def _operations(prompt: Prompt) -> list[str]:
    return [step.operation for step in prompt.data_flow_path]


# -- positive -----------------------------------------------------------------


def test_route_to_tool_path_crosses_four_files() -> None:
    inventory = run_scan(CANDIDATE).inventory
    prompt = _system(inventory)

    assert prompt.user_controlled is True
    assert prompt.source_kind == "http_request"
    assert prompt.usage.reachable is Reachability.TRUE
    assert prompt.reachability_path[0] == "http_route:POST"
    flow_files = {step.file for step in prompt.data_flow_path}
    assert {"app/api/support/route.ts", "lib/prompts.ts", "lib/agent.ts"} <= flow_files
    assert "unresolved_call" not in _operations(prompt)

    [capability] = prompt.capabilities
    assert capability.tool_name == "runDiagnostic"
    assert capability.kind == "command_execution"
    assert capability.controlled_parameters == ["command"]
    assert {item.file for item in capability.source_evidence} == {"lib/tools/diagnostics.ts"}

    [path] = build_impact_paths(inventory)
    assert path.severity.value == "critical"
    assert "approved runbooks" not in prompt.model_dump_json()


def test_barrel_reexports_are_followed(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    (root / "lib" / "index.ts").write_text(
        "export * from './prompts';\nexport { runDiagnostic as diagnostics } from "
        "'./tools/diagnostics';\n",
        encoding="utf-8",
    )
    _edit(
        root,
        "lib/agent.ts",
        "import { buildInstructions } from './prompts';\n"
        "import { runDiagnostic } from './tools/diagnostics';",
        "import { buildInstructions, diagnostics as runDiagnostic } from './index';",
    )
    prompt = _system(run_scan(root).inventory)
    assert prompt.user_controlled is True
    assert [c.kind for c in prompt.capabilities] == ["command_execution"]


def test_namespace_import_is_followed(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    _edit(
        root,
        "lib/agent.ts",
        "import { buildInstructions } from './prompts';",
        "import * as prompts from './prompts';",
    )
    _edit(root, "lib/agent.ts", "buildInstructions(problem)", "prompts.buildInstructions(problem)")
    assert _system(run_scan(root).inventory).user_controlled is True


# -- negative -----------------------------------------------------------------


def test_identical_bom_baseline_has_no_privileged_path() -> None:
    inventory = run_scan(FIXTURES / "xfile-ts-baseline").inventory
    prompt = _system(inventory)
    assert prompt.user_controlled is False
    assert prompt.capabilities  # the same tool is still bound
    user = [e for e in inventory.entities if isinstance(e, Prompt) and e.kind == "user"]
    assert user and user[0].user_controlled is True  # user role alone is not privileged
    assert build_impact_paths(inventory) == []


def test_unbound_tool_is_not_a_capability(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    _edit(root, "lib/agent.ts", "    tools: { runDiagnostic },\n", "")
    inventory = run_scan(root).inventory
    assert _system(inventory).capabilities == []
    assert build_impact_paths(inventory) == []


def test_fixed_command_is_not_model_controlled(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    _edit(root, "lib/tools/diagnostics.ts", "execSync(command,", "execSync('uptime',")
    inventory = run_scan(root).inventory
    assert _system(inventory).capabilities == []
    assert build_impact_paths(inventory) == []


# -- unknown ------------------------------------------------------------------


def test_without_tsconfig_the_alias_is_unresolved(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    (root / "tsconfig.json").unlink()
    prompt = _system(run_scan(root).inventory)
    # The route no longer resolves to runSupportAgent: not proven, never "safe".
    assert prompt.user_controlled is None
    assert prompt.usage.reachable is Reachability.UNKNOWN


def test_external_helper_is_potential_not_proven(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    _edit(
        root,
        "lib/agent.ts",
        "import { buildInstructions } from './prompts';",
        "import { buildInstructions } from 'prompt-kit';",
    )
    prompt = _system(run_scan(root).inventory)
    assert prompt.user_controlled is True
    assert "unresolved_call" in _operations(prompt)


def test_dynamic_import_stays_unresolved(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    _edit(
        root,
        "lib/agent.ts",
        "    system: buildInstructions(problem),",
        "    system: (await import(process.env.PROMPTS!)).POLICY,",
    )
    prompt = _system(run_scan(root).inventory)
    assert prompt.user_controlled is not True
    assert build_impact_paths(run_scan(root).inventory) == []


# -- stability ----------------------------------------------------------------


def test_cyclic_imports_terminate(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    (root / "lib" / "a.ts").write_text(
        "import { pong } from './b';\nexport function ping(x: string) { return pong(x); }\n",
        encoding="utf-8",
    )
    (root / "lib" / "b.ts").write_text(
        "import { ping } from './a';\nexport function pong(x: string) { return ping(x); }\n",
        encoding="utf-8",
    )
    _edit(
        root,
        "lib/prompts.ts",
        "const POLICY",
        "import { ping } from './a';\nconst POLICY",
    )
    _edit(root, "lib/prompts.ts", "${problem}", "${ping(problem)}")
    prompt = _system(run_scan(root).inventory)
    assert "cycle" in _operations(prompt)
    assert prompt.user_controlled is not False


def test_same_export_name_in_two_modules_binds_the_imported_one(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    (root / "lib" / "tools" / "safe.ts").write_text(
        "import { tool } from 'ai';\n"
        "export const runDiagnostic = tool({ execute: async ({ command }) => command });\n",
        encoding="utf-8",
    )
    [capability] = _system(run_scan(root).inventory).capabilities
    assert {item.file for item in capability.source_evidence} == {"lib/tools/diagnostics.ts"}
    _edit(root, "lib/agent.ts", "'./tools/diagnostics'", "'./tools/safe'")
    assert _system(run_scan(root).inventory).capabilities == []
