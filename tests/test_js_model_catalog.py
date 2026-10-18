"""Gateway-routed and catalog-declared model ids in JS/TS (vercel/ai-chatbot shape).

The positive cases reproduce the external-benchmark false negatives.  The
negative cases pin the precision side: an id is never invented for a dynamic
argument, a lookalike string outside an AI codebase is not a model, and a
catalog entry is recorded as *declared*, never as invoked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.inventory import Inventory
from aibom.models.entities import Model, Service
from aibom.service import run_scan

PACKAGE_JSON = '{"name": "fixture", "version": "0.0.0", "dependencies": {"ai": "5.0.0"}}'

MODELS_TS = """\
export const DEFAULT_CHAT_MODEL = "moonshotai/kimi-k2.5";

export const titleModel = {
  id: "moonshotai/kimi-k2.5",
  name: "Kimi K2.5",
};

export const chatModels: ChatModel[] = [
  { id: "deepseek/deepseek-v3.2", name: "DeepSeek V3.2", provider: "deepseek" },
  { id: "openai/gpt-oss-20b", name: "GPT OSS 20B", provider: "openai" },
];
"""

PROVIDERS_TS = """\
import { gateway } from "ai";
import { titleModel } from "./models";

export function getLanguageModel(modelId: string) {
  return gateway.languageModel(modelId);
}

export function getTitleModel() {
  return gateway.languageModel(titleModel.id);
}
"""


def _write(root: Path, files: dict[str, str], package: str | None = PACKAGE_JSON) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    if package is not None:
        (root / "package.json").write_text(package, encoding="utf-8")


def _models(inventory: Inventory) -> dict[str, Model]:
    return {e.name: e for e in inventory.entities if isinstance(e, Model)}


def _services(inventory: Inventory) -> dict[str, Service]:
    return {e.name: e for e in inventory.entities if isinstance(e, Service)}


def test_gateway_model_resolved_through_imported_object(tmp_path: Path) -> None:
    _write(tmp_path, {"lib/ai/models.ts": MODELS_TS, "lib/ai/providers.ts": PROVIDERS_TS})
    inventory = run_scan(tmp_path).inventory

    kimi = _models(inventory)["moonshotai/kimi-k2.5"]
    assert kimi.usage.invoked is True
    assert kimi.provider == "moonshotai"
    locations = {(item.file, item.line_start) for item in kimi.source_evidence}
    # The call site and the declaration it resolved to are both kept.
    assert ("lib/ai/providers.ts", 9) in locations
    assert ("lib/ai/models.ts", 4) in locations
    assert any(step.operation == "member" for step in kimi.resolution_path)
    assert all(step.value is None for step in kimi.resolution_path)


def test_catalog_entries_are_declared_not_invoked(tmp_path: Path) -> None:
    _write(tmp_path, {"lib/ai/models.ts": MODELS_TS, "lib/ai/providers.ts": PROVIDERS_TS})
    models = _models(run_scan(tmp_path).inventory)

    for name in ("deepseek/deepseek-v3.2", "openai/gpt-oss-20b"):
        assert models[name].usage.declared is True
        assert models[name].usage.invoked is False


def test_gateway_service_recorded_even_when_model_is_dynamic(tmp_path: Path) -> None:
    _write(tmp_path, {"lib/ai/providers.ts": PROVIDERS_TS.replace("titleModel.id", "modelId")})
    inventory = run_scan(tmp_path).inventory

    gateway = _services(inventory)["vercel-ai-gateway"]
    assert gateway.usage.invoked is True
    # Nothing resolvable was passed, so no model id is invented.
    assert not _models(inventory)


def test_environment_model_id_is_not_invented(tmp_path: Path) -> None:
    source = (
        'import { gateway } from "ai";\n'
        "export const m = gateway.languageModel(process.env.CHAT_MODEL!);\n"
    )
    _write(tmp_path, {"lib/p.ts": source})
    assert not _models(run_scan(tmp_path).inventory)


def test_lookalike_ids_outside_an_ai_codebase_are_ignored(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {"src/config.ts": MODELS_TS},
        package='{"name": "fixture", "version": "0.0.0", "dependencies": {"react": "18.0.0"}}',
    )
    assert not _models(run_scan(tmp_path).inventory)


def test_non_model_slash_strings_are_ignored(tmp_path: Path) -> None:
    source = (
        'import { generateText } from "ai";\n'
        "export const routes = [\n"
        '  { id: "react/jsx-runtime" },\n'
        '  { id: "users/profile" },\n'
        '  { id: "openai/" },\n'
        '  { id: "openai/1234" },\n'
        "];\n"
        'export const MODEL_DIR = "public/models";\n'
        "// see openai/gpt-4.1 in the docs\n"
    )
    _write(tmp_path, {"lib/routes.ts": source})
    assert not _models(run_scan(tmp_path).inventory)


def test_gateway_requires_the_sdk_import(tmp_path: Path) -> None:
    # A local object called `gateway` is not the AI Gateway.
    source = (
        'import { generateText } from "ai";\n'
        "const gateway = { languageModel: (id: string) => id };\n"
        'export const m = gateway.languageModel("openai/gpt-4.1");\n'
    )
    _write(tmp_path, {"lib/p.ts": source})
    inventory = run_scan(tmp_path).inventory
    assert "vercel-ai-gateway" not in _services(inventory)
    assert "openai/gpt-4.1" not in _models(inventory)


_CHECKOUT = Path(__file__).resolve().parents[1] / "benchmark" / "checkouts" / "ai-chatbot"
_GROUND_TRUTH = (
    Path(__file__).resolve().parents[1] / "benchmark" / "ground_truth_public" / "ai-chatbot.json"
)


@pytest.mark.skipif(not _CHECKOUT.is_dir(), reason="pinned vercel/ai-chatbot checkout absent")
def test_ai_chatbot_external_regression() -> None:
    """The pinned public case: every previously missed model and the gateway."""
    import json

    from benchmark.evaluate import evaluate_case

    report = evaluate_case(json.loads(_GROUND_TRUTH.read_text(encoding="utf-8")), _CHECKOUT)
    assert report["false_negatives"] == []
    assert report["false_positives"] == []
