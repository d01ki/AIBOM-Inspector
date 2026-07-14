"""AST detector for Hugging Face models, pipelines, and datasets."""

from __future__ import annotations

from collections.abc import Iterable

from aibom.detectors.base import ScanContext
from aibom.detectors.python.common import (
    argument_node,
    dataset_entity,
    model_entity,
    require_python,
    resolve_argument,
    revision_value,
)
from aibom.detectors.python.value_resolver import ValueResolver
from aibom.detectors.result import Detection

_ROOTS = {
    "transformers",
    "diffusers",
    "sentence_transformers",
    "huggingface_hub",
    "datasets",
    "langchain_huggingface",
}


class HuggingFacePythonDetector:
    detector_id = "python.huggingface.ast"

    def supports(self, path: str) -> bool:
        return path.lower().endswith(".py")

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = require_python(context)
        if not module.has_import(*_ROOTS):
            return
        resolver = ValueResolver(module)
        for call in module.calls:
            qualified = module.qualified_name(call.func) or ""
            qualified_root = qualified.split(".", 1)[0]
            if qualified_root in _ROOTS and qualified.endswith(".from_pretrained"):
                model_arg = argument_node(
                    call,
                    ("pretrained_model_name_or_path", "model_name_or_path", "repo_id"),
                    positional=0,
                )
                if model_arg is None:
                    continue
                revision = revision_value(call, resolver)
                for resolved in resolve_argument(module, call, model_arg, resolver):
                    yield Detection(
                        model_entity(
                            context,
                            call,
                            resolved,
                            detector_id=self.detector_id,
                            provider=_provider_for(resolved.value.value),
                            pattern="huggingface-from-pretrained",
                            revision=revision,
                        )
                    )
                continue

            if qualified_root in _ROOTS and qualified.endswith(".pipeline"):
                model_arg = argument_node(call, ("model", "model_name"))
                if model_arg is None:
                    continue
                revision = revision_value(call, resolver)
                for resolved in resolve_argument(module, call, model_arg, resolver):
                    yield Detection(
                        model_entity(
                            context,
                            call,
                            resolved,
                            detector_id=self.detector_id,
                            provider=_provider_for(resolved.value.value),
                            pattern="huggingface-pipeline-model",
                            revision=revision,
                        )
                    )
                continue

            if qualified.endswith(".load_dataset") or qualified in {
                "datasets.load_dataset",
                "load_dataset",
            }:
                dataset_arg = argument_node(call, ("path", "repo_id"), positional=0)
                if dataset_arg is None:
                    continue
                for resolved in resolve_argument(module, call, dataset_arg, resolver):
                    entity = dataset_entity(
                        context,
                        call,
                        resolved,
                        detector_id=self.detector_id,
                        pattern="huggingface-load-dataset",
                    )
                    if entity is not None:
                        yield Detection(entity)
                continue

            if qualified.startswith("huggingface_hub."):
                repo_arg = argument_node(call, ("repo_id",))
                if repo_arg is None:
                    continue
                for resolved in resolve_argument(module, call, repo_arg, resolver):
                    yield Detection(
                        model_entity(
                            context,
                            call,
                            resolved,
                            detector_id=self.detector_id,
                            provider="huggingface",
                            pattern="huggingface-repo-id",
                            revision=revision_value(call, resolver),
                        )
                    )


def _provider_for(value: object | None) -> str:
    if isinstance(value, str) and (value.startswith((".", "/", "~")) or "\\" in value):
        return "local"
    return "huggingface"
