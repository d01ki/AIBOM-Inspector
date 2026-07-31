"""Evidence-backed trust-boundary paths through AI prompt sinks.

An inventory says which AI components exist.  Exposure paths add the missing
security context: whether untrusted input is proven to reach a prompt sink,
which trust boundary it crosses, and which model consumes it.

The path deliberately contains only sanitized static-analysis metadata.  Prompt
content is represented by the existing hash when it is statically known and is
never copied into a path.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass

from pydantic import BaseModel, Field

from aibom.inventory import Inventory
from aibom.models.analysis import Reachability, ResolutionStep
from aibom.models.entities import EntityType, Model, Prompt, RelationshipType
from aibom.models.evidence import Evidence
from aibom.policy import entity_in_production_scope

_PRIVILEGED_PROMPT_KINDS = {"system", "developer"}


class ExposurePath(BaseModel):
    """A proven untrusted-input path into an AI prompt sink."""

    id: str = Field(description="Stable path fingerprint used for drift comparison.")
    prompt_anchor: str = Field(
        description="Line-insensitive prompt sink identity used across revisions."
    )
    prompt_id: str
    prompt_name: str
    source_kind: str
    sink_kind: str
    trust_boundary: str
    privileged: bool
    model_ids: list[str] = Field(default_factory=list)
    model_names: list[str] = Field(default_factory=list)
    reachable: Reachability = Reachability.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0)
    source_evidence: list[Evidence] = Field(default_factory=list)
    data_flow_path: list[ResolutionStep] = Field(default_factory=list)

    @property
    def label(self) -> str:
        models = ", ".join(self.model_names) if self.model_names else "unresolved model"
        return f"{self.source_kind} -> {self.sink_kind} -> {models}"


@dataclass(frozen=True)
class PromptSlot:
    """A prompt identity that remains stable when unrelated line numbers move."""

    prompt: Prompt
    key: tuple[str, str, str]
    ordinal: int
    anchor: str


def prompt_slots(inventory: Inventory) -> list[PromptSlot]:
    """Return prompts grouped by file/kind/sink and ordered within each group.

    Prompt entity names include source line numbers for human readability.
    Those names are intentionally unsuitable for revision-to-revision matching:
    adding an unrelated import would make a prompt look removed and re-added.
    This slot identity ignores line numbers while retaining an ordinal for files
    that contain more than one prompt of the same kind and sink.
    """

    groups: dict[tuple[str, str, str], list[Prompt]] = defaultdict(list)
    for entity in inventory.by_type(EntityType.PROMPT):
        if not isinstance(entity, Prompt):
            continue
        if not entity_in_production_scope(entity):
            continue
        file = _sink_file(entity)
        key = (file, entity.kind, entity.sink_kind or "")
        groups[key].append(entity)

    slots: list[PromptSlot] = []
    for key in sorted(groups):
        prompts = sorted(groups[key], key=_sink_position)
        for ordinal, prompt in enumerate(prompts):
            raw = "\x1f".join((*key, str(ordinal)))
            anchor = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            slots.append(
                PromptSlot(
                    prompt=prompt,
                    key=key,
                    ordinal=ordinal,
                    anchor=f"prompt-slot:{anchor}",
                )
            )
    return slots


def build_exposure_paths(inventory: Inventory) -> list[ExposurePath]:
    """Synthesize confirmed untrusted-input paths from inventory evidence."""

    entities = {entity.id: entity for entity in inventory.entities}
    linked_models: dict[str, list[Model]] = defaultdict(list)
    for relationship in inventory.relationships:
        if relationship.relationship is not RelationshipType.FLOWS_TO:
            continue
        target = entities.get(relationship.target_id)
        if isinstance(target, Model):
            linked_models[relationship.source_id].append(target)

    models_by_name = {
        entity.name: entity
        for entity in inventory.by_type(EntityType.MODEL)
        if isinstance(entity, Model)
    }
    paths: list[ExposurePath] = []
    for slot in prompt_slots(inventory):
        prompt = slot.prompt
        if prompt.user_controlled is not True or not prompt.source_kind or not prompt.sink_kind:
            continue

        models = list(linked_models.get(prompt.id, ()))
        for name in prompt.model_refs:
            model = models_by_name.get(name)
            if model is not None and all(existing.id != model.id for existing in models):
                models.append(model)
        models.sort(key=lambda model: model.name)

        model_names = [model.name for model in models]
        raw = "\x1f".join(
            (
                slot.anchor,
                prompt.source_kind,
                prompt.trust_boundary or "unknown",
                *model_names,
            )
        )
        path_id = f"exposure:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"
        confidence = min(
            (evidence.confidence for evidence in prompt.source_evidence),
            default=0.0,
        )
        paths.append(
            ExposurePath(
                id=path_id,
                prompt_anchor=slot.anchor,
                prompt_id=prompt.id,
                prompt_name=prompt.name,
                source_kind=prompt.source_kind,
                sink_kind=prompt.sink_kind,
                trust_boundary=prompt.trust_boundary or "unknown",
                privileged=prompt.kind in _PRIVILEGED_PROMPT_KINDS,
                model_ids=[model.id for model in models],
                model_names=model_names or list(prompt.model_refs),
                reachable=prompt.usage.reachable,
                confidence=confidence,
                source_evidence=[item.model_copy() for item in prompt.source_evidence],
                data_flow_path=[item.model_copy() for item in prompt.data_flow_path],
            )
        )
    return sorted(paths, key=lambda path: (not path.privileged, path.id))


def _sink_file(prompt: Prompt) -> str:
    for evidence in prompt.source_evidence:
        if evidence.kind == "sink":
            return evidence.file
    if prompt.source_evidence:
        return prompt.source_evidence[0].file
    return "<unknown>"


def _sink_position(prompt: Prompt) -> tuple[int, int, str]:
    for evidence in prompt.source_evidence:
        if evidence.kind == "sink":
            return (
                evidence.line_start,
                evidence.column_start or 0,
                prompt.name,
            )
    if prompt.source_evidence:
        evidence = prompt.source_evidence[0]
        return (evidence.line_start, evidence.column_start or 0, prompt.name)
    return (0, 0, prompt.name)
