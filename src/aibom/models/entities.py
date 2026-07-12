"""Core entities of the unified AIBOManagement schema.

Every entity carries ``source_evidence`` — see :mod:`aibom.models.evidence`.
Entity identities are deterministic (derived from type + natural key) so that
repeated scans and merges are stable and content-addressable.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field, computed_field

from aibom.models.evidence import Evidence


class EntityType(str, Enum):
    """Discriminator for the kind of AI supply-chain component."""

    MODEL = "model"
    DATASET = "dataset"
    PROMPT = "prompt"
    AGENT = "agent"
    SERVICE = "service"
    LICENSE = "license"


class RelationshipType(str, Enum):
    """Typed edges between entities in the dependency graph."""

    DEPENDS_ON = "depends_on"
    FINE_TUNED_FROM = "fine_tuned_from"
    TRAINED_ON = "trained_on"
    SERVED_BY = "served_by"
    INVOKES = "invokes"
    USES_PROMPT = "uses_prompt"
    LICENSED_UNDER = "licensed_under"


def _slug(*parts: str) -> str:
    """Build a short, stable identity hash from natural-key parts."""
    raw = "\x1f".join(p.strip().lower() for p in parts if p)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return digest


class Entity(BaseModel):
    """Base class for every inventory component."""

    type: EntityType
    name: str = Field(description="Human-readable natural key for the component.")
    source_evidence: list[Evidence] = Field(
        default_factory=list,
        description="Where this entity was observed. Must be non-empty for real findings.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Deterministic identity: ``<type>:<hash(name)>``."""
        return f"{self.type.value}:{_slug(self.type.value, self.name)}"

    def natural_key(self) -> tuple[str, str]:
        """Key used to deduplicate entities across collectors."""
        return (self.type.value, self.name.strip().lower())


class Model(Entity):
    """A machine-learning model reference (e.g. a Hugging Face repo)."""

    type: EntityType = EntityType.MODEL
    provider: str | None = Field(default=None, description="e.g. 'huggingface', 'openai'.")
    revision: str | None = Field(default=None, description="Pinned commit/tag, if any.")
    revision_pinned: bool = Field(default=False)
    formats: list[str] = Field(
        default_factory=list, description="Serialization formats seen (safetensors, gguf, pickle…)."
    )
    license: str | None = None
    author: str | None = None
    has_model_card: bool | None = None


class Dataset(Entity):
    """A dataset reference."""

    type: EntityType = EntityType.DATASET
    source: str | None = Field(default=None, description="e.g. 'huggingface', local path, URL.")
    license: str | None = None
    provenance: str | None = None


class Prompt(Entity):
    """A prompt: a template file or a hardcoded system/user prompt."""

    type: EntityType = EntityType.PROMPT
    kind: str = Field(default="template", description="'system' | 'template' | 'user'.")
    content_hash: str | None = Field(default=None, description="Hash of the prompt text.")


class Agent(Entity):
    """An agent construction (framework + bound tools + model refs)."""

    type: EntityType = EntityType.AGENT
    framework: str | None = Field(default=None, description="e.g. 'langchain', 'langgraph'.")
    tools: list[str] = Field(default_factory=list)
    model_refs: list[str] = Field(default_factory=list)


class Service(Entity):
    """An external tool/service dependency (MCP server, API endpoint)."""

    type: EntityType = EntityType.SERVICE
    endpoint: str | None = None
    kind: str = Field(default="api", description="'api' | 'mcp' | 'other'.")


class License(Entity):
    """A license, keyed by SPDX id where possible."""

    type: EntityType = EntityType.LICENSE
    spdx_id: str | None = None
    compatibility_class: str | None = None


class Relationship(BaseModel):
    """A typed, evidence-backed edge between two entities."""

    source_id: str
    target_id: str
    relationship: RelationshipType
    source_evidence: list[Evidence] = Field(default_factory=list)
