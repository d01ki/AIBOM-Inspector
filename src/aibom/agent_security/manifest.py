"""``aibom-identity.yaml`` — the explicit agent -> identity -> policy mapping.

The manifest is the *only* way an agent acquires a ``RUNS_AS`` edge in P0:
source code alone never names the cloud principal a process runs as.  Keys are
validated strictly (unknown keys are errors) and credential-looking keys are
rejected without echoing their values.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aibom.agent_security.safeio import (
    MAX_MANIFEST_BYTES,
    InputError,
    load_structured,
    read_bounded,
    safe_path,
)

DEFAULT_MANIFEST = "aibom-identity.yaml"
MAX_ENTRIES = 500

_SECRET_KEY = re.compile(
    r"(secret|password|passwd|token|access[_-]?key|private[_-]?key|credential|session[_-]?key)",
    re.IGNORECASE,
)
_SOURCE = re.compile(r"^[^:]+\.py:[A-Za-z_][A-Za-z0-9_]*$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AgentMapping(_Strict):
    agent_ref: str = Field(min_length=1, max_length=200)
    source: str = Field(description="<workspace-relative .py file>:<assigned variable>")
    identity_ref: str = Field(min_length=1, max_length=300)

    @field_validator("source")
    @classmethod
    def _source_shape(cls, value: str) -> str:
        value = value.replace("\\", "/")
        if not _SOURCE.match(value):
            raise ValueError("source must look like 'path/to/file.py:variable'")
        return value


class IdentityDefinition(_Strict):
    id: str = Field(min_length=1, max_length=300)
    provider: str = Field(pattern=r"^aws$")
    policies: list[str] = Field(default_factory=list, max_length=50)
    provenance: str = "explicit_manifest"

    @field_validator("provenance")
    @classmethod
    def _provenance(cls, value: str) -> str:
        if value != "explicit_manifest":
            raise ValueError("only 'explicit_manifest' provenance is supported")
        return value


class ToolDeclaration(_Strict):
    """Explicit tool -> IAM action mapping for tools the AST pass cannot see into."""

    source: str = Field(description="<workspace-relative .py file>:<tool function>")
    actions: list[str] = Field(min_length=1, max_length=50)
    resources: list[str] = Field(default_factory=lambda: ["*"], max_length=50)

    @field_validator("source")
    @classmethod
    def _source_shape(cls, value: str) -> str:
        value = value.replace("\\", "/")
        if not _SOURCE.match(value):
            raise ValueError("source must look like 'path/to/file.py:function'")
        return value

    @field_validator("actions")
    @classmethod
    def _actions(cls, value: list[str]) -> list[str]:
        for action in value:
            if not re.fullmatch(r"[a-z0-9\-]+:[A-Za-z0-9]+", action):
                raise ValueError(f"'{action}' is not a concrete IAM action (service:Action)")
        return value


class McpServerMapping(_Strict):
    """Identity an MCP server *process* runs as (it is not the agent's process)."""

    source: str = Field(description="Workspace-relative .py file defining the server.")
    identity_ref: str = Field(min_length=1, max_length=300)

    @field_validator("source")
    @classmethod
    def _source_shape(cls, value: str) -> str:
        value = value.replace("\\", "/")
        if not re.fullmatch(r"[^:]+\.py", value):
            raise ValueError("source must be a workspace-relative .py file")
        return value


class IdentityManifest(_Strict):
    schema_version: int
    agents: list[AgentMapping] = Field(default_factory=list, max_length=MAX_ENTRIES)
    identities: list[IdentityDefinition] = Field(default_factory=list, max_length=MAX_ENTRIES)
    tools: list[ToolDeclaration] = Field(default_factory=list, max_length=MAX_ENTRIES)
    mcp_servers: list[McpServerMapping] = Field(default_factory=list, max_length=MAX_ENTRIES)

    @field_validator("schema_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("only schema_version 1 is supported")
        return value


def load_manifest(root: Path, reference: str | Path) -> tuple[IdentityManifest, str]:
    """Load and validate a manifest; returns it with its display path.

    A relative ``reference`` resolves inside ``root`` (the scan target).  An
    absolute path is accepted only because the operator typed it; references
    *inside* the manifest are always confined to ``root``.
    """
    ref = Path(reference)
    if ref.is_absolute():
        path = ref.resolve()
        display = path.name
    else:
        path = safe_path(root, str(reference), label="identity manifest")
        display = str(reference).replace("\\", "/")
    if not path.is_file():
        raise InputError(f"identity manifest not found: {display}")
    text = read_bounded(path, MAX_MANIFEST_BYTES, label="identity manifest")
    data = load_structured(text, label=display)
    if not isinstance(data, dict):
        raise InputError(f"{display}: top level must be a mapping")
    _reject_secret_keys(data, display, "")
    try:
        manifest = IdentityManifest.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(item) for item in first["loc"])
        raise InputError(f"{display}: {where}: {first['msg']}") from None
    for identity in manifest.identities:
        for policy in identity.policies:
            safe_path(root, policy, label=f"{display}: identity '{identity.id}' policy")
    ids = [identity.id for identity in manifest.identities]
    if len(ids) != len(set(ids)):
        raise InputError(f"{display}: duplicate identity id")
    refs = [agent.agent_ref for agent in manifest.agents]
    if len(refs) != len(set(refs)):
        raise InputError(f"{display}: duplicate agent_ref")
    return manifest, display


def _reject_secret_keys(value: Any, display: str, where: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                raise InputError(
                    f"{display}: key '{where}{key}' looks like a credential; the identity "
                    "manifest must reference identities, never contain credentials"
                )
            _reject_secret_keys(item, display, f"{where}{key}.")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_keys(item, display, f"{where}{index}.")
