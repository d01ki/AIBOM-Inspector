"""Approved-agent registry (``approved_agents.yaml``) — operator input only.

The registry is never auto-discovered inside the scanned target: a third-party
repository must not be able to declare its own agents approved.  Without a
registry every agent's ``management_status`` stays ``unknown``; with one, an
agent is ``registered`` when its ``agent_ref`` or ``file:variable`` source (or
an alias) is listed, and ``unregistered`` otherwise.  Nothing is ever labeled
"shadow".

.. code-block:: yaml

    schema_version: 1
    agents:
      - agent_ref: "agent:reviewer"
        aliases: ["app/agent.py:reviewer"]
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aibom.agent_security.safeio import (
    MAX_MANIFEST_BYTES,
    InputError,
    load_structured,
    read_bounded,
)


class _Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    agent_ref: str = Field(min_length=1, max_length=200)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    owner: str | None = Field(default=None, max_length=200)


class AgentRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    agents: list[_Entry] = Field(default_factory=list, max_length=5000)

    @field_validator("schema_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("only schema_version 1 is supported")
        return value

    def refs(self) -> set[str]:
        found: set[str] = set()
        for entry in self.agents:
            found.add(normalize(entry.agent_ref))
            found.update(normalize(alias) for alias in entry.aliases)
        return found


def normalize(value: str) -> str:
    return value.strip().replace("\\", "/").lower()


def load_registry(path: str | Path) -> tuple[AgentRegistry, str]:
    file = Path(path).expanduser().resolve()
    display = file.name
    if not file.is_file():
        raise InputError(f"agent registry not found: {path}")
    text = read_bounded(file, MAX_MANIFEST_BYTES, label="agent registry")
    data = load_structured(text, label=display)
    if not isinstance(data, dict):
        raise InputError(f"{display}: top level must be a mapping")
    try:
        return AgentRegistry.model_validate(data), display
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(item) for item in first["loc"])
        raise InputError(f"{display}: {where}: {first['msg']}") from None
