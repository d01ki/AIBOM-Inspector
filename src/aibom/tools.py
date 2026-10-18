"""Join tools to the agents that bind them and grade how reachable each one is.

Detectors record each tool where it is defined.  Whether it is *bound*, and
whether untrusted input can steer it, depends on prompt analysis in other
files, so it is decided here, after collection.  See :class:`Tool` for the
state ladder.
"""

from __future__ import annotations

from collections import defaultdict

from aibom.inventory import Inventory
from aibom.models.entities import (
    TOOL_STATES,
    Prompt,
    Relationship,
    RelationshipType,
    Tool,
    ToolCapability,
)

_PRIVILEGED = {"system", "developer"}


def state_rank(state: str) -> int:
    return TOOL_STATES.index(state) if state in TOOL_STATES else 0


def link_tools(inventory: Inventory) -> None:
    """Upgrade tool states from bindings and proven steerability (idempotent)."""
    tools = [entity for entity in inventory.entities if isinstance(entity, Tool)]
    by_name: dict[str, list[Tool]] = defaultdict(list)
    for tool in tools:
        by_name[tool.tool_name].append(tool)

    for tool in tools:
        if tool.framework == "mcp" and tool.capabilities:
            # Any MCP client - and the model driving it - chooses the arguments.
            _raise(tool, "potentially_reachable")

    for prompt in (e for e in inventory.entities if isinstance(e, Prompt)):
        for name in prompt.tool_refs:
            bound = _match(by_name.get(name, []), prompt.capabilities, name)
            if bound is None:
                continue
            _raise(bound, "bound")
            if prompt.name not in bound.bound_by:
                bound.bound_by.append(prompt.name)
            if (
                prompt.kind in _PRIVILEGED
                and prompt.user_controlled is True
                and bound.capabilities
            ):
                _raise(bound, "potentially_reachable")
                bound.trust_boundary = bound.trust_boundary or prompt.trust_boundary
            inventory.add_relationship(
                Relationship(
                    source_id=prompt.id,
                    target_id=bound.id,
                    relationship=RelationshipType.INVOKES,
                )
            )


def _match(candidates: list[Tool], capabilities: list[ToolCapability], name: str) -> Tool | None:
    """The tool a binding refers to; ambiguity is left unresolved."""
    if len(candidates) == 1:
        return candidates[0]
    files = {
        item.source_evidence[-1].file
        for item in capabilities
        if item.tool_name == name and item.source_evidence
    }
    matching = [
        tool
        for tool in candidates
        if any(
            capability.source_evidence and capability.source_evidence[-1].file in files
            for capability in tool.capabilities
        )
    ]
    return matching[0] if len(matching) == 1 else None


def _raise(tool: Tool, state: str) -> None:
    if state_rank(state) > state_rank(tool.state):
        tool.state = state
