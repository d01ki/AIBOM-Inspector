"""SARIF 2.1.0 log for agent privilege drift (additions and reviews only).

Kept separate from :mod:`aibom.export.sarif` so the existing findings log is
unchanged.  Each result points at the first source location of its evidence
(the tool's operation line, else the policy file) and carries the stable
change ID as a partial fingerprint, so re-runs deduplicate in Code Scanning.
Removals are not alerts and are omitted.
"""

from __future__ import annotations

import json
import re
from typing import Any

from aibom import __version__
from aibom.agent_security.models import PrivilegeChange, PrivilegeDriftReport

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/d01ki/AIBOM-Inspector/blob/main/docs/agent-privilege-drift.md"

RULES: dict[str, tuple[str, str]] = {
    "permission_scope_expanded": (
        "AIBOM-AGENT-001",
        "An agent tool operation became potentially allowed by the supplied identity policy.",
    ),
    "privilege_path_added": (
        "AIBOM-AGENT-002",
        "A new agent -> tool -> cloud operation path is potentially allowed.",
    ),
    "privileged_identity_binding_added": (
        "AIBOM-AGENT-003",
        "An agent tool operation is now potentially allowed through a different identity.",
    ),
    "identity_permission_expanded": (
        "AIBOM-AGENT-004",
        "An agent identity gained a grant that no analyzed tool operation uses.",
    ),
    "review_required": (
        "AIBOM-AGENT-005",
        "An agent capability verdict changed to or from unknown; review required.",
    ),
    "delegate_path_added": (
        "AIBOM-AGENT-006",
        "An agent can delegate to another agent whose operation is potentially allowed.",
    ),
    "unregistered_agent_added": (
        "AIBOM-AGENT-007",
        "An agent is not listed in the supplied approved-agent registry.",
    ),
    "mcp_tool_exposure_added": (
        "AIBOM-AGENT-008",
        "An MCP tool became exposed to an analyzed agent.",
    ),
}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}
_LINE_REF = re.compile(r"^(?P<file>.+):(?P<line>\d+)$")


def to_sarif(report: PrivilegeDriftReport) -> dict[str, Any]:
    changes = [c for c in report.changes if c.type in RULES]
    used = sorted({c.type for c in changes}, key=lambda t: RULES[t][0])
    index = {kind: position for position, kind in enumerate(used)}
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIBOM Inspector (agent privilege drift)",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": [_rule(kind) for kind in used],
                    }
                },
                "results": [_result(change, index[change.type]) for change in changes],
            }
        ],
    }


def to_sarif_json(report: PrivilegeDriftReport) -> str:
    return json.dumps(to_sarif(report), indent=2) + "\n"


def _rule(kind: str) -> dict[str, Any]:
    rule_id, text = RULES[kind]
    return {
        "id": rule_id,
        "name": kind,
        "shortDescription": {"text": text},
        "helpUri": _INFO_URI,
        "properties": {"tags": ["security", "ai-agent", "privilege-drift"]},
    }


def _result(change: PrivilegeChange, rule_index: int) -> dict[str, Any]:
    subject = change.agent or change.identity or "agent"
    message = (
        f"{change.type}: {subject} {change.action or ''} on {change.affected_resource or '-'} "
        f"(certainty: {change.certainty}; identity-policy-only, not effective AWS "
        "authorization)."
    )
    if change.remediation is not None:
        message += f" Fix: {change.remediation.recommended_actions[0]}"
    return {
        "ruleId": RULES[change.type][0],
        "ruleIndex": rule_index,
        "level": _LEVEL.get(change.severity, "note"),
        "message": {"text": message},
        "locations": [_location(change)],
        "partialFingerprints": {"aibomChangeId": change.id},
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(change.severity, "1.0"),
            "certainty": change.certainty,
            "changeStatus": change.change_status,
        },
    }


def _location(change: PrivilegeChange) -> dict[str, Any]:
    line_refs = [ref for ref in change.evidence if _LINE_REF.match(ref)]
    if line_refs:
        match = _LINE_REF.match(line_refs[-1])
        assert match is not None
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": match["file"]},
                "region": {"startLine": int(match["line"])},
            }
        }
    file = change.evidence[0].split("#", 1)[0] if change.evidence else "aibom-identity.yaml"
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file},
            "region": {"startLine": 1},
        }
    }
