"""SARIF 2.1.0 export — findings as a static-analysis interchange log.

SARIF (Static Analysis Results Interchange Format, OASIS standard) is what
CI platforms ingest natively: upload the file produced here to GitHub Code
Scanning, Azure DevOps, or any SARIF viewer and every finding appears as an
annotated alert at its `file:line`, with the rule metadata, remediation, and
severity carried along.

Like every output of the tool, the log is deterministic: same inventory in,
byte-identical SARIF out.
"""

from __future__ import annotations

import json
from typing import Any

from aibom import __version__
from aibom.models.findings import Finding, Severity

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_INFO_URI = "https://github.com/d01ki/AIBOM-Inspector"

# SARIF has three notification levels; GitHub additionally reads the numeric
# "security-severity" rule property (CVSS-like 0-10) to bucket alerts.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Render ``findings`` as a SARIF 2.1.0 log (single run)."""
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id in rule_index:
            continue
        rule_index[finding.rule_id] = len(rules)
        rules.append(_rule(finding))

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AIBOM Inspector",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": [_result(f, rule_index[f.rule_id]) for f in findings],
            }
        ],
    }


def to_sarif_json(findings: list[Finding]) -> str:
    """Serialize :func:`to_sarif` deterministically."""
    return json.dumps(to_sarif(findings), indent=2, sort_keys=False) + "\n"


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("-", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.remediation},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", "ai-supply-chain", finding.category.value],
        },
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    message = finding.title
    if finding.entity_name:
        message = f"{message} ({finding.entity_name})"
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{message}. {finding.remediation}"},
        "locations": [_location(finding)],
    }
    fingerprint = _fingerprint(finding)
    if fingerprint:
        result["partialFingerprints"] = {"aibomFinding/v1": fingerprint}
    return result


def _location(finding: Finding) -> dict[str, Any]:
    if not finding.source_evidence:
        # SARIF requires a location object; an artifact-less finding (e.g. a
        # resolver-derived one) is anchored to the repo root.
        return {"physicalLocation": {"artifactLocation": {"uri": "."}}}
    ev = finding.source_evidence[0]
    region: dict[str, Any] = {"startLine": ev.line_start, "endLine": ev.line_end}
    if ev.column_start is not None:
        region["startColumn"] = ev.column_start
    if ev.column_end is not None:
        region["endColumn"] = ev.column_end
    if ev.snippet:
        region["snippet"] = {"text": ev.snippet}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": ev.file.replace("\\", "/")},
            "region": region,
        }
    }


def _fingerprint(finding: Finding) -> str:
    """Stable identity so re-uploads update alerts instead of duplicating them."""
    parts = [finding.rule_id, finding.entity_name or ""]
    if finding.source_evidence:
        ev = finding.source_evidence[0]
        parts.append(ev.file.replace("\\", "/"))
        parts.append(str(ev.line_start))
    return "/".join(p for p in parts if p)
