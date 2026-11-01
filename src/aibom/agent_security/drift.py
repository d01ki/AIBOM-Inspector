"""Security-semantic privilege drift between two agent-security reports.

Independent from the component diff: the AI-BOM can be identical while an
agent's potential capabilities change.  Comparison uses stable keys
(``agent|tool|action|resource``), never line numbers.

Rules that keep the result honest:

* ``unknown -> potentially_allowed`` is ``review_required``, not a confirmed
  addition, and never gates CI; missing data alone cannot create a Critical;
* a policy grant that no bound tool operation uses is reported separately as
  ``identity_permission_expanded`` — it does not claim the agent can act;
* severity (operation hazard + external input) and certainty are separate axes.
"""

from __future__ import annotations

import hashlib

from aibom.agent_security import iam
from aibom.agent_security.models import (
    AgentSecurityReport,
    CapabilityPath,
    Permission,
    PrivilegeChange,
    PrivilegeDriftReport,
    RemediationAdvice,
    ResolutionStatus,
    Verdict,
)
from aibom.agent_security.operations import HAZARD_SEVERITY, hazard_for_action

_LEVELS = ["info", "low", "medium", "high", "critical"]
_ALLOWED = Verdict.POTENTIALLY_ALLOWED
_NOT_ALLOWED = {Verdict.NO_MATCHING_ALLOW, Verdict.EXPLICITLY_DENIED}


def compare_reports(
    baseline: AgentSecurityReport,
    candidate: AgentSecurityReport,
    *,
    bom_identical: bool | None = None,
    bom_differences: list[str] | None = None,
    retest_command: str = "aibom diff <baseline> <candidate> --agent-privileges",
) -> PrivilegeDriftReport:
    before = {path.key: path for path in baseline.capability_paths}
    after = {path.key: path for path in candidate.capability_paths}
    changes: list[PrivilegeChange] = []
    for key in sorted(before.keys() | after.keys()):
        change = _path_change(before.get(key), after.get(key), baseline, candidate, retest_command)
        if change is not None:
            changes.append(change)
    changes.extend(_permission_changes(baseline, candidate, changes, retest_command))
    changes.extend(_permission_removals(baseline, candidate, changes))
    changes.extend(_delegate_changes(baseline, candidate))
    changes.extend(_registry_changes(baseline, candidate, retest_command))
    changes.sort(key=lambda c: (-_LEVELS.index(c.severity), c.type, c.id))
    return PrivilegeDriftReport(
        baseline=baseline.target,
        candidate=candidate.target,
        bom_components_unchanged=bom_identical,
        bom_differences=bom_differences or [],
        security_drift=any(c.type != "potential_privilege_removed" for c in changes),
        scope_mismatch=_scope_mismatch(baseline, candidate),
        changes=changes,
        unknowns_baseline=len(baseline.unknowns),
        unknowns_candidate=len(candidate.unknowns),
    )


# -- capability paths -------------------------------------------------------------


def _path_change(
    old: CapabilityPath | None,
    new: CapabilityPath | None,
    baseline: AgentSecurityReport,
    candidate: AgentSecurityReport,
    retest: str,
) -> PrivilegeChange | None:
    old_verdict = old.verdict if old else None
    new_verdict = new.verdict if new else None
    path = new or old
    assert path is not None
    if new is not None and new_verdict is _ALLOWED:
        if old_verdict is _ALLOWED:
            if old is not None and old.identity_id != new.identity_id:
                return _addition(
                    "privileged_identity_binding_added", old, new, baseline, candidate, retest
                )
            return None
        if old_verdict is Verdict.UNKNOWN:
            return _review(old, new, "baseline verdict was unknown", baseline, candidate)
        if old is None:
            return _addition("privilege_path_added", old, new, baseline, candidate, retest)
        if old.identity_id != new.identity_id:
            return _addition(
                "privileged_identity_binding_added", old, new, baseline, candidate, retest
            )
        return _addition("permission_scope_expanded", old, new, baseline, candidate, retest)
    if old is not None and old_verdict is _ALLOWED:
        if new_verdict is Verdict.UNKNOWN:
            return _review(old, new, "candidate verdict is unknown", baseline, candidate)
        return PrivilegeChange(
            id=_change_id("potential_privilege_removed", path.key),
            type="potential_privilege_removed",
            change_status="supported",
            agent=path.agent_id,
            identity=path.identity_id,
            tool=path.tool_id,
            action=path.action,
            affected_resource=path.resource,
            before=_allowed_actions(baseline, path),
            after=_allowed_actions(candidate, path),
            before_verdict=old_verdict.value if old_verdict else None,
            after_verdict=new_verdict.value if new_verdict else "absent",
            severity="info",
            severity_reasons=["capability no longer potentially allowed"],
            certainty="conditional",
            evidence=_refs(new or old),
        )
    if old_verdict != new_verdict and Verdict.UNKNOWN in {old_verdict, new_verdict}:
        if old is None or new is None:
            return None  # a new/removed unknown path is listed in the report's unknowns
        return _review(old, new, "verdict changed to/from unknown", baseline, candidate, cap="info")
    return None


def _addition(
    kind: str,
    old: CapabilityPath | None,
    new: CapabilityPath,
    baseline: AgentSecurityReport,
    candidate: AgentSecurityReport,
    retest: str,
) -> PrivilegeChange:
    severity, reasons = _severity(new.hazard, new.external_input)
    evidence = _refs(new)
    statements = [ref for ref in evidence if "#/Statement/" in ref]
    actions = [
        f"Remove {new.action} from {stmt} if agent '{new.agent_id}' does not need it, "
        f"or narrow its Resource below {new.resource}."
        for stmt in statements
    ] or [f"Remove or narrow the grant for {new.action} on {new.resource}."]
    actions.append(
        f"Review whether agent '{new.agent_id}' should run as '{new.identity_id}' "
        "(aibom-identity.yaml)."
    )
    actions.append(f"Require human approval before tool '{new.tool_name}' performs {new.action}.")
    why = (
        f"Agent '{new.agent_id}' binds tool '{new.tool_name}', whose code performs "
        f"{new.action} on {new.resource}; the supplied identity policy for "
        f"'{new.identity_id}' now matches it with an Allow."
    )
    if kind == "privilege_path_added":
        why = (
            f"A new agent/tool/operation path appeared: '{new.agent_id}' -> "
            f"'{new.tool_name}' -> {new.action}, and the supplied policy allows it."
        )
    return PrivilegeChange(
        id=_change_id(kind, new.key),
        type=kind,
        change_status="supported",
        agent=new.agent_id,
        identity=new.identity_id,
        tool=new.tool_id,
        action=new.action,
        affected_resource=new.resource,
        before=_allowed_actions(baseline, new),
        after=_allowed_actions(candidate, new),
        before_verdict=old.verdict.value if old else "absent",
        after_verdict=new.verdict.value,
        severity=severity,
        severity_reasons=reasons,
        certainty="conditional",
        evidence=evidence,
        remediation=RemediationAdvice(
            why_it_matters=why,
            conditions=list(new.constraints),
            recommended_actions=actions,
            retest_command=retest,
        ),
        gates=True,
    )


def _review(
    old: CapabilityPath | None,
    new: CapabilityPath | None,
    reason: str,
    baseline: AgentSecurityReport,
    candidate: AgentSecurityReport,
    *,
    cap: str = "medium",
) -> PrivilegeChange:
    path = new or old
    assert path is not None
    severity, reasons = _severity(path.hazard, path.external_input)
    severity = min(severity, cap, key=_LEVELS.index)
    return PrivilegeChange(
        id=_change_id("review_required", path.key),
        type="review_required",
        change_status="review_required",
        agent=path.agent_id,
        identity=path.identity_id,
        tool=path.tool_id,
        action=path.action,
        affected_resource=path.resource,
        before=_allowed_actions(baseline, path),
        after=_allowed_actions(candidate, path),
        before_verdict=old.verdict.value if old else "absent",
        after_verdict=new.verdict.value if new else "absent",
        severity=severity,
        severity_reasons=[*reasons, f"capped at {cap}: {reason}"],
        certainty="unknown",
        evidence=_refs(path),
    )


# -- identity permissions not tied to a tool ---------------------------------------


def _permission_changes(
    baseline: AgentSecurityReport,
    candidate: AgentSecurityReport,
    path_changes: list[PrivilegeChange],
    retest: str,
) -> list[PrivilegeChange]:
    # A path-level change (supported or review_required) already reports the grant.
    explained = {(c.identity, c.action) for c in path_changes if c.agent is not None}
    old_allow: dict[str, list[Permission]] = {}
    for permission in baseline.permissions:
        if permission.effect == "Allow":
            old_allow.setdefault(permission.identity_id, []).append(permission)
    baseline_ids = {identity.id for identity in baseline.identities}
    found: dict[str, PrivilegeChange] = {}
    for permission in candidate.permissions:
        if permission.effect != "Allow" or permission.identity_id not in baseline_ids:
            continue
        existing = old_allow.get(permission.identity_id, [])
        if any(
            iam.glob_match(old.action, permission.action, ignore_case=True)
            and iam.glob_match(old.resource, permission.resource, ignore_case=False)
            for old in existing
        ):
            continue
        if (
            any(
                identity == permission.identity_id
                and action is not None
                and iam.glob_match(permission.action, action, ignore_case=True)
                for identity, action in explained
            )
            and "*" not in permission.action
        ):
            continue
        hazard = hazard_for_action(permission.action)
        severity, reasons = _severity(hazard, False)
        severity = min(severity, "medium", key=_LEVELS.index)
        key = f"{permission.identity_id}|{permission.action}|{permission.resource}"
        found[key] = PrivilegeChange(
            id=_change_id("identity_permission_expanded", key),
            type="identity_permission_expanded",
            change_status="supported",
            identity=permission.identity_id,
            action=permission.action,
            affected_resource=permission.resource,
            before=sorted({p.action for p in existing}),
            after=sorted(
                {
                    p.action
                    for p in candidate.permissions
                    if p.identity_id == permission.identity_id and p.effect == "Allow"
                }
            ),
            severity=severity,
            severity_reasons=[
                *reasons,
                "capped at medium: no analyzed agent tool operation uses this grant",
            ],
            certainty="conditional",
            evidence=[permission.evidence.ref()],
            remediation=RemediationAdvice(
                why_it_matters=(
                    f"Identity '{permission.identity_id}' gained {permission.action} on "
                    f"{permission.resource}. No analyzed tool uses it, so this does not "
                    "show that an agent can perform it — but it widens what any code "
                    "running as this identity could do."
                ),
                conditions=list(iam.STANDARD_CONSTRAINTS),
                recommended_actions=[
                    f"Remove {permission.action} from {permission.evidence.ref()} unless "
                    "another workload requires it.",
                ],
                retest_command=retest,
            ),
        )
    return list(found.values())


def _permission_removals(
    baseline: AgentSecurityReport,
    candidate: AgentSecurityReport,
    path_changes: list[PrivilegeChange],
) -> list[PrivilegeChange]:
    """Clean Allow grants of a shared identity that the candidate no longer has."""
    removed_paths = {
        (c.identity, c.action) for c in path_changes if c.type == "potential_privilege_removed"
    }
    candidate_ids = {identity.id for identity in candidate.identities}
    new_allow = [p for p in candidate.permissions if p.effect == "Allow"]
    found: dict[str, PrivilegeChange] = {}
    for permission in baseline.permissions:
        if permission.effect != "Allow" or permission.identity_id not in candidate_ids:
            continue
        if (permission.identity_id, permission.action) in removed_paths:
            continue
        if any(
            new.identity_id == permission.identity_id
            and iam.glob_match(new.action, permission.action, ignore_case=True)
            and iam.glob_match(new.resource, permission.resource, ignore_case=False)
            for new in new_allow
        ):
            continue
        key = f"{permission.identity_id}|{permission.action}|{permission.resource}"
        found[key] = PrivilegeChange(
            id=_change_id("potential_privilege_removed", key),
            type="potential_privilege_removed",
            change_status="supported",
            identity=permission.identity_id,
            action=permission.action,
            affected_resource=permission.resource,
            before_verdict="granted",
            after_verdict="not_granted",
            severity="info",
            severity_reasons=["identity grant removed from supplied policies"],
            certainty="conditional",
            evidence=[permission.evidence.ref()],
        )
    return list(found.values())


# -- delegation and registry ------------------------------------------------------------


def _delegate_changes(
    baseline: AgentSecurityReport, candidate: AgentSecurityReport
) -> list[PrivilegeChange]:
    """A parent newly able to *delegate to* a potentially allowed child capability.

    Always ``review_required``: handoff guards, approvals and identity
    propagation are not analyzed, so this never claims the parent can act.
    """
    before = {path.key: path for path in baseline.delegate_paths}
    found: list[PrivilegeChange] = []
    for path in candidate.delegate_paths:
        if path.child_verdict is not _ALLOWED:
            continue
        old = before.get(path.key)
        if old is not None and old.child_verdict is _ALLOWED:
            continue
        severity, reasons = _severity(path.hazard, False)
        severity = min(severity, "medium", key=_LEVELS.index)
        refs: list[str] = []
        for evidence in path.evidence:
            if evidence.ref() not in refs:
                refs.append(evidence.ref())
        found.append(
            PrivilegeChange(
                id=_change_id("delegate_path_added", path.key),
                type="delegate_path_added",
                change_status="review_required",
                agent=path.parent_id,
                identity=path.child_identity_id,
                tool=path.tool_id,
                action=path.action,
                affected_resource=path.resource,
                before_verdict=old.child_verdict.value if old else "absent",
                after_verdict=f"child:{path.child_verdict.value}",
                severity=severity,
                severity_reasons=[
                    *reasons,
                    f"via {path.mechanism} to '{path.child_id}'; capped at medium: "
                    "delegation guards and identity propagation are unverified",
                ],
                certainty="unknown",
                evidence=refs,
            )
        )
    return found


def _registry_changes(
    baseline: AgentSecurityReport, candidate: AgentSecurityReport, retest: str
) -> list[PrivilegeChange]:
    """Agents present in the candidate that the supplied registry does not list."""
    if candidate.scope.registry is None:
        return []
    before = {agent.id: agent.management_status for agent in baseline.agents}
    found: list[PrivilegeChange] = []
    for agent in candidate.agents:
        if agent.management_status != "unregistered" or before.get(agent.id) == "unregistered":
            continue
        found.append(
            PrivilegeChange(
                id=_change_id("unregistered_agent_added", agent.id),
                type="unregistered_agent_added",
                change_status="supported",
                agent=agent.id,
                identity=agent.identity_id,
                before_verdict=before.get(agent.id, "absent"),
                after_verdict="unregistered",
                severity="medium",
                severity_reasons=["agent is not listed in the supplied approved-agent registry"],
                certainty="conditional",
                evidence=[evidence.ref() for evidence in agent.evidence],
                remediation=RemediationAdvice(
                    why_it_matters=(
                        f"Agent '{agent.id}' ({agent.source}) is not in the approved-agent "
                        "registry, so its tools and identity have not been reviewed."
                    ),
                    conditions=["registry-supplied-by-operator", "name-or-alias-match-only"],
                    recommended_actions=[
                        "Register the agent (agent_ref or file:variable alias) after review, "
                        "or remove it.",
                    ],
                    retest_command=retest,
                ),
                gates=True,
            )
        )
    return found


# -- helpers -------------------------------------------------------------------------


def _severity(hazard: str, external_input: bool) -> tuple[str, list[str]]:
    base = HAZARD_SEVERITY.get(hazard, "medium")
    reasons = [f"operation hazard '{hazard}' -> {base}"]
    if external_input:
        index = min(_LEVELS.index(base) + 1, len(_LEVELS) - 1)
        base = _LEVELS[index]
        reasons.append("agent instructions reach untrusted input -> +1")
    return base, reasons


def _allowed_actions(report: AgentSecurityReport, path: CapabilityPath) -> list[str]:
    return sorted(
        {
            item.action
            for item in report.capability_paths
            if item.agent_id == path.agent_id
            and item.resource == path.resource
            and item.verdict is _ALLOWED
        }
    )


def _refs(path: CapabilityPath | None) -> list[str]:
    if path is None:
        return []
    refs: list[str] = []
    for evidence in path.evidence:
        ref = evidence.ref()
        if ref not in refs:
            refs.append(ref)
    return refs


def _change_id(kind: str, key: str) -> str:
    return f"{kind}:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:12]}"


def _scope_mismatch(baseline: AgentSecurityReport, candidate: AgentSecurityReport) -> list[str]:
    notes: list[str] = []
    if (baseline.scope.manifest is None) != (candidate.scope.manifest is None):
        side = "baseline" if baseline.scope.manifest is None else "candidate"
        notes.append(f"identity manifest missing in {side}")
    old = {p.id: p.status for p in baseline.policies}
    new = {p.id: p.status for p in candidate.policies}
    for policy_id in sorted(old.keys() | new.keys()):
        left = old.get(policy_id)
        right = new.get(policy_id)
        if left != right and ResolutionStatus.RESOLVED in {left, right}:
            notes.append(
                f"policy {policy_id}: baseline={left.value if left else 'absent'}, "
                f"candidate={right.value if right else 'absent'}"
            )
    return notes
