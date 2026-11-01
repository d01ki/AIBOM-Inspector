"""Strictly bounded, offline evaluation of AWS IAM *identity* policy documents.

Evaluated: ``Effect`` (Allow/Deny), ``Action`` and ``Resource`` (string or
list, ``*``/``?`` wildcards), ``Sid``.  Explicit Deny wins.

Not evaluated — and therefore never turned into a positive verdict:
``NotAction``, ``NotResource``, ``Condition``, policy variables, ``Principal``
in an identity policy, resource-based policies, SCPs, permission boundaries,
session policies and role trust policies.  A statement that uses any of them
and *could* apply makes the result ``unknown``.  A missing or unparsable
policy makes the result ``unknown`` too: an unseen policy is never assumed
absent.

``potentially_allowed`` means "an Allow in the supplied identity policies
matches and no supplied Deny does".  It is not an AWS effective-permission
result; see :data:`STANDARD_CONSTRAINTS`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aibom.agent_security.models import (
    AuthorizationPolicy,
    Permission,
    PolicyStatement,
    ResolutionStatus,
    SecEvidence,
    Verdict,
)
from aibom.agent_security.safeio import (
    MAX_POLICY_BYTES,
    InputError,
    read_bounded,
    safe_path,
)

STANDARD_CONSTRAINTS = ["identity-policy-only", "runtime-identity-unverified"]

_SUPPORTED = {"Sid", "Effect", "Action", "Resource"}
_KNOWN_UNSUPPORTED = {"NotAction", "NotResource", "Condition", "Principal", "NotPrincipal"}
_MAX_STATEMENTS = 500


def load_policy(root: Path, reference: str) -> AuthorizationPolicy:
    """Parse one policy file; problems become a non-resolved policy, not an exception.

    Path-safety violations still raise :class:`InputError` — those are input
    errors, not analysis gaps.
    """
    policy_id = reference.strip().replace("\\", "/")
    path = safe_path(root, reference, label=f"policy '{reference}'")
    if not path.is_file():
        return AuthorizationPolicy(
            id=policy_id, status=ResolutionStatus.MISSING, error="policy file not found"
        )
    try:
        text = read_bounded(path, MAX_POLICY_BYTES, label=f"policy '{reference}'")
        document = json.loads(text)
    except (InputError, UnicodeDecodeError, json.JSONDecodeError, FileNotFoundError) as exc:
        message = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
        return AuthorizationPolicy(
            id=policy_id, status=ResolutionStatus.UNRESOLVED, error=f"unparsable: {message}"
        )
    return parse_policy_document(policy_id, document)


def parse_policy_document(policy_id: str, document: Any) -> AuthorizationPolicy:
    if not isinstance(document, dict):
        return _invalid(policy_id, "policy document must be a JSON object")
    raw = document.get("Statement")
    statements_raw = [raw] if isinstance(raw, dict) else raw
    if not isinstance(statements_raw, list) or not statements_raw:
        return _invalid(policy_id, "missing Statement")
    if len(statements_raw) > _MAX_STATEMENTS:
        return _invalid(policy_id, "too many statements")
    statements: list[PolicyStatement] = []
    for index, item in enumerate(statements_raw):
        if not isinstance(item, dict):
            return _invalid(policy_id, f"Statement {index} is not an object")
        effect = item.get("Effect")
        if effect not in {"Allow", "Deny"}:
            return _invalid(policy_id, f"Statement {index} has invalid Effect")
        unsupported = sorted(key for key in item if key not in _SUPPORTED)
        actions = _string_list(item.get("Action"))
        resources = _string_list(item.get("Resource"))
        if actions is None or resources is None:
            return _invalid(policy_id, f"Statement {index} has a non-string Action/Resource")
        if not actions and "NotAction" not in item:
            return _invalid(policy_id, f"Statement {index} has no Action")
        if not resources and "NotResource" not in item:
            return _invalid(policy_id, f"Statement {index} has no Resource")
        sid = item.get("Sid")
        statements.append(
            PolicyStatement(
                index=index,
                sid=sid if isinstance(sid, str) else None,
                effect=effect,
                actions=actions,
                resources=resources,
                unsupported=unsupported,
            )
        )
    return AuthorizationPolicy(id=policy_id, statements=statements)


def _invalid(policy_id: str, message: str) -> AuthorizationPolicy:
    return AuthorizationPolicy(id=policy_id, status=ResolutionStatus.UNSUPPORTED, error=message)


def _string_list(value: Any) -> list[str] | None:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def statement_pointer(statement: PolicyStatement) -> str:
    return f"/Statement/{statement.index}"


def statement_evidence(policy: AuthorizationPolicy, statement: PolicyStatement) -> SecEvidence:
    sid = f" Sid={statement.sid}" if statement.sid else ""
    return SecEvidence(
        file=policy.id,
        pointer=statement_pointer(statement),
        kind="iam_policy",
        detail=f"{statement.effect}{sid}",
    )


def clean_permissions(identity_id: str, policies: list[AuthorizationPolicy]) -> list[Permission]:
    """Grant patterns from statements that use only evaluated elements."""
    found: list[Permission] = []
    for policy in policies:
        for statement in policy.statements:
            if statement.unsupported:
                continue
            for action in statement.actions:
                for resource in statement.resources:
                    found.append(
                        Permission(
                            identity_id=identity_id,
                            effect=statement.effect,
                            action=action,
                            resource=resource,
                            evidence=statement_evidence(policy, statement),
                        )
                    )
    return found


# -- evaluation -------------------------------------------------------------------


@dataclass
class Evaluation:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    evidence: list[SecEvidence] = field(default_factory=list)


def evaluate(
    policies: list[AuthorizationPolicy],
    action: str,
    resource: str,
    *,
    resource_resolved: bool,
) -> Evaluation:
    """Evaluate one request against the supplied identity policies."""
    if not policies:
        return Evaluation(Verdict.UNKNOWN, ["no_policies_supplied"])
    reasons: list[str] = []
    clean_allow: list[SecEvidence] = []
    clean_deny: list[SecEvidence] = []
    maybe_allow: list[SecEvidence] = []
    maybe_deny: list[SecEvidence] = []
    for policy in policies:
        if policy.status is not ResolutionStatus.RESOLVED:
            reasons.append(f"policy_{policy.status.value}:{policy.id}")
            continue
        for statement in policy.statements:
            applies, why = _applies(statement, action, resource, resource_resolved)
            if applies == "no":
                continue
            evidence = statement_evidence(policy, statement)
            if applies == "yes":
                (clean_allow if statement.effect == "Allow" else clean_deny).append(evidence)
            else:
                reasons.append(f"{why}:{policy.id}#{statement_pointer(statement)}")
                (maybe_allow if statement.effect == "Allow" else maybe_deny).append(evidence)

    if clean_deny:
        return Evaluation(Verdict.EXPLICITLY_DENIED, ["explicit_deny_matched"], clean_deny)
    unavailable = any(reason.startswith("policy_") for reason in reasons)
    if unavailable:
        return Evaluation(Verdict.UNKNOWN, reasons, clean_allow + maybe_allow + maybe_deny)
    if maybe_deny and (clean_allow or maybe_allow):
        return Evaluation(
            Verdict.UNKNOWN,
            ["deny_statement_not_evaluable", *reasons],
            clean_allow + maybe_allow + maybe_deny,
        )
    if clean_allow:
        return Evaluation(Verdict.POTENTIALLY_ALLOWED, ["allow_matched"], clean_allow)
    if maybe_allow:
        return Evaluation(Verdict.UNKNOWN, reasons, maybe_allow)
    return Evaluation(Verdict.NO_MATCHING_ALLOW, ["no_allow_matched"])


def _applies(
    statement: PolicyStatement, action: str, resource: str, resource_resolved: bool
) -> tuple[str, str]:
    """``yes`` | ``no`` | ``maybe`` plus the reason for ``maybe``."""
    unsupported = set(statement.unsupported)
    if "Principal" in unsupported or "NotPrincipal" in unsupported:
        return "maybe", "principal_in_identity_policy"
    unknown_keys = unsupported - _KNOWN_UNSUPPORTED
    if unknown_keys:
        return "maybe", "unrecognized_element"

    if "NotAction" in unsupported:
        action_state = "maybe"
    else:
        action_state = (
            "yes"
            if any(glob_match(p, action, ignore_case=True) for p in statement.actions)
            else "no"
        )
    if action_state == "no":
        return "no", ""

    if "NotResource" in unsupported:
        resource_state = "maybe"
    else:
        resource_state = _resource_state(statement.resources, resource, resource_resolved)
    if resource_state == "no":
        return "no", ""

    if "NotAction" in unsupported:
        return "maybe", "not_action_not_evaluated"
    if "NotResource" in unsupported:
        return "maybe", "not_resource_not_evaluated"
    if "Condition" in unsupported:
        return "maybe", "condition_not_evaluated"
    if resource_state == "maybe":
        return "maybe", "resource_not_comparable"
    return "yes", ""


def _resource_state(patterns: list[str], resource: str, resolved: bool) -> str:
    """Does a statement's Resource cover the request?

    A resolved request is a concrete ARN.  An unresolved one is itself a
    pattern (``arn:aws:s3:::bucket/*`` when the key is a tool parameter): it is
    covered only when the statement provably includes *every* instance, and is
    ``maybe`` when the two merely overlap.
    """
    state = "no"
    for pattern in patterns:
        if "${" in pattern:
            state = "maybe"
            continue
        if pattern == "*":
            return "yes"
        if resolved:
            if glob_match(pattern, resource, ignore_case=False):
                return "yes"
            continue
        if _covers(pattern, resource):
            return "yes"
        if _overlaps(pattern, resource):
            state = "maybe"
    return state


def _literal_prefix(value: str) -> str:
    cut = [index for index in (value.find("*"), value.find("?")) if index >= 0]
    return value[: min(cut)] if cut else value


def _covers(pattern: str, request: str) -> bool:
    """Every concrete ARN the request pattern can denote matches ``pattern``."""
    if pattern.endswith("*") and "*" not in pattern[:-1] and "?" not in pattern:
        return _literal_prefix(request).startswith(pattern[:-1])
    return False


def _overlaps(pattern: str, request: str) -> bool:
    left, right = _literal_prefix(pattern), _literal_prefix(request)
    if left == pattern and right == request:
        return left == right
    if left == pattern:  # concrete statement ARN vs request pattern
        return left.startswith(right)
    if right == request:
        return right.startswith(left)
    return left.startswith(right) or right.startswith(left)


def glob_match(pattern: str, value: str, *, ignore_case: bool) -> bool:
    """IAM-style wildcard match: ``*`` any run, ``?`` one character, nothing else."""
    regex = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    )
    flags = re.IGNORECASE | re.DOTALL if ignore_case else re.DOTALL
    return re.fullmatch(regex, value, flags) is not None


def pattern_covered(candidate: str, baseline: list[str], *, ignore_case: bool) -> bool:
    """Whether a candidate grant pattern is already implied by one of ``baseline``."""
    return any(glob_match(pattern, candidate, ignore_case=ignore_case) for pattern in baseline)
