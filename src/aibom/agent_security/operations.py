"""Recognize AWS SDK (boto3) operations inside Python tool functions.

Supported, deliberately narrow pattern — anything else is not reported:

* ``client = boto3.client("s3")`` (module level or in the function), then
  ``client.<method>(...)``; the client may also be imported from another
  project module (``from app.clients import s3``);
* ``boto3.client("s3").<method>(...)`` directly;
* the call may sit in the tool body or in a project helper the tool calls,
  followed through resolvable calls up to :data:`MAX_HELPER_DEPTH` hops.  Each
  hop is kept as evidence so the path is auditable.

Only methods in :data:`ACTIONS` are mapped to IAM actions.  ``boto3.resource``,
sessions and ``getattr`` dispatch are out of scope.  Argument *values* are
resolved only to build a resource ARN, and only from literals in the function
that makes the call: a bucket passed in as a helper parameter stays ``*``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from aibom.agent_security.models import SecEvidence, SourceType, ToolOperation
from aibom.detectors.project import ProjectIndex
from aibom.detectors.python.parser import PythonModule
from aibom.detectors.python.value_resolver import ValueResolver

MAX_HELPER_DEPTH = 3


@dataclass(frozen=True)
class ActionSpec:
    action: str
    hazard: str
    resource: str  # s3_object | s3_bucket | dynamodb_table | any
    bucket_arg: tuple[str, int] = ("Bucket", -1)  # keyword, positional index
    key_arg: tuple[str, int] = ("Key", -1)


ACTIONS: dict[tuple[str, str], ActionSpec] = {
    ("s3", "get_object"): ActionSpec("s3:GetObject", "read", "s3_object"),
    ("s3", "download_file"): ActionSpec(
        "s3:GetObject", "read", "s3_object", ("Bucket", 0), ("Key", 1)
    ),
    ("s3", "put_object"): ActionSpec("s3:PutObject", "write", "s3_object"),
    ("s3", "upload_file"): ActionSpec(
        "s3:PutObject", "write", "s3_object", ("Bucket", 1), ("Key", 2)
    ),
    ("s3", "copy_object"): ActionSpec("s3:PutObject", "write", "s3_object"),
    ("s3", "delete_object"): ActionSpec("s3:DeleteObject", "delete", "s3_object"),
    ("s3", "delete_objects"): ActionSpec("s3:DeleteObject", "delete", "s3_object"),
    ("s3", "list_objects"): ActionSpec("s3:ListBucket", "list", "s3_bucket"),
    ("s3", "list_objects_v2"): ActionSpec("s3:ListBucket", "list", "s3_bucket"),
    ("dynamodb", "get_item"): ActionSpec("dynamodb:GetItem", "read", "dynamodb_table"),
    ("dynamodb", "query"): ActionSpec("dynamodb:Query", "read", "dynamodb_table"),
    ("dynamodb", "scan"): ActionSpec("dynamodb:Scan", "read", "dynamodb_table"),
    ("dynamodb", "put_item"): ActionSpec("dynamodb:PutItem", "write", "dynamodb_table"),
    ("dynamodb", "update_item"): ActionSpec("dynamodb:UpdateItem", "write", "dynamodb_table"),
    ("dynamodb", "delete_item"): ActionSpec("dynamodb:DeleteItem", "delete", "dynamodb_table"),
    ("secretsmanager", "get_secret_value"): ActionSpec(
        "secretsmanager:GetSecretValue", "secrets_read", "any"
    ),
    ("iam", "create_access_key"): ActionSpec("iam:CreateAccessKey", "admin", "any"),
    ("iam", "attach_role_policy"): ActionSpec("iam:AttachRolePolicy", "admin", "any"),
    ("iam", "put_role_policy"): ActionSpec("iam:PutRolePolicy", "admin", "any"),
}

HAZARD_SEVERITY = {
    "list": "low",
    "read": "medium",
    "write": "high",
    "delete": "high",
    "secrets_read": "high",
    "admin": "critical",
}


def hazard_for_action(action: str) -> str:
    """Hazard of a concrete or wildcard IAM action (used for policy-only changes)."""
    for spec in ACTIONS.values():
        if spec.action.lower() == action.lower():
            return spec.hazard
    lowered = action.lower()
    if lowered == "*" or lowered.startswith("iam:") or lowered.endswith(":*"):
        return "admin"
    verb = lowered.split(":", 1)[-1]
    if verb.startswith(("delete", "remove", "terminate")):
        return "delete"
    if verb.startswith(("put", "create", "update", "attach", "write", "copy")):
        return "write"
    if verb.startswith("list"):
        return "list"
    return "read"


def detect_operations(
    module: PythonModule,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tool_id: str,
    tool_name: str,
    project: ProjectIndex | None = None,
) -> list[ToolOperation]:
    """Operations performed by ``function`` or the project helpers it calls."""
    return _walk(module, function, tool_id, tool_name, project, chain=[], visited=set())


def _walk(
    module: PythonModule,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tool_id: str,
    tool_name: str,
    project: ProjectIndex | None,
    *,
    chain: list[SecEvidence],
    visited: set[tuple[str, int]],
) -> list[ToolOperation]:
    key = (module.relative_path, function.lineno)
    if key in visited or len(chain) > MAX_HELPER_DEPTH:
        return []
    visited.add(key)
    resolver = ValueResolver(module)
    found: list[ToolOperation] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            service = _client_service(module, resolver, node.func.value, node, project)
            if service is not None:
                spec = ACTIONS.get((service, node.func.attr))
                if spec is not None:
                    found.append(
                        _operation(module, node, resolver, spec, service, tool_id, tool_name, chain)
                    )
                continue
        if project is None or len(chain) >= MAX_HELPER_DEPTH:
            continue
        helper = project.python_function(module, node.func)
        if helper is None or helper.info.node is function:
            continue
        hop = SecEvidence(
            file=module.relative_path,
            line=node.lineno,
            kind="ast",
            detail=f"calls helper {helper.module.relative_path}:{helper.info.name}",
        )
        found.extend(
            _walk(
                helper.module,
                helper.info.node,
                tool_id,
                tool_name,
                project,
                chain=[*chain, hop],
                visited=visited,
            )
        )
    return found


def _operation(
    module: PythonModule,
    node: ast.Call,
    resolver: ValueResolver,
    spec: ActionSpec,
    service: str,
    tool_id: str,
    tool_name: str,
    chain: list[SecEvidence],
) -> ToolOperation:
    assert isinstance(node.func, ast.Attribute)
    resource, resolved = _resource(spec, node, resolver)
    return ToolOperation(
        tool_id=tool_id,
        tool_name=tool_name,
        action=spec.action,
        resource=resource,
        resource_resolved=resolved,
        hazard=spec.hazard,
        source_type=SourceType.OBSERVED_STATIC,
        evidence=[
            *(item.model_copy() for item in chain),
            SecEvidence(
                file=module.relative_path,
                line=node.lineno,
                kind="ast",
                detail=f"boto3 {service}.{node.func.attr} -> {spec.action}",
            ),
        ],
    )


def _client_service(
    module: PythonModule,
    resolver: ValueResolver,
    receiver: ast.AST,
    at: ast.AST,
    project: ProjectIndex | None = None,
) -> str | None:
    constructor: ast.AST | None = receiver
    owner, owner_resolver = module, resolver
    if isinstance(receiver, ast.Name):
        assignment = module.assignment_for(receiver.id, at)
        constructor = assignment.value if assignment is not None else None
        if constructor is None and project is not None and receiver.id in module.aliases:
            # `from app.clients import s3`: the client is built where it is defined.
            symbol = project.python_symbol(module, receiver.id)
            bindings = symbol.module.assignments.get((None, symbol.name)) if symbol else None
            if symbol is not None and bindings:
                constructor = max(bindings, key=lambda item: item.line).value
                owner, owner_resolver = symbol.module, ValueResolver(symbol.module)
    if not isinstance(constructor, ast.Call):
        return None
    if (owner.qualified_name(constructor.func) or "") != "boto3.client":
        return None
    argument: ast.AST | None = constructor.args[0] if constructor.args else None
    for keyword in constructor.keywords:
        if keyword.arg == "service_name":
            argument = keyword.value
    if argument is None:
        return None
    value = owner_resolver.resolve(argument)
    return value.value if value.resolved and isinstance(value.value, str) else None


def _argument(call: ast.Call, keyword: str, position: int) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    if 0 <= position < len(call.args):
        return call.args[position]
    return None


def _literal(resolver: ValueResolver, node: ast.AST | None) -> str | None:
    if node is None:
        return None
    value = resolver.resolve(node)
    if value.resolved and isinstance(value.value, str) and value.value:
        return value.value
    return None


def _resource(spec: ActionSpec, call: ast.Call, resolver: ValueResolver) -> tuple[str, bool]:
    if spec.resource in {"s3_object", "s3_bucket"}:
        bucket = _literal(resolver, _argument(call, *spec.bucket_arg))
        if bucket is None:
            return ("arn:aws:s3:::*", False)
        if spec.resource == "s3_bucket":
            return (f"arn:aws:s3:::{bucket}", True)
        key = _literal(resolver, _argument(call, *spec.key_arg))
        if key is None:
            return (f"arn:aws:s3:::{bucket}/*", False)
        return (f"arn:aws:s3:::{bucket}/{key}", True)
    if spec.resource == "dynamodb_table":
        table = _literal(resolver, _argument(call, "TableName", -1))
        return (f"arn:aws:dynamodb:*:*:table/{table or '*'}", False)
    return ("*", False)
