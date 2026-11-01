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
from aibom.detectors.project import ProjectIndex, PyFunctionRef, python_returns
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
    derived: bool = False  # action derived from the API name, not from the table


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

# boto3 methods that are not API operations (no IAM action) or need an override.
_NOT_API = {
    "get_paginator",
    "get_waiter",
    "can_paginate",
    "close",
    "generate_presigned_url",
    "generate_presigned_post",
}
_OVERRIDES: dict[tuple[str, str], str] = {
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    ("s3", "head_object"): "s3:GetObject",
    ("s3", "head_bucket"): "s3:ListBucket",
    ("s3", "upload_fileobj"): "s3:PutObject",
    ("s3", "download_fileobj"): "s3:GetObject",
    ("s3", "list_object_versions"): "s3:ListBucketVersions",
}
# boto3 service name -> IAM action prefix, where they differ.
_PREFIX = {
    "stepfunctions": "states",
    "elbv2": "elasticloadbalancing",
    "elb": "elasticloadbalancing",
    "sesv2": "ses",
    "iot-data": "iot",
    "s3control": "s3",
    "opensearch": "es",
    "logs": "logs",
}


def spec_for(service: str, method: str) -> ActionSpec | None:
    """Table entry, else an IAM action derived from the API name (flagged as derived).

    boto3 method ``create_user`` is the ``CreateUser`` API; for most services the
    IAM action has the same name.  Exceptions are tabled; derived actions carry
    ``derived=True`` so verdicts mark them ``action-derived-from-api-name``.
    """
    spec = ACTIONS.get((service, method))
    if spec is not None:
        return spec
    if method.startswith("_") or method in _NOT_API or not method.islower():
        return None
    action = _OVERRIDES.get((service, method))
    if action is None:
        prefix = _PREFIX.get(service, service)
        action = f"{prefix}:{''.join(part.capitalize() for part in method.split('_'))}"
    return ActionSpec(action, hazard_for_action(action), "any", derived=True)


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
    if lowered == "*" or lowered.endswith(":*"):
        return "admin"
    service, _, verb = lowered.partition(":")
    if verb.startswith(("delete", "remove", "terminate", "detach")):
        hazard = "delete"
    elif verb.startswith(
        ("put", "create", "update", "attach", "write", "copy", "add", "pass", "set")
    ):
        hazard = "write"
    elif verb.startswith("list"):
        hazard = "list"
    else:
        hazard = "read"
    if service in {"iam", "sts", "organizations"} and hazard in {"write", "delete"}:
        return "admin"  # identity changes are privilege changes
    if service == "secretsmanager" and verb.startswith("getsecretvalue"):
        return "secrets_read"
    return hazard


def detect_operations(
    module: PythonModule,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tool_id: str,
    tool_name: str,
    project: ProjectIndex | None = None,
) -> list[ToolOperation]:
    """Operations performed by ``function`` or the project helpers it calls."""
    found = _walk(module, function, tool_id, tool_name, project, chain=[], visited=set())
    for operation in found:
        operation.tool_file = module.relative_path
    return found


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
                spec = spec_for(service, node.func.attr)
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
        derived_action=spec.derived,
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
    """The boto3 service of a client expression, when statically certain."""
    constructor: ast.AST | None = receiver
    owner = module
    if isinstance(receiver, ast.Name):
        assignment = module.assignment_for(receiver.id, at)
        constructor = assignment.value if assignment is not None else None
        if constructor is None and project is not None and receiver.id in module.aliases:
            # `from app.clients import s3`: the client is built where it is defined.
            symbol = project.python_symbol(module, receiver.id)
            bindings = symbol.module.assignments.get((None, symbol.name)) if symbol else None
            if symbol is not None and bindings:
                constructor = max(bindings, key=lambda item: item.line).value
                owner = symbol.module
    if not isinstance(constructor, ast.Call):
        return None
    return _constructor_service(owner, constructor, project, {}, 0)


def _constructor_service(
    module: PythonModule,
    call: ast.Call,
    project: ProjectIndex | None,
    bindings: dict[str, ast.AST],
    depth: int,
) -> str | None:
    """``boto3.client("s3")``, ``<boto3 Session>.client("s3")`` or a factory returning one.

    A factory is a project function whose every ``return`` is such a client;
    ``boto3.client(service_name)`` with ``service_name`` a factory parameter is
    resolved from the literal argument at this call site.  All returns must
    agree on one service.
    """
    if depth > MAX_HELPER_DEPTH:
        return None
    qualified = module.qualified_name(call.func) or ""
    is_session_client = (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "client"
        and _is_session(module, call.func.value, call)
    )
    if qualified == "boto3.client" or is_session_client:
        argument: ast.AST | None = call.args[0] if call.args else None
        for keyword in call.keywords:
            if keyword.arg == "service_name":
                argument = keyword.value
        if argument is None:
            return None
        value = ValueResolver(module).resolve(argument, bindings=bindings)
        return value.value if value.resolved and isinstance(value.value, str) else None
    if project is None:
        return None
    factory = project.python_function(module, call.func) or _self_method(module, call)
    if factory is None:
        return None
    returns = python_returns(factory.info.node)
    if not returns:
        return None
    parameters = [
        a.arg for a in [*factory.info.node.args.posonlyargs, *factory.info.node.args.args]
    ]
    if parameters[:1] == ["self"] and isinstance(call.func, ast.Attribute):
        parameters = parameters[1:]
    passed: dict[str, ast.AST] = {}
    for index, positional in enumerate(call.args):
        if index < len(parameters) and not isinstance(positional, ast.Starred):
            passed[parameters[index]] = _literal_node(module, positional, bindings)
    for keyword in call.keywords:
        if keyword.arg:
            passed[keyword.arg] = _literal_node(module, keyword.value, bindings)
    services: set[str | None] = set()
    for returned in returns:
        if not isinstance(returned, ast.Call):
            return None
        services.add(_constructor_service(factory.module, returned, project, passed, depth + 1))
    if len(services) != 1:
        return None
    return services.pop()


def _self_method(module: PythonModule, call: ast.Call) -> PyFunctionRef | None:
    """``self.factory(...)`` inside a method resolves to the same class's method."""
    func = call.func
    if not (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "self"
    ):
        return None
    enclosing = module.enclosing_function(call)
    if enclosing is None or "." not in enclosing.qualified_name:
        return None
    owner = enclosing.qualified_name.rsplit(".", 1)[0]
    info = module.functions.get(f"{owner}.{func.attr}")
    return PyFunctionRef(module, info) if info is not None else None


def _literal_node(module: PythonModule, node: ast.AST, bindings: dict[str, ast.AST]) -> ast.AST:
    """Freeze a call-site argument to a literal so it can cross into the factory."""
    value = ValueResolver(module).resolve(node, bindings=bindings)
    if value.resolved and isinstance(value.value, str):
        return ast.Constant(value=value.value)
    return node


def _is_session(module: PythonModule, node: ast.AST, at: ast.AST) -> bool:
    sessions = {"boto3.Session", "boto3.session.Session"}
    if isinstance(node, ast.Call):
        return (module.qualified_name(node.func) or "") in sessions
    if isinstance(node, ast.Name):
        assignment = module.assignment_for(node.id, at)
        return (
            assignment is not None
            and isinstance(assignment.value, ast.Call)
            and (module.qualified_name(assignment.value.func) or "") in sessions
        )
    return False


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
