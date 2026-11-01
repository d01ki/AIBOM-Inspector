"""Static MCP capability graph: client -> server -> tool, never by running a server.

Recognized, deliberately narrow:

* **Server definitions** (Python): ``srv = FastMCP(...)`` from ``mcp`` /
  ``fastmcp``, and functions decorated ``@srv.tool`` / ``@srv.tool(...)``.
* **Agent connections** (Python OpenAI Agents SDK): ``Agent(mcp_servers=[s])``
  where ``s`` is an ``MCPServerStdio`` / ``MCPServerSse`` /
  ``MCPServerStreamableHttp`` constructed in the same module (assignment or
  ``async with ... as s``) or imported from another project module.  A stdio
  server is linked to a repository server file only when its literal
  ``command``/``args`` name a ``.py`` file or ``-m package.module`` that is part
  of the analyzed project.  ``tool_filter`` is honored when it is a literal
  ``create_static_tool_filter(...)`` call or ``{"allowed_tool_names": ...}``.
* **Client configuration files**: ``.mcp.json``, ``mcp.json``,
  ``claude_desktop_config.json`` and ``mcp_config.json`` with ``mcpServers``
  (or VS Code's ``servers``).  These are *configured* servers; no analyzed agent
  binds them, so they never form capability paths.

Only the command's base name and the resolved repository file are retained;
other arguments, URLs and ``env`` values are never stored (they often carry
tokens).
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from aibom.agent_security.models import SecEvidence
from aibom.detectors.project import ProjectIndex
from aibom.detectors.python.parser import FunctionInfo, PythonModule
from aibom.detectors.python.value_resolver import ValueResolver

CONFIG_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json"}
MAX_CONFIG_BYTES = 1024 * 1024
_CLIENTS = {
    "MCPServerStdio": "stdio",
    "MCPServerSse": "sse",
    "MCPServerStreamableHttp": "streamable_http",
}


@dataclass
class ToolDef:
    """A function registered as a tool; it may live in another module than the server."""

    file: str
    info: FunctionInfo
    registration: str = "decorator"  # decorator | call

    @property
    def name(self) -> str:
        return self.info.name


@dataclass
class ServerDef:
    id: str
    file: str
    variable: str
    name: str | None
    tools: list[ToolDef] = field(default_factory=list)
    evidence: list[SecEvidence] = field(default_factory=list)

    def add(self, tool: ToolDef) -> None:
        if not any(t.file == tool.file and t.info is tool.info for t in self.tools):
            self.tools.append(tool)


@dataclass
class Connection:
    client_kind: str  # agent | config
    client_ref: str
    server_label: str
    transport: str
    launch: str | None = None  # sanitized: command basename + repository file
    server_id: str | None = None
    allowed: set[str] | None = None  # None: no static filter
    blocked: set[str] = field(default_factory=set)
    filter_status: str = "none"  # none | static | unresolved
    approval: str = "none"  # none | always | never | per_tool | unresolved
    approval_tools: set[str] = field(default_factory=set)
    unresolved_reason: str | None = None
    evidence: list[SecEvidence] = field(default_factory=list)

    def exposes(self, tool_name: str) -> bool:
        if tool_name in self.blocked:
            return False
        return self.allowed is None or tool_name in self.allowed


# -- servers ---------------------------------------------------------------------------


def find_servers(
    modules: list[PythonModule], project: ProjectIndex | None = None
) -> dict[str, list[ServerDef]]:
    """``file -> servers`` defined in that file, with their registered tools.

    Two registration styles are recognized:

    * decorator: ``@srv.tool`` / ``@srv.tool(...)`` on a function in the
      server's module;
    * call: ``srv.tool(...)(fn)`` anywhere in the project, where ``srv`` is the
      module-level server or a parameter of a registration function/method
      (``Tools().register(srv)``), and ``fn`` is a function or ``self.method``.
    """
    found: dict[str, dict[str, ServerDef]] = {}
    for module in modules:
        if not module.has_import("mcp", "fastmcp"):
            continue
        servers = _module_servers(module)
        if not servers:
            continue
        for info in module.functions.values():
            for decorator in info.node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "tool"
                    and isinstance(target.value, ast.Name)
                    and target.value.id in servers
                ):
                    servers[target.value.id].add(ToolDef(module.relative_path, info))
        found[module.relative_path] = servers
    if project is not None:
        for module in modules:
            _call_style(module, project, found)
    return {file: sorted(servers.values(), key=lambda s: s.id) for file, servers in found.items()}


def _module_servers(module: PythonModule) -> dict[str, ServerDef]:
    servers: dict[str, ServerDef] = {}
    resolver = ValueResolver(module)
    for (scope, name), assignments in module.assignments.items():
        if scope is not None:
            continue
        for assignment in assignments:
            value = assignment.value
            if not isinstance(value, ast.Call):
                continue
            qualified = module.qualified_name(value.func) or ""
            # FastMCP was renamed MCPServer in newer `mcp` releases.  The
            # Agents SDK's `agents.mcp.MCPServer` is a client type, not a server.
            if not (
                qualified.startswith(("mcp.", "fastmcp."))
                and qualified.endswith((".FastMCP", ".MCPServer"))
            ):
                continue
            label = _literal(resolver, value.args[0] if value.args else None)
            for keyword in value.keywords:
                if keyword.arg == "name":
                    label = _literal(resolver, keyword.value)
            servers[name] = ServerDef(
                id=f"mcp-server:{module.relative_path}:{name}",
                file=module.relative_path,
                variable=name,
                name=label,
                evidence=[
                    SecEvidence(
                        file=module.relative_path,
                        line=assignment.line,
                        kind="ast",
                        detail=qualified.rsplit(".", 1)[-1] + "(...)",
                    )
                ],
            )
    return servers


def _call_style(
    module: PythonModule, project: ProjectIndex, found: dict[str, dict[str, ServerDef]]
) -> None:
    for call in module.calls:
        inner = call.func
        if not (
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr == "tool"
            and isinstance(inner.func.value, ast.Name)
            and call.args
        ):
            continue
        receiver = inner.func.value.id
        function = module.enclosing_function(call)
        tool = _registered_function(module, call.args[0], function, project)
        if tool is None:
            continue
        for server in _servers_for(module, receiver, function, project, found):
            server.add(ToolDef(tool[0].relative_path, tool[1], registration="call"))


def _registered_function(
    module: PythonModule, target: ast.AST, function: FunctionInfo | None, project: ProjectIndex
) -> tuple[PythonModule, FunctionInfo] | None:
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
        and function is not None
        and "." in function.qualified_name
    ):
        owner = function.qualified_name.rsplit(".", 1)[0]
        info = module.functions.get(f"{owner}.{target.attr}")
        return (module, info) if info is not None else None
    resolved = project.python_function(module, target)
    return (resolved.module, resolved.info) if resolved is not None else None


def _servers_for(
    module: PythonModule,
    receiver: str,
    function: FunctionInfo | None,
    project: ProjectIndex,
    found: dict[str, dict[str, ServerDef]],
) -> list[ServerDef]:
    local = found.get(module.relative_path, {})
    if receiver in local:
        return [local[receiver]]
    if function is None:
        return []
    arguments = function.node.args
    parameters = [a.arg for a in [*arguments.posonlyargs, *arguments.args]]
    if receiver not in parameters:
        return []
    is_method = "." in function.qualified_name and parameters[:1] == ["self"]
    index = parameters.index(receiver) - (1 if is_method else 0)
    servers: list[ServerDef] = []
    for caller_module, call in _registration_calls(module, function, project):
        passed: ast.AST | None = call.args[index] if 0 <= index < len(call.args) else None
        for keyword in call.keywords:
            if keyword.arg == receiver:
                passed = keyword.value
        if isinstance(passed, ast.Name):
            server = found.get(caller_module.relative_path, {}).get(passed.id)
            if server is not None and server not in servers:
                servers.append(server)
    return servers


def _registration_calls(
    module: PythonModule, function: FunctionInfo, project: ProjectIndex
) -> list[tuple[PythonModule, ast.Call]]:
    """Call sites of a registration function, including ``Cls().method(...)`` / ``obj.method``."""
    if "." not in function.qualified_name:
        return project.python_callers(module, function)[:16]
    owner, method = function.qualified_name.rsplit(".", 1)
    sites: list[tuple[PythonModule, ast.Call]] = []
    for caller in project.python.values():
        for call in caller.calls:
            if not (isinstance(call.func, ast.Attribute) and call.func.attr == method):
                continue
            instance = call.func.value
            constructor: ast.AST | None = instance
            if isinstance(instance, ast.Name):
                assignment = caller.assignment_for(instance.id, call)
                constructor = assignment.value if assignment is not None else None
            if not isinstance(constructor, ast.Call):
                continue
            if _defines_class(caller, constructor.func, module, owner, project):
                sites.append((caller, call))
    return sites[:16]


def _defines_class(
    caller: PythonModule, func: ast.AST, module: PythonModule, owner: str, project: ProjectIndex
) -> bool:
    if not isinstance(func, ast.Name) or func.id != owner.rsplit(".", 1)[-1]:
        return False
    if caller is module:
        return True
    symbol = project.python_symbol(caller, func.id)
    return symbol is not None and symbol.module is module


# -- agent-side connections -----------------------------------------------------------------


def agent_connections(
    module: PythonModule,
    call: ast.Call,
    agent_ref: str,
    project: ProjectIndex,
    servers: dict[str, list[ServerDef]],
) -> list[Connection]:
    expression = next((k.value for k in call.keywords if k.arg == "mcp_servers"), None)
    if expression is None:
        return []
    evidence = [
        SecEvidence(
            file=module.relative_path, line=call.lineno, kind="ast", detail="Agent(mcp_servers=...)"
        )
    ]
    if not isinstance(expression, (ast.List, ast.Tuple)):
        return [_unresolved(agent_ref, "mcp_servers", "mcp_servers_not_a_literal_list", evidence)]
    found: list[Connection] = []
    for item in expression.elts:
        located = _client_constructor(module, item, call, project)
        label = module.source_segment(item, limit=60)
        if located is None:
            found.append(_unresolved(agent_ref, label, "mcp_client_unresolved", evidence))
            continue
        owner, constructor, transport = located
        connection = _from_constructor(
            owner, constructor, transport, agent_ref, label, project, servers
        )
        connection.evidence = [
            *evidence,
            SecEvidence(
                file=owner.relative_path,
                line=constructor.lineno,
                kind="ast",
                detail=f"{transport} MCP client",
            ),
        ]
        found.append(connection)
    return found


def _unresolved(client: str, label: str, reason: str, evidence: list[SecEvidence]) -> Connection:
    return Connection(
        client_kind="agent",
        client_ref=client,
        server_label=label,
        transport="unknown",
        unresolved_reason=reason,
        evidence=evidence,
    )


def _client_constructor(
    module: PythonModule, item: ast.AST, at: ast.AST, project: ProjectIndex, depth: int = 0
) -> tuple[PythonModule, ast.Call, str] | None:
    """Resolve an ``mcp_servers`` entry to the client constructor call.

    Assignments and ``async with ... as x`` are searched in the same function
    as the use.  When the name is a parameter of that function, each resolved
    call site is followed one hop; every caller must agree on the transport
    (the first consistent constructor is kept).
    """
    if isinstance(item, ast.Call):
        transport = _transport(module, item)
        return (module, item, transport) if transport else None
    if not isinstance(item, ast.Name):
        return None
    assignment = module.assignment_for(item.id, at)
    if assignment is not None and isinstance(assignment.value, ast.Call):
        transport = _transport(module, assignment.value)
        if transport:
            return module, assignment.value, transport
    function = module.enclosing_function(at)
    scope: ast.AST = function.node if function is not None else module.tree
    for node in ast.walk(scope):  # `async with MCPServerStdio(...) as server:`
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for with_item in node.items:
                target = with_item.optional_vars
                value = with_item.context_expr
                if (
                    isinstance(target, ast.Name)
                    and target.id == item.id
                    and isinstance(value, ast.Call)
                    and _transport(module, value)
                ):
                    return module, value, _transport(module, value) or "unknown"
    if function is not None and depth == 0:
        arguments = function.node.args
        positional = [a.arg for a in [*arguments.posonlyargs, *arguments.args]]
        if item.id in positional or item.id in [a.arg for a in arguments.kwonlyargs]:
            found: list[tuple[PythonModule, ast.Call, str]] = []
            for caller_module, call in project.python_callers(module, function)[:8]:
                passed = _passed_argument(call, item.id, positional)
                if passed is None:
                    continue
                located = _client_constructor(caller_module, passed, call, project, depth + 1)
                if located is not None:
                    found.append(located)
            if found and len({transport for _, _, transport in found}) == 1:
                return found[0]
            return None
    if item.id in module.aliases:
        symbol = project.python_symbol(module, item.id)
        bindings = symbol.module.assignments.get((None, symbol.name)) if symbol else None
        if symbol is not None and bindings:
            bound = max(bindings, key=lambda a: a.line).value
            if isinstance(bound, ast.Call) and _transport(symbol.module, bound):
                return symbol.module, bound, _transport(symbol.module, bound) or "unknown"
    return None


def _passed_argument(call: ast.Call, name: str, positional: list[str]) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    if name in positional:
        index = positional.index(name)
        if index < len(call.args) and not any(
            isinstance(arg, ast.Starred) for arg in call.args[: index + 1]
        ):
            return call.args[index]
    return None


def _transport(module: PythonModule, call: ast.Call) -> str | None:
    if not module.has_import("agents"):
        return None
    qualified = module.qualified_name(call.func) or ""
    return _CLIENTS.get(qualified.rsplit(".", 1)[-1]) if qualified.startswith("agents") else None


def _from_constructor(
    module: PythonModule,
    call: ast.Call,
    transport: str,
    agent_ref: str,
    label: str,
    project: ProjectIndex,
    servers: dict[str, list[ServerDef]],
) -> Connection:
    resolver = ValueResolver(module)
    params = _dict_node(
        module, next((k.value for k in call.keywords if k.arg == "params"), None), call
    )
    for keyword in call.keywords:
        if keyword.arg == "name":
            label = _literal(resolver, keyword.value) or label
    connection = Connection(
        client_kind="agent", client_ref=agent_ref, server_label=label, transport=transport
    )
    _apply_filter(module, resolver, call, connection)
    _apply_approval(resolver, call, connection)
    if transport != "stdio":
        connection.unresolved_reason = "remote_server_tools_unknown"
        return connection
    if params is None:
        connection.unresolved_reason = "params_not_literal"
        return connection
    command = _literal(resolver, _dict_get(params, "command"))
    args_node = _dict_get(params, "args")
    args: list[str] = []
    if isinstance(args_node, (ast.List, ast.Tuple)):
        args = [value for value in (_literal(resolver, e) for e in args_node.elts) if value]
    _link(connection, command, args, project, servers)
    return connection


def _apply_filter(
    module: PythonModule, resolver: ValueResolver, call: ast.Call, connection: Connection
) -> None:
    expression = next((k.value for k in call.keywords if k.arg == "tool_filter"), None)
    if expression is None:
        return
    pairs: dict[str, ast.AST] = {}
    if isinstance(expression, ast.Call) and (module.qualified_name(expression.func) or "").endswith(
        "create_static_tool_filter"
    ):
        pairs = {k.arg: k.value for k in expression.keywords if k.arg}
    elif isinstance(expression, ast.Dict):
        for key, value in zip(expression.keys, expression.values, strict=True):
            name = _literal(resolver, key) if key is not None else None
            if name:
                pairs[name] = value
    else:
        connection.filter_status = "unresolved"
        return
    allowed = _string_list(resolver, pairs.get("allowed_tool_names"))
    blocked = _string_list(resolver, pairs.get("blocked_tool_names"))
    if (pairs.get("allowed_tool_names") is not None and allowed is None) or (
        pairs.get("blocked_tool_names") is not None and blocked is None
    ):
        connection.filter_status = "unresolved"
        return
    connection.allowed = set(allowed) if allowed is not None else None
    connection.blocked = set(blocked or [])
    connection.filter_status = "static"


def _apply_approval(resolver: ValueResolver, call: ast.Call, connection: Connection) -> None:
    """``require_approval="always" | "never" | {"always": {"tool_names": [...]}}``."""
    expression = next((k.value for k in call.keywords if k.arg == "require_approval"), None)
    if expression is None:
        return
    literal = _literal(resolver, expression)
    if literal in {"always", "never"}:
        connection.approval = literal
        return
    if isinstance(expression, ast.Dict):
        always = _dict_get(expression, "always")
        names = _dict_get(always, "tool_names") if isinstance(always, ast.Dict) else None
        listed = _string_list(resolver, names)
        if listed is not None:
            connection.approval = "per_tool"
            connection.approval_tools = set(listed)
            return
    connection.approval = "unresolved"


# -- client configuration files -------------------------------------------------------------


def config_connections(
    root: Path, files: list[Path], project: ProjectIndex, servers: dict[str, list[ServerDef]]
) -> tuple[list[Connection], list[tuple[str, str]]]:
    """Connections declared by MCP client config files, plus (file, error) problems."""
    found: list[Connection] = []
    problems: list[tuple[str, str]] = []
    for path in files:
        if path.name.lower() not in CONFIG_NAMES:
            continue
        rel = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > MAX_CONFIG_BYTES:
                problems.append((rel, "config_too_large"))
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            problems.append((rel, "config_unparsable"))
            continue
        if not isinstance(data, dict):
            continue
        entries = data.get("mcpServers", data.get("servers"))
        if not isinstance(entries, dict):
            continue
        for name, entry in sorted(entries.items()):
            if not isinstance(entry, dict):
                continue
            url = entry.get("url") or entry.get("serverUrl")
            command = entry.get("command") if isinstance(entry.get("command"), str) else None
            raw_args = entry.get("args")
            args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
            connection = Connection(
                client_kind="config",
                client_ref=f"mcp-client:{rel}",
                server_label=str(name)[:80],
                transport="remote" if url else "stdio",
                evidence=[SecEvidence(file=rel, pointer=f"/mcpServers/{name}", kind="config")],
            )
            if url:
                connection.unresolved_reason = "remote_server_tools_unknown"
            else:
                _link(connection, command, args, project, servers)
            found.append(connection)
    return found, problems


# -- shared helpers ---------------------------------------------------------------------------


def _link(
    connection: Connection,
    command: str | None,
    args: list[str],
    project: ProjectIndex,
    servers: dict[str, list[ServerDef]],
) -> None:
    base = PurePosixPath((command or "").replace("\\", "/")).name or None
    candidates: list[str] = []
    tokens = [command or "", *args]
    for index, token in enumerate(tokens):
        token = token.replace("\\", "/")
        if token.endswith(".py"):
            candidates.append(token[2:] if token.startswith("./") else token)
        if token == "-m" and index + 1 < len(tokens):
            dotted = tokens[index + 1].replace(".", "/")
            candidates.extend([f"{dotted}.py", f"{dotted}/__main__.py"])
    for candidate in candidates:
        if candidate in project.python and candidate in servers:
            defined = servers[candidate]
            if len(defined) != 1:
                connection.unresolved_reason = "multiple_servers_in_file"
                return
            connection.server_id = defined[0].id
            connection.launch = f"{base or '?'} {candidate}"
            return
    connection.launch = base
    connection.unresolved_reason = (
        "server_outside_analyzed_sources" if candidates or command else "launch_not_literal"
    )


def _dict_node(module: PythonModule, node: ast.AST | None, at: ast.AST) -> ast.Dict | None:
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.Name):
        assignment = module.assignment_for(node.id, at)
        if assignment is not None and isinstance(assignment.value, ast.Dict):
            return assignment.value
    return None


def _dict_get(node: ast.Dict, key: str) -> ast.AST | None:
    for item_key, value in zip(node.keys, node.values, strict=True):
        if isinstance(item_key, ast.Constant) and item_key.value == key:
            return value
    return None


def _literal(resolver: ValueResolver, node: ast.AST | None) -> str | None:
    if node is None:
        return None
    value = resolver.resolve(node)
    return value.value if value.resolved and isinstance(value.value, str) else None


def _string_list(resolver: ValueResolver, node: ast.AST | None) -> list[str] | None:
    if node is None:
        return None
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values = [_literal(resolver, item) for item in node.elts]
    if any(value is None for value in values):
        return None
    return [value for value in values if value is not None]
