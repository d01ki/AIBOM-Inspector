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
class ServerDef:
    id: str
    file: str
    variable: str
    name: str | None
    tools: list[FunctionInfo] = field(default_factory=list)
    evidence: list[SecEvidence] = field(default_factory=list)


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
    unresolved_reason: str | None = None
    evidence: list[SecEvidence] = field(default_factory=list)

    def exposes(self, tool_name: str) -> bool:
        if tool_name in self.blocked:
            return False
        return self.allowed is None or tool_name in self.allowed


# -- servers ---------------------------------------------------------------------------


def find_servers(modules: list[PythonModule]) -> dict[str, list[ServerDef]]:
    """``file -> servers`` defined in that file, with their decorated tools."""
    found: dict[str, list[ServerDef]] = {}
    for module in modules:
        if not module.has_import("mcp", "fastmcp"):
            continue
        servers: dict[str, ServerDef] = {}
        resolver = ValueResolver(module)
        for (scope, name), assignments in module.assignments.items():
            if scope is not None:
                continue
            for assignment in assignments:
                value = assignment.value
                if not isinstance(value, ast.Call):
                    continue
                if not (module.qualified_name(value.func) or "").endswith("FastMCP"):
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
                            detail="FastMCP(...)",
                        )
                    ],
                )
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
                    servers[target.value.id].tools.append(info)
        found[module.relative_path] = sorted(servers.values(), key=lambda s: s.id)
    return found


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
    module: PythonModule, item: ast.AST, at: ast.AST, project: ProjectIndex
) -> tuple[PythonModule, ast.Call, str] | None:
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
    for node in ast.walk(module.tree):  # `async with MCPServerStdio(...) as server:`
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
    if item.id in module.aliases:
        symbol = project.python_symbol(module, item.id)
        bindings = symbol.module.assignments.get((None, symbol.name)) if symbol else None
        if symbol is not None and bindings:
            bound = max(bindings, key=lambda a: a.line).value
            if isinstance(bound, ast.Call) and _transport(symbol.module, bound):
                return symbol.module, bound, _transport(symbol.module, bound) or "unknown"
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
