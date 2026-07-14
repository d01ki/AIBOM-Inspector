"""Safe Python AST parsing and a lightweight same-file call graph."""

from __future__ import annotations

import ast
import io
import tokenize
from collections import deque
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from aibom.models.analysis import Reachability, SourceContext

_ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "options", "route"}
_ENTRYPOINT_DECORATORS = _ROUTE_DECORATORS | {"command", "task", "tool"}
_ENTRYPOINT_BASES = {"app", "api", "router", "blueprint", "cli", "mcp"}
_LAMBDA_NAMES = {"handler", "lambda_handler"}


@dataclass(frozen=True)
class Assignment:
    name: str
    value: ast.AST
    line: int
    scope: str | None


@dataclass
class FunctionInfo:
    name: str
    qualified_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    calls: set[str] = field(default_factory=set)
    entrypoint_kind: str | None = None


class _Index(ast.NodeVisitor):
    def __init__(self) -> None:
        self.parents: dict[int, ast.AST] = {}
        self.scopes: dict[int, str | None] = {}
        self.aliases: dict[str, str] = {}
        self.import_nodes: list[ast.Import | ast.ImportFrom] = []
        self.assignments: dict[tuple[str | None, str], list[Assignment]] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self.calls: list[ast.Call] = []
        self.docstring_lines: set[int] = set()
        self.main_guard_nodes: set[int] = set()
        self._scope: list[str] = []
        self._main_depth = 0

    @property
    def scope(self) -> str | None:
        return ".".join(self._scope) if self._scope else None

    def generic_visit(self, node: ast.AST) -> None:
        self.scopes[id(node)] = self.scope
        for child in ast.iter_child_nodes(node):
            self.parents[id(child)] = node
        super().generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:  # noqa: N802
        self._record_docstring(node.body)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        self._record_docstring(node.body)
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent_scope = self.scope
        qualified = f"{parent_scope}.{node.name}" if parent_scope else node.name
        self.scopes[id(node)] = parent_scope
        info = FunctionInfo(
            name=node.name,
            qualified_name=qualified,
            node=node,
            entrypoint_kind=_entrypoint_kind(node),
        )
        self.functions[qualified] = info
        self._record_docstring(node.body)
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        self.import_nodes.append(node)
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        self.import_nodes.append(node)
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}".strip(".")

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        for target in node.targets:
            for name in _target_names(target):
                self._add_assignment(name, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        if node.value is not None:
            for name in _target_names(node.target):
                self._add_assignment(name, node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        self.calls.append(node)
        if self._main_depth:
            self.main_guard_nodes.add(id(node))
        if self.scope is not None:
            info = self.functions.get(self.scope)
            if info is not None:
                called = _unqualified_call_name(node.func)
                if called:
                    info.calls.add(called)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self.scopes[id(node)] = self.scope
        is_main = _is_main_guard(node.test)
        if not is_main:
            self.generic_visit(node)
            return
        for child in ast.iter_child_nodes(node):
            self.parents[id(child)] = node
        self.visit(node.test)
        self._main_depth += 1
        for statement in node.body:
            self.visit(statement)
        self._main_depth -= 1
        for statement in node.orelse:
            self.visit(statement)

    def _add_assignment(self, name: str, value: ast.AST, line: int) -> None:
        key = (self.scope, name)
        self.assignments.setdefault(key, []).append(
            Assignment(name=name, value=value, line=line, scope=self.scope)
        )

    def _record_docstring(self, body: list[ast.stmt]) -> None:
        if not body:
            return
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            end = getattr(first, "end_lineno", first.lineno)
            self.docstring_lines.update(range(first.lineno, end + 1))


@dataclass
class PythonModule:
    """Parsed Python source plus indices used by multiple detectors."""

    relative_path: str
    source: str
    tree: ast.Module
    parents: dict[int, ast.AST]
    scopes: dict[int, str | None]
    aliases: dict[str, str]
    import_nodes: list[ast.Import | ast.ImportFrom]
    assignments: dict[tuple[str | None, str], list[Assignment]]
    functions: dict[str, FunctionInfo]
    calls: list[ast.Call]
    docstring_lines: set[int]
    main_guard_nodes: set[int]

    def qualified_name(self, node: ast.AST) -> str | None:
        """Return a dotted symbol name with import aliases expanded."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = self.qualified_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return None

    def source_segment(self, node: ast.AST, *, limit: int = 240) -> str:
        segment = ast.get_source_segment(self.source, node)
        if segment is None:
            lines = self.source.splitlines()
            line = getattr(node, "lineno", 1)
            segment = lines[line - 1] if 0 < line <= len(lines) else ""
        return " ".join(segment.strip().split())[:limit]

    def scope_for(self, node: ast.AST) -> str | None:
        return self.scopes.get(id(node))

    def enclosing_function(self, node: ast.AST) -> FunctionInfo | None:
        scope = self.scope_for(node)
        return self.functions.get(scope) if scope is not None else None

    def assignment_for(self, name: str, node: ast.AST) -> Assignment | None:
        line = getattr(node, "lineno", 1)
        scope = self.scope_for(node)
        for key in ((scope, name), (None, name)):
            candidates = [a for a in self.assignments.get(key, []) if a.line <= line]
            if candidates:
                return max(candidates, key=lambda a: a.line)
        return None

    def has_import(self, *roots: str) -> bool:
        expected = set(roots)
        return any(value.split(".", 1)[0] in expected for value in self.aliases.values())

    def reachability(self, node: ast.AST) -> tuple[Reachability, list[str]]:
        """Conservatively classify same-file reachability for ``node``."""
        if id(node) in self.main_guard_nodes:
            return Reachability.TRUE, ["python.__main__"]
        scope = self.scope_for(node)
        if scope is None:
            return Reachability.UNKNOWN, []

        entrypoints = {
            name: info for name, info in self.functions.items() if info.entrypoint_kind is not None
        }
        target = scope.split(".", 1)[0]
        queue: deque[tuple[str, list[str]]] = deque()
        seen: set[str] = set()
        simple_to_qualified = {info.name: name for name, info in self.functions.items()}
        for name, info in entrypoints.items():
            display = f"{info.entrypoint_kind}:{info.name}"
            queue.append((name, [display]))
        for call in self.calls:
            if id(call) not in self.main_guard_nodes:
                continue
            called = _unqualified_call_name(call.func)
            qualified = simple_to_qualified.get(called or "")
            if qualified is not None:
                queue.append((qualified, ["python.__main__", called or qualified]))
        if not queue:
            return Reachability.UNKNOWN, []

        while queue:
            current, path = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            current_simple = current.split(".")[-1]
            if current == scope or current_simple == target:
                return Reachability.TRUE, path
            current_info = self.functions.get(current)
            if current_info is None:
                continue
            for called in sorted(current_info.calls):
                qualified = simple_to_qualified.get(called)
                if qualified is not None:
                    queue.append((qualified, [*path, called]))
        return Reachability.FALSE, []

    def sanitized_source(self) -> str:
        """Blank comments/docstrings while preserving source line numbers."""
        lines = self.source.splitlines(keepends=True)
        for line_no in self.docstring_lines:
            if 0 < line_no <= len(lines):
                newline = "\n" if lines[line_no - 1].endswith("\n") else ""
                lines[line_no - 1] = newline
        try:
            for token in tokenize.generate_tokens(io.StringIO("".join(lines)).readline):
                if token.type != tokenize.COMMENT:
                    continue
                row, column = token.start
                if 0 < row <= len(lines):
                    newline = "\n" if lines[row - 1].endswith("\n") else ""
                    lines[row - 1] = lines[row - 1][:column].rstrip() + newline
        except (IndentationError, tokenize.TokenError):
            pass
        return "".join(lines)


def parse_python(source: str, relative_path: str) -> PythonModule:
    """Parse Python source without importing or executing it."""
    tree = ast.parse(source, filename=relative_path, type_comments=True)
    index = _Index()
    index.visit(tree)
    return PythonModule(
        relative_path=relative_path,
        source=source,
        tree=tree,
        parents=index.parents,
        scopes=index.scopes,
        aliases=index.aliases,
        import_nodes=index.import_nodes,
        assignments=index.assignments,
        functions=index.functions,
        calls=index.calls,
        docstring_lines=index.docstring_lines,
        main_guard_nodes=index.main_guard_nodes,
    )


def classify_source_context(relative_path: str) -> SourceContext:
    path = PurePosixPath(relative_path.lower())
    parts = set(path.parts)
    name = path.name
    if {"tests", "test", "testing", "fixtures"} & parts or name.startswith("test_"):
        return SourceContext.TEST
    if {"examples", "example", "samples", "sample", "demo", "demos"} & parts:
        return SourceContext.EXAMPLE
    if {"docs", "doc", "documentation"} & parts:
        return SourceContext.DOCS
    return SourceContext.PRODUCTION


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _unqualified_call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _entrypoint_kind(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    if node.name in _LAMBDA_NAMES:
        return "lambda"
    for decorator in node.decorator_list:
        func = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not isinstance(func, ast.Attribute) or func.attr not in _ENTRYPOINT_DECORATORS:
            continue
        base = _unqualified_call_name(func.value)
        if base not in _ENTRYPOINT_BASES:
            continue
        if func.attr in _ROUTE_DECORATORS:
            return "http_route"
        if func.attr == "tool":
            return "mcp_tool"
        if func.attr == "task":
            return "task"
        return "cli"
    return None


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    if not isinstance(node.ops[0], ast.Eq):
        return False
    left, right = node.left, node.comparators[0]
    values = (left, right)
    return any(isinstance(v, ast.Name) and v.id == "__name__" for v in values) and any(
        isinstance(v, ast.Constant) and v.value == "__main__" for v in values
    )
