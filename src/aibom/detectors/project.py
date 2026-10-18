"""Project-wide module and symbol index for bounded cross-file analysis.

Per-file detectors see one syntax tree.  This index lets them follow the small,
statically resolvable subset of cross-module references that real applications
use to split a prompt flow across files:

* Python ``import x.y`` / ``from x.y import z`` / ``from ..x import z``;
* JS/TS relative specifiers (``./x``, ``../x``), ``export { a } from``,
  ``export * from``, and ``tsconfig.json`` ``paths`` patterns of the
  ``"@/*": ["./*"]`` shape.

Anything else — dynamic ``import()``, ``importlib``, package-manager resolution
of a bare specifier, a re-export chain longer than the bound — is *unresolved*,
which callers must report as ``unknown`` rather than as safe.

The index never imports, executes, or installs anything.  It only reads the
syntax trees the collector already built.
"""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from aibom.detectors.javascript.nodes import (
    CallExpr,
    FunctionNode,
    Identifier,
    MemberExpr,
    Node,
    ReturnStmt,
    VarDecl,
    children,
    walk,
)
from aibom.detectors.javascript.parser import JsFunctionInfo, JsModule
from aibom.detectors.python.parser import FunctionInfo, PythonModule

# Bounds.  They keep the worst case linear in the repository size: a flow may
# cross at most this many call boundaries, fan out to this many call sites per
# function, and spend this many expression visits in total.
MAX_CALL_DEPTH = 4
MAX_CALL_SITES = 8
MAX_TRACE_STEPS = 4_000
_MAX_REEXPORT_HOPS = 6

_JS_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_LINE_COMMENT = re.compile(r"(?m)(^|[^:\"'])//.*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


class Budget:
    """A shared, mutable visit counter so one trace cannot explode."""

    def __init__(self, limit: int = MAX_TRACE_STEPS) -> None:
        self.limit = limit
        self.used = 0
        self.exhausted = False

    def spend(self) -> bool:
        """Consume one unit; return False (and latch) once the bound is hit."""
        self.used += 1
        if self.used > self.limit:
            self.exhausted = True
        return not self.exhausted


@dataclass(frozen=True)
class PyFunctionRef:
    module: PythonModule
    info: FunctionInfo


@dataclass(frozen=True)
class PySymbolRef:
    """A top-level binding in a project Python module."""

    module: PythonModule
    name: str


@dataclass(frozen=True)
class JsSymbolRef:
    """A top-level binding (function or variable) in a project JS/TS module."""

    module: JsModule
    name: str
    #: the bound value: a function node or a variable initializer
    value: Node | None


@dataclass
class ProjectIndex:
    """All successfully parsed Python and JS/TS modules of one scan."""

    python: dict[str, PythonModule] = field(default_factory=dict)
    javascript: dict[str, JsModule] = field(default_factory=dict)
    #: ``compilerOptions.paths`` as (prefix, star?, [target prefixes])
    ts_paths: list[tuple[str, bool, list[str]]] = field(default_factory=list)
    ts_base: str = ""
    _py_names: dict[str, list[str]] = field(default_factory=dict)
    _py_callers: dict[tuple[str, str], list[tuple[PythonModule, ast.Call]]] | None = None
    _js_callers: dict[tuple[str, str], list[tuple[JsModule, CallExpr]]] | None = None
    _py_cache: dict[tuple[str, str], PySymbolRef | None] = field(default_factory=dict)

    # -- construction -------------------------------------------------------

    def add_python(self, module: PythonModule) -> None:
        self.python[module.relative_path] = module
        for name in _python_module_names(module.relative_path):
            self._py_names.setdefault(name, []).append(module.relative_path)

    def add_javascript(self, module: JsModule) -> None:
        self.javascript[module.relative_path] = module

    def load_tsconfig(self, text: str, directory: str = "") -> None:
        """Read ``baseUrl`` and ``paths`` from a tsconfig/jsconfig, if parseable."""
        cleaned = _TRAILING_COMMA.sub(
            r"\1", _LINE_COMMENT.sub(r"\1", _BLOCK_COMMENT.sub("", text))
        )
        try:
            document = json.loads(cleaned)
        except ValueError:
            return
        options = document.get("compilerOptions") if isinstance(document, dict) else None
        if not isinstance(options, dict):
            return
        base = options.get("baseUrl")
        base_dir = _join(directory, base) if isinstance(base, str) else directory
        self.ts_base = base_dir
        paths = options.get("paths")
        if not isinstance(paths, dict):
            return
        for pattern, targets in sorted(paths.items()):
            if not isinstance(pattern, str) or not isinstance(targets, list):
                continue
            star = pattern.endswith("*")
            prefix = pattern[:-1] if star else pattern
            resolved = [
                _join(base_dir, target[:-1] if star and target.endswith("*") else target)
                for target in targets
                if isinstance(target, str)
            ]
            if resolved:
                self.ts_paths.append((prefix, star, resolved))
        # Longest prefix first, the way TypeScript picks a pattern.
        self.ts_paths.sort(key=lambda item: -len(item[0]))

    # -- Python -------------------------------------------------------------

    def python_module(self, importer: PythonModule, dotted: str, level: int) -> PythonModule | None:
        """Resolve an import of ``dotted`` (with relative ``level``) to a module."""
        if level:
            package = PurePosixPath(importer.relative_path).parent
            for _ in range(level - 1):
                package = package.parent
            base = "" if str(package) == "." else str(package).replace("/", ".")
            dotted = ".".join(part for part in (base, dotted) if part)
            candidates = [
                path
                for path in self._py_names.get(dotted, [])
                if _python_dotted(path) == dotted
            ]
        else:
            candidates = self._py_names.get(dotted, [])
            exact = [path for path in candidates if _python_dotted(path) == dotted]
            if exact:
                candidates = exact
            elif "." not in dotted:
                # `import json` must never bind to some project's utils/json.py.
                return None
        unique = sorted(set(candidates))
        if len(unique) != 1:
            return None
        return self.python.get(unique[0])

    def python_symbol(self, module: PythonModule, name: str) -> PySymbolRef | None:
        """Follow an imported local name to the module that defines it."""
        key = (module.relative_path, name)
        if key in self._py_cache:
            return self._py_cache[key]
        self._py_cache[key] = None  # cycle guard
        found = self._python_symbol(module, name, 0)
        self._py_cache[key] = found
        return found

    def _python_symbol(self, module: PythonModule, name: str, hops: int) -> PySymbolRef | None:
        if hops > _MAX_REEXPORT_HOPS:
            return None
        root = name.split(".", 1)[0]
        dotted = module.aliases.get(root)
        if dotted is None:
            return None
        rest = name.split(".")[1:]
        level = module.import_levels.get(root, 0)
        full = ".".join([dotted, *rest])
        parts = full.split(".")
        # `from pkg.mod import f` -> module pkg.mod, symbol f; `import pkg.mod`
        # then `pkg.mod.f` -> the same.  Try the longest module prefix first.
        for split in range(len(parts) - 1, 0, -1):
            target = self.python_module(module, ".".join(parts[:split]), level)
            if target is None:
                continue
            symbol = ".".join(parts[split:])
            if "." in symbol:
                return None
            if _python_defines(target, symbol):
                return PySymbolRef(target, symbol)
            if symbol in target.aliases:  # a re-export, e.g. in __init__.py
                return self._python_symbol(target, symbol, hops + 1)
            return None
        return None

    def python_function(self, module: PythonModule, node: ast.AST) -> PyFunctionRef | None:
        """Resolve a call target (``f`` or ``mod.f``) to a project function."""
        if isinstance(node, ast.Name):
            local = _python_local_function(module, node.id, module.scope_for(node))
            if local is not None:
                return PyFunctionRef(module, local)
            name = node.id
        elif isinstance(node, ast.Attribute):
            dotted = _python_dotted_name(node)
            if dotted is None:
                return None
            name = dotted
        else:
            return None
        symbol = self.python_symbol(module, name)
        if symbol is None:
            return None
        info = symbol.module.functions.get(symbol.name)
        return PyFunctionRef(symbol.module, info) if info is not None else None

    def python_callers(
        self, module: PythonModule, info: FunctionInfo
    ) -> list[tuple[PythonModule, ast.Call]]:
        """Every resolved call site of ``info`` across the project."""
        if self._py_callers is None:
            self._py_callers = defaultdict(list)
            for caller in self.python.values():
                for call in caller.calls:
                    target = self.python_function(caller, call.func)
                    if target is not None:
                        self._py_callers[
                            (target.module.relative_path, target.info.qualified_name)
                        ].append((caller, call))
        return self._py_callers.get((module.relative_path, info.qualified_name), [])

    # -- JavaScript / TypeScript ---------------------------------------------

    def js_module(self, importer: JsModule, specifier: str) -> JsModule | None:
        """Resolve an import specifier to a project module, or None."""
        bases: list[str] = []
        if specifier.startswith(("./", "../")) or specifier in {".", ".."}:
            bases.append(_join(str(PurePosixPath(importer.relative_path).parent), specifier))
        else:
            for prefix, star, targets in self.ts_paths:
                if star and specifier.startswith(prefix):
                    rest = specifier[len(prefix):]
                    bases.extend(f"{target}{rest}" for target in targets)
                    break
                if not star and specifier == prefix:
                    bases.extend(targets)
                    break
        for base in bases:
            found = self._js_file(base)
            if found is not None:
                return found
        return None

    def _js_file(self, base: str) -> JsModule | None:
        base = base.strip("/")
        stem = base
        for extension in (".js", ".jsx", ".mjs", ".cjs"):
            # TS sources import `./x.js` and mean `./x.ts`.
            if base.endswith(extension):
                stem = base[: -len(extension)]
                break
        candidates = [base]
        candidates.extend(f"{stem}{extension}" for extension in _JS_EXTENSIONS)
        candidates.extend(f"{base}/index{extension}" for extension in _JS_EXTENSIONS)
        for candidate in candidates:
            module = self.javascript.get(candidate)
            if module is not None:
                return module
        return None

    def js_symbol(self, module: JsModule, local: str) -> JsSymbolRef | None:
        """Follow an imported binding to the module that defines it."""
        alias = module.aliases.get(local)
        if alias is None:
            return None
        specifier, imported = alias
        target = self.js_module(module, specifier)
        if target is None or imported == "*":
            return None
        return self.js_export(target, imported, 0)

    def js_export(self, module: JsModule, name: str, hops: int) -> JsSymbolRef | None:
        """Find the binding ``module`` exports as ``name``."""
        if hops > _MAX_REEXPORT_HOPS:
            return None
        if name in module.reexports:
            source, local = module.reexports[name]
            if not source:
                return _js_top_level(module, local) or self.js_symbol(module, local)
            target = self.js_module(module, source)
            return self.js_export(target, local, hops + 1) if target is not None else None
        if name == "default":
            for info in module.functions.values():
                if (
                    info.node.exported
                    and "." not in info.qualified_name
                    and (info.node.name in {None, ""} or info.name.startswith("fn@"))
                ):
                    return JsSymbolRef(module, info.name, info.node)
            return None
        found = _js_top_level(module, name)
        if found is not None:
            return found
        for source in module.star_exports:
            target = self.js_module(module, source)
            if target is not None:
                found = self.js_export(target, name, hops + 1)
                if found is not None:
                    return found
        return None

    def js_function(self, module: JsModule, callee: Node) -> tuple[JsModule, JsFunctionInfo] | None:
        """Resolve a call target to a project function definition."""
        if isinstance(callee, Identifier):
            local = _js_local_function(module, callee.name, module.scope_for(callee))
            if local is not None:
                return module, local
            symbol = self.js_symbol(module, callee.name)
        elif (
            isinstance(callee, MemberExpr)
            and not callee.computed
            and isinstance(callee.obj, Identifier)
            and isinstance(callee.prop, Identifier)
            and module.aliases.get(callee.obj.name, ("", ""))[1] == "*"
        ):
            # `import * as helpers from './helpers'; helpers.build(x)`
            target = self.js_module(module, module.aliases[callee.obj.name][0])
            symbol = (
                self.js_export(target, callee.prop.name, 0) if target is not None else None
            )
        else:
            return None
        if symbol is None or not isinstance(symbol.value, FunctionNode):
            return None
        info = symbol.module.functions_by_node.get(id(symbol.value))
        return (symbol.module, info) if info is not None else None

    def js_callers(self, module: JsModule, info: JsFunctionInfo) -> list[tuple[JsModule, CallExpr]]:
        """Every resolved call site of ``info`` across the project."""
        if self._js_callers is None:
            self._js_callers = defaultdict(list)
            for caller in self.javascript.values():
                for call in caller.calls:
                    target = self.js_function(caller, call.callee)
                    if target is not None:
                        self._js_callers[
                            (target[0].relative_path, target[1].qualified_name)
                        ].append((caller, call))
        return self._js_callers.get((module.relative_path, info.qualified_name), [])


# -- helpers ------------------------------------------------------------------


def js_returns(function: FunctionNode) -> list[Node]:
    """Return expressions of ``function`` itself, not of nested functions."""
    if function.expression_body is not None:
        return [function.expression_body]
    found: list[Node] = []
    stack: list[Node] = list(reversed(function.body))
    while stack:
        node = stack.pop()
        if isinstance(node, FunctionNode):
            continue
        if isinstance(node, ReturnStmt) and node.argument is not None:
            found.append(node.argument)
            continue
        stack.extend(reversed(list(children(node))))
    return found


def python_returns(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST] | None:
    """Return expressions of ``function``; None for generators (not modeled)."""
    found: list[ast.AST] = []
    stack: list[ast.AST] = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return None
        if isinstance(node, ast.Return):
            if node.value is not None:
                found.append(node.value)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return found


def _python_local_function(
    module: PythonModule, name: str, scope: str | None
) -> FunctionInfo | None:
    current = scope
    while True:
        qualified = f"{current}.{name}" if current else name
        info = module.functions.get(qualified)
        # A method is never the target of a bare-name call.
        if info is not None and (current is None or current in module.functions):
            return info
        if current is None:
            return None
        current = current.rsplit(".", 1)[0] if "." in current else None


def _js_local_function(module: JsModule, name: str, scope: str | None) -> JsFunctionInfo | None:
    current = scope
    while True:
        qualified = f"{current}.{name}" if current else name
        info = module.functions.get(qualified)
        if info is not None:
            return info
        if current is None:
            return None
        current = current.rsplit(".", 1)[0] if "." in current else None


def _js_top_level(module: JsModule, name: str) -> JsSymbolRef | None:
    info = module.functions.get(name)
    if info is not None:
        return JsSymbolRef(module, name, info.node)
    bindings = module.assignments.get((None, name))
    if bindings:
        return JsSymbolRef(module, name, bindings[0].value)
    for node in module.program.body:
        if isinstance(node, VarDecl) and node.name == name and node.init is None:
            return JsSymbolRef(module, name, None)
    return None


def _python_defines(module: PythonModule, name: str) -> bool:
    return name in module.functions or (None, name) in module.assignments or any(
        isinstance(node, ast.ClassDef) and node.name == name for node in module.tree.body
    )


def _python_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _python_dotted(path: str) -> str:
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _python_module_names(path: str) -> list[str]:
    """Every dotted name under which ``path`` may be importable.

    The full path is always a candidate.  So is every suffix, because a project
    commonly runs from a sub-directory (``src/``, ``app/``, ``backend/``) that
    is on ``sys.path``; :meth:`ProjectIndex.python_module` refuses ambiguous
    suffixes rather than guessing.
    """
    dotted = _python_dotted(path)
    if not dotted:
        return []
    parts = dotted.split(".")
    return [".".join(parts[index:]) for index in range(len(parts))]


def _join(directory: str, relative: str) -> str:
    parts: list[str] = [part for part in directory.split("/") if part and part != "."]
    for part in relative.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


__all__ = [
    "MAX_CALL_DEPTH",
    "MAX_CALL_SITES",
    "Budget",
    "JsSymbolRef",
    "ProjectIndex",
    "PyFunctionRef",
    "PySymbolRef",
    "js_returns",
    "python_returns",
    "walk",
]
