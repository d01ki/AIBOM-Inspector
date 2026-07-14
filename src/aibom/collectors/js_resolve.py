"""Lightweight JavaScript/TypeScript value resolution.

TypeScript/JavaScript is the second most common language for AI apps (Vercel AI
SDK, LangChain.js, MCP servers, Next.js RAG). The line-level regex pass already
catches quoted model ids and SDK imports; this adds the indirection real code
uses — a model id assigned to a ``const`` (directly, or from a
``process.env.X || <default>`` fallback) and then passed as a ``model:`` property
or via the ``{ model }`` shorthand is resolved to its concrete value.

This is a regex + symbol-table resolver, not a full parser (no Node/tree-sitter
dependency): robust for the common patterns, and — like the rest of the tool —
it never executes the code and never guesses unresolved values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aibom.collectors.ast_python import classify_model
from aibom.models.entities import Model
from aibom.models.evidence import Evidence

# const/let/var NAME = "literal"
_JS_VAR_ASSIGN = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*"""
    r"""(['"`])([^'"`\n]+)\2""",
)
# const NAME = process.env.FOO || "default"  (also ?? default)
_JS_ENV_ASSIGN = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*"""
    r"""process\.env\.\w+\s*(?:\|\||\?\?)\s*(['"`])([^'"`\n]+)\2""",
)
# model: IDENT   or   model = IDENT   (bare identifier, not a member/string)
_JS_MODEL_VAR = re.compile(r"""\bmodel\s*[:=]\s*([A-Za-z_$][\w$]*)\b(?!\s*[.(])""")
# { model }  or  { model, ... }  shorthand -> resolves a var literally named "model"
_JS_MODEL_SHORTHAND = re.compile(r"""\{\s*model\s*[,}]""")
# model: process.env.FOO || "default"
_JS_MODEL_ENV = re.compile(
    r"""\bmodel\s*:\s*process\.env\.\w+\s*(?:\|\||\?\?)\s*(['"`])([^'"`\n]+)\1""",
)

_KIND_CONFIDENCE = {"variable": 0.85, "env_default": 0.8}


@dataclass
class _Resolved:
    value: str
    kind: str


def detect_javascript(text: str, rel: str) -> list[Model]:
    """Return Model entities resolved from JS/TS variable indirection."""
    symbols = _symbol_table(text)
    out: list[Model] = []
    seen: set[tuple[str, int]] = set()

    def emit(value: str, kind: str, pos: int) -> None:
        provider = classify_model(value, lenient=False)
        if provider is None:
            return
        line = text.count("\n", 0, pos) + 1
        key = (value, line)
        if key in seen:
            return
        seen.add(key)
        ev = Evidence(
            file=rel, line_start=line, line_end=line,
            snippet=f"model={value} [{kind}]"[:200],
            matched_pattern=f"js-model:{kind}",
            confidence=_KIND_CONFIDENCE.get(kind, 0.8),
        )
        out.append(Model(name=value, provider=provider, source_evidence=[ev]))

    for m in _JS_MODEL_ENV.finditer(text):
        emit(m.group(2), "env_default", m.start())
    for m in _JS_MODEL_VAR.finditer(text):
        resolved = symbols.get(m.group(1))
        if resolved is not None:
            emit(resolved.value, resolved.kind, m.start())
    for m in _JS_MODEL_SHORTHAND.finditer(text):
        resolved = symbols.get("model")
        if resolved is not None:
            emit(resolved.value, resolved.kind, m.start())
    return out


def _symbol_table(text: str) -> dict[str, _Resolved]:
    table: dict[str, _Resolved] = {}
    for m in _JS_VAR_ASSIGN.finditer(text):
        table[m.group(1)] = _Resolved(m.group(3), "variable")
    # env defaults override plain literals for the same name (more informative).
    for m in _JS_ENV_ASSIGN.finditer(text):
        table[m.group(1)] = _Resolved(m.group(3), "env_default")
    return table
