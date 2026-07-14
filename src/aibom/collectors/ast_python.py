"""AST-based Python detector with lightweight value resolution.

Regex/line matching misses the way real code is written: model names arrive
through variables, dicts, f-strings, string concatenation, environment-variable
defaults, and import aliases. This detector parses the file with :mod:`ast` and
resolves those values statically. For example, a model id assigned to a variable
(directly, from a dict entry, or from an ``os.getenv`` default) and then passed
as a ``model=`` argument is resolved to its concrete value with a note of *how*
it was resolved — cases the line-level regex detectors cannot see.

Design constraints (Black Hat plan §7, §28):

* **Never executes the code.** It only reads the AST — no ``eval``/``exec``/import.
* **No guessing.** Unresolvable values are dropped, never invented.
* **Fallback-safe.** A parse error yields no detections (the regex pass still ran).
* **Evidence-backed.** Every detection carries ``file:line`` and the resolution kind.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from aibom.models.entities import Dataset, Model
from aibom.models.evidence import Evidence

_WEIGHT_SUFFIXES = (
    ".safetensors", ".gguf", ".onnx", ".h5", ".pt", ".pth", ".ckpt",
    ".pkl", ".pickle", ".msgpack", ".bin", ".pb",
)
_RE_LLM_MODEL = re.compile(
    r"^(?:gpt-|o1|o3|o4|chatgpt-|claude-|gemini-|text-embedding-|text-davinci-"
    r"|dall-e|whisper|tts-|voyage-|mistral-|mixtral-|deepseek-|command-)"
    r"[A-Za-z0-9._\-]*$"
)

# Call keywords that name a model, and how strict to be about the resolved value.
_MODEL_KWARGS = ("model", "model_id", "model_name", "model_name_or_path", "repo_id")

# Confidence per resolution kind (syntax is certain; value certainty varies).
_KIND_CONFIDENCE = {
    "literal": 0.95,
    "variable": 0.9,
    "dict": 0.9,
    "concat": 0.9,
    "fstring": 0.9,
    "env_default": 0.85,
}


@dataclass
class _Resolved:
    value: str
    kind: str


def detect_python(text: str, rel: str) -> list[Model | Dataset]:
    """Return Model/Dataset entities found by AST analysis of ``text``."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []  # not Python 3 / unparseable — regex fallback already ran

    resolver = _Resolver(tree)
    out: list[Model | Dataset] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        out.extend(resolver.detections_for_call(node, rel))
    return _dedupe(out)


class _Resolver:
    """Resolves simple static values from a module's assignments."""

    def __init__(self, tree: ast.Module) -> None:
        # name -> resolved value (last simple assignment wins; scope flattened,
        # which is enough for the common module/function-constant pattern).
        self._names: dict[str, _Resolved] = {}
        self._dicts: dict[str, dict[str, _Resolved]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind(target, node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._bind(node.target, node.value)

    def _bind(self, target: ast.expr, value: ast.expr) -> None:
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, ast.Dict):
            resolved = self._dict_literal(value)
            if resolved:
                self._dicts[target.id] = resolved
        r = self._resolve(value)
        if r is not None:
            self._names[target.id] = r

    # -- call handling ---------------------------------------------------------

    def detections_for_call(self, call: ast.Call, rel: str) -> list[Model | Dataset]:
        func = call.func
        fname = func.attr if isinstance(func, ast.Attribute) else (
            func.id if isinstance(func, ast.Name) else None
        )
        out: list[Model | Dataset] = []

        # datasets.load_dataset with a literal or variable name argument
        if fname == "load_dataset":
            arg = call.args[0] if call.args else None
            r = self._resolve(arg) if arg is not None else None
            if r is not None:
                out.append(self._dataset(r, rel, call.lineno))
            return out

        # from_pretrained(<model>, ...) — first positional or the pretrained kwarg
        if fname == "from_pretrained":
            arg = call.args[0] if call.args else _kwarg(call, "pretrained_model_name_or_path")
            r = self._resolve(arg) if arg is not None else None
            if r is not None:
                m = self._model(r, rel, call.lineno, "from_pretrained", lenient=True)
                if m is not None:
                    out.append(m)
            return out

        # model=/model_id=/repo_id=… keyword on any call (pipeline, SDK, wrappers)
        lenient = fname in {"pipeline"}
        for kw in call.keywords:
            if kw.arg not in _MODEL_KWARGS:
                continue
            r = self._resolve(kw.value)
            if r is None:
                continue
            ctx = f"{fname or 'call'}:{kw.arg}"
            is_lenient = lenient or kw.arg in {"repo_id", "model_name_or_path"}
            m = self._model(r, rel, call.lineno, ctx, lenient=is_lenient)
            if m is not None:
                out.append(m)
        return out

    # -- entity builders -------------------------------------------------------

    def _model(
        self, r: _Resolved, rel: str, line: int, ctx: str, *, lenient: bool
    ) -> Model | None:
        provider = classify_model(r.value, lenient=lenient)
        if provider is None:
            return None
        conf = _KIND_CONFIDENCE.get(r.kind, 0.8)
        note = "" if r.kind == "literal" else f" [{r.kind}]"
        ev = Evidence(
            file=rel, line_start=line, line_end=line,
            snippet=f"{ctx}={r.value}{note}"[:200],
            matched_pattern=f"ast-{ctx}:{r.kind}", confidence=conf,
        )
        fmts: list[str] = []
        if provider == "local" and "." in r.value:
            fmts = [r.value.rsplit(".", 1)[-1].lower()]
        return Model(name=r.value, provider=provider, formats=fmts, source_evidence=[ev])

    def _dataset(self, r: _Resolved, rel: str, line: int) -> Dataset:
        conf = _KIND_CONFIDENCE.get(r.kind, 0.8)
        note = "" if r.kind == "literal" else f" [{r.kind}]"
        ev = Evidence(
            file=rel, line_start=line, line_end=line,
            snippet=f"load_dataset={r.value}{note}"[:200],
            matched_pattern=f"ast-load_dataset:{r.kind}", confidence=conf,
        )
        return Dataset(name=r.value, source="huggingface", source_evidence=[ev])

    # -- value resolution ------------------------------------------------------

    def _resolve(self, node: ast.expr | None, depth: int = 0) -> _Resolved | None:
        if node is None or depth > 6:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _Resolved(node.value, "literal")
        if isinstance(node, ast.Name):
            base = self._names.get(node.id)
            if base is None:
                return None
            # Surface *how* the bound value was resolved (env_default, concat…);
            # only a plain literal assignment reads as a mere "variable".
            kind = "variable" if base.kind == "literal" else base.kind
            return _Resolved(base.value, kind)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve(node.left, depth + 1)
            right = self._resolve(node.right, depth + 1)
            if left and right:
                return _Resolved(left.value + right.value, "concat")
            return None
        if isinstance(node, ast.JoinedStr):
            return self._resolve_fstring(node, depth)
        if isinstance(node, ast.Subscript):
            return self._resolve_subscript(node)
        if isinstance(node, ast.Call):
            return self._resolve_env(node)
        return None

    def _resolve_fstring(self, node: ast.JoinedStr, depth: int) -> _Resolved | None:
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner = self._resolve(value.value, depth + 1)
                if inner is None:
                    return None  # a dynamic piece -> don't guess
                parts.append(inner.value)
            else:
                return None
        return _Resolved("".join(parts), "fstring")

    def _resolve_subscript(self, node: ast.Subscript) -> _Resolved | None:
        if not isinstance(node.value, ast.Name):
            return None
        table = self._dicts.get(node.value.id)
        if table is None:
            return None
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            hit = table.get(key.value)
            return _Resolved(hit.value, "dict") if hit else None
        return None

    def _resolve_env(self, node: ast.Call) -> _Resolved | None:
        """os.getenv('X', 'default') / os.environ.get('X', 'default') -> default."""
        func = node.func
        name = None
        if isinstance(func, ast.Attribute):
            name = func.attr
        if name not in {"getenv", "get"}:
            return None
        # need it to be an environ-ish access with a string default (2nd positional)
        if len(node.args) < 2:
            return None
        default = self._resolve(node.args[1], depth=1)
        if default is None:
            return None
        return _Resolved(default.value, "env_default")

    def _dict_literal(self, node: ast.Dict) -> dict[str, _Resolved]:
        out: dict[str, _Resolved] = {}
        for key, value in zip(node.keys, node.values, strict=False):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                r = self._resolve(value)
                if r is not None:
                    out[key.value] = r
        return out


# ── helpers ──────────────────────────────────────────────────────────────────


def classify_model(value: str, *, lenient: bool) -> str | None:
    """Return a provider for a model-like string, or None if it isn't one.

    Shared by the Python and JavaScript/TypeScript resolvers.
    """
    v = value.strip()
    if not v or " " in v or "\n" in v:
        return None
    if v.startswith((".", "/", "~")) or "\\" in v or v.lower().endswith(_WEIGHT_SUFFIXES):
        return "local"
    if _RE_LLM_MODEL.match(v):
        return "anthropic" if v.startswith("claude-") else "openai"
    if "/" in v and not v.startswith(("http://", "https://")):
        return "huggingface"
    # A bare id like "bert-base-uncased" is a model only in a model-ish context.
    if lenient and re.fullmatch(r"[A-Za-z0-9][\w.\-]{1,}", v):
        return "huggingface"
    return None


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _dedupe(entities: list[Model | Dataset]) -> list[Model | Dataset]:
    seen: set[tuple[str, str, int]] = set()
    out: list[Model | Dataset] = []
    for e in entities:
        ev = e.source_evidence[0]
        key = (e.natural_key()[1], ev.file, ev.line_start)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out
