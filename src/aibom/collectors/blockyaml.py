"""A small, line-numbered reader for the block YAML that package managers write.

``pnpm-lock.yaml`` and yarn berry's ``yarn.lock`` are machine-written YAML in a
narrow subset: indentation-nested mappings, ``- item`` lists of scalars, plain
or quoted scalars, and one-line flow mappings such as
``resolution: {integrity: sha512-…}``. This reader covers that subset and
nothing more, so the project needs no YAML dependency, and every node keeps
the 1-indexed line it came from, which is what evidence must cite.

Anything outside the subset (anchors, multi-line flow collections, block
scalars) is skipped rather than guessed at: a value the reader cannot read is
absent, never invented. It never raises on malformed input.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Node:
    """One mapping key (or the document root) and what it holds."""

    line: int
    value: str | None = None
    children: dict[str, Node] = field(default_factory=dict)
    items: list[str] = field(default_factory=list)

    def get(self, key: str) -> Node | None:
        return self.children.get(key)

    def scalar(self, key: str) -> str | None:
        child = self.children.get(key)
        return child.value if child is not None and child.value else None


def parse(text: str) -> Node:
    """Parse ``text`` into a tree of :class:`Node`; the root is line 0."""
    root = Node(line=0)
    stack: list[tuple[int, Node]] = [(-1, root)]
    skip_deeper_than: int | None = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if skip_deeper_than is not None:
            if indent > skip_deeper_than:
                continue
            skip_deeper_than = None
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if stripped.startswith("- ") or stripped == "-":
            item = unquote(stripped[1:].strip())
            if item:
                parent.items.append(item)
            continue
        split = _split_key(stripped)
        if split is None:
            # Not a key: a wrapped scalar or a construct outside the subset.
            continue
        key, rest = split
        node = Node(line=lineno)
        parent.children.setdefault(key, node)
        if not rest:
            stack.append((indent, node))
        elif rest.startswith("{"):
            node.children = _flow_map(rest, lineno)
        elif rest[0] in "|>[&*!":
            # Block scalar, flow sequence, anchor, alias or tag: not read.
            skip_deeper_than = indent
        else:
            node.value = unquote(rest)
    return root


def _split_key(text: str) -> tuple[str, str] | None:
    """``key: rest`` -> ``(key, rest)``; quoted keys may contain ``:``."""
    if text[0] in "'\"":
        end = _closing_quote(text, text[0])
        if end is None or text[end + 1 : end + 2] != ":":
            return None
        rest = text[end + 2 :]
        if rest and not rest.startswith(" "):
            return None
        return unquote(text[: end + 1]), rest.strip()
    sep = text.find(": ")
    if sep > 0:
        return text[:sep].strip(), text[sep + 2 :].strip()
    if len(text) > 1 and text.endswith(":"):
        return text[:-1].strip(), ""
    return None


def _closing_quote(text: str, quote: str) -> int | None:
    i = 1
    while i < len(text):
        ch = text[i]
        if quote == "'" and ch == "'":
            if text[i + 1 : i + 2] == "'":
                i += 2
                continue
            return i
        if quote == '"':
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                return i
        i += 1
    return None


def unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return text


def _flow_map(text: str, lineno: int) -> dict[str, Node]:
    """``{a: b, c: 'd'}`` on one line -> scalar children; nested flow is skipped."""
    if not text.endswith("}"):
        return {}
    out: dict[str, Node] = {}
    for part in split_top_level(text[1:-1]):
        split = _split_key(part.strip()) if part.strip() else None
        if split is None:
            continue
        key, value = split
        if value and value[0] not in "{[":
            out.setdefault(key, Node(line=lineno, value=unquote(value)))
    return out


def split_top_level(text: str) -> list[str]:
    """Split on commas outside quotes and nested brackets."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts
