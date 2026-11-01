"""Safe, bounded reading of user-supplied identity manifests and policy files.

Two guarantees:

* **No path escapes.**  Every referenced file is resolved (symlinks included)
  and must stay inside the workspace root; absolute paths, URLs and drive
  letters are rejected outright.
* **No code paths in the parser.**  ``aibom-identity.yaml`` is read with a
  small, strict YAML *subset* parser (block mappings, block lists, flow lists of
  scalars, quoted/plain scalars).  Anchors, aliases, tags, block scalars and
  multi-document streams are rejected rather than interpreted, so a manifest is
  always data and never an instruction.  JSON manifests are accepted too.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

MAX_MANIFEST_BYTES = 256 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_LINES = 5000
MAX_DEPTH = 12


class InputError(ValueError):
    """User-supplied input is unsafe or malformed; the CLI exits with code 2."""


_DRIVE = re.compile(r"^[A-Za-z]:")


def safe_path(root: Path, reference: str, *, label: str) -> Path:
    """Resolve ``reference`` under ``root`` or raise :class:`InputError`."""
    if not isinstance(reference, str) or not reference.strip():
        raise InputError(f"{label}: empty path")
    ref = reference.strip().replace("\\", "/")
    if "://" in ref or ref.startswith("/") or _DRIVE.match(ref) or "\x00" in ref:
        raise InputError(f"{label}: '{reference}' must be a workspace-relative path")
    if ".." in PurePosixPath(ref).parts:
        raise InputError(f"{label}: '{reference}' must not contain '..'")
    base = root.resolve()
    resolved = (base / ref).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise InputError(f"{label}: '{reference}' resolves outside the workspace") from None
    return resolved


def read_bounded(path: Path, limit: int, *, label: str) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FileNotFoundError(f"{label}: cannot read {path.name}: {exc.strerror}") from None
    if size > limit:
        raise InputError(f"{label}: {path.name} is {size} bytes (limit {limit})")
    return path.read_text(encoding="utf-8", errors="strict")


def relative_to_root(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


# -- strict YAML subset ---------------------------------------------------------


def load_structured(text: str, *, label: str) -> Any:
    """Parse JSON or the supported YAML subset."""
    stripped = text.lstrip("﻿").strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise InputError(f"{label}: invalid JSON ({exc.msg} at line {exc.lineno})") from None
    return _YamlSubset(stripped, label).parse()


class _YamlSubset:
    def __init__(self, text: str, label: str) -> None:
        self.label = label
        raw = text.splitlines()
        if len(raw) > MAX_LINES:
            raise InputError(f"{label}: too many lines")
        self.lines: list[tuple[int, int, str]] = []
        for number, line in enumerate(raw, start=1):
            if "\t" in line[: len(line) - len(line.lstrip())]:
                raise self.error(number, "tabs are not allowed for indentation")
            content = _strip_comment(line).rstrip()
            if not content.strip():
                continue
            if content.strip() in {"---", "..."}:
                if self.lines:
                    raise self.error(number, "multi-document streams are not supported")
                continue
            indent = len(content) - len(content.lstrip(" "))
            self.lines.append((number, indent, content.strip()))
        self.pos = 0

    def error(self, line: int, message: str) -> InputError:
        return InputError(f"{self.label}: line {line}: {message}")

    def parse(self) -> Any:
        if not self.lines:
            return {}
        value = self._block(self.lines[0][1], 0)
        if self.pos != len(self.lines):
            number = self.lines[self.pos][0]
            raise self.error(number, "unexpected indentation")
        return value

    def _block(self, indent: int, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise self.error(self.lines[self.pos][0], "nesting too deep")
        _, _, content = self.lines[self.pos]
        if content == "-" or content.startswith("- "):
            return self._list(indent, depth)
        return self._mapping(indent, depth)

    def _list(self, indent: int, depth: int) -> list[Any]:
        items: list[Any] = []
        while self.pos < len(self.lines):
            number, line_indent, content = self.lines[self.pos]
            if line_indent < indent:
                break
            if line_indent > indent or not (content == "-" or content.startswith("- ")):
                raise self.error(number, "expected a list item")
            rest = content[1:].strip()
            if not rest:
                self.pos += 1
                items.append(self._nested(indent, number, depth))
            elif _looks_like_key(rest):
                # "- key: value" opens a mapping whose keys align with "key".
                self.lines[self.pos] = (number, indent + 2, rest)
                items.append(self._mapping(indent + 2, depth + 1))
            else:
                self.pos += 1
                items.append(self._scalar(rest, number))
        return items

    def _mapping(self, indent: int, depth: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while self.pos < len(self.lines):
            number, line_indent, content = self.lines[self.pos]
            if line_indent < indent:
                break
            if line_indent > indent:
                raise self.error(number, "unexpected indentation")
            if content.startswith("- "):
                break
            key, sep, rest = _split_key(content)
            if not sep:
                raise self.error(number, "expected 'key: value'")
            if key in result:
                raise self.error(number, f"duplicate key '{key}'")
            self.pos += 1
            if rest:
                result[key] = self._scalar(rest, number)
            else:
                result[key] = self._nested(indent, number, depth, allow_same_indent_list=True)
        return result

    def _nested(
        self, indent: int, number: int, depth: int, *, allow_same_indent_list: bool = False
    ) -> Any:
        if self.pos >= len(self.lines):
            return None
        _, next_indent, content = self.lines[self.pos]
        same_level_list = (
            allow_same_indent_list and next_indent == indent and content.startswith("-")
        )
        if next_indent > indent or same_level_list:
            return self._block(next_indent, depth + 1)
        return None

    def _scalar(self, text: str, number: int) -> Any:
        if text[0] in "&*!|>{%@`":
            raise self.error(number, f"unsupported YAML construct '{text[0]}'")
        if text.startswith("["):
            if not text.endswith("]"):
                raise self.error(number, "unterminated flow list")
            inner = text[1:-1].strip()
            if not inner:
                return []
            return [self._scalar(part.strip(), number) for part in _split_flow(inner, self, number)]
        if text[0] in "\"'":
            return _unquote(text, self, number)
        if text in {"null", "~", "Null", "NULL"}:
            return None
        if text in {"true", "True", "TRUE"}:
            return True
        if text in {"false", "False", "FALSE"}:
            return False
        if re.fullmatch(r"-?\d{1,18}", text):
            return int(text)
        return text


def _strip_comment(line: str) -> str:
    quote: str | None = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _looks_like_key(text: str) -> bool:
    key, sep, _ = _split_key(text)
    return bool(sep) and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-]*", key))


def _split_key(text: str) -> tuple[str, str, str]:
    if text[:1] in "\"'":
        return "", "", text
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_\-]*):(\s+(.*))?$", text)
    if not match:
        return "", "", text
    return match.group(1), ":", (match.group(3) or "").strip()


def _split_flow(inner: str, parser: _YamlSubset, number: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in inner:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            current.append(char)
        elif char == ",":
            parts.append("".join(current))
            current = []
        elif char in "[]{}":
            raise parser.error(number, "nested flow collections are not supported")
        else:
            current.append(char)
    if quote:
        raise parser.error(number, "unterminated quoted string")
    parts.append("".join(current))
    return [part for part in parts if part.strip()]


def _unquote(text: str, parser: _YamlSubset, number: int) -> str:
    quote = text[0]
    if len(text) < 2 or text[-1] != quote:
        raise parser.error(number, "unterminated quoted string")
    body = text[1:-1]
    if quote == "'":
        return body.replace("''", "'")
    if "\\" in body:
        body = body.replace('\\"', '"').replace("\\\\", "\\")
    return body
