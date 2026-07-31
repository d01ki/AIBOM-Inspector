"""Tolerant JavaScript/TypeScript tokenizer.

The scanner is deliberately forgiving: unfamiliar syntax degrades into ordinary
punctuation tokens rather than raising.  It never evaluates the source it reads.

Template literals are emitted as a single ``template`` token holding their raw
body; :mod:`aibom.detectors.javascript.parser` re-scans that body so nested
``${...}`` expressions keep correct line numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

# Longest-first so that '>>>=' wins over '>>>' and '>>' over '>'.
_PUNCTUATORS = sorted(
    (
        ">>>=",
        "...",
        "===",
        "!==",
        "**=",
        "<<=",
        ">>=",
        ">>>",
        "&&=",
        "||=",
        "??=",
        "=>",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "??",
        "?.",
        "**",
        "++",
        "--",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "&=",
        "|=",
        "^=",
        "<<",
        ">>",
        "{",
        "}",
        "(",
        ")",
        "[",
        "]",
        ";",
        ",",
        "<",
        ">",
        "+",
        "-",
        "*",
        "/",
        "%",
        "&",
        "|",
        "^",
        "!",
        "~",
        "?",
        ":",
        "=",
        ".",
        "@",
        "#",
    ),
    key=len,
    reverse=True,
)

# After these, a '/' starts a regular expression rather than a division.
_REGEX_PRECEDING_KEYWORDS = frozenset(
    {
        "return",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
        "yield",
        "await",
    }
)
_REGEX_FORBIDDEN_PUNCTUATION = frozenset({")", "]", "++", "--"})

_IDENT_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$")
_IDENT_PART = _IDENT_START | frozenset("0123456789")


@dataclass(frozen=True)
class Token:
    """A single lexical unit with 1-based line and column positions."""

    type: str  # name | number | string | template | punct | regex
    value: str  # identifier text, decoded string value, or punctuator
    raw: str
    line: int
    column: int
    end_line: int

    @property
    def is_name(self) -> bool:
        return self.type == "name"

    def is_punct(self, *values: str) -> bool:
        return self.type == "punct" and self.value in values


def tokenize(source: str) -> list[Token]:
    """Scan ``source`` into tokens, skipping comments and whitespace."""
    return _Scanner(source).run()


class _Scanner:
    def __init__(self, source: str) -> None:
        self.src = source
        self.pos = 0
        self.line = 1
        self.line_start = 0
        self.tokens: list[Token] = []

    def run(self) -> list[Token]:
        while self.pos < len(self.src):
            if self._skip_trivia():
                continue
            char = self.src[self.pos]
            if char in _IDENT_START:
                self._read_name()
            elif char.isdigit() or (char == "." and self._peek(1).isdigit()):
                self._read_number()
            elif char in "'\"":
                self._read_string(char)
            elif char == "`":
                self._read_template()
            elif char == "/" and self._regex_allowed():
                self._read_regex()
            else:
                self._read_punctuator()
        return self.tokens

    # -- trivia ---------------------------------------------------------

    def _skip_trivia(self) -> bool:
        char = self.src[self.pos]
        if char == "\n":
            self._newline()
            return True
        if char in " \t\r\f\v ﻿":
            self.pos += 1
            return True
        if char == "/" and self._peek(1) == "/":
            while self.pos < len(self.src) and self.src[self.pos] != "\n":
                self.pos += 1
            return True
        if char == "/" and self._peek(1) == "*":
            self.pos += 2
            while self.pos < len(self.src):
                if self.src[self.pos] == "*" and self._peek(1) == "/":
                    self.pos += 2
                    return True
                if self.src[self.pos] == "\n":
                    self._newline()
                else:
                    self.pos += 1
            return True
        return False

    def _newline(self) -> None:
        self.pos += 1
        self.line += 1
        self.line_start = self.pos

    def _peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.src[index] if index < len(self.src) else ""

    # -- token readers --------------------------------------------------

    def _read_name(self) -> None:
        start, line, column = self.pos, self.line, self._column()
        while self.pos < len(self.src) and self.src[self.pos] in _IDENT_PART:
            self.pos += 1
        raw = self.src[start : self.pos]
        self._emit("name", raw, raw, line, column)

    def _read_number(self) -> None:
        start, line, column = self.pos, self.line, self._column()
        while self.pos < len(self.src):
            char = self.src[self.pos]
            if (
                char in _IDENT_PART
                or char == "."
                or (char in "+-" and self.src[self.pos - 1] in "eE")
            ):
                self.pos += 1
            else:
                break
        raw = self.src[start : self.pos]
        self._emit("number", raw, raw, line, column)

    def _read_string(self, quote: str) -> None:
        start, line, column = self.pos, self.line, self._column()
        self.pos += 1
        chunks: list[str] = []
        while self.pos < len(self.src):
            char = self.src[self.pos]
            if char == "\\":
                chunks.append(self._read_escape())
                continue
            if char == quote:
                self.pos += 1
                break
            if char == "\n":  # unterminated; bail out at the line break
                self._newline()
                break
            chunks.append(char)
            self.pos += 1
        self._emit("string", "".join(chunks), self.src[start : self.pos], line, column)

    def _read_escape(self) -> str:
        """Consume a backslash escape, returning its literal-ish text."""
        self.pos += 1  # the backslash
        if self.pos >= len(self.src):
            return ""
        char = self.src[self.pos]
        if char == "\n":
            self._newline()
            return ""
        self.pos += 1
        return {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0"}.get(
            char, char
        )

    def _read_template(self) -> None:
        """Read a whole template literal, including nested ``${}`` templates."""
        start, line, column = self.pos, self.line, self._column()
        self.pos += 1  # opening backtick
        depth = 0
        while self.pos < len(self.src):
            char = self.src[self.pos]
            if char == "\\":
                self._read_escape()
                continue
            if char == "\n":
                self._newline()
                continue
            if char == "$" and self._peek(1) == "{":
                depth += 1
                self.pos += 2
                continue
            if depth and char in "'\"":
                # A quoted string inside ${...} may hold braces or backticks.
                self._read_string(char)
                self.tokens.pop()
                continue
            if char == "}" and depth:
                depth -= 1
                self.pos += 1
                continue
            if char == "`":
                if depth == 0:
                    self.pos += 1
                    break
                # A nested template inside ${...}: consume it recursively.
                self._read_template()
                self.tokens.pop()
                continue
            self.pos += 1
        raw = self.src[start : self.pos]
        self._emit("template", raw, raw, line, column)

    def _read_regex(self) -> None:
        start, line, column = self.pos, self.line, self._column()
        self.pos += 1
        in_class = False
        while self.pos < len(self.src):
            char = self.src[self.pos]
            if char == "\\":
                self.pos += 2
                continue
            if char == "\n":  # unterminated regex; treat as punctuation
                self.pos = start + 1
                self._emit("punct", "/", "/", line, column)
                return
            if char == "[":
                in_class = True
            elif char == "]":
                in_class = False
            elif char == "/" and not in_class:
                self.pos += 1
                break
            self.pos += 1
        while self.pos < len(self.src) and self.src[self.pos] in _IDENT_PART:
            self.pos += 1
        raw = self.src[start : self.pos]
        self._emit("regex", raw, raw, line, column)

    def _read_punctuator(self) -> None:
        line, column = self.line, self._column()
        for punct in _PUNCTUATORS:
            if self.src.startswith(punct, self.pos):
                self.pos += len(punct)
                self._emit("punct", punct, punct, line, column)
                return
        char = self.src[self.pos]
        self.pos += 1
        self._emit("punct", char, char, line, column)

    # -- helpers --------------------------------------------------------

    def _column(self) -> int:
        return self.pos - self.line_start + 1

    def _emit(self, type_: str, value: str, raw: str, line: int, column: int) -> None:
        self.tokens.append(
            Token(
                type=type_,
                value=value,
                raw=raw,
                line=line,
                column=column,
                end_line=self.line,
            )
        )

    def _regex_allowed(self) -> bool:
        """Decide whether '/' opens a regex, using the previous token."""
        if not self.tokens:
            return True
        previous = self.tokens[-1]
        if previous.type in {"number", "string", "template", "regex"}:
            return False
        if previous.is_name:
            return previous.value in _REGEX_PRECEDING_KEYWORDS
        return previous.value not in _REGEX_FORBIDDEN_PUNCTUATION
