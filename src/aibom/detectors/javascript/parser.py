"""Tolerant recursive-descent parser for the analyzed JavaScript/TypeScript subset.

The parser never evaluates the source.  Anything it does not model — TypeScript
type syntax, decorators, exotic statements — is skipped or reduced to
:class:`~aibom.detectors.javascript.nodes.Unknown` so a single unusual
construct cannot abort the scan of a file.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypedDict

from aibom.detectors.javascript.nodes import (
    ArrayExpr,
    AssignExpr,
    AwaitExpr,
    BinaryExpr,
    Block,
    CallExpr,
    ClassDecl,
    ConditionalExpr,
    ExpressionStmt,
    FunctionNode,
    Identifier,
    ImportDecl,
    Literal,
    MemberExpr,
    Node,
    ObjectExpr,
    Param,
    Program,
    Property,
    ReturnStmt,
    SequenceExpr,
    SpreadExpr,
    TemplateLiteral,
    UnaryExpr,
    Unknown,
    VarDecl,
    children,
    walk,
)
from aibom.detectors.javascript.tokenizer import Token, tokenize

_OPEN_BRACKETS = frozenset({"(", "[", "{"})
_CLOSE_BRACKETS = frozenset({")", "]", "}"})
_DECLARATION_KEYWORDS = frozenset({"const", "let", "var"})
_SKIPPED_DECLARATIONS = frozenset({"interface", "enum", "namespace", "module", "declare"})
_PARAM_MODIFIERS = frozenset({"public", "private", "protected", "readonly", "override"})
_MEMBER_MODIFIERS = frozenset(
    {"public", "private", "protected", "readonly", "static", "abstract", "override", "declare"}
)
_UNARY_KEYWORDS = frozenset({"typeof", "void", "delete"})

# Binary operator precedence (higher binds tighter).
_BINARY_PRECEDENCE: dict[str, int] = {
    "??": 1,
    "||": 2,
    "&&": 3,
    "|": 4,
    "^": 5,
    "&": 6,
    "==": 7,
    "!=": 7,
    "===": 7,
    "!==": 7,
    "<": 8,
    ">": 8,
    "<=": 8,
    ">=": 8,
    "instanceof": 8,
    "in": 8,
    "<<": 9,
    ">>": 9,
    ">>>": 9,
    "+": 10,
    "-": 10,
    "*": 11,
    "/": 11,
    "%": 11,
    "**": 12,
}
_ASSIGNMENT_OPERATORS = frozenset(
    {"=", "+=", "-=", "*=", "/=", "%=", "**=", "&&=", "||=", "??=", "&=", "|=", "^=", "<<=", ">>="}
)

#: Statement handlers all accept the `exported` flag and may produce no node.
_StatementHandler = Callable[..., Node | None]

#: Bracket-nesting ceiling; beyond it the parser stops descending.
_MAX_NESTING = 60


class _Position(TypedDict):
    """Source position keywords shared by every node constructor."""

    line: int
    column: int
    end_line: int


class Parser:
    """Token-stream parser producing the bounded node tree."""

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.i = 0
        self.depth = 0

    # -- token helpers --------------------------------------------------

    def at_end(self) -> bool:
        return self.i >= len(self.tokens)

    def peek(self, offset: int = 0) -> Token | None:
        index = self.i + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def advance(self) -> Token | None:
        token = self.peek()
        if token is not None:
            self.i += 1
        return token

    def at_punct(self, *values: str) -> bool:
        token = self.peek()
        return token is not None and token.is_punct(*values)

    def at_name(self, *values: str) -> bool:
        token = self.peek()
        return token is not None and token.is_name and token.value in values

    def eat_punct(self, *values: str) -> bool:
        if self.at_punct(*values):
            self.i += 1
            return True
        return False

    def eat_name(self, *values: str) -> bool:
        if self.at_name(*values):
            self.i += 1
            return True
        return False

    def _line(self) -> int:
        token = self.peek()
        return token.line if token is not None else 1

    def _position(self, token: Token | None) -> _Position:
        if token is None:
            return {"line": 1, "column": 1, "end_line": 1}
        return {"line": token.line, "column": token.column, "end_line": token.end_line}

    def _skip_balanced(self) -> None:
        """Consume one balanced bracket group starting at the current token."""
        if not self.at_punct("(", "[", "{"):
            return
        depth = 0
        while not self.at_end():
            token = self.advance()
            if token is None or token.type != "punct":
                continue
            if token.value in _OPEN_BRACKETS:
                depth += 1
            elif token.value in _CLOSE_BRACKETS:
                depth -= 1
                if depth <= 0:
                    return

    def _skip_type(self, stops: frozenset[str]) -> None:
        """Skip a TypeScript type until one of ``stops`` at bracket depth zero."""
        depth = 0
        while not self.at_end():
            token = self.peek()
            if token is None:
                return
            value = token.value
            # A stop wins over bracket bookkeeping: '{' both opens a function
            # body and nests an object type, and the caller decides which.
            if depth == 0 and value in stops:
                return
            if token.type == "punct":
                if value in _OPEN_BRACKETS or value == "<":
                    depth += 1
                elif value in _CLOSE_BRACKETS or value == ">":
                    if depth == 0:
                        return
                    depth -= 1
            self.i += 1

    def _skip_generic_parameters(self) -> None:
        if not self.at_punct("<"):
            return
        depth = 0
        while not self.at_end():
            token = self.advance()
            if token is None or token.type != "punct":
                continue
            if token.value == "<":
                depth += 1
            elif token.value == ">":
                depth -= 1
                if depth <= 0:
                    return
            elif token.value == ">>":
                depth -= 2
                if depth <= 0:
                    return
            elif token.value in {"{", ";"}:  # not a generic after all
                return

    # -- program & statements -------------------------------------------

    def parse_program(self) -> Program:
        start = self.peek()
        body: list[Node] = []
        while not self.at_end():
            before = self.i
            statement = self.parse_statement()
            if statement is not None:
                body.append(statement)
            if self.i == before:  # guarantee forward progress
                self.i += 1
        return Program(body=body, **self._position(start))

    def parse_statement(self, *, exported: bool = False) -> Node | None:
        token = self.peek()
        if token is None:
            return None
        if token.is_punct(";"):
            self.i += 1
            return None
        if token.is_punct("@"):  # decorator
            self.i += 1
            self._parse_call_member(self._parse_primary())
            return None
        if token.is_punct("{"):
            return self._parse_block()
        if token.is_name:
            handler = self._statement_keyword(token.value)
            if handler is not None:
                return handler(exported=exported)
        return self._parse_expression_statement()

    def _statement_keyword(self, keyword: str) -> _StatementHandler | None:
        if keyword == "import":
            return self._parse_import
        if keyword == "export":
            return self._parse_export
        if keyword in _DECLARATION_KEYWORDS:
            return self._parse_var_declaration
        if keyword == "function":
            return self._parse_function_declaration
        if keyword == "async" and self._next_is_name("function"):
            return self._parse_function_declaration
        if keyword == "class":
            return self._parse_class
        if keyword == "return":
            return self._parse_return
        if keyword == "type" and self._next_is_type_alias():
            return self._parse_skipped_declaration
        if keyword in _SKIPPED_DECLARATIONS:
            return self._parse_skipped_declaration
        if keyword in {"if", "for", "while", "switch", "catch", "with"}:
            return self._parse_control_flow
        if keyword in {"try", "finally", "do", "else"}:
            return self._parse_bare_block
        if keyword in {"throw", "break", "continue", "debugger", "yield"}:
            return self._parse_simple_jump
        return None

    def _next_is_name(self, value: str) -> bool:
        token = self.peek(1)
        return token is not None and token.is_name and token.value == value

    def _next_is_type_alias(self) -> bool:
        """Distinguish `type X = ...` from a variable literally named `type`."""
        name = self.peek(1)
        following = self.peek(2)
        return (
            name is not None
            and name.is_name
            and following is not None
            and (following.is_punct("=") or following.is_punct("<"))
        )

    def _parse_block(self) -> Block:
        start = self.peek()
        self.i += 1  # '{'
        body: list[Node] = []
        while not self.at_end() and not self.at_punct("}"):
            before = self.i
            statement = self.parse_statement()
            if statement is not None:
                body.append(statement)
            if self.i == before:
                self.i += 1
        self.eat_punct("}")
        return Block(body=body, **self._position(start))

    def _parse_import(self, *, exported: bool = False) -> Node | None:
        start = self.peek()
        if self.peek(1) is not None and self.peek(1).is_punct("(", "."):  # type: ignore[union-attr]
            return self._parse_expression_statement()  # dynamic import()
        self.i += 1  # 'import'
        if self.eat_name("type"):  # `import type { X } from 'y'` carries no runtime binding
            self._skip_to_statement_end()
            return None
        specifiers: dict[str, str] = {}
        if self.at_punct("*"):
            self.i += 1
            self.eat_name("as")
            local = self.advance()
            if local is not None and local.is_name:
                specifiers[local.value] = "*"
        elif self.at_punct("{"):
            specifiers.update(self._parse_named_import_specifiers())
        else:
            default = self.peek()
            if default is not None and default.is_name:
                self.i += 1
                specifiers[default.value] = "default"
            if self.eat_punct(","):
                if self.at_punct("{"):
                    specifiers.update(self._parse_named_import_specifiers())
                elif self.at_punct("*"):
                    self.i += 1
                    self.eat_name("as")
                    local = self.advance()
                    if local is not None and local.is_name:
                        specifiers[local.value] = "*"
        source = ""
        if self.eat_name("from"):
            module = self.peek()
            if module is not None and module.type == "string":
                source = module.value
                self.i += 1
        elif (token := self.peek()) is not None and token.type == "string":
            source = token.value  # bare side-effect import
            self.i += 1
        self._skip_to_statement_end()
        return ImportDecl(source=source, specifiers=specifiers, **self._position(start))

    def _parse_named_import_specifiers(self) -> dict[str, str]:
        specifiers: dict[str, str] = {}
        self.eat_punct("{")
        while not self.at_end() and not self.at_punct("}"):
            if self.eat_punct(","):
                continue
            self.eat_name("type")
            imported = self.advance()
            if imported is None or not imported.is_name:
                continue
            local = imported.value
            if self.eat_name("as"):
                alias = self.advance()
                if alias is not None and alias.is_name:
                    local = alias.value
            specifiers[local] = imported.value
        self.eat_punct("}")
        return specifiers

    def _parse_export(self, *, exported: bool = False) -> Node | None:
        self.i += 1  # 'export'
        if self.at_punct("{") or self.at_punct("*"):
            self._skip_to_statement_end()
            return None
        self.eat_name("default")
        if self.at_end():
            return None
        return self.parse_statement(exported=True)

    def _parse_skipped_declaration(self, *, exported: bool = False) -> None:
        self.i += 1
        while not self.at_end() and not self.at_punct("{", ";"):
            self.i += 1
        if self.at_punct("{"):
            self._skip_balanced()
        else:
            self.eat_punct(";")
        return None

    def _parse_var_declaration(self, *, exported: bool = False) -> Node | None:
        start = self.peek()
        kind = start.value if start is not None else "const"
        self.i += 1
        declarations: list[Node] = []
        while not self.at_end():
            names, properties = self._parse_binding_target()
            if self.at_punct(":"):
                self.i += 1
                self._skip_type(frozenset({"=", ";", ","}))
            init: Node | None = None
            if self.eat_punct("="):
                init = self._parse_assignment()
            for name in names or [""]:
                if not name:
                    continue
                declarations.append(
                    VarDecl(
                        name=name,
                        init=init,
                        kind=kind,
                        properties=properties,
                        exported=exported,
                        **self._position(start),
                    )
                )
            if not self.eat_punct(","):
                break
        self.eat_punct(";")
        if not declarations:
            return None
        if len(declarations) == 1:
            return declarations[0]
        return Block(body=declarations, **self._position(start))

    def _parse_binding_target(self) -> tuple[list[str], list[str]]:
        """Return (local binding names, source property names) for a binding."""
        token = self.peek()
        if token is None:
            return [], []
        if token.is_name:
            self.i += 1
            return [token.value], []
        if token.is_punct("{"):
            return self._parse_object_pattern()
        if token.is_punct("["):
            return self._parse_array_pattern()
        return [], []

    def _parse_object_pattern(self) -> tuple[list[str], list[str]]:
        names: list[str] = []
        properties: list[str] = []
        self.eat_punct("{")
        while not self.at_end() and not self.at_punct("}"):
            if self.eat_punct(",") or self.eat_punct("..."):
                continue
            key = self.advance()
            if key is None:
                break
            if not (key.is_name or key.type in {"string", "number"}):
                continue
            properties.append(str(key.value))
            if self.eat_punct(":"):
                nested_names, _ = self._parse_binding_target()
                names.extend(nested_names)
            else:
                names.append(str(key.value))
            if self.eat_punct("="):
                self._parse_assignment()
        self.eat_punct("}")
        return names, properties

    def _parse_array_pattern(self) -> tuple[list[str], list[str]]:
        names: list[str] = []
        self.eat_punct("[")
        while not self.at_end() and not self.at_punct("]"):
            if self.eat_punct(",") or self.eat_punct("..."):
                continue
            nested_names, _ = self._parse_binding_target()
            if not nested_names:
                self.i += 1
                continue
            names.extend(nested_names)
            if self.eat_punct("="):
                self._parse_assignment()
        self.eat_punct("]")
        return names, []

    def _parse_function_declaration(self, *, exported: bool = False) -> Node | None:
        start = self.peek()
        is_async = self.eat_name("async")
        self.eat_name("function")
        self.eat_punct("*")
        name: str | None = None
        token = self.peek()
        if token is not None and token.is_name:
            name = token.value
            self.i += 1
        return self._parse_function_rest(
            start, name=name, is_async=is_async, exported=exported
        )

    def _parse_function_rest(
        self,
        start: Token | None,
        *,
        name: str | None,
        is_async: bool,
        exported: bool = False,
    ) -> FunctionNode:
        self._skip_generic_parameters()
        params = self._parse_params()
        if self.at_punct(":"):
            self.i += 1
            self._skip_type(frozenset({"{", "=>", ";"}))
        body: list[Node] = []
        if self.at_punct("{"):
            body = self._parse_block().body
        return FunctionNode(
            name=name,
            params=params,
            body=body,
            is_arrow=False,
            is_async=is_async,
            exported=exported,
            **self._position(start),
        )

    def _parse_params(self) -> list[Param]:
        params: list[Param] = []
        if not self.at_punct("("):
            return params
        self.i += 1
        while not self.at_end() and not self.at_punct(")"):
            if self.eat_punct(",") or self.eat_punct("..."):
                continue
            while self.at_punct("@"):
                self.i += 1
                self._parse_call_member(self._parse_primary())
            while (token := self.peek()) is not None and (
                token.is_name and token.value in _PARAM_MODIFIERS
            ):
                self.i += 1
            line = self._line()
            names, properties = self._parse_binding_target()
            if not names and not properties:
                self.i += 1
                continue
            self.eat_punct("?")
            if self.at_punct(":"):
                self.i += 1
                self._skip_type(frozenset({",", ")", "="}))
            if self.eat_punct("="):
                self._parse_assignment()
            for name in names:
                params.append(Param(name=name, properties=list(properties), line=line))
        self.eat_punct(")")
        return params

    def _parse_class(self, *, exported: bool = False) -> Node:
        start = self.peek()
        self.i += 1  # 'class'
        name: str | None = None
        token = self.peek()
        if token is not None and token.is_name:
            name = token.value
            self.i += 1
        self._skip_generic_parameters()
        while not self.at_end() and not self.at_punct("{"):
            self.i += 1
        body = self._parse_class_body()
        return ClassDecl(name=name, body=body, **self._position(start))

    def _parse_class_body(self) -> list[Node]:
        body: list[Node] = []
        if not self.at_punct("{"):
            return body
        self.i += 1
        while not self.at_end() and not self.at_punct("}"):
            before = self.i
            member = self._parse_class_member()
            if member is not None:
                body.append(member)
            if self.i == before:
                self.i += 1
        self.eat_punct("}")
        return body

    def _parse_class_member(self) -> Node | None:
        if self.eat_punct(";"):
            return None
        while self.at_punct("@"):
            self.i += 1
            self._parse_call_member(self._parse_primary())
        start = self.peek()
        is_async = False
        while (token := self.peek()) is not None and token.is_name:
            if token.value in _MEMBER_MODIFIERS:
                self.i += 1
                continue
            if token.value == "async" and not self._next_is_punct("(", "=", ":", ";"):
                is_async = True
                self.i += 1
                continue
            break
        self.eat_punct("*")
        self.eat_punct("#")
        name_token = self.peek()
        if name_token is None:
            return None
        if name_token.is_punct("["):
            self._skip_balanced()
            name = None
        elif name_token.is_name or name_token.type in {"string", "number"}:
            name = str(name_token.value)
            self.i += 1
        else:
            self.i += 1
            return None
        self.eat_punct("?")
        self.eat_punct("!")
        if self.at_punct("(") or self.at_punct("<"):
            return self._parse_function_rest(start, name=name, is_async=is_async)
        if self.at_punct(":"):
            self.i += 1
            self._skip_type(frozenset({"=", ";", "}"}))
        if self.eat_punct("="):
            init = self._parse_assignment()
            self.eat_punct(";")
            return VarDecl(name=name or "", init=init, kind="property", **self._position(start))
        self.eat_punct(";")
        return None

    def _next_is_punct(self, *values: str) -> bool:
        token = self.peek(1)
        return token is not None and token.is_punct(*values)

    def _parse_return(self, *, exported: bool = False) -> Node:
        start = self.peek()
        self.i += 1
        argument: Node | None = None
        if not self.at_punct(";", "}") and not self.at_end():
            argument = self._parse_expression()
        self.eat_punct(";")
        return ReturnStmt(argument=argument, **self._position(start))

    def _parse_control_flow(self, *, exported: bool = False) -> Node:
        start = self.peek()
        self.i += 1
        header: list[Node] = []
        if self.at_punct("("):
            header = self._parse_parenthesized_statements()
        body: list[Node] = []
        if self.at_punct("{"):
            body = self._parse_block().body
        elif not self.at_end() and not self.at_punct(";"):
            statement = self.parse_statement()
            if statement is not None:
                body = [statement]
        return Block(body=[*header, *body], **self._position(start))

    def _parse_parenthesized_statements(self) -> list[Node]:
        """Parse a `(...)` header, tolerating `for (const x of y)` forms."""
        found: list[Node] = []
        self.eat_punct("(")
        while not self.at_end() and not self.at_punct(")"):
            before = self.i
            if self.at_name(*_DECLARATION_KEYWORDS):
                self.i += 1
                names, _ = self._parse_binding_target()
                if self.at_punct(":"):
                    self.i += 1
                    self._skip_type(frozenset({"=", ";", ")"}))
                if self.eat_name("of", "in") or self.eat_punct("="):
                    value = self._parse_assignment()
                    for name in names:
                        found.append(
                            VarDecl(name=name, init=value, kind="const", **self._position(None))
                        )
            elif self.at_punct(";", ","):
                self.i += 1
            else:
                expression = self._parse_assignment()
                found.append(ExpressionStmt(expression=expression, **self._position(None)))
                self.eat_name("of", "in")
            if self.i == before:
                self.i += 1
        self.eat_punct(")")
        return found

    def _parse_bare_block(self, *, exported: bool = False) -> Node | None:
        start = self.peek()
        self.i += 1
        if self.at_punct("("):  # `do ... while (...)`
            self._parse_parenthesized_statements()
        if self.at_punct("{"):
            return Block(body=self._parse_block().body, **self._position(start))
        return self.parse_statement()

    def _parse_simple_jump(self, *, exported: bool = False) -> Node | None:
        start = self.peek()
        self.i += 1
        if self.at_punct(";", "}") or self.at_end():
            self.eat_punct(";")
            return None
        expression = self._parse_expression()
        self.eat_punct(";")
        return ExpressionStmt(expression=expression, **self._position(start))

    def _parse_expression_statement(self) -> Node:
        start = self.peek()
        expression = self._parse_expression()
        self.eat_punct(";")
        return ExpressionStmt(expression=expression, **self._position(start))

    def _skip_to_statement_end(self) -> None:
        while not self.at_end() and not self.at_punct(";"):
            token = self.peek()
            if token is not None and token.is_name and token.value in _DECLARATION_KEYWORDS:
                return
            self.i += 1
        self.eat_punct(";")

    # -- expressions ----------------------------------------------------

    def _parse_expression(self) -> Node:
        start = self.peek()
        first = self._parse_assignment()
        if not self.at_punct(","):
            return first
        expressions = [first]
        while self.eat_punct(","):
            if self.at_end() or self.at_punct(")", "]", "}", ";"):
                break
            expressions.append(self._parse_assignment())
        return SequenceExpr(expressions=expressions, **self._position(start))

    def _parse_assignment(self) -> Node:
        start = self.peek()
        arrow = self._try_parse_arrow()
        if arrow is not None:
            return arrow
        target = self._parse_conditional()
        token = self.peek()
        if token is not None and token.type == "punct" and token.value in _ASSIGNMENT_OPERATORS:
            self.i += 1
            value = self._parse_assignment()
            return AssignExpr(
                op=token.value, target=target, value=value, **self._position(start)
            )
        return target

    def _try_parse_arrow(self) -> Node | None:
        """Parse an arrow function, restoring the position when it is not one."""
        start_index = self.i
        start = self.peek()
        is_async = False
        if self.at_name("async"):
            following = self.peek(1)
            if following is None or not (following.is_punct("(") or following.is_name):
                return None
            is_async = True
            self.i += 1

        token = self.peek()
        if token is None:
            self.i = start_index
            return None

        if token.is_name and self._next_is_punct("=>"):
            self.i += 1
            self.i += 1  # '=>'
            return self._parse_arrow_body(
                start, [Param(name=token.value, line=token.line)], is_async
            )

        if not token.is_punct("(") and not token.is_punct("<"):
            self.i = start_index
            return None

        self._skip_generic_parameters()
        if not self.at_punct("("):
            self.i = start_index
            return None
        params = self._parse_params()
        if self.at_punct(":"):
            self.i += 1
            self._skip_type(frozenset({"=>", ";", ",", ")"}))
        if not self.eat_punct("=>"):
            self.i = start_index
            return None
        return self._parse_arrow_body(start, params, is_async)

    def _parse_arrow_body(
        self, start: Token | None, params: list[Param], is_async: bool
    ) -> FunctionNode:
        if self.at_punct("{"):
            body = self._parse_block().body
            return FunctionNode(
                name=None,
                params=params,
                body=body,
                is_arrow=True,
                is_async=is_async,
                **self._position(start),
            )
        expression = self._parse_assignment()
        return FunctionNode(
            name=None,
            params=params,
            body=[],
            is_arrow=True,
            is_async=is_async,
            expression_body=expression,
            **self._position(start),
        )

    def _parse_conditional(self) -> Node:
        start = self.peek()
        test = self._parse_binary(0)
        if not self.at_punct("?"):
            return test
        self.i += 1
        consequent = self._parse_assignment()
        if not self.eat_punct(":"):
            return consequent
        alternate = self._parse_assignment()
        return ConditionalExpr(
            test=test, consequent=consequent, alternate=alternate, **self._position(start)
        )

    def _parse_binary(self, min_precedence: int) -> Node:
        start = self.peek()
        left = self._parse_unary()
        while not self.at_end():
            token = self.peek()
            if token is None:
                break
            operator = token.value
            if token.is_name and operator in {"instanceof", "in"}:
                pass
            elif token.type != "punct" or operator not in _BINARY_PRECEDENCE:
                break
            precedence = _BINARY_PRECEDENCE.get(operator)
            if precedence is None or precedence < min_precedence:
                break
            self.i += 1
            right = self._parse_binary(precedence + 1)
            left = BinaryExpr(op=operator, left=left, right=right, **self._position(start))
        return left

    def _parse_unary(self) -> Node:
        start = self.peek()
        if start is None:
            return Unknown(label="empty")
        if start.is_punct("!", "~", "+", "-", "++", "--"):
            self.i += 1
            return UnaryExpr(
                op=start.value, argument=self._parse_unary(), **self._position(start)
            )
        if start.is_name and start.value in _UNARY_KEYWORDS:
            self.i += 1
            return UnaryExpr(
                op=start.value, argument=self._parse_unary(), **self._position(start)
            )
        if start.is_name and start.value == "await":
            self.i += 1
            return AwaitExpr(argument=self._parse_unary(), **self._position(start))
        if start.is_punct("..."):
            self.i += 1
            return SpreadExpr(argument=self._parse_assignment(), **self._position(start))
        expression = self._parse_call_member(self._parse_primary())
        if self.at_punct("++", "--"):
            self.i += 1
        return expression

    def _parse_call_member(self, node: Node) -> Node:
        while not self.at_end():
            token = self.peek()
            if token is None:
                break
            if token.is_punct(".", "?."):
                following = self.peek(1)
                if (
                    token.value == "?."
                    and following is not None
                    and following.is_punct("(", "[")
                ):
                    self.i += 1  # optional call/index: let the loop handle it
                    continue
                self.i += 1
                prop = self.advance()
                if prop is None:
                    break
                node = MemberExpr(
                    obj=node,
                    prop=Identifier(name=str(prop.value), **self._position(prop)),
                    computed=False,
                    optional=token.value == "?.",
                    line=node.line,
                    column=node.column,
                    end_line=prop.end_line,
                )
                continue
            if token.is_punct("["):
                self.i += 1
                index = self._parse_expression()
                self.eat_punct("]")
                node = MemberExpr(
                    obj=node,
                    prop=index,
                    computed=True,
                    line=node.line,
                    column=node.column,
                    end_line=self._line(),
                )
                continue
            if token.is_punct("("):
                args = self._parse_arguments()
                node = CallExpr(
                    callee=node,
                    args=args,
                    line=node.line,
                    column=node.column,
                    end_line=self._line(),
                )
                continue
            if token.is_punct("!"):  # TypeScript non-null assertion
                self.i += 1
                continue
            if token.is_punct("<") and self._looks_like_type_arguments():
                self._skip_generic_parameters()
                continue
            if token.is_name and token.value in {"as", "satisfies"}:
                self.i += 1
                self._skip_type(
                    frozenset({",", ")", "]", "}", ";", "=>", "?", ":"})
                )
                continue
            if token.type == "template":  # tagged template
                self.i += 1
                continue
            break
        return node

    def _looks_like_type_arguments(self) -> bool:
        """Only treat `<...>` as type arguments when a call follows it."""
        depth = 0
        index = self.i
        while index < len(self.tokens) and index - self.i < 64:
            token = self.tokens[index]
            if token.type == "punct":
                if token.value == "<":
                    depth += 1
                elif token.value == ">":
                    depth -= 1
                    if depth == 0:
                        following = (
                            self.tokens[index + 1] if index + 1 < len(self.tokens) else None
                        )
                        return following is not None and following.is_punct("(")
                elif token.value in {";", "{", "}", "(", ")"}:
                    return False
            index += 1
        return False

    def _parse_arguments(self) -> list[Node]:
        args: list[Node] = []
        self.eat_punct("(")
        while not self.at_end() and not self.at_punct(")"):
            if self.eat_punct(","):
                continue
            before = self.i
            args.append(self._parse_assignment())
            if self.i == before:
                self.i += 1
        self.eat_punct(")")
        return args

    def _parse_primary(self) -> Node:
        token = self.peek()
        if token is None:
            return Unknown(label="empty")
        position = self._position(token)

        if self.depth >= _MAX_NESTING:
            # Pathological nesting: consume the group and stop descending
            # rather than exhausting the interpreter stack.
            if token.is_punct("(", "[", "{"):
                self._skip_balanced()
            else:
                self.i += 1
            return Unknown(label="max_nesting", **position)

        if token.type == "string":
            self.i += 1
            return Literal(value=token.value, raw=token.raw, **position)
        if token.type == "number":
            self.i += 1
            return Literal(value=_number_value(token.value), raw=token.raw, **position)
        if token.type == "regex":
            self.i += 1
            return Unknown(label="regex", **position)
        if token.type == "template":
            self.i += 1
            return _parse_template_literal(token)
        if token.is_punct("(", "[", "{"):
            self.depth += 1
            try:
                if token.is_punct("("):
                    self.i += 1
                    expression = self._parse_expression()
                    self.eat_punct(")")
                    return expression
                if token.is_punct("["):
                    return self._parse_array()
                return self._parse_object()
            finally:
                self.depth -= 1
        if token.is_name:
            if token.value in {"function"} or (
                token.value == "async" and self._next_is_name("function")
            ):
                node = self._parse_function_declaration()
                return node if node is not None else Unknown(label="function", **position)
            if token.value == "class":
                return self._parse_class()
            if token.value == "new":
                return self._parse_new()
            if token.value in {"true", "false"}:
                self.i += 1
                return Literal(value=token.value == "true", raw=token.raw, **position)
            if token.value == "null":
                self.i += 1
                return Literal(value=None, raw=token.raw, **position)
            self.i += 1
            return Identifier(name=token.value, **position)
        self.i += 1
        return Unknown(label=token.value, **position)

    def _parse_new(self) -> Node:
        start = self.peek()
        self.i += 1  # 'new'
        callee = self._parse_primary()
        while self.at_punct(".", "?."):
            self.i += 1
            prop = self.advance()
            if prop is None:
                break
            callee = MemberExpr(
                obj=callee,
                prop=Identifier(name=str(prop.value), **self._position(prop)),
                **self._position(start),
            )
        if self.at_punct("<") and self._looks_like_type_arguments():
            self._skip_generic_parameters()
        args = self._parse_arguments() if self.at_punct("(") else []
        return CallExpr(callee=callee, args=args, is_new=True, **self._position(start))

    def _parse_array(self) -> Node:
        start = self.peek()
        self.i += 1
        elements: list[Node] = []
        while not self.at_end() and not self.at_punct("]"):
            if self.eat_punct(","):
                continue
            before = self.i
            elements.append(self._parse_assignment())
            if self.i == before:
                self.i += 1
        self.eat_punct("]")
        return ArrayExpr(elements=elements, **self._position(start))

    def _parse_object(self) -> Node:
        start = self.peek()
        self.i += 1
        properties: list[Property] = []
        while not self.at_end() and not self.at_punct("}"):
            if self.eat_punct(","):
                continue
            before = self.i
            prop = self._parse_object_property()
            if prop is not None:
                properties.append(prop)
            if self.i == before:
                self.i += 1
        self.eat_punct("}")
        return ObjectExpr(properties=properties, **self._position(start))

    def _parse_object_property(self) -> Property | None:
        if self.at_punct("..."):
            self.i += 1
            value = self._parse_assignment()
            return Property(key=None, value=value, computed=True, line=value.line)
        start = self.peek()
        if start is None:
            return None
        is_async = False
        if start.is_name and start.value in {"get", "set"} and not self._next_is_punct(
            ",", ":", "(", "}"
        ):
            self.i += 1
        elif start.is_name and start.value == "async" and not self._next_is_punct(
            ",", ":", "(", "}"
        ):
            is_async = True
            self.i += 1
        self.eat_punct("*")

        key_token = self.peek()
        if key_token is None:
            return None
        if key_token.is_punct("["):
            self._skip_balanced()
            key = None
        elif key_token.is_name or key_token.type in {"string", "number"}:
            key = str(key_token.value)
            self.i += 1
        else:
            self.i += 1
            return None

        if self.at_punct("(") or self.at_punct("<"):  # method shorthand
            function = self._parse_function_rest(key_token, name=key, is_async=is_async)
            return Property(key=key, value=function, line=key_token.line)
        if self.eat_punct(":"):
            value = self._parse_assignment()
            return Property(key=key, value=value, line=key_token.line)
        if self.eat_punct("="):  # pattern default in an object literal position
            self._parse_assignment()
        return Property(
            key=key,
            value=Identifier(name=key or "", **self._position(key_token)),
            shorthand=True,
            line=key_token.line,
        )


def _number_value(raw: str) -> object:
    try:
        if raw.lower().startswith(("0x", "0b", "0o")):
            return int(raw, 0)
        return float(raw) if any(c in raw for c in ".eE") else int(raw)
    except ValueError:
        return raw


def _parse_template_literal(token: Token) -> TemplateLiteral:
    """Split a template token into static text and parsed sub-expressions."""
    raw = token.raw
    quasis: list[str] = []
    expressions: list[Node] = []
    text: list[str] = []
    index = 1  # skip the opening backtick
    end = len(raw) - 1 if raw.endswith("`") and len(raw) > 1 else len(raw)
    while index < end:
        char = raw[index]
        if char == "\\" and index + 1 < end:
            text.append(raw[index + 1])
            index += 2
            continue
        if char == "$" and index + 1 < end and raw[index + 1] == "{":
            start = index + 2
            depth = 1
            cursor = start
            while cursor < end and depth:
                current = raw[cursor]
                if current in "\"'`":
                    cursor = _skip_quoted(raw, cursor, end)
                    continue
                if current == "{":
                    depth += 1
                elif current == "}":
                    depth -= 1
                    if depth == 0:
                        break
                cursor += 1
            body = raw[start:cursor]
            quasis.append("".join(text))
            text = []
            line_offset = raw.count("\n", 0, start)
            expressions.append(_parse_fragment(body, token.line + line_offset))
            index = cursor + 1
            continue
        text.append(char)
        index += 1
    quasis.append("".join(text))
    return TemplateLiteral(
        quasis=quasis,
        expressions=expressions,
        line=token.line,
        column=token.column,
        end_line=token.end_line,
    )


def _skip_quoted(raw: str, index: int, end: int) -> int:
    quote = raw[index]
    cursor = index + 1
    while cursor < end:
        if raw[cursor] == "\\":
            cursor += 2
            continue
        if raw[cursor] == quote:
            return cursor + 1
        cursor += 1
    return cursor


def _parse_fragment(source: str, base_line: int) -> Node:
    """Parse an interpolated expression, rebasing its line numbers."""
    tokens = [
        Token(
            type=item.type,
            value=item.value,
            raw=item.raw,
            line=item.line + base_line - 1,
            column=item.column,
            end_line=item.end_line + base_line - 1,
        )
        for item in tokenize(source)
    ]
    if not tokens:
        return Unknown(label="empty", line=base_line, end_line=base_line)
    parser = Parser(tokens)
    return parser._parse_expression()


# ---------------------------------------------------------------------------
# Module index
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JsAssignment:
    name: str
    value: Node
    line: int
    scope: str | None


@dataclass
class JsFunctionInfo:
    name: str
    qualified_name: str
    node: FunctionNode
    params: list[Param] = field(default_factory=list)
    entrypoint_kind: str | None = None


# Exported functions whose name *is* the HTTP method (Next.js App Router,
# Remix-style route modules, SvelteKit endpoints).
_HTTP_METHOD_EXPORTS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)
_HTTP_ROUTER_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "all", "use"}
)
_HTTP_ROUTER_OBJECTS = frozenset({"app", "router", "server", "api", "fastify"})
_TOOL_REGISTRARS = frozenset({"tool", "registerTool", "setRequestHandler", "addTool"})
_LAMBDA_NAMES = frozenset({"handler", "lambdaHandler", "main"})


@dataclass
class JsModule:
    """A parsed JS/TS file plus the indices the detectors need."""

    relative_path: str
    source: str
    program: Program
    #: local binding -> (module specifier, imported name | 'default' | '*')
    aliases: dict[str, tuple[str, str]] = field(default_factory=dict)
    imports: set[str] = field(default_factory=set)
    assignments: dict[tuple[str | None, str], list[JsAssignment]] = field(default_factory=dict)
    functions: dict[str, JsFunctionInfo] = field(default_factory=dict)
    functions_by_node: dict[int, JsFunctionInfo] = field(default_factory=dict)
    scopes: dict[int, str | None] = field(default_factory=dict)
    calls: list[CallExpr] = field(default_factory=list)

    def qualified_name(self, node: Node) -> str | None:
        """Return a dotted symbol path, expanding import aliases at the root."""
        if isinstance(node, Identifier):
            alias = self.aliases.get(node.name)
            if alias is None:
                return node.name
            module, imported = alias
            if imported in {"default", "*"}:
                return module
            return f"{module}.{imported}"
        if isinstance(node, MemberExpr):
            if node.computed:
                if isinstance(node.prop, Literal) and isinstance(node.prop.value, str):
                    parent = self.qualified_name(node.obj)
                    return f"{parent}.{node.prop.value}" if parent else node.prop.value
                return self.qualified_name(node.obj)
            parent = self.qualified_name(node.obj)
            name = node.prop.name if isinstance(node.prop, Identifier) else ""
            return f"{parent}.{name}" if parent else name
        if isinstance(node, CallExpr):
            return self.qualified_name(node.callee)
        if isinstance(node, AwaitExpr):
            return self.qualified_name(node.argument)
        return None

    def local_name(self, node: Node) -> str | None:
        """Return the dotted path *without* expanding import aliases."""
        if isinstance(node, Identifier):
            return node.name
        if isinstance(node, MemberExpr) and not node.computed:
            parent = self.local_name(node.obj)
            name = node.prop.name if isinstance(node.prop, Identifier) else ""
            return f"{parent}.{name}" if parent else name
        return None

    def scope_for(self, node: Node) -> str | None:
        return self.scopes.get(id(node))

    def enclosing_function(self, node: Node) -> JsFunctionInfo | None:
        scope = self.scope_for(node)
        return self.functions.get(scope) if scope is not None else None

    def assignment_for(self, name: str, node: Node) -> JsAssignment | None:
        """Resolve ``name`` to its nearest preceding binding in scope."""
        line = node.line
        scope = self.scope_for(node)
        seen: set[str | None] = set()
        while True:
            if scope in seen:
                break
            seen.add(scope)
            candidates = [
                item for item in self.assignments.get((scope, name), []) if item.line <= line
            ]
            if candidates:
                return max(candidates, key=lambda item: item.line)
            if scope is None:
                break
            scope = scope.rsplit(".", 1)[0] if "." in scope else None
        return None

    def has_import(self, *modules: str) -> bool:
        """Return whether any import came from one of ``modules`` (or a subpath)."""
        for source in self.imports:
            for module in modules:
                if source == module or source.startswith(f"{module}/"):
                    return True
        return False


def parse_javascript(source: str, relative_path: str) -> JsModule:
    """Parse JS/TS source into a :class:`JsModule` without executing it."""
    program = Parser(tokenize(source)).parse_program()
    module = JsModule(relative_path=relative_path, source=source, program=program)
    _Indexer(module).run()
    _classify_entrypoints(module)
    return module


def _classify_entrypoints(module: JsModule) -> None:
    """Label functions that receive input from outside the application.

    Two shapes are recognized: a framework-named export (``export async function
    POST``), and a callback handed to a router or tool registrar
    (``app.post('/x', handler)``, ``server.tool('name', schema, handler)``).
    """
    for info in module.functions.values():
        node = info.node
        if node.exported and node.name in _HTTP_METHOD_EXPORTS:
            info.entrypoint_kind = "http_route"
        elif node.exported and node.name in _LAMBDA_NAMES:
            info.entrypoint_kind = "lambda"

    for call in module.calls:
        kind = _registrar_entrypoint_kind(module, call)
        if kind is None:
            continue
        for argument in call.args:
            target = argument.argument if isinstance(argument, AwaitExpr) else argument
            if not isinstance(target, FunctionNode):
                continue
            callback = module.functions_by_node.get(id(target))
            if callback is not None and callback.entrypoint_kind is None:
                callback.entrypoint_kind = kind


def _registrar_entrypoint_kind(module: JsModule, call: CallExpr) -> str | None:
    callee = call.callee
    if not isinstance(callee, MemberExpr) or callee.computed:
        return None
    method = callee.prop.name if isinstance(callee.prop, Identifier) else ""
    base = module.local_name(callee.obj) or ""
    root = base.split(".")[0]
    if method in _TOOL_REGISTRARS:
        return "mcp_tool"
    if method in _HTTP_ROUTER_METHODS and root in _HTTP_ROUTER_OBJECTS:
        return "http_route"
    return None


class _Indexer:
    """Second pass: record scopes, bindings, imports, and call sites."""

    def __init__(self, module: JsModule) -> None:
        self.module = module
        self.anonymous = 0

    def run(self) -> None:
        self._visit_body(self.module.program.body, None)

    def _visit_body(self, body: list[Node], scope: str | None) -> None:
        for node in body:
            self._visit(node, scope)

    def _visit(self, node: Node, scope: str | None) -> None:
        self.module.scopes[id(node)] = scope

        if isinstance(node, ImportDecl):
            self._record_import(node)
            return
        if isinstance(node, VarDecl):
            self._record_var(node, scope)
            return
        if isinstance(node, FunctionNode):
            self._visit_function(node, scope)
            return
        if isinstance(node, ClassDecl):
            inner = f"{scope}.{node.name}" if scope and node.name else (node.name or scope)
            self._visit_body(node.body, inner)
            return
        if isinstance(node, CallExpr):
            self.module.calls.append(node)
        elif isinstance(node, AssignExpr) and isinstance(node.target, Identifier):
            # `x = req.body.q` after a bare `let x` still binds a traceable value.
            self.module.assignments.setdefault((scope, node.target.name), []).append(
                JsAssignment(
                    name=node.target.name, value=node.value, line=node.line, scope=scope
                )
            )

        for child in children(node):
            self._visit(child, scope)

    def _visit_function(self, node: FunctionNode, scope: str | None) -> None:
        name = node.name
        if name is None:
            self.anonymous += 1
            name = f"fn@{node.line}#{self.anonymous}"
        qualified = f"{scope}.{name}" if scope else name
        info = JsFunctionInfo(
            name=node.name or name,
            qualified_name=qualified,
            node=node,
            params=list(node.params),
        )
        self.module.functions[qualified] = info
        self.module.functions_by_node[id(node)] = info
        self._visit_body(node.body, qualified)
        if node.expression_body is not None:
            self._visit(node.expression_body, qualified)

    def _record_import(self, node: ImportDecl) -> None:
        if not node.source:
            return
        self.module.imports.add(node.source)
        for local, imported in node.specifiers.items():
            self.module.aliases[local] = (node.source, imported)

    def _record_var(self, node: VarDecl, scope: str | None) -> None:
        init = node.init
        if init is not None:
            if isinstance(init, FunctionNode):
                # `export const POST = async (req) => {...}` names the function
                # through its binding, which is what entrypoint naming keys on.
                init.name = init.name or node.name
                init.exported = init.exported or node.exported
            required = _require_source(self.module, init)
            if required is not None:
                self.module.imports.add(required)
                imported = node.properties[0] if len(node.properties) == 1 else "default"
                self.module.aliases[node.name] = (required, imported)
            self.module.assignments.setdefault((scope, node.name), []).append(
                JsAssignment(name=node.name, value=init, line=node.line, scope=scope)
            )
            self._visit(init, scope)


def _require_source(module: JsModule, node: Node) -> str | None:
    """Return the module name for `require('x')` / `await import('x')`."""
    target = node.argument if isinstance(node, AwaitExpr) else node
    if isinstance(target, MemberExpr):
        target = target.obj
    if not isinstance(target, CallExpr) or not target.args:
        return None
    callee = module.local_name(target.callee)
    if callee not in {"require", "import"}:
        return None
    first = target.args[0]
    if isinstance(first, Literal) and isinstance(first.value, str):
        return first.value
    return None


__all__ = [
    "JsAssignment",
    "JsFunctionInfo",
    "JsModule",
    "Parser",
    "parse_javascript",
    "walk",
]
