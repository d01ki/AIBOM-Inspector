"""Node model for the bounded JavaScript/TypeScript syntax tree.

The tree keeps only what the behavioral analysis needs — bindings, call and
member expressions, object/array/template composition, and function bodies.
Type-level TypeScript syntax is skipped during parsing rather than represented.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass
class Node:
    """Base node carrying 1-based source positions."""

    line: int = 1
    column: int = 1
    end_line: int = 1


@dataclass
class Identifier(Node):
    name: str = ""


@dataclass
class Literal(Node):
    value: object = None
    raw: str = ""


@dataclass
class TemplateLiteral(Node):
    """A template literal split into static text and interpolated expressions."""

    quasis: list[str] = field(default_factory=list)
    expressions: list[Node] = field(default_factory=list)


@dataclass
class MemberExpr(Node):
    obj: Node = field(default_factory=Node)
    prop: Node = field(default_factory=Node)
    computed: bool = False
    optional: bool = False


@dataclass
class CallExpr(Node):
    callee: Node = field(default_factory=Node)
    args: list[Node] = field(default_factory=list)
    is_new: bool = False


@dataclass
class Property:
    key: str | None = None
    value: Node = field(default_factory=Node)
    computed: bool = False
    shorthand: bool = False
    line: int = 1


@dataclass
class ObjectExpr(Node):
    properties: list[Property] = field(default_factory=list)


@dataclass
class ArrayExpr(Node):
    elements: list[Node] = field(default_factory=list)


@dataclass
class SpreadExpr(Node):
    argument: Node = field(default_factory=Node)


@dataclass
class BinaryExpr(Node):
    op: str = "+"
    left: Node = field(default_factory=Node)
    right: Node = field(default_factory=Node)


@dataclass
class UnaryExpr(Node):
    op: str = "!"
    argument: Node = field(default_factory=Node)


@dataclass
class ConditionalExpr(Node):
    test: Node = field(default_factory=Node)
    consequent: Node = field(default_factory=Node)
    alternate: Node = field(default_factory=Node)


@dataclass
class AwaitExpr(Node):
    argument: Node = field(default_factory=Node)


@dataclass
class AssignExpr(Node):
    op: str = "="
    target: Node = field(default_factory=Node)
    value: Node = field(default_factory=Node)


@dataclass
class SequenceExpr(Node):
    expressions: list[Node] = field(default_factory=list)


@dataclass
class Param:
    """A function parameter; ``properties`` holds destructured member names."""

    name: str = ""
    properties: list[str] = field(default_factory=list)
    line: int = 1


@dataclass
class FunctionNode(Node):
    name: str | None = None
    params: list[Param] = field(default_factory=list)
    body: list[Node] = field(default_factory=list)
    is_arrow: bool = False
    is_async: bool = False
    expression_body: Node | None = None
    exported: bool = False


@dataclass
class VarDecl(Node):
    name: str = ""
    init: Node | None = None
    kind: str = "const"
    properties: list[str] = field(default_factory=list)
    exported: bool = False


@dataclass
class ImportDecl(Node):
    source: str = ""
    #: local binding name -> imported name ('default', '*', or the export name)
    specifiers: dict[str, str] = field(default_factory=dict)


@dataclass
class ReturnStmt(Node):
    argument: Node | None = None


@dataclass
class ExpressionStmt(Node):
    expression: Node = field(default_factory=Node)


@dataclass
class Block(Node):
    body: list[Node] = field(default_factory=list)


@dataclass
class ClassDecl(Node):
    name: str | None = None
    body: list[Node] = field(default_factory=list)


@dataclass
class Program(Node):
    body: list[Node] = field(default_factory=list)


@dataclass
class Unknown(Node):
    """A construct the bounded parser deliberately does not model."""

    label: str = ""


def children(node: Node) -> Iterator[Node]:
    """Yield the direct child nodes of ``node`` in source-ish order."""
    if isinstance(node, (Program, Block, ClassDecl)):
        yield from node.body
    elif isinstance(node, FunctionNode):
        yield from node.body
        if node.expression_body is not None:
            yield node.expression_body
    elif isinstance(node, MemberExpr):
        yield node.obj
        yield node.prop
    elif isinstance(node, CallExpr):
        yield node.callee
        yield from node.args
    elif isinstance(node, ObjectExpr):
        for prop in node.properties:
            yield prop.value
    elif isinstance(node, ArrayExpr):
        yield from node.elements
    elif isinstance(node, TemplateLiteral):
        yield from node.expressions
    elif isinstance(node, BinaryExpr):
        yield node.left
        yield node.right
    elif isinstance(node, (UnaryExpr, AwaitExpr, SpreadExpr)):
        yield node.argument
    elif isinstance(node, ConditionalExpr):
        yield node.test
        yield node.consequent
        yield node.alternate
    elif isinstance(node, AssignExpr):
        yield node.target
        yield node.value
    elif isinstance(node, SequenceExpr):
        yield from node.expressions
    elif isinstance(node, VarDecl):
        if node.init is not None:
            yield node.init
    elif isinstance(node, ReturnStmt):
        if node.argument is not None:
            yield node.argument
    elif isinstance(node, ExpressionStmt):
        yield node.expression


def walk(node: Node) -> Iterator[Node]:
    """Yield ``node`` and every descendant, depth-first."""
    yield node
    for child in children(node):
        yield from walk(child)
