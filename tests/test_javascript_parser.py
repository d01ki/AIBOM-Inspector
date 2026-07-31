"""Tests for the bounded JavaScript/TypeScript parser.

The parser is tolerant by contract: unusual or invalid syntax must degrade, not
raise, because one odd file must never abort a repository scan.
"""

from __future__ import annotations

import pytest

from aibom.detectors.javascript.nodes import (
    CallExpr,
    FunctionNode,
    Literal,
    TemplateLiteral,
    walk,
)
from aibom.detectors.javascript.parser import parse_javascript
from aibom.detectors.javascript.tokenizer import tokenize


def test_tokenizer_separates_regex_from_division() -> None:
    tokens = tokenize("const r = /a\\/b[/]/gi; const q = (a) / 2;")
    kinds = [(t.type, t.value) for t in tokens if t.type in {"regex", "punct"}]
    assert ("regex", "/a\\/b[/]/gi") in kinds
    assert ("punct", "/") in kinds


def test_imports_with_scoped_and_prefixed_module_names() -> None:
    module = parse_javascript(
        "import { execSync } from 'node:child_process';\n"
        "import { openai } from '@ai-sdk/openai';\n"
        "import Anthropic from '@anthropic-ai/sdk';\n"
        "import * as fs from 'fs';\n",
        "a.ts",
    )
    assert module.aliases["execSync"] == ("node:child_process", "execSync")
    assert module.aliases["openai"] == ("@ai-sdk/openai", "openai")
    assert module.aliases["Anthropic"] == ("@anthropic-ai/sdk", "default")
    assert module.aliases["fs"] == ("fs", "*")
    assert module.has_import("@ai-sdk/openai")
    assert not module.has_import("openai")  # a prefix must not match a scope


def test_require_is_treated_as_an_import() -> None:
    module = parse_javascript(
        "const { exec } = require('child_process');\nexec('ls');", "a.js"
    )
    assert module.has_import("child_process")
    assert module.qualified_name(module.calls[-1].callee) == "child_process.exec"


def test_typescript_annotations_do_not_swallow_the_function_body() -> None:
    module = parse_javascript(
        "export async function POST(request: Request): Promise<Response> {\n"
        "  const body = await request.json();\n"
        "  return Response.json(body);\n"
        "}\n",
        "route.ts",
    )
    info = module.functions["POST"]
    assert info.entrypoint_kind == "http_route"
    assert [param.name for param in info.params] == ["request"]
    assert len(info.node.body) == 2


def test_destructured_parameters_become_individual_bindings() -> None:
    module = parse_javascript("const f = async ({ command, path: p }) => run(command, p);", "a.ts")
    params = next(iter(module.functions.values())).params
    assert sorted(param.name for param in params) == ["command", "p"]


def test_template_literal_splits_static_text_from_expressions() -> None:
    module = parse_javascript("const t = `Policy: ${a.b} and ${c}`;", "a.ts")
    template = next(n for n in walk(module.program) if isinstance(n, TemplateLiteral))
    assert template.quasis == ["Policy: ", " and ", ""]
    assert len(template.expressions) == 2


def test_nested_template_and_quoted_braces_stay_balanced() -> None:
    module = parse_javascript('const t = `a${`b${c("}")}d`}e`;', "a.ts")
    template = next(n for n in walk(module.program) if isinstance(n, TemplateLiteral))
    assert template.quasis[0] == "a"
    assert template.quasis[-1] == "e"


def test_express_callback_is_classified_as_an_entrypoint() -> None:
    module = parse_javascript(
        "app.post('/x', async (req, res) => { res.send(req.body.q); });", "server.js"
    )
    kinds = {info.entrypoint_kind for info in module.functions.values()}
    assert "http_route" in kinds


def test_mcp_tool_handler_is_classified_as_an_entrypoint() -> None:
    module = parse_javascript(
        "server.tool('summarize', {}, async ({ note }) => note);", "mcp.ts"
    )
    kinds = {info.entrypoint_kind for info in module.functions.values()}
    assert "mcp_tool" in kinds


def test_exported_arrow_takes_its_binding_name() -> None:
    module = parse_javascript("export const GET = async (req) => req.url;", "route.ts")
    assert any(
        info.name == "GET" and info.entrypoint_kind == "http_route"
        for info in module.functions.values()
    )


def test_assignment_for_prefers_the_nearest_enclosing_scope() -> None:
    module = parse_javascript(
        "const value = 'outer';\nfunction f() { const value = 'inner'; return use(value); }",
        "a.ts",
    )
    call = next(
        node
        for node in walk(module.program)
        if isinstance(node, CallExpr) and module.local_name(node.callee) == "use"
    )
    argument = call.args[0]
    assignment = module.assignment_for("value", argument)
    assert assignment is not None
    assert isinstance(assignment.value, Literal)
    assert assignment.value.value == "inner"


@pytest.mark.parametrize(
    "source",
    [
        "const A = () => <div className={x}>{a / b}</div>;",  # JSX
        "@Injectable()\nexport class S { constructor(@Inject(X) private x: T) {} }",
        "function* g() { yield* other(); }",
        "a?.b?.[c]?.(d) ?? e; obj!.x!.y;",
        'const a = "unterminated;\nconst b = 1;',
        "export enum E { A = 1 }\ntype T<A> = { [K in keyof A]: A[K] };",
        "const x = " + "(" * 300 + "1" + ")" * 300 + ";",
        "",
    ],
)
def test_unusual_syntax_degrades_instead_of_raising(source: str) -> None:
    module = parse_javascript(source, "weird.tsx")
    assert module.program is not None


def test_declaration_after_unusual_syntax_is_still_indexed() -> None:
    """Tolerance is only useful if the parser recovers, not just survives."""
    module = parse_javascript(
        "export enum E { A = 1 }\n"
        'declare module "x" {}\n'
        "type T<A> = { [K in keyof A]: A[K] };\n"
        "const model = 'gpt-4.1';\n",
        "a.ts",
    )
    assignment = module.assignments[(None, "model")][0]
    assert isinstance(assignment.value, Literal)
    assert assignment.value.value == "gpt-4.1"


def test_class_methods_are_indexed() -> None:
    module = parse_javascript(
        "class S {\n  private readonly x: string = 'a';\n"
        "  async run(a: number): Promise<void> { call(a); }\n}",
        "a.ts",
    )
    assert "S.run" in module.functions
    assert isinstance(module.functions["S.run"].node, FunctionNode)
