"""JS/TS model identifiers reached through an AI gateway or declared in a catalog.

Applications built on the Vercel AI SDK often never pass a model literal to a
provider factory.  They declare gateway-style ids (``"openai/gpt-4.1"``) in a
data structure, and route every call through ``gateway.languageModel(id)``.
Two separate facts are recorded, and kept separate on purpose:

* **invoked** — a gateway call whose model argument resolves statically, within
  the file or through a resolvable import (``titleModel.id``), to an id;
* **declared** — an id sitting in a model catalog (``chatModels: ChatModel[]``)
  or a ``*model*`` constant.  It stays in the inventory, but nothing claims it
  is ever called.

An argument that cannot be resolved (a function parameter, ``process.env``, a
runtime lookup) yields no model at all — the gateway service is still recorded,
and the id is not invented.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from aibom.detectors.base import ScanContext
from aibom.detectors.javascript.nodes import (
    ArrayExpr,
    AwaitExpr,
    BinaryExpr,
    Block,
    CallExpr,
    Identifier,
    Literal,
    MemberExpr,
    Node,
    ObjectExpr,
    TemplateLiteral,
    VarDecl,
)
from aibom.detectors.javascript.parser import JsModule
from aibom.detectors.project import ProjectIndex
from aibom.detectors.result import Detection
from aibom.models.analysis import (
    ConfidenceFactors,
    Reachability,
    ResolutionStep,
    UsageState,
    ValueResolution,
)
from aibom.models.entities import Model, Service
from aibom.models.evidence import Evidence

_MAX_DEPTH = 12
_SUPPORTED_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

GATEWAY_SERVICE = "vercel-ai-gateway"
_GATEWAY_MODULES = ("ai", "@ai-sdk/gateway")
_GATEWAY_METHODS = frozenset({"languageModel", "textEmbeddingModel", "imageModel"})

# Vendors that publish models under gateway-style `vendor/model` ids.  A string
# only counts when its vendor is on this list, which is what keeps package
# names, routes, and MIME types out of the model inventory.
_MODEL_VENDORS = frozenset(
    {
        "alibaba",
        "amazon",
        "anthropic",
        "bedrock",
        "cerebras",
        "cohere",
        "deepinfra",
        "deepseek",
        "fireworks",
        "google",
        "groq",
        "inception",
        "meta",
        "meta-llama",
        "minimax",
        "mistral",
        "mistralai",
        "moonshotai",
        "morph",
        "nvidia",
        "openai",
        "perplexity",
        "qwen",
        "togetherai",
        "vercel",
        "vertex",
        "voyage",
        "xai",
        "zai",
    }
)
_MODEL_ID = re.compile(r"^(?P<vendor>[a-z0-9][a-z0-9-]*)/(?P<model>[A-Za-z0-9][\w.:\-]{0,79})$")
_MODEL_KEYS = frozenset({"id", "model", "modelId", "model_id"})
_AI_MODULES = frozenset({"ai", "openai", "langchain", "@anthropic-ai/sdk"})
_AI_MODULE_PREFIXES = ("@ai-sdk/", "@openai/", "@anthropic-ai/", "@langchain/", "@openrouter/")


def gateway_model_id(value: object) -> str | None:
    """Return the vendor of a gateway-style model id, or None."""
    if not isinstance(value, str):
        return None
    match = _MODEL_ID.match(value.strip())
    if match is None or match.group("vendor") not in _MODEL_VENDORS:
        return None
    if not any(character.isalpha() for character in match.group("model")):
        return None
    return match.group("vendor")


@dataclass(frozen=True)
class _Resolved:
    value: object
    module: JsModule
    node: Node
    steps: tuple[ResolutionStep, ...]


class ModelCatalogJavaScriptDetector:
    """Detect gateway model calls and declared gateway-style model ids."""

    detector_id = "javascript.model-catalog.ast"

    def supports(self, path: str) -> bool:
        lowered = path.lower()
        if lowered.endswith((".d.ts", ".min.js")):
            return False
        return lowered.endswith(_SUPPORTED_SUFFIXES)

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = context.javascript
        if module is None:
            return
        for call in module.calls:
            vendor = _provider_factory(module, call)
            if vendor is not None and call.args:
                resolved = _static(context.project, module, call.args[0], 0, ())
                if resolved is not None and _plausible_model_id(resolved.value):
                    yield Detection(self._model(context, call, resolved, provider=vendor))
                continue
            if not _is_gateway_call(module, call):
                continue
            yield Detection(self._service(context, call))
            if not call.args:
                continue
            resolved = _static(context.project, module, call.args[0], 0, ())
            if resolved is None or gateway_model_id(resolved.value) is None:
                continue
            yield Detection(self._model(context, call, resolved))
        if _project_uses_ai(context.project, module):
            for literal, symbol in _catalog_literals(module):
                yield Detection(self._declared(context, literal, symbol))

    def _service(self, context: ScanContext, call: CallExpr) -> Service:
        return Service(
            name=GATEWAY_SERVICE,
            kind="api",
            source_evidence=[
                _evidence(context.relative_path, call, self.detector_id, "ai-gateway-call", 0.9)
            ],
            detector_ids=[self.detector_id],
            usage=UsageState(declared=True, imported=True, instantiated=True, invoked=True),
            confidence_factors=ConfidenceFactors(
                syntax_confidence=1.0,
                value_resolution_confidence=1.0,
                framework_identification_confidence=0.95,
            ),
            source_contexts=[context.source_context],
            value_resolution=ValueResolution.NOT_APPLICABLE,
        )

    def _model(
        self,
        context: ScanContext,
        call: CallExpr,
        resolved: _Resolved,
        *,
        provider: str | None = None,
    ) -> Model:
        value = str(resolved.value).strip()
        evidence = [
            _evidence(context.relative_path, call, self.detector_id, "ai-gateway-model", 0.92)
        ]
        declared_elsewhere = (
            resolved.module.relative_path != context.relative_path
            or resolved.node.line != call.line
        )
        if declared_elsewhere:
            evidence.append(
                _evidence(
                    resolved.module.relative_path,
                    resolved.node,
                    self.detector_id,
                    "model-id-declaration",
                    0.92,
                )
            )
        return Model(
            name=value,
            provider=provider or gateway_model_id(value),
            source_evidence=evidence,
            detector_ids=[self.detector_id],
            usage=UsageState(
                declared=True,
                imported=True,
                instantiated=True,
                invoked=True,
                reachable=Reachability.UNKNOWN,
            ),
            confidence_factors=ConfidenceFactors(
                syntax_confidence=1.0,
                value_resolution_confidence=0.95,
                framework_identification_confidence=0.95,
                reachability_confidence=0.25,
            ),
            resolution_path=[*resolved.steps, _step(context.relative_path, call, "gateway_call")],
            source_contexts=[context.source_context],
            value_resolution=ValueResolution.RESOLVED,
        )

    def _declared(self, context: ScanContext, literal: Literal, symbol: str) -> Model:
        value = str(literal.value).strip()
        return Model(
            name=value,
            provider=gateway_model_id(value),
            source_evidence=[
                _evidence(
                    context.relative_path, literal, self.detector_id, "model-catalog-entry", 0.85
                )
            ],
            detector_ids=[self.detector_id],
            # Declared only: a catalog entry is not evidence that the id is called.
            usage=UsageState(declared=True),
            confidence_factors=ConfidenceFactors(
                syntax_confidence=1.0,
                value_resolution_confidence=1.0,
                framework_identification_confidence=0.7,
            ),
            resolution_path=[_step(context.relative_path, literal, "catalog_entry", symbol)],
            source_contexts=[context.source_context],
            value_resolution=ValueResolution.RESOLVED,
        )


_FACTORY_METHODS = frozenset(
    {"chat", "responses", "completion", "languageModel", "textEmbeddingModel", "embedding", "image"}
)


def _provider_factory(module: JsModule, call: CallExpr) -> str | None:
    """``google('gemini-2.5-pro')`` / ``openai.chat('gpt-4o')`` from ``@ai-sdk/<vendor>``.

    Only the provider instance the package exports by the vendor's own name
    counts (``@ai-sdk/google`` -> ``google``), so an unrelated function that
    happens to take a string is never read as a model factory.
    """
    qualified = module.qualified_name(call.callee) or ""
    if not qualified.startswith("@ai-sdk/"):
        return None
    package, _, member = qualified[len("@ai-sdk/"):].partition(".")
    vendor = package.split("/", 1)[0]
    if vendor in {"gateway", "provider", "provider-utils", "react", "rsc", "ui-utils", "otel"}:
        return None
    if member == vendor or (
        member.startswith(f"{vendor}.") and member.split(".", 1)[1] in _FACTORY_METHODS
    ):
        return vendor
    return None


def _plausible_model_id(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    lowered = text.lower()
    if not text or len(text) > 120 or " " in text:
        return False
    if lowered.startswith("sk-") or (len(text) >= 48 and text.isalnum()):
        return False
    return any(character.isalpha() for character in text)


def _is_gateway_call(module: JsModule, call: CallExpr) -> bool:
    if not module.has_import(*_GATEWAY_MODULES):
        return False
    qualified = module.qualified_name(call.callee) or ""
    for root in _GATEWAY_MODULES:
        if qualified in {f"{root}.gateway", f"{root}.createGateway"}:
            return True
        prefix = f"{root}.gateway."
        if qualified.startswith(prefix) and qualified[len(prefix):] in _GATEWAY_METHODS:
            return True
    return False


def _project_uses_ai(project: ProjectIndex | None, module: JsModule) -> bool:
    """A catalog only counts in a codebase that imports an AI SDK somewhere."""
    modules = project.javascript.values() if project is not None else [module]
    return any(
        source in _AI_MODULES or source.startswith(_AI_MODULE_PREFIXES)
        for item in modules
        for source in item.imports
    )


def _catalog_literals(module: JsModule) -> Iterable[tuple[Literal, str]]:
    """Gateway-style ids in top-level model catalogs and ``*model*`` constants."""
    for declaration in _top_level_declarations(module.program.body):
        init = declaration.init
        if init is None:
            continue
        if isinstance(init, Literal):
            if "model" in declaration.name.lower() and gateway_model_id(init.value):
                yield init, declaration.name
            continue
        yield from (
            (literal, declaration.name) for literal in _catalog_entries(init, 0)
        )


def _catalog_entries(node: Node, depth: int) -> Iterable[Literal]:
    if depth > 3:
        return
    if isinstance(node, ArrayExpr):
        for element in node.elements:
            yield from _catalog_entries(element, depth + 1)
    elif isinstance(node, ObjectExpr):
        for prop in node.properties:
            value = prop.value
            if (
                prop.key in _MODEL_KEYS
                and isinstance(value, Literal)
                and gateway_model_id(value.value)
            ):
                yield value
            elif isinstance(value, (ObjectExpr, ArrayExpr)):
                yield from _catalog_entries(value, depth + 1)


def _top_level_declarations(body: list[Node]) -> Iterable[VarDecl]:
    for node in body:
        if isinstance(node, VarDecl):
            yield node
        elif isinstance(node, Block):
            yield from (item for item in node.body if isinstance(item, VarDecl))


def _static(
    project: ProjectIndex | None,
    module: JsModule,
    node: Node | None,
    depth: int,
    steps: tuple[ResolutionStep, ...],
) -> _Resolved | None:
    """Resolve a statically known value, following imports when the index can."""
    if node is None or depth > _MAX_DEPTH:
        return None
    if isinstance(node, Literal):
        return _Resolved(node.value, module, node, steps)
    if isinstance(node, TemplateLiteral):
        if node.expressions:
            return None
        return _Resolved("".join(node.quasis), module, node, steps)
    if isinstance(node, AwaitExpr):
        return _static(project, module, node.argument, depth + 1, steps)
    if isinstance(node, BinaryExpr) and node.op == "+":
        left = _static(project, module, node.left, depth + 1, steps)
        right = _static(project, module, node.right, depth + 1, steps)
        if (
            left is not None
            and right is not None
            and isinstance(left.value, str)
            and isinstance(right.value, str)
        ):
            return _Resolved(left.value + right.value, module, node, steps)
        return None
    if isinstance(node, Identifier):
        target = _binding(project, module, node)
        if target is None:
            return None
        target_module, value = target
        step = _step(target_module.relative_path, value, "variable_reference", node.name)
        return _static(project, target_module, value, depth + 1, (*steps, step))
    if isinstance(node, MemberExpr) and not node.computed and isinstance(node.prop, Identifier):
        base = _object(project, module, node.obj, depth + 1)
        if base is None:
            return None
        base_module, obj = base
        for prop in obj.properties:
            if prop.key == node.prop.name:
                step = _step(base_module.relative_path, prop.value, "member", node.prop.name)
                return _static(project, base_module, prop.value, depth + 1, (*steps, step))
    return None


def _object(
    project: ProjectIndex | None, module: JsModule, node: Node, depth: int
) -> tuple[JsModule, ObjectExpr] | None:
    if depth > _MAX_DEPTH:
        return None
    if isinstance(node, ObjectExpr):
        return module, node
    if isinstance(node, Identifier):
        target = _binding(project, module, node)
        if target is not None:
            return _object(project, target[0], target[1], depth + 1)
    return None


def _binding(
    project: ProjectIndex | None, module: JsModule, node: Identifier
) -> tuple[JsModule, Node] | None:
    """A ``const`` binding in this file, or an imported one the index can resolve."""
    assignment = module.assignment_for(node.name, node)
    if assignment is not None:
        return module, assignment.value
    if project is None:
        return None
    symbol = project.js_symbol(module, node.name)
    if symbol is None or symbol.value is None:
        return None
    return symbol.module, symbol.value


def _step(file: str, node: Node, operation: str, symbol: str | None = None) -> ResolutionStep:
    return ResolutionStep(
        file=file,
        line=node.line,
        column=node.column or None,
        symbol=symbol,
        value=None,
        operation=operation,
    )


def _evidence(
    file: str, node: Node, detector_id: str, pattern: str, confidence: float
) -> Evidence:
    snippet = f"<{pattern}>"
    if isinstance(node, CallExpr):
        snippet = f"<{pattern}:call>"
    elif isinstance(node, Literal) and isinstance(node.value, str):
        snippet = f"<{pattern}:{node.value.strip()}>"
    return Evidence(
        file=file,
        line_start=node.line,
        line_end=node.end_line,
        column_start=node.column,
        snippet=snippet,
        matched_pattern=pattern,
        confidence=confidence,
        detector_id=detector_id,
        kind="ast",
    )
