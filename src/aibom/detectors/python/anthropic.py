"""AST detector for Anthropic SDK and LangChain Anthropic invocations."""

from __future__ import annotations

from collections.abc import Iterable

from aibom.detectors.base import ScanContext
from aibom.detectors.python.common import (
    argument_node,
    assigned_name,
    imported_roots,
    model_entity,
    require_python,
    resolve_argument,
    root_name,
    safe_endpoint,
    service_entity,
)
from aibom.detectors.python.value_resolver import ValueResolver
from aibom.detectors.result import Detection

_ROOTS = {"anthropic", "langchain_anthropic"}
_CONSTRUCTORS = {
    "anthropic.Anthropic",
    "anthropic.AsyncAnthropic",
    "anthropic.AnthropicBedrock",
    "anthropic.AsyncAnthropicBedrock",
    "langchain_anthropic.ChatAnthropic",
}
_API_SUFFIXES = (".messages.create", ".messages.stream", ".completions.create")


class AnthropicPythonDetector:
    detector_id = "python.anthropic.ast"

    def supports(self, path: str) -> bool:
        return path.lower().endswith(".py")

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = require_python(context)
        resolver = ValueResolver(module)
        for node in module.import_nodes:
            if imported_roots(node) & _ROOTS:
                yield Detection(
                    service_entity(
                        context,
                        node,
                        detector_id=self.detector_id,
                        name="anthropic",
                        endpoint="https://api.anthropic.com",
                        state="imported",
                        pattern="anthropic-import",
                        confidence=0.75,
                    )
                )

        clients: set[str] = set()
        for call in module.calls:
            qualified = module.qualified_name(call.func) or ""
            if qualified not in _CONSTRUCTORS:
                continue
            bound = assigned_name(module, call)
            if bound:
                clients.add(bound)
            state = "invoked" if qualified.startswith("langchain_anthropic.") else "instantiated"
            yield Detection(
                service_entity(
                    context,
                    call,
                    detector_id=self.detector_id,
                    name="anthropic",
                    endpoint="https://api.anthropic.com",
                    state=state,
                    pattern=f"anthropic-{state}",
                    confidence=0.95,
                )
            )
            endpoint_arg = argument_node(call, ("base_url",))
            if endpoint_arg is not None:
                endpoint = safe_endpoint(resolver.resolve(endpoint_arg).value)
                if endpoint is not None:
                    yield Detection(
                        service_entity(
                            context,
                            call,
                            detector_id=self.detector_id,
                            name=endpoint,
                            endpoint=endpoint,
                            state="instantiated",
                            pattern="anthropic-custom-endpoint",
                            confidence=0.98,
                        )
                    )
            model_arg = argument_node(call, ("model", "model_name"))
            if model_arg is not None:
                for resolved in resolve_argument(module, call, model_arg, resolver):
                    yield Detection(
                        model_entity(
                            context,
                            call,
                            resolved,
                            detector_id=self.detector_id,
                            provider="anthropic",
                            pattern="anthropic-model-argument",
                        )
                    )

        for call in module.calls:
            qualified = module.qualified_name(call.func) or ""
            root = root_name(call.func)
            client_call = root in clients and qualified.endswith(_API_SUFFIXES)
            direct_call = qualified.startswith("anthropic.") and qualified.endswith(_API_SUFFIXES)
            factory_call = module.has_import(*_ROOTS) and qualified.endswith(_API_SUFFIXES)
            if not (client_call or direct_call or factory_call):
                continue
            yield Detection(
                service_entity(
                    context,
                    call,
                    detector_id=self.detector_id,
                    name="anthropic",
                    endpoint="https://api.anthropic.com",
                    state="invoked",
                    pattern="anthropic-api-call",
                    confidence=0.99,
                )
            )
            model_arg = argument_node(call, ("model", "model_name"))
            if model_arg is None:
                continue
            for resolved in resolve_argument(module, call, model_arg, resolver):
                yield Detection(
                    model_entity(
                        context,
                        call,
                        resolved,
                        detector_id=self.detector_id,
                        provider="anthropic",
                        pattern="anthropic-model-argument",
                    )
                )
