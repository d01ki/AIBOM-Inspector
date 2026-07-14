"""AST detector for OpenAI SDK and LangChain OpenAI model invocations."""

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

_ROOTS = {"openai", "langchain_openai"}
_CONSTRUCTORS = {
    "openai.OpenAI",
    "openai.AsyncOpenAI",
    "openai.AzureOpenAI",
    "openai.AsyncAzureOpenAI",
    "langchain_openai.ChatOpenAI",
    "langchain_openai.AzureChatOpenAI",
}
_API_SUFFIXES = (
    ".responses.create",
    ".chat.completions.create",
    ".completions.create",
    ".embeddings.create",
    ".images.generate",
    ".audio.transcriptions.create",
    ".beta.assistants.create",
)


class OpenAIPythonDetector:
    detector_id = "python.openai.ast"

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
                        name="openai",
                        endpoint="https://api.openai.com",
                        state="imported",
                        pattern="openai-import",
                        confidence=0.75,
                    )
                )

        clients: set[str] = set()
        for call in module.calls:
            qualified = module.qualified_name(call.func) or ""
            if qualified in _CONSTRUCTORS:
                bound = assigned_name(module, call)
                if bound:
                    clients.add(bound)
                state = "invoked" if qualified.startswith("langchain_openai.") else "instantiated"
                yield Detection(
                    service_entity(
                        context,
                        call,
                        detector_id=self.detector_id,
                        name="openai",
                        endpoint="https://api.openai.com",
                        state=state,
                        pattern=f"openai-{state}",
                        confidence=0.95,
                    )
                )
                endpoint_arg = argument_node(call, ("base_url", "azure_endpoint"))
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
                                pattern="openai-custom-endpoint",
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
                                provider="openai",
                                pattern="openai-model-argument",
                            )
                        )

        for call in module.calls:
            qualified = module.qualified_name(call.func) or ""
            root = root_name(call.func)
            client_call = root in clients and qualified.endswith(_API_SUFFIXES)
            direct_call = qualified.startswith("openai.") and qualified.endswith(_API_SUFFIXES)
            factory_call = module.has_import(*_ROOTS) and qualified.endswith(_API_SUFFIXES)
            if not (client_call or direct_call or factory_call):
                continue
            yield Detection(
                service_entity(
                    context,
                    call,
                    detector_id=self.detector_id,
                    name="openai",
                    endpoint="https://api.openai.com",
                    state="invoked",
                    pattern="openai-api-call",
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
                        provider="openai",
                        pattern="openai-model-argument",
                    )
                )
