"""Python agent and MCP tools, with the operations their parameters reach.

Every decorated tool is recorded, bound or not, so the inventory can say which
tools exist and how far each one is from untrusted input.  The capability
proof is the same one impact paths use: a tool parameter must reach a
recognized operation; a fixed command is not a capability.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from aibom.detectors.base import ScanContext
from aibom.detectors.python.common import require_python
from aibom.detectors.python.prompt_flow import (
    _BoundTool,
    _capabilities_in,
    _function_parameters,
    tool_framework,
)
from aibom.detectors.result import Detection
from aibom.models.analysis import ConfidenceFactors, UsageState, ValueResolution
from aibom.models.entities import Tool
from aibom.models.evidence import Evidence


class ToolCapabilityPythonDetector:
    detector_id = "python.tool-capability.ast"

    def supports(self, path: str) -> bool:
        return path.lower().endswith(".py")

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        module = require_python(context)
        for info in module.functions.values():
            framework = tool_framework(module, info.node)
            if framework is None:
                continue
            tool = _BoundTool(info.name, module, info.node)
            controlled = {name: {name} for name in _function_parameters(info.node)}
            capabilities = _capabilities_in(
                tool,
                module,
                info.node,
                controlled,
                self.detector_id,
                context.project,
                chain=[],
                visited=set(),
            )
            registered = framework == "mcp"
            yield Detection(
                Tool(
                    name=f"{info.name}@{context.relative_path}",
                    tool_name=info.name,
                    framework=framework,
                    state="registered" if registered else "declared",
                    trust_boundary="tool_caller_to_application" if registered else None,
                    capabilities=capabilities,
                    source_evidence=[_evidence(context.relative_path, info.node, framework)],
                    detector_ids=[self.detector_id],
                    usage=UsageState(declared=True, instantiated=registered),
                    confidence_factors=ConfidenceFactors(
                        syntax_confidence=1.0,
                        value_resolution_confidence=1.0,
                        framework_identification_confidence=0.95,
                    ),
                    source_contexts=[context.source_context],
                    value_resolution=ValueResolution.RESOLVED,
                )
            )


def _evidence(file: str, node: ast.FunctionDef | ast.AsyncFunctionDef, framework: str) -> Evidence:
    return Evidence(
        file=file,
        line_start=node.lineno,
        line_end=node.lineno,
        column_start=node.col_offset + 1,
        snippet=f"<{framework} tool:{node.name}>",
        matched_pattern=f"tool-definition:{framework}",
        confidence=0.95,
        detector_id=ToolCapabilityPythonDetector.detector_id,
        kind="ast",
    )
