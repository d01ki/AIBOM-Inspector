"""Bounded static value resolution for Python AST expressions."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from aibom.detectors.python.parser import PythonModule
from aibom.models.analysis import ResolutionStep

_MAX_DEPTH = 20


@dataclass(frozen=True)
class ResolvedValue:
    """A resolved value or an explicit unresolved result with an audit path."""

    value: object | None
    resolved: bool
    kind: str
    confidence: float
    steps: tuple[ResolutionStep, ...] = ()
    environment_variable: str | None = None


class ValueResolver:
    """Resolve literals and simple references without evaluating target code."""

    def __init__(self, module: PythonModule) -> None:
        self.module = module

    def resolve(
        self,
        node: ast.AST,
        *,
        bindings: dict[str, ast.AST] | None = None,
    ) -> ResolvedValue:
        return self._resolve(node, bindings or {}, set(), 0)

    def _resolve(
        self,
        node: ast.AST,
        bindings: dict[str, ast.AST],
        seen: set[tuple[str | None, str]],
        depth: int,
    ) -> ResolvedValue:
        if depth > _MAX_DEPTH:
            return self._unresolved(node, "max_depth")

        if isinstance(node, ast.Constant) and isinstance(
            node.value, (str, int, float, bool, type(None))
        ):
            return ResolvedValue(
                value=node.value,
                resolved=True,
                kind="literal",
                confidence=1.0,
                steps=(self._step(node, None, node.value, "literal"),),
            )

        if isinstance(node, ast.Name):
            if node.id in bindings:
                resolved = self._resolve(bindings[node.id], bindings, seen, depth + 1)
                return self._prepend(resolved, self._step(node, node.id, None, "argument"))
            reference_key = (self.module.scope_for(node), node.id)
            if reference_key in seen:
                return self._unresolved(node, "cycle", symbol=node.id)
            assignment = self.module.assignment_for(node.id, node)
            if assignment is None:
                return self._unresolved(node, "unknown_symbol", symbol=node.id)
            resolved = self._resolve(
                assignment.value,
                bindings,
                {*seen, reference_key},
                depth + 1,
            )
            return self._prepend(
                resolved,
                self._step(assignment.value, node.id, resolved.value, "variable_reference"),
                kind="variable" if resolved.resolved else resolved.kind,
                confidence=min(resolved.confidence, 0.95),
            )

        if isinstance(node, ast.Dict):
            result: dict[object, object] = {}
            dict_steps: list[ResolutionStep] = []
            dict_confidence = 1.0
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if key_node is None:
                    return self._unresolved(node, "dict_unpack")
                key_resolved = self._resolve(key_node, bindings, seen, depth + 1)
                value_resolved = self._resolve(value_node, bindings, seen, depth + 1)
                if not key_resolved.resolved or not value_resolved.resolved:
                    return self._unresolved(node, "unresolved_dict")
                result[key_resolved.value] = value_resolved.value
                dict_steps.extend((*key_resolved.steps, *value_resolved.steps))
                dict_confidence = min(
                    dict_confidence, key_resolved.confidence, value_resolved.confidence
                )
            return ResolvedValue(result, True, "dictionary", dict_confidence, tuple(dict_steps))

        if isinstance(node, (ast.List, ast.Tuple)):
            values: list[object] = []
            sequence_steps: list[ResolutionStep] = []
            sequence_confidence = 1.0
            for element in node.elts:
                resolved = self._resolve(element, bindings, seen, depth + 1)
                if not resolved.resolved:
                    return self._unresolved(node, "unresolved_sequence")
                values.append(resolved.value)
                sequence_steps.extend(resolved.steps)
                sequence_confidence = min(sequence_confidence, resolved.confidence)
            sequence_value: object = tuple(values) if isinstance(node, ast.Tuple) else values
            return ResolvedValue(
                sequence_value,
                True,
                "sequence",
                sequence_confidence,
                tuple(sequence_steps),
            )

        env_name = self._environment_subscript(node)
        if env_name is not None:
            return ResolvedValue(
                None,
                False,
                "environment",
                0.6,
                (self._step(node, env_name, None, "environment_lookup"),),
                environment_variable=env_name,
            )

        if isinstance(node, ast.Subscript):
            container = self._resolve(node.value, bindings, seen, depth + 1)
            subscript_key = self._resolve(node.slice, bindings, seen, depth + 1)
            if container.resolved and subscript_key.resolved:
                try:
                    selected_value = container.value[subscript_key.value]  # type: ignore[index]
                except (KeyError, IndexError, TypeError):
                    return self._unresolved(node, "missing_subscript")
                subscript_steps = (
                    *container.steps,
                    *subscript_key.steps,
                    self._step(node, None, selected_value, "subscript"),
                )
                return ResolvedValue(
                    selected_value, True, "dictionary_lookup", 0.9, subscript_steps
                )
            return self._unresolved(node, "unresolved_subscript")

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve(node.left, bindings, seen, depth + 1)
            right = self._resolve(node.right, bindings, seen, depth + 1)
            if (
                left.resolved
                and right.resolved
                and isinstance(left.value, str)
                and isinstance(right.value, str)
            ):
                concatenated_value = left.value + right.value
                return ResolvedValue(
                    concatenated_value,
                    True,
                    "string_concatenation",
                    min(left.confidence, right.confidence, 0.95),
                    (
                        *left.steps,
                        *right.steps,
                        self._step(node, None, concatenated_value, "concatenate"),
                    ),
                )
            return self._unresolved(node, "unresolved_concatenation")

        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            fstring_steps: list[ResolutionStep] = []
            fstring_confidence = 0.95
            for part in node.values:
                target = part.value if isinstance(part, ast.FormattedValue) else part
                resolved = self._resolve(target, bindings, seen, depth + 1)
                if not resolved.resolved or not isinstance(resolved.value, (str, int, float, bool)):
                    return self._unresolved(node, "unresolved_fstring")
                parts.append(str(resolved.value))
                fstring_steps.extend(resolved.steps)
                fstring_confidence = min(fstring_confidence, resolved.confidence)
            fstring_value = "".join(parts)
            fstring_steps.append(self._step(node, None, fstring_value, "fstring"))
            return ResolvedValue(
                fstring_value, True, "fstring", fstring_confidence, tuple(fstring_steps)
            )

        if isinstance(node, ast.Call):
            env = self._resolve_environment(node, bindings, seen, depth)
            if env is not None:
                return env
            mapping = self._resolve_mapping_get(node, bindings, seen, depth)
            if mapping is not None:
                return mapping

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            operand = self._resolve(node.operand, bindings, seen, depth + 1)
            if operand.resolved and isinstance(operand.value, (int, float)):
                unary_value = -operand.value if isinstance(node.op, ast.USub) else operand.value
                return ResolvedValue(unary_value, True, "unary", operand.confidence, operand.steps)

        return self._unresolved(node, "dynamic_expression")

    def _resolve_environment(
        self,
        node: ast.Call,
        bindings: dict[str, ast.AST],
        seen: set[tuple[str | None, str]],
        depth: int,
    ) -> ResolvedValue | None:
        name = self.module.qualified_name(node.func)
        if name not in {"os.getenv", "os.environ.get"} or not node.args:
            return None
        env = self._resolve(node.args[0], bindings, seen, depth + 1)
        env_name = str(env.value) if env.resolved and isinstance(env.value, str) else None
        if len(node.args) < 2:
            return ResolvedValue(
                None,
                False,
                "environment",
                0.6,
                (self._step(node, env_name, None, "environment_lookup"),),
                environment_variable=env_name,
            )
        default = self._resolve(node.args[1], bindings, seen, depth + 1)
        if not default.resolved:
            return self._unresolved(node, "unresolved_environment_default", symbol=env_name)
        return ResolvedValue(
            default.value,
            True,
            "environment_default",
            min(default.confidence, 0.9),
            (*default.steps, self._step(node, env_name, default.value, "environment_default")),
            environment_variable=env_name,
        )

    def _resolve_mapping_get(
        self,
        node: ast.Call,
        bindings: dict[str, ast.AST],
        seen: set[tuple[str | None, str]],
        depth: int,
    ) -> ResolvedValue | None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "get" or not node.args:
            return None
        mapping = self._resolve(node.func.value, bindings, seen, depth + 1)
        key = self._resolve(node.args[0], bindings, seen, depth + 1)
        if not mapping.resolved or not isinstance(mapping.value, dict) or not key.resolved:
            return None
        if key.value in mapping.value:
            value = mapping.value[key.value]
        elif len(node.args) > 1:
            default = self._resolve(node.args[1], bindings, seen, depth + 1)
            if not default.resolved:
                return self._unresolved(node, "unresolved_mapping_default")
            value = default.value
        else:
            value = None
        return ResolvedValue(
            value,
            True,
            "dictionary_lookup",
            min(mapping.confidence, key.confidence, 0.9),
            (*mapping.steps, *key.steps, self._step(node, None, value, "mapping_get")),
        )

    def _environment_subscript(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Subscript):
            return None
        if self.module.qualified_name(node.value) != "os.environ":
            return None
        key = self._resolve(node.slice, {}, set(), 1)
        return str(key.value) if key.resolved and isinstance(key.value, str) else None

    def _step(
        self,
        node: ast.AST,
        symbol: str | None,
        value: Any,
        operation: str,
    ) -> ResolutionStep:
        # Intermediate literals can belong to unrelated keys in a configuration
        # dictionary (including credentials). The final resolved component name
        # is recorded on the entity; literal values are intentionally omitted
        # from the audit trail.
        displayed = None if operation == "literal" else _display_value(value)
        return ResolutionStep(
            file=self.module.relative_path,
            line=getattr(node, "lineno", None),
            column=(getattr(node, "col_offset", -1) + 1) or None,
            symbol=symbol,
            value=displayed,
            operation=operation,
        )

    def _unresolved(self, node: ast.AST, kind: str, *, symbol: str | None = None) -> ResolvedValue:
        return ResolvedValue(
            None,
            False,
            kind,
            0.4,
            (self._step(node, symbol, None, kind),),
            environment_variable=symbol if kind.startswith("environment") else None,
        )

    @staticmethod
    def _prepend(
        result: ResolvedValue,
        step: ResolutionStep,
        *,
        kind: str | None = None,
        confidence: float | None = None,
    ) -> ResolvedValue:
        return ResolvedValue(
            result.value,
            result.resolved,
            kind or result.kind,
            result.confidence if confidence is None else confidence,
            (step, *result.steps),
            result.environment_variable,
        )


def _display_value(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:160]
    if isinstance(value, dict):
        return "<dict>"
    if isinstance(value, (list, tuple)):
        return f"<{type(value).__name__}:{len(value)}>"
    return f"<{type(value).__name__}>"
