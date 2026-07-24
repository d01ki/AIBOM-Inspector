"""Per-repository scan configuration.

An organization pins one scanning policy across many repositories by
committing it next to the code, instead of copy-pasting CLI flags into every
pipeline. Configuration is read from the scan target, first match wins:

1. ``aibom.toml`` at the target root (the whole file is the config table);
2. ``[tool.aibom]`` in the target's ``pyproject.toml``.

CLI flags always override config values. Unknown keys are rejected so a typo
(``ignore_rule`` vs ``ignore_rules``) fails loudly instead of silently
scanning with the wrong policy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aibom.models.findings import Severity

CONFIG_FILE = "aibom.toml"


class ConfigError(ValueError):
    """Raised when a config file exists but cannot be used."""


class ScanConfig(BaseModel):
    """Validated scan defaults; every field also exists as a CLI flag."""

    model_config = ConfigDict(extra="forbid")

    fail_on: Severity | None = Field(
        default=None, description="Exit non-zero if any finding is at/above this severity."
    )
    min_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Drop entities whose best evidence is below this."
    )
    disable_detectors: list[str] = Field(
        default_factory=list, description="Stable detector IDs to disable."
    )
    ignore_rules: list[str] = Field(
        default_factory=list,
        description="Finding rule IDs to suppress; 'PREFIX-*' matches a family (e.g. 'OSV-*').",
    )


def load_config(target: str | Path) -> ScanConfig:
    """Load the scan config for ``target``, or defaults if none is present."""
    root = Path(target)
    raw = _read_config_table(root)
    if raw is None:
        return ScanConfig()
    try:
        return ScanConfig.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(loc) for loc in first["loc"]) or "config"
        raise ConfigError(f"invalid aibom config: {where}: {first['msg']}") from exc


def _read_config_table(root: Path) -> dict[str, Any] | None:
    dedicated = root / CONFIG_FILE
    if dedicated.is_file():
        table = _parse_toml(dedicated)
        if table is None:
            raise ConfigError(f"cannot parse {dedicated.name}: not valid TOML")
        return table

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        table = _parse_toml(pyproject)
        if table is not None:
            tool = table.get("tool")
            if isinstance(tool, dict):
                section = tool.get("aibom")
                if isinstance(section, dict):
                    return section
    return None


def _parse_toml(path: Path) -> dict[str, Any] | None:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        result = tomllib.loads(raw)
    except (ValueError, TypeError, OSError):
        return None
    return result if isinstance(result, dict) else None


def ignored(rule_id: str, patterns: list[str]) -> bool:
    """True if ``rule_id`` matches an ignore pattern (exact, or 'PREFIX-*')."""
    for pattern in patterns:
        if pattern.endswith("*"):
            if rule_id.startswith(pattern[:-1]):
                return True
        elif rule_id == pattern:
            return True
    return False
