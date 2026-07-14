"""A pragmatic SPDX license-id table shared by the exporter and risk rules.

Not the full SPDX list — just the ids commonly seen on model/dataset cards.
Anything not here is treated as a free-text (non-SPDX) license name.
"""

from __future__ import annotations

# canonical-cased id keyed by its lowercase form
_SPDX: dict[str, str] = {
    "apache-2.0": "Apache-2.0", "mit": "MIT", "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause", "gpl-2.0": "GPL-2.0", "gpl-3.0": "GPL-3.0",
    "gpl-3.0-only": "GPL-3.0-only", "gpl-3.0-or-later": "GPL-3.0-or-later",
    "lgpl-2.1": "LGPL-2.1", "lgpl-3.0": "LGPL-3.0", "agpl-3.0": "AGPL-3.0",
    "mpl-2.0": "MPL-2.0", "isc": "ISC", "unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0", "cc-by-4.0": "CC-BY-4.0", "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "cc-by-nc-4.0": "CC-BY-NC-4.0", "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
    "cc-by-nc-nd-4.0": "CC-BY-NC-ND-4.0",
}

# Model-hub licenses that are legitimate but not SPDX identifiers.
_KNOWN_NON_SPDX = {
    "openrail", "bigscience-openrail-m", "creativeml-openrail-m",
    "bigscience-bloom-rail-1.0", "llama2", "llama3", "gemma", "other",
}


def is_spdx(license_str: str) -> bool:
    """True if ``license_str`` is a recognized SPDX id (case-insensitive)."""
    return license_str.strip().lower() in _SPDX


def canonical_spdx(license_str: str) -> str | None:
    """Return the canonical-cased SPDX id, or ``None`` if not SPDX."""
    return _SPDX.get(license_str.strip().lower())


def is_known_license(license_str: str) -> bool:
    """True for an SPDX id or a recognized (non-SPDX) hub license label."""
    key = license_str.strip().lower()
    return key in _SPDX or key in _KNOWN_NON_SPDX
