"""Vulnerability mapping — correlate discovered packages with known advisories.

Uses OSV.dev (the Open Source Vulnerabilities database) to map the AI packages
found in a repo's manifests to known CVE/GHSA advisories, producing
evidence-backed vulnerability findings. Network-optional and read-only.
"""

from __future__ import annotations

from aibom.vuln.osv import OSVClient, OSVMapper

__all__ = ["OSVClient", "OSVMapper"]
