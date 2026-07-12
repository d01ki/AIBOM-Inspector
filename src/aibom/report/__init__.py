"""Reporting — render a scan into a shareable document.

The HTML report is fully self-contained (inline CSS, no external requests), so
it can be attached to a ticket or opened offline. It presents the security
score, the deterministic findings with their evidence, and the AI inventory.
"""

from __future__ import annotations

from aibom.report.html import render_html

__all__ = ["render_html"]
