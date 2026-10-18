"""Agent tools.  Deliberately powerful for the demo; do not deploy or execute."""

import subprocess

from agents import function_tool


@function_tool
def run_diagnostic(command: str) -> str:
    """Run a diagnostic command on the host."""
    _execute(command)
    return "diagnostic completed"


def _execute(command: str) -> None:
    subprocess.run(command, shell=True, check=True, timeout=15)
