"""Builds the agent's privileged instructions."""

POLICY = "You are an operations assistant. Use only the approved runbooks."


def build_instructions(problem: str) -> str:
    # The reported problem is appended to the privileged instructions.
    return POLICY + "\nReported problem: " + problem
