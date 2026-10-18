"""Builds the agent's privileged instructions."""

POLICY = "You are an operations assistant. Use only the approved runbooks."


def build_instructions(problem: str) -> str:
    # Only a fixed category label reaches the privileged instructions.
    return POLICY + "\nCategory: " + _category(problem)


def _category(problem: str) -> str:
    if "disk" in problem:
        return "storage"
    return "general"
