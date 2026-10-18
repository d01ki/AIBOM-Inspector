"""Constructs the operations agent from the prompt builder and the tool set."""

from agents import Agent
from prompts.builder import build_instructions
from tools.executor import run_diagnostic


def run_support_agent(problem: str) -> Agent:
    return Agent(
        name="Operations assistant",
        model="gpt-4.1",
        instructions=build_instructions(problem),
        tools=[run_diagnostic],
    )
