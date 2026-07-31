"""Safe baseline for the impact-drift demo; static fixture only."""

import subprocess

from agents import Agent, function_tool
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
BASE_INSTRUCTIONS = "You are an operations assistant. Follow the fixed runbook."


class SupportRequest(BaseModel):
    diagnostic_request: str


@function_tool
def run_diagnostic(command: str) -> str:
    """Run a diagnostic command. Intentionally powerful for the demo."""
    subprocess.run(command, shell=True, check=True, timeout=15)
    return "diagnostic completed"


@app.post("/support")
def support(request: SupportRequest) -> dict[str, str]:
    agent = Agent(
        name="Operations assistant",
        model="gpt-4.1",
        instructions=BASE_INSTRUCTIONS,
        tools=[run_diagnostic],
    )
    return {"agent": agent.name, "request_received": str(bool(request.diagnostic_request))}
