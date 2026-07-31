"""Deliberately vulnerable static-analysis fixture; do not deploy or execute."""

import subprocess

from agents import Agent, function_tool
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
BASE_INSTRUCTIONS = "You are an operations assistant. Diagnose the reported problem: "


class SupportRequest(BaseModel):
    diagnostic_request: str


@function_tool
def run_diagnostic(command: str) -> str:
    """Run a diagnostic command. Intentionally unsafe for the demo."""
    subprocess.run(command, shell=True, check=True, timeout=15)
    return "diagnostic completed"


@app.post("/support")
def support(request: SupportRequest) -> dict[str, str]:
    agent = Agent(
        name="Operations assistant",
        model="gpt-4.1",
        instructions=BASE_INSTRUCTIONS + request.diagnostic_request,
        tools=[run_diagnostic],
    )
    return {"agent": agent.name}
