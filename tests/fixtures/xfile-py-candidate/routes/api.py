"""HTTP layer of the cross-file demo; static fixture only, never executed."""

from assistant.main import run_support_agent
from fastapi import FastAPI

app = FastAPI()


@app.post("/support")
def support(problem: str) -> dict[str, str]:
    agent = run_support_agent(problem)
    return {"agent": agent.name}
