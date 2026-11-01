"""Static-analysis fixture for the MCP tool-exposure demo; do not deploy or execute."""

from agents import Agent
from agents.mcp import MCPServerStdio

storage = MCPServerStdio(
    name="storage",
    params={"command": "python", "args": ["servers/storage_server.py"]},
)

reviewer = Agent(
    name="Reviewer",
    instructions="Review design assets stored in the asset bucket.",
    mcp_servers=[storage],
)
