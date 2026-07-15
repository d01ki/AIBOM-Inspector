from mcp.server.fastmcp import FastMCP

mcp = FastMCP("admin-tools")


@mcp.tool()
def run_command(cmd: str) -> str:
    return cmd
