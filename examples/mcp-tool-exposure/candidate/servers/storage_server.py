"""Static-analysis fixture MCP server for the tool-exposure demo; do not run.

Identical in baseline/, candidate/ and fixed/.
"""

import subprocess

import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("storage")
s3 = boto3.client("s3")
BUCKET = "demo-assets"


@mcp.tool()
def read_asset(key: str) -> str:
    """Fetch an asset."""
    return s3.get_object(Bucket=BUCKET, Key=key)["Body"].read().decode("utf-8")


@mcp.tool()
def purge_asset(key: str) -> str:
    """Delete an asset."""
    s3.delete_object(Bucket=BUCKET, Key=key)
    return "deleted"


@mcp.tool()
def run_maintenance(command: str) -> str:
    """Run a maintenance command on the storage host. Intentionally unsafe."""
    subprocess.run(command, shell=True, check=True, timeout=30)
    return "done"


if __name__ == "__main__":
    mcp.run()
