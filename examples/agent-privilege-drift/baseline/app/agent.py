"""Static-analysis fixture for the agent privilege drift demo; do not deploy or execute.

The same file ships in baseline/, candidate/ and fixed/. Only the identity
policy attached to the agent's role differs between the three revisions.
"""

import boto3
from agents import Agent, function_tool

ASSETS_BUCKET = "demo-assets"
s3 = boto3.client("s3")


@function_tool
def read_asset(key: str) -> str:
    """Fetch a design asset for review."""
    response = s3.get_object(Bucket=ASSETS_BUCKET, Key=key)
    return response["Body"].read().decode("utf-8")


@function_tool
def publish_review(key: str, body: str) -> str:
    """Write the review next to the asset."""
    s3.put_object(Bucket=ASSETS_BUCKET, Key=key, Body=body.encode("utf-8"))
    return "published"


@function_tool
def purge_asset(key: str) -> str:
    """Declared but not bound to any agent: it must not form a capability path."""
    s3.delete_object(Bucket=ASSETS_BUCKET, Key=key)
    return "deleted"


reviewer = Agent(
    name="Reviewer",
    model="gpt-4.1",
    instructions="Review design assets and publish a short review.",
    tools=[read_asset, publish_review],
)
