"""Versioned data model for agent identity, authorization and capability paths.

Everything here lives in its own ``agent_security`` namespace so the existing
inventory JSON, SARIF and CycloneDX outputs stay byte-for-byte unchanged.

Vocabulary, kept deliberately narrow:

* a *verdict* is about the **supplied** identity policies only.  It never claims
  AWS effective authorization (SCPs, boundaries, session and resource policies
  are out of scope), so ``potentially_allowed`` always carries constraints and
  ``proven`` is always ``False``;
* ``no_matching_allow_in_supplied_policies`` is **not** "cannot happen";
* ``unknown`` always carries a machine-readable reason.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


class SourceType(str, Enum):
    """How a node or edge became known."""

    OBSERVED_STATIC = "observed_static"
    EXPLICIT_MANIFEST = "explicit_manifest"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class ResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"
    MISSING = "missing"


class Verdict(str, Enum):
    """Bounded evaluation of one action/resource against supplied policies."""

    POTENTIALLY_ALLOWED = "potentially_allowed"
    EXPLICITLY_DENIED = "explicitly_denied"
    NO_MATCHING_ALLOW = "no_matching_allow_in_supplied_policies"
    UNKNOWN = "unknown"


class SecEvidence(BaseModel):
    """A pointer a reviewer can re-check: a source line or a JSON pointer."""

    file: str
    line: int | None = Field(default=None, ge=1)
    pointer: str | None = Field(default=None, description="RFC 6901 pointer into a JSON file.")
    kind: str = Field(description="ast | manifest | iam_policy")
    detail: str | None = Field(default=None, description="Sanitized description, never secrets.")

    def ref(self) -> str:
        if self.pointer is not None:
            return f"{self.file}#{self.pointer}"
        if self.line is not None:
            return f"{self.file}:{self.line}"
        return self.file


class UnknownItem(BaseModel):
    """Something the analysis could not resolve — never silently treated as safe."""

    subject: str
    reason: str = Field(description="Stable machine-readable reason code.")
    detail: str = ""
    evidence: list[SecEvidence] = Field(default_factory=list)


class ToolOperation(BaseModel):
    """A cloud operation a tool is shown (or declared) to perform."""

    tool_id: str
    tool_name: str
    tool_file: str | None = Field(default=None, description="File defining the tool.")
    action: str = Field(description="IAM action, e.g. s3:PutObject.")
    resource: str = Field(description="Requested ARN; '*' when unresolved.")
    resource_resolved: bool = False
    hazard: str = Field(description="read | list | write | delete | secrets_read | admin")
    source_type: SourceType = SourceType.OBSERVED_STATIC
    derived_action: bool = Field(
        default=False, description="IAM action derived from the boto3 API name."
    )
    evidence: list[SecEvidence] = Field(default_factory=list)


class AgentIdentity(BaseModel):
    """A cloud identity an agent is declared to run as."""

    id: str
    provider: str
    policies: list[str] = Field(default_factory=list)
    provenance: SourceType = SourceType.EXPLICIT_MANIFEST
    evidence: list[SecEvidence] = Field(default_factory=list)


class PolicyStatement(BaseModel):
    index: int
    sid: str | None = None
    effect: str
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(
        default_factory=list, description="Elements present but not evaluated."
    )


class AuthorizationPolicy(BaseModel):
    """A parsed identity policy document (bounded AWS subset)."""

    id: str = Field(description="Workspace-relative path; stable across revisions.")
    provider: str = "aws"
    status: ResolutionStatus = ResolutionStatus.RESOLVED
    error: str | None = None
    statements: list[PolicyStatement] = Field(default_factory=list)


class Permission(BaseModel):
    """A grant pattern from a clean (fully evaluated) statement."""

    identity_id: str
    effect: str
    action: str
    resource: str
    evidence: SecEvidence


class AgentRecord(BaseModel):
    id: str = Field(description="Manifest agent_ref when mapped, else agent:<file>:<symbol>.")
    source: str = Field(description="<file>:<symbol> of the constructor assignment.")
    display_name: str | None = None
    framework: str = "openai-agents"
    identity_id: str | None = None
    identity_source_type: SourceType = SourceType.UNKNOWN
    tool_ids: list[str] = Field(default_factory=list)
    mcp_tool_ids: list[str] = Field(
        default_factory=list, description="MCP tools exposed through connected servers."
    )
    external_input: bool = Field(
        default=False, description="Agent instructions proven to reach untrusted input."
    )
    management_status: str = Field(
        default="unknown",
        description="unknown (no registry supplied) | registered | unregistered",
    )
    evidence: list[SecEvidence] = Field(default_factory=list)


class CapabilityPath(BaseModel):
    """agent -RUNS_AS-> identity, agent -BINDS_TOOL-> tool -REACHES-> operation."""

    key: str = Field(description="Stable key: agent|identity|tool|action|resource.")
    agent_id: str
    identity_id: str | None
    tool_id: str
    tool_name: str
    action: str
    resource: str
    hazard: str
    verdict: Verdict
    confidence_level: str = Field(description="conditional | unknown | n/a")
    constraints: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[SecEvidence] = Field(default_factory=list)
    external_input: bool = False
    via: str = Field(default="direct", description="direct | mcp")
    mcp_server_id: str | None = None
    proven: bool = False


class McpToolRecord(BaseModel):
    tool_id: str
    name: str
    capability_kinds: list[str] = Field(
        default_factory=list, description="Inventory capabilities, e.g. command_execution."
    )
    capability_severity: str | None = None


class McpServerRecord(BaseModel):
    """An MCP server defined in the analyzed sources (never started)."""

    id: str
    file: str
    name: str | None = None
    identity_id: str | None = None
    status: str = Field(description="connected | configured | defined")
    tools: list[McpToolRecord] = Field(default_factory=list)
    evidence: list[SecEvidence] = Field(default_factory=list)


class McpConnectionRecord(BaseModel):
    """A client (analyzed agent or client config file) declaring an MCP server."""

    client_kind: str = Field(description="agent | config")
    client_ref: str
    server_label: str
    transport: str
    launch: str | None = Field(default=None, description="Command basename + repository file.")
    server_id: str | None = None
    filter_status: str = Field(description="none | static | unresolved")
    approval: str = Field(
        default="none",
        description="require_approval: none | always | never | per_tool | unresolved",
    )
    exposed_tool_ids: list[str] = Field(default_factory=list)
    unresolved_reason: str | None = None
    evidence: list[SecEvidence] = Field(default_factory=list)


class Delegation(BaseModel):
    """An explicit handoff or agent-as-tool edge between two agents (one hop)."""

    parent_id: str
    child_id: str | None = Field(default=None, description="None when the target is unresolved.")
    child_ref: str = Field(description="Source expression naming the delegate, sanitized.")
    mechanism: str = Field(description="handoff | agent_as_tool")
    guard_status: str = Field(
        default="unknown",
        description="Handoff guards, approvals and identity propagation are not analyzed.",
    )
    evidence: list[SecEvidence] = Field(default_factory=list)


class DelegateCapabilityPath(BaseModel):
    """A child agent's capability reachable from a parent through delegation.

    Never merged into the parent's own capability paths: the parent's verdict
    is always ``unknown`` because guards and identity propagation are unverified.
    """

    key: str = Field(description="Stable key: parent|child|tool|action|resource.")
    parent_id: str
    child_id: str
    mechanism: str
    tool_id: str
    tool_name: str
    action: str
    resource: str
    hazard: str
    child_identity_id: str | None
    child_verdict: Verdict
    verdict: Verdict = Verdict.UNKNOWN
    reasons: list[str] = Field(
        default_factory=lambda: [
            "delegation_guard_unverified",
            "identity_context_propagation_unknown",
        ]
    )
    evidence: list[SecEvidence] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    kind: str
    label: str
    source_type: SourceType
    resolution_status: ResolutionStatus = ResolutionStatus.RESOLVED
    evidence: list[SecEvidence] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: str
    source_type: SourceType
    resolution_status: ResolutionStatus = ResolutionStatus.RESOLVED
    evidence: list[SecEvidence] = Field(default_factory=list)


class AnalysisScope(BaseModel):
    """What this analysis can and cannot see — part of every report."""

    frameworks: list[str] = Field(default_factory=lambda: ["python:openai-agents"])
    policy_language: str = "aws-iam-identity-policy-subset"
    evaluated_elements: list[str] = Field(
        default_factory=lambda: ["Effect", "Action", "Resource", "Sid"]
    )
    not_evaluated: list[str] = Field(
        default_factory=lambda: [
            "NotAction",
            "NotResource",
            "Condition",
            "resource-based policies",
            "SCP",
            "permission boundaries",
            "session policies",
            "role trust policies",
        ]
    )
    manifest: str | None = None
    registry: str | None = Field(
        default=None, description="Approved-agent registry supplied by the operator, if any."
    )
    policies_visible: list[str] = Field(default_factory=list)


class AgentSecurityReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    target: str
    scope: AnalysisScope = Field(default_factory=AnalysisScope)
    agents: list[AgentRecord] = Field(default_factory=list)
    identities: list[AgentIdentity] = Field(default_factory=list)
    policies: list[AuthorizationPolicy] = Field(default_factory=list)
    permissions: list[Permission] = Field(default_factory=list)
    operations: list[ToolOperation] = Field(default_factory=list)
    capability_paths: list[CapabilityPath] = Field(default_factory=list)
    delegations: list[Delegation] = Field(default_factory=list)
    mcp_servers: list[McpServerRecord] = Field(default_factory=list)
    mcp_connections: list[McpConnectionRecord] = Field(default_factory=list)
    delegate_paths: list[DelegateCapabilityPath] = Field(default_factory=list)
    unknowns: list[UnknownItem] = Field(default_factory=list)
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class RemediationAdvice(BaseModel):
    why_it_matters: str
    conditions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    retest_command: str


class PrivilegeChange(BaseModel):
    """One security-semantic change between two agent-security reports."""

    id: str
    type: str = Field(
        description=(
            "permission_scope_expanded | privilege_path_added | "
            "privileged_identity_binding_added | identity_permission_expanded | "
            "potential_privilege_removed | review_required | delegate_path_added | "
            "unregistered_agent_added | mcp_tool_exposure_added"
        )
    )
    change_status: str = Field(description="supported | review_required")
    agent: str | None = None
    identity: str | None = None
    tool: str | None = None
    action: str | None = None
    affected_resource: str | None = None
    before: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)
    before_verdict: str | None = None
    after_verdict: str | None = None
    severity: str = Field(description="info | low | medium | high | critical")
    severity_reasons: list[str] = Field(default_factory=list)
    certainty: str = Field(description="conditional | unknown")
    evidence: list[str] = Field(default_factory=list)
    remediation: RemediationAdvice | None = None
    gates: bool = Field(default=False, description="Only supported additions can fail CI.")


class PrivilegeDriftReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    baseline: str
    candidate: str
    bom_components_unchanged: bool | None = None
    bom_differences: list[str] = Field(default_factory=list)
    security_drift: bool
    scope_mismatch: list[str] = Field(
        default_factory=list, description="Visibility differences that weaken the comparison."
    )
    changes: list[PrivilegeChange] = Field(default_factory=list)
    unknowns_baseline: int = 0
    unknowns_candidate: int = 0
