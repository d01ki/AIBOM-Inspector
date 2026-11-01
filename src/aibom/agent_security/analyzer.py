"""Build an :class:`AgentSecurityReport`: agent -> tool -> operation x identity -> policy.

Edges are created only from evidence:

* ``agent -BINDS_TOOL-> tool`` — the explicit ``tools=[...]`` list of an OpenAI
  Agents SDK ``Agent(...)`` constructor, resolved by the same binding analysis
  the AIBOM inventory uses (same tool component IDs);
* ``tool -REACHES_OPERATION-> operation`` — a recognized boto3 call in the tool
  body, or an explicit ``tools:`` declaration in the identity manifest;
* ``agent -RUNS_AS-> identity`` — the identity manifest only, matched by
  ``<file>:<assigned variable>``; never inferred from names;
* ``identity -ATTACHES_POLICY-> policy`` and ``ALLOWS_ACTION``/``DENIES_ACTION``
  — bounded IAM parsing (:mod:`aibom.agent_security.iam`).

Nothing in the scanned repository is imported or executed.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from aibom.agent_security import iam
from aibom.agent_security.manifest import (
    DEFAULT_MANIFEST,
    AgentMapping,
    IdentityManifest,
    load_manifest,
)
from aibom.agent_security.models import (
    AgentIdentity,
    AgentRecord,
    AgentSecurityReport,
    AnalysisScope,
    AuthorizationPolicy,
    CapabilityPath,
    GraphEdge,
    GraphNode,
    ResolutionStatus,
    SecEvidence,
    SourceType,
    ToolOperation,
    UnknownItem,
    Verdict,
)
from aibom.agent_security.operations import detect_operations, hazard_for_action
from aibom.collectors.repo import RepoCollector
from aibom.detectors.project import ProjectIndex
from aibom.detectors.python.parser import PythonModule, classify_source_context
from aibom.detectors.python.prompt_flow import (
    _OPENAI_AGENT_CONSTRUCTORS,
    _bound_tools,
    tool_framework,
)
from aibom.detectors.python.value_resolver import ValueResolver
from aibom.inventory import Inventory
from aibom.models.analysis import SourceContext
from aibom.models.entities import Prompt, Tool


@dataclass
class _AgentSite:
    module: PythonModule
    call: ast.Call
    symbol: str | None
    ambiguous: bool = False

    @property
    def source(self) -> str:
        name = self.symbol or f"<anonymous@{self.call.lineno}>"
        return f"{self.module.relative_path}:{name}"


def analyze(
    target: str | Path,
    inventory: Inventory | None = None,
    *,
    manifest: str | Path | None = None,
    auto_manifest: bool = True,
    display_target: str | None = None,
) -> AgentSecurityReport:
    """Analyze ``target``; raises :class:`~aibom.agent_security.safeio.InputError`."""
    root = Path(target).resolve()
    if root.is_file():
        root = root.parent
    loaded: IdentityManifest | None = None
    manifest_display: str | None = None
    if manifest is not None:
        loaded, manifest_display = load_manifest(root, manifest)
    elif auto_manifest and (root / DEFAULT_MANIFEST).is_file():
        loaded, manifest_display = load_manifest(root, DEFAULT_MANIFEST)

    project = RepoCollector(root).index_project()
    report = AgentSecurityReport(
        target=display_target or root.name,
        scope=AnalysisScope(manifest=manifest_display),
    )
    _Builder(root, project, inventory, loaded, report).run()
    return report


class _Builder:
    def __init__(
        self,
        root: Path,
        project: ProjectIndex,
        inventory: Inventory | None,
        manifest: IdentityManifest | None,
        report: AgentSecurityReport,
    ) -> None:
        self.root = root
        self.project = project
        self.inventory = inventory
        self.manifest = manifest
        self.report = report
        self.tool_ids: dict[str, str] = {}
        if inventory is not None:
            for entity in inventory.entities:
                if isinstance(entity, Tool):
                    self.tool_ids[entity.name] = entity.id
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}

    # -- orchestration -----------------------------------------------------------

    def run(self) -> None:
        modules = [
            module
            for path, module in sorted(self.project.python.items())
            if classify_source_context(path) is SourceContext.PRODUCTION
        ]
        operations = self._tool_operations(modules)
        identities, policies = self._identities()
        agents = self._agents(modules, identities)
        self.report.operations = [op for ops in operations.values() for op in ops]
        self.report.identities = list(identities.values())
        self.report.policies = list(policies.values())
        self.report.scope.policies_visible = sorted(
            policy.id for policy in policies.values() if policy.status is ResolutionStatus.RESOLVED
        )
        for identity in identities.values():
            attached = [policies[p] for p in identity.policies if p in policies]
            self.report.permissions.extend(iam.clean_permissions(identity.id, attached))
            self._identity_graph(identity, attached)
        for agent in agents:
            self.report.agents.append(agent)
            self._agent_paths(agent, operations, identities, policies)
        self.report.nodes = sorted(self.nodes.values(), key=lambda n: n.id)
        self.report.edges = sorted(self.edges.values(), key=lambda e: e.id)
        self.report.capability_paths.sort(key=lambda p: p.key)

    # -- tools and operations ----------------------------------------------------

    def _tool_id(self, name: str, relative_path: str) -> str:
        key = f"{name}@{relative_path}"
        return self.tool_ids.get(key) or Tool(name=key, tool_name=name).id

    def _tool_operations(self, modules: list[PythonModule]) -> dict[str, list[ToolOperation]]:
        found: dict[str, list[ToolOperation]] = defaultdict(list)
        for module in modules:
            for info in module.functions.values():
                if tool_framework(module, info.node) is None:
                    continue
                tool_id = self._tool_id(info.name, module.relative_path)
                found[tool_id].extend(detect_operations(module, info.node, tool_id, info.name))
        if self.manifest is None:
            return found
        for declaration in self.manifest.tools:
            file, _, function = declaration.source.rpartition(":")
            declared = self.project.python.get(file)
            if declared is None or not any(
                info.name == function for info in declared.functions.values()
            ):
                self.report.unknowns.append(
                    UnknownItem(
                        subject=f"tool:{declaration.source}",
                        reason="manifest_tool_unresolved",
                        detail="declared tool function not found in the analyzed sources",
                        evidence=[SecEvidence(file=self._manifest_file(), kind="manifest")],
                    )
                )
                continue
            tool_id = self._tool_id(function, file)
            for action in declaration.actions:
                for resource in declaration.resources:
                    found[tool_id].append(
                        ToolOperation(
                            tool_id=tool_id,
                            tool_name=function,
                            action=action,
                            resource=resource,
                            resource_resolved="*" not in resource and "?" not in resource,
                            hazard=hazard_for_action(action),
                            source_type=SourceType.EXPLICIT_MANIFEST,
                            evidence=[
                                SecEvidence(
                                    file=self._manifest_file(),
                                    kind="manifest",
                                    detail=f"tools[{declaration.source}]",
                                )
                            ],
                        )
                    )
        return found

    def _manifest_file(self) -> str:
        return self.report.scope.manifest or DEFAULT_MANIFEST

    # -- identities --------------------------------------------------------------

    def _identities(
        self,
    ) -> tuple[dict[str, AgentIdentity], dict[str, AuthorizationPolicy]]:
        identities: dict[str, AgentIdentity] = {}
        policies: dict[str, AuthorizationPolicy] = {}
        if self.manifest is None:
            return identities, policies
        for definition in self.manifest.identities:
            refs = [p.replace("\\", "/") for p in definition.policies]
            identities[definition.id] = AgentIdentity(
                id=definition.id,
                provider=definition.provider,
                policies=refs,
                evidence=[
                    SecEvidence(
                        file=self._manifest_file(),
                        kind="manifest",
                        detail=f"identities[{definition.id}]",
                    )
                ],
            )
            for ref in refs:
                if ref not in policies:
                    policy = iam.load_policy(self.root, ref)
                    policies[ref] = policy
                    if policy.status is not ResolutionStatus.RESOLVED:
                        self.report.unknowns.append(
                            UnknownItem(
                                subject=f"policy:{ref}",
                                reason=f"policy_{policy.status.value}",
                                detail=policy.error or "",
                            )
                        )
                    else:
                        for statement in policy.statements:
                            if statement.unsupported:
                                self.report.unknowns.append(
                                    UnknownItem(
                                        subject=f"policy:{ref}#/Statement/{statement.index}",
                                        reason="unsupported_policy_elements",
                                        detail=", ".join(statement.unsupported),
                                        evidence=[iam.statement_evidence(policy, statement)],
                                    )
                                )
        return identities, policies

    # -- agents ------------------------------------------------------------------

    def _agent_sites(self, modules: list[PythonModule]) -> list[_AgentSite]:
        sites: list[_AgentSite] = []
        for module in modules:
            if not module.has_import("agents"):
                continue
            local: list[_AgentSite] = []
            for call in module.calls:
                if (module.qualified_name(call.func) or "") not in _OPENAI_AGENT_CONSTRUCTORS:
                    continue
                local.append(_AgentSite(module, call, _assigned_symbol(module, call)))
            counts: dict[str | None, int] = defaultdict(int)
            for site in local:
                counts[site.symbol] += 1
            for site in local:
                site.ambiguous = site.symbol is not None and counts[site.symbol] > 1
            sites.extend(local)
        return sites

    def _agents(
        self, modules: list[PythonModule], identities: dict[str, AgentIdentity]
    ) -> list[AgentRecord]:
        sites = self._agent_sites(modules)
        mappings = {m.source: m for m in self.manifest.agents} if self.manifest else {}
        used: set[str] = set()
        records: list[AgentRecord] = []
        for site in sites:
            mapping = mappings.get(site.source) if site.symbol and not site.ambiguous else None
            if mapping is not None:
                used.add(site.source)
            if site.symbol and site.ambiguous and site.source in mappings:
                used.add(site.source)
                self.report.unknowns.append(
                    UnknownItem(
                        subject=f"agent:{site.source}",
                        reason="agent_source_ambiguous",
                        detail="several Agent(...) assignments share this variable name; "
                        "no identity was bound",
                        evidence=[_ast_evidence(site.module, site.call, "Agent(...)")],
                    )
                )
            records.append(self._agent_record(site, mapping, identities))
        for source in sorted(set(mappings) - used):
            self.report.unknowns.append(
                UnknownItem(
                    subject=f"agent:{source}",
                    reason="manifest_agent_unresolved",
                    detail="no Agent(...) assignment with this file:variable was found",
                    evidence=[SecEvidence(file=self._manifest_file(), kind="manifest")],
                )
            )
        return records

    def _agent_record(
        self,
        site: _AgentSite,
        mapping: AgentMapping | None,
        identities: dict[str, AgentIdentity],
    ) -> AgentRecord:
        resolver = ValueResolver(site.module)
        display: str | None = None
        for keyword in site.call.keywords:
            if keyword.arg == "name":
                value = resolver.resolve(keyword.value)
                if value.resolved and isinstance(value.value, str):
                    display = value.value
        evidence = [_ast_evidence(site.module, site.call, "Agent(...)")]
        agent_id = f"agent:{site.source}"
        identity_id: str | None = None
        identity_source = SourceType.UNKNOWN
        if mapping is not None:
            agent_id = mapping.agent_ref
            identity_id = mapping.identity_ref
            identity_source = SourceType.EXPLICIT_MANIFEST
            if identity_id not in identities:
                self.report.unknowns.append(
                    UnknownItem(
                        subject=agent_id,
                        reason="identity_undefined",
                        detail=f"identity_ref '{identity_id}' is not defined under identities",
                    )
                )
        elif not site.ambiguous:
            self.report.unknowns.append(
                UnknownItem(
                    subject=agent_id,
                    reason="identity_unmapped",
                    detail="no identity manifest entry maps this agent; its runtime "
                    "identity is unknown",
                    evidence=evidence,
                )
            )

        tool_ids: list[str] = []
        for bound in _bound_tools(site.module, site.call, self.project):
            if bound.function is None:
                self.report.unknowns.append(
                    UnknownItem(
                        subject=f"{agent_id}:tool:{bound.name}",
                        reason="tool_definition_unresolved",
                        detail="bound tool could not be resolved to a function definition",
                        evidence=evidence,
                    )
                )
                continue
            tool_ids.append(self._tool_id(bound.name, bound.module.relative_path))

        return AgentRecord(
            id=agent_id,
            source=site.source,
            display_name=display,
            identity_id=identity_id,
            identity_source_type=identity_source,
            tool_ids=tool_ids,
            external_input=self._external_input(site),
            evidence=evidence,
        )

    def _external_input(self, site: _AgentSite) -> bool:
        if self.inventory is None:
            return False
        line = site.call.lineno
        for keyword in site.call.keywords:
            if keyword.arg == "instructions":
                line = getattr(keyword.value, "lineno", line)
        name = f"agent-instructions@{site.module.relative_path}:{line}"
        return any(
            isinstance(entity, Prompt) and entity.name == name and entity.user_controlled is True
            for entity in self.inventory.entities
        )

    # -- paths and graph ---------------------------------------------------------

    def _agent_paths(
        self,
        agent: AgentRecord,
        operations: dict[str, list[ToolOperation]],
        identities: dict[str, AgentIdentity],
        policies: dict[str, AuthorizationPolicy],
    ) -> None:
        self._node(
            agent.id,
            "agent",
            agent.display_name or agent.source,
            SourceType.OBSERVED_STATIC,
            evidence=agent.evidence,
        )
        identity = identities.get(agent.identity_id) if agent.identity_id else None
        if agent.identity_id is not None:
            self._node(
                agent.identity_id,
                "identity",
                agent.identity_id,
                SourceType.EXPLICIT_MANIFEST,
                ResolutionStatus.RESOLVED if identity else ResolutionStatus.MISSING,
            )
            self._edge(
                agent.id,
                agent.identity_id,
                "RUNS_AS",
                SourceType.EXPLICIT_MANIFEST,
                evidence=[
                    SecEvidence(
                        file=self._manifest_file(),
                        kind="manifest",
                        detail=f"agents[{agent.source}]",
                    )
                ],
            )
        attached = [policies[p] for p in identity.policies if p in policies] if identity else []

        for tool_id in agent.tool_ids:
            ops = operations.get(tool_id, [])
            tool_name = ops[0].tool_name if ops else tool_id
            self._node(tool_id, "tool", tool_name, SourceType.OBSERVED_STATIC)
            self._edge(
                agent.id, tool_id, "BINDS_TOOL", SourceType.OBSERVED_STATIC, evidence=agent.evidence
            )
            for op in ops:
                op_id = f"operation:{op.action}|{op.resource}"
                self._node(
                    op_id,
                    "operation",
                    f"{op.action} {op.resource}",
                    op.source_type,
                    ResolutionStatus.RESOLVED
                    if op.resource_resolved
                    else ResolutionStatus.UNRESOLVED,
                )
                self._edge(
                    tool_id, op_id, "REACHES_OPERATION", op.source_type, evidence=op.evidence
                )
                self.report.capability_paths.append(self._path(agent, identity, attached, op))

    def _path(
        self,
        agent: AgentRecord,
        identity: AgentIdentity | None,
        attached: list[AuthorizationPolicy],
        op: ToolOperation,
    ) -> CapabilityPath:
        constraints = list(iam.STANDARD_CONSTRAINTS)
        if not op.resource_resolved:
            constraints.append("resource-partially-resolved")
        if op.source_type is SourceType.EXPLICIT_MANIFEST:
            constraints.append("operation-declared-in-manifest")
        evidence: list[SecEvidence]
        if agent.identity_id is None:
            verdict, reasons, evidence = Verdict.UNKNOWN, ["identity_unmapped"], []
        elif identity is None:
            verdict, reasons, evidence = Verdict.UNKNOWN, ["identity_undefined"], []
        else:
            result = iam.evaluate(
                attached, op.action, op.resource, resource_resolved=op.resource_resolved
            )
            verdict, reasons, evidence = result.verdict, result.reasons, result.evidence
        confidence = {
            Verdict.POTENTIALLY_ALLOWED: "conditional",
            Verdict.UNKNOWN: "unknown",
        }.get(verdict, "n/a")
        return CapabilityPath(
            key="|".join([agent.id, op.tool_id, op.action, op.resource]),
            agent_id=agent.id,
            identity_id=agent.identity_id,
            tool_id=op.tool_id,
            tool_name=op.tool_name,
            action=op.action,
            resource=op.resource,
            hazard=op.hazard,
            verdict=verdict,
            confidence_level=confidence,
            constraints=constraints if verdict is Verdict.POTENTIALLY_ALLOWED else [],
            reasons=reasons,
            evidence=[*agent.evidence, *op.evidence, *evidence],
            external_input=agent.external_input,
            proven=False,
        )

    def _identity_graph(self, identity: AgentIdentity, attached: list[AuthorizationPolicy]) -> None:
        self._node(identity.id, "identity", identity.id, SourceType.EXPLICIT_MANIFEST)
        for ref in identity.policies:
            policy = next((p for p in attached if p.id == ref), None)
            status = policy.status if policy else ResolutionStatus.MISSING
            self._node(f"policy:{ref}", "policy", ref, SourceType.EXPLICIT_MANIFEST, status)
            self._edge(
                identity.id,
                f"policy:{ref}",
                "ATTACHES_POLICY",
                SourceType.EXPLICIT_MANIFEST,
                status,
            )
            if policy is None:
                continue
            for statement in policy.statements:
                kind = "ALLOWS_ACTION" if statement.effect == "Allow" else "DENIES_ACTION"
                state = (
                    ResolutionStatus.UNSUPPORTED
                    if statement.unsupported
                    else ResolutionStatus.RESOLVED
                )
                for action in statement.actions:
                    perm_id = f"permission:{action}"
                    self._node(perm_id, "permission", action, SourceType.OBSERVED_STATIC)
                    self._edge(
                        f"policy:{ref}",
                        perm_id,
                        kind,
                        SourceType.OBSERVED_STATIC,
                        state,
                        evidence=[iam.statement_evidence(policy, statement)],
                    )
                    for resource in statement.resources:
                        res_id = f"resource:{resource}"
                        self._node(res_id, "resource", resource, SourceType.OBSERVED_STATIC)
                        self._edge(
                            perm_id,
                            res_id,
                            "TARGETS_RESOURCE",
                            SourceType.OBSERVED_STATIC,
                            state,
                            evidence=[iam.statement_evidence(policy, statement)],
                        )

    def _node(
        self,
        node_id: str,
        kind: str,
        label: str,
        source_type: SourceType,
        status: ResolutionStatus = ResolutionStatus.RESOLVED,
        *,
        evidence: list[SecEvidence] | None = None,
    ) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                id=node_id,
                kind=kind,
                label=label,
                source_type=source_type,
                resolution_status=status,
                evidence=list(evidence or []),
            )

    def _edge(
        self,
        source: str,
        target: str,
        kind: str,
        source_type: SourceType,
        status: ResolutionStatus = ResolutionStatus.RESOLVED,
        *,
        evidence: list[SecEvidence] | None = None,
    ) -> None:
        edge_id = f"{kind}:{source}->{target}"
        existing = self.edges.get(edge_id)
        if existing is not None:
            existing.evidence.extend(e for e in evidence or [] if e not in existing.evidence)
            return
        self.edges[edge_id] = GraphEdge(
            id=edge_id,
            source=source,
            target=target,
            kind=kind,
            source_type=source_type,
            resolution_status=status,
            evidence=list(evidence or []),
        )


def _assigned_symbol(module: PythonModule, call: ast.Call) -> str | None:
    parent = module.parents.get(id(call))
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
        target = parent.targets[0]
        if isinstance(target, ast.Name):
            return target.id
    if isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
        return parent.target.id
    return None


def _ast_evidence(module: PythonModule, node: ast.AST, detail: str) -> SecEvidence:
    return SecEvidence(
        file=module.relative_path, line=getattr(node, "lineno", None), kind="ast", detail=detail
    )
