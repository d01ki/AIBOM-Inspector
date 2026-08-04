# Black Hat novelty and positioning

**Landscape review date:** 2026-07-28
**Capability update:** 2026-07-31 (syntax-aware TypeScript/JavaScript analysis)

## Executive conclusion

Repository-wide AI inventory is no longer a sufficient novelty claim. Publicly
documented tools now discover models, prompts, agents, tools, and MCP components
from source code, and several export CycloneDX AI/ML-BOMs.

AIBOM Inspector's defensible focus is narrower:

> **A privacy-preserving behavioral AIBOM that connects untrusted input,
> privileged instructions, a model, an explicit agent-tool binding, and a
> tool-parameter-controlled operation—then gates revisions on newly introduced
> end-to-end paths even when the component inventory is unchanged.**

As of 2026-07-31 that analysis is **language-symmetric**: the same role-aware
prompt lineage, direct-binding requirement, and drift gate run on TypeScript and
JavaScript as on Python. This matters because the agent ecosystem competitors
document most thoroughly (Vercel AI SDK, OpenAI Agents, MCP servers, Next.js
route handlers) is largely TypeScript, while deep source-level prompt-role taint
has been demonstrated mostly on Python.

This is a stronger claim than "the first AIBOM scanner." It is demonstrable,
falsifiable, and backed by checked-in tests. It should be presented as the
project's differentiator, not as a universal "industry first" unless a formal
prior-art review supports that wording.

## The blind spot

Consider two revisions of the same application:

```python
# Baseline
{"role": "system", "content": POLICY}

# Candidate
{"role": "system", "content": POLICY + request.user_input}
```

Both revisions can have an identical component BOM: the same OpenAI SDK, model,
agent framework, and packages. A component-only diff reports no meaningful
change. AIBOM Inspector reports:

```text
CRITICAL  impact_path_added
http_request -> Agent.instructions -> gpt-4.1 -> run_diagnostic
command -> subprocess.run
```

The powerful tool and model can already exist in both revisions. The new
security fact is that an untrusted value now enters privileged instructions,
making the directly bound, parameter-controlled operation newly steerable. The
report contains sanitized source/sink/capability evidence and a prompt hash
where possible, never the prompt body or tool argument values.

## What is technically distinct

The differentiator is the combination of:

1. **Role-aware prompt analysis.** System/developer instructions are separated
   from user messages rather than treating the whole messages array as tainted.
2. **Bounded source-to-sink proof.** HTTP, CLI, MCP tool, event, file,
   retrieval, database, and environment sources are followed into supported
   OpenAI and Anthropic sinks.
3. **Behavioral usage state.** Declared, imported, instantiated, invoked, and
   reachable are separate states; a package declaration is not treated as
   execution.
4. **Privacy-preserving lineage.** Prompt bodies are not serialized. Static
   content uses hashes; flow steps retain symbols and locations but clear
   values.
5. **Trust-Boundary Drift.** `aibom diff` compares behavior as well as
   components and can fail CI when a new privileged exposure appears.
6. **Direct capability correlation.** An impact path requires an explicit
   `tools=[...]` binding, a recognized tool decorator, and bounded flow from a
   tool parameter into a high-impact operation. Co-location, an unbound helper,
   or a fixed command is insufficient.
7. **Blast-Radius Drift.** The diff promotes a newly connected
   source→instructions→bound-tool→operation chain, instead of reporting the
   already-existing powerful tool as newly added.
8. **Standard-compatible evidence.** Prompt lineage and bound capabilities are
   retained as CycloneDX
   `aibom:*` properties and file/line relationships instead of living only in a
   proprietary dashboard.
9. **Deterministic and non-executing.** No scanned code, model, or MCP server is
   executed, and no LLM verdict is required.
10. **Language-symmetric TypeScript analysis.** JS/TS is parsed with a
    dependency-free tolerant parser, not matched with regexes: import aliases
    (including `node:` prefixes and npm scopes), destructured tool parameters,
    template-literal composition, and TypeScript type syntax are all handled.
    There is no Node.js runtime, no bundling step, and no npm install of the
    target — so a repository is analyzed without ever running its toolchain.

No individual item should be presented as unique by itself. The value is the
integrated, auditable workflow.

## Competitive landscape

This table compares publicly documented capabilities, not private roadmaps or
undocumented implementation details.

| Project | Publicly documented strength | AIBOM Inspector positioning |
|---|---|---|
| [OWASP AIBOM Generator](https://genai.owasp.org/resource/owasp-aibom-generator/) | Hugging Face model metadata, visualization, completeness, CycloneDX | Starts from application source and resolves actual use, prompt flow, and revision drift. |
| [Snyk AI-BOM](https://docs.snyk.io/developer-tools/snyk-cli/commands/aibom) | Python source discovery and MCP component graph in CycloneDX 1.6 | Local/offline deterministic analysis plus role-aware prompt lineage and behavioral diff. |
| [Cisco AI BOM](https://cisco-ai-defense.github.io/docs/aibom) | Source/container inventory, catalog matching, workflow call-path context, derived relationships | Treats untrusted-to-privileged prompt flow as first-class evidence and compares it across revisions without an LLM. |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Prompt injection, MCP toxic-flow inputs, sensitive data, and destructive-capability findings | Do not claim toxic-flow or destructive-capability detection as unique. The narrower distinction is application-source prompt-role lineage joined to a direct tool operation and identical-component revision drift, without starting MCP servers. |
| [Agent Audit](https://github.com/HeadyZhang/agent-audit) | Static tool-boundary taint from decorated tool parameters to dangerous sinks, prompt-injection rules, and CI gates | Do not claim tool-parameter taint as unique. AIBOM Inspector adds the consuming model/prompt trust boundary, AIBOM/CycloneDX identity, and path-level before/after comparison. |
| [AIBOM](https://aibom.dev/docs) | Multi-language and bulk GitHub scanning, generic component drift, signing | Does not compete on fleet breadth; focuses on security-semantic drift inside a repository. |
| [ZeroPath AI-BOM](https://zeropath.com/products/aibom) | Per-repository models, datasets, agents, SDKs, MCP, CycloneDX | Open, local-first proof paths and prompt-body minimization are the focus. |
| [agent-bom](https://github.com/msaad00/agent-bom) | Broad cloud/runtime/MCP graph, blast radius, multi-hop exposure paths | Avoid a generic attack-path claim. Differentiate on code-level prompt-role taint and identical-inventory Trust-Boundary Drift. |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Installed agent/MCP/skill discovery and runtime MCP inspection | Scans application source without starting declared MCP commands; produces AIBOM and CI artifacts. |
| [ModelScan](https://github.com/protectai/modelscan) | Unsafe serialization inside supplied model files | Finds where a model is referenced and whether an input-to-prompt path reaches it; deep binary inspection remains complementary. |
| [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) | Standard representation for ML transparency | Uses the standard as an interchange base and adds evidence/behavioral properties; it does not claim the format itself as novelty. |

## Claims to use and avoid

Use:

- "Detects security-significant AI behavior drift that component-only AIBOM
  diffs miss."
- "Shows a newly connected source→privileged-instructions→model→bound-tool→
  operation path even when every component already existed."
- "Proves bounded untrusted-input paths into privileged prompts without storing
  prompt bodies."
- "Static-only and deterministic: it never imports target code, loads model
  weights, or starts MCP servers."
- "Every detected component, flow, and finding is tied to file/line evidence."
- "The same behavioral drift gate runs on TypeScript agent code without
  installing or executing the project's npm toolchain."

Avoid:

- "The first AIBOM scanner."
- "The only repository-wide AIBOM."
- "The only AIBOM attack-path tool."
- "The first agent taint analyzer" or "the only toxic-flow scanner."
- "Full reachability" or "complete taint analysis." Current analysis is bounded
  and same-file.
- "Zero false positives" beyond the exact checked-in benchmark set.
- "A complete TypeScript/JavaScript parser." It is a deliberately bounded subset
  parser: it models bindings, calls, members, objects, templates, and function
  bodies, and skips type-level syntax. It is tolerant, not spec-compliant.
- "Cross-file TypeScript taint." JS/TS flow tracing is same-file, exactly like
  the Python analysis; a tool defined in another module is not followed.

## Suggested Black Hat abstract paragraph

> Existing AI-BOMs can tell defenders that two releases use the same model,
> SDK, agent, and command-running tool. That inventory can remain identical
> while one edit begins concatenating HTTP input into the agent's privileged
> instructions. AIBOM Inspector introduces a behavioral AIBOM that connects
> prompt-role taint to an explicit tool binding and a model-controlled parameter
> reaching a high-impact operation. Its Blast-Radius Drift gate reports the new
> end-to-end path—not a newly added component—using privacy-preserving,
> file/line evidence in CycloneDX, SARIF, JSON, and an offline report.

## Two-minute demo

```bash
./aibom demo
```

Demo sequence:

1. Point to the critical path:
   `http_request → Agent.instructions → gpt-4.1 → run_diagnostic(command) →
   subprocess.run`.
2. Point to the operation line and the explicit statement that runtime exploit
   success is not claimed.
3. Show `impact_path_added` for Python: baseline and candidate have the same
   model, tool, package set, and dangerous operation; only the
   input-to-instructions connection changed.
4. Show the same verdict for TypeScript, where the sink is
   `generateText({ system })`, the binding is `tools: { runDiagnostic: tool(…) }`,
   and the operation is `execSync(command)` — the same reasoning, a different
   ecosystem, and no npm install.
5. The drift demo is a CLI capability: `aibom demo` runs the Python and
   TypeScript comparisons offline — no URL, API key, or network needed. The web
   UI covers single-revision scans only.

## Evidence still needed before the talk

- Expand the public benchmark from **six** repositories to at least 20,
  including mixed-role prompt cases. (Was two; `vercel/ai-chatbot`,
  `expressjs/express`, `psf/requests`, and `encode/httpx` were curated
  2026-07-31.)
- Close the TypeScript recall gap the corpus exposed: model ids declared in a
  data structure and resolved through `gateway.languageModel(id)` are not
  followed, giving public-corpus recall of 0.79 for TypeScript vs 1.00 for
  Python.
- ~~Add JavaScript/TypeScript syntax-aware prompt-flow analysis~~ — shipped
  2026-07-31 (`javascript.prompt-flow.ast`).
- ~~Measure JS/TS precision separately from Python~~ — shipped 2026-07-31
  (`## By language` in the benchmark report).
- Measure drift precision on real pull requests, not only synthetic revisions.
- Publish a pinned comparison corpus and commands so competitors and reviewers
  can reproduce the capability matrix.
- Keep the novelty claim dated. This market changes quickly.
