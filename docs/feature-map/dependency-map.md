# Dependency map

## Overview

The map connects every inventoried component (packages, models, services,
datasets, prompts, agents, and tools) with typed, **evidence-backed** edges.
It feeds three outputs: the graph JSON (`/api/scan` → `graph`), the UI
*Dependencies* tab, and the CycloneDX `dependencies` section (CISA 2026
*Component Dependency Relationship*). An edge exists only if a scanned line
proves it. The edge rules are in
[architecture.md#dependency-map](../architecture.md#dependency-map).

## Entry points

- CLI: `aibom scan <path> -o inv.json` writes `relationships[]`;
  `-c bom.json` writes `dependencies[]`; `-r report.html` draws the graph.
- API: `POST /api/scan`, `POST /api/demo` → `graph.nodes`, `graph.edges[]`
  (`source`, `target`, `type`, `evidence[]`). The demo APIs carry one map per
  revision: `/api/agent-drift/demo` → `revisions.<stage>.graph`,
  `/api/diff/demo` → `baseline.graph` / `candidate.graph`.
- UI: results → **Dependencies** tab → *Graph* (the default when a lockfile
  records relations) draws package → package arrows from the lockfile, laid
  out by depth (longest path, so every arrow runs left to right); click a
  package for its version, scope and the lockfile line of each edge. *Table*
  lists the same packages. The **AI usage map** tab shows the AI components.
  The privilege-drift and MCP demos draw a *Dependency map* that follows the
  Baseline / Candidate / Fixed toggle; the Compare demo draws the candidate's.
- Demo: the bundled sample (`tests/fixtures/impact-demo`) ships a real
  `uv.lock` (generated with `uv lock` for its three pins), so *Try the bundled
  sample* shows a 44-package graph with 77 lockfile-cited edges offline.
  `impact-demo-baseline` carries the same `uv.lock`, so the same-file drift demo
  still compares identical components (`test_same_components_can_gain_a_new_critical_blast_radius`).

## Source

- `src/aibom/collectors/dependencies.py`: manifests (11 ecosystems), AI flag
- `src/aibom/collectors/lockfiles.py`: lockfile packages and `depends_on` edges
- `src/aibom/linking.py`: `model → service`, `component → SDK package`, and MCP
  `tool → server`, `config/prompt → server`
- `src/aibom/tools.py` (`link_tools`): `prompt -invokes-> tool`, citing the agent constructor
- `src/aibom/collectors/repo.py` (`_link_intra_file`): prompt→model and agent co-location
- `src/aibom/graph.py`: projection into nodes and edges, plus visibility rules
- `src/aibom/export/cyclonedx.py` (`_dependencies`), `src/aibom/report/html.py` (`_graph_section`)
- `web/index.html`: `renderGraph`, `edgeStyle`, `connectionsHtml`

## Depends on

Scan pipeline (entities must exist before they can be linked). The policy
view: `production_view` removes test, example, and docs entities before the
graph is built.

## Normal paths

- A lockfile with a graph (npm v1/v3, poetry, uv, Cargo, composer, Gemfile)
  produces `package -depends_on-> package` edges that cite the declaring line.
- A model whose provider service was found yields `model -served_by-> service`.
- A model, service, or dataset in a file that imports a same-provider AI
  package yields `-depends_on-> package`, citing the import line.
- A plain package directly required by an AI package is drawn (one hop).
- An MCP tool registered in a server file is `served_by` that server; a config
  or agent file naming the server script `invokes` it.

## Error paths

- Malformed lockfile JSON or TOML: the file is skipped and the scan still
  succeeds (`OSError`/`ValueError` are swallowed per file).
- A requirement on something the lock did not resolve (`php`, an uninstalled
  extra, a package from another lockfile): no edge.
- A file that is unreadable or larger than 1 MB is not linked. The linker
  never reads outside the scan root.

## Boundaries

- Empty repository: `nodes == []`, `edges == []`, and the UI shows "No
  components to graph."
- `Pipfile.lock` and hashed `requirements.txt` flatten the graph, so they
  produce packages but no edges.
- PyPI names are compared after PEP 503 normalization (`PyYAML` == `pyyaml`).
- Cargo dependency strings with versions (`"serde 1.0.1 (registry+…)"`).
- A file importing two providers (`openai` and `transformers`) links each
  model only to its own provider's SDK.
- Large repositories: thousands of edges. `add_relationship` is O(1) per edge.

## How to verify

| Check | Proves |
|---|---|
| `pytest tests/test_dependency_edges.py tests/test_linking.py tests/test_graph.py tests/test_lockfiles.py tests/test_dependencies.py` | edge rules, negatives, graph visibility, report arrows |
| smoke `scan` of `locked-ai-app` with `-c` | CycloneDX `dependsOn` is non-empty for locked packages |
| `python scripts/verify_ui.py --fixture vulnerable-ai-app` | the real browser draws directed edges, a legend, and the Connections panel, with no console errors |
| `python scripts/verify_ui.py --fixture demos` | the sample, privilege-drift, MCP and Compare demos each draw a non-empty map whose edges all carry evidence |

## Expected results

- `locked-ai-app`: `openai → form-data-encoder`, `transformers → tokenizers`,
  `anthropic → httpx`, `ruby-openai → faraday`.
- `vulnerable-ai-app`: `gpt-4o-mini -served_by-> openai` and `-depends_on->
  openai (package)` citing `app.py:8`. No `gpt-4o-mini → transformers`.
- UI: `edges == edges_with_arrow`, a non-empty legend, and no console errors.
- Demos: sample 5 nodes / 5 edges, privilege drift 7 / 6, MCP 8 / 6 (only the
  unused `openai-agents` is unlinked), Compare 5 / 5.

## Evidence

pytest output and exit code. The smoke `bom.json` with its `dependencies`
section. `verify-out/<run>/ui-<fixture>.png` and `.json` (node and edge
counts, the panel text, and console errors).

## Known gaps / what usually breaks

- uv.lock lists the scanned project itself as a `[[package]]`
  (`source = { virtual = "." }`); it used to appear as its own transitive
  dependency. `_is_uv_project` skips it, held by
  `test_the_uv_project_itself_is_not_a_dependency`.
- `pnpm-lock.yaml` and `yarn.lock` are not parsed (no package nodes or edges
  for those projects).
- PHP and Ruby source imports are not linked (`openai-php/client`,
  `ruby-openai` stay unlinked to models).
- Model IDs chosen at run time (gateway catalogs) cannot be linked.
- An MCP server started by a built artefact (`dist/server.js`) or a package
  name rather than its source path is not linked to its launcher.
- A new edge rule that forgets `source_evidence`: the demo UI check and
  `test_prompt_tool_bindings_cite_the_agent_constructor` fail.
- The service `openai` and the package `openai` share a label. Read the type
  shown in the panel.

```json verify
{
  "id": "dependency-map",
  "paths": [
    "src/aibom/collectors/dependencies.py",
    "src/aibom/collectors/lockfiles.py",
    "src/aibom/linking.py",
    "src/aibom/tools.py",
    "src/aibom/graph.py",
    "src/aibom/inventory.py",
    "src/aibom/models/entities.py",
    "src/aibom/export/cyclonedx.py",
    "src/aibom/report/html.py",
    "web/index.html",
    "web/app.js",
    "tests/fixtures/locked-ai-app/*",
    "tests/fixtures/impact-demo/*"
  ],
  "tests": [
    "tests/test_dependency_edges.py",
    "tests/test_linking.py",
    "tests/test_graph.py",
    "tests/test_lockfiles.py",
    "tests/test_dependencies.py"
  ],
  "smoke": [
    {
      "name": "scan locked-ai-app to CycloneDX",
      "cmd": ["{py}", "-m", "aibom.cli", "scan", "tests/fixtures/locked-ai-app", "-q",
              "-c", "{out}/locked-bom.json"],
      "expect_exit": 0,
      "expect_files": ["{out}/locked-bom.json"]
    },
    {
      "name": "CycloneDX carries lockfile dependsOn edges",
      "cmd": ["{py}", "-c",
              "import json,sys; d=json.load(open(sys.argv[1])); n=sum(len(x['dependsOn']) for x in d['dependencies'][1:]); print('component dependsOn edges:', n); sys.exit(0 if n else 1)",
              "{out}/locked-bom.json"],
      "expect_exit": 0,
      "expect_output": "component dependsOn edges:"
    }
  ],
  "ui": ["vulnerable-ai-app", "locked-ai-app", "demos"],
  "manual": []
}
```
