# CISA 2026 SBOM Minimum Elements — gap analysis and implementation

On **29 July 2026** CISA, NSA, FBI and international partners published
[*2026 Minimum Elements for a Software Bill of Materials (SBOM)*][cisa], which
**replaces the 2021 NTIA minimum elements**. Two things make it directly
relevant to this project:

1. the baseline now explicitly covers **AI software** (and SaaS, and open
   source) — an AIBOM is not exempt from being a conforming SBOM;
2. the required data fields grew from 7 to ~17, and *depth* (top-level
   dependencies) became **coverage** (all components, transitively).

This document records what AIBOM Inspector emitted **before** the update, what
the 2026 baseline asks for, and what changed in response.

> **Sourcing caveat.** `cisa.gov` and `media.defense.gov` are blocked by the
> egress policy of the environment this analysis was written in, so the field
> names and groupings below were reconstructed from CISA's resource page and
> public reporting rather than read out of the PDF. Verify them against
> [Appendix A of the publication][cisa] before quoting this table in an audit.
> The table lives in one place in code —
> `src/aibom/compliance/minimum_elements.py`, one `ElementSpec` per element — so
> a correction is a one-line edit that the evaluator, the CLI, the HTML report
> and the web UI all pick up.

[cisa]: https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom

## 1. What changed against the 2021 baseline

| Area | 2021 (NTIA) | 2026 (CISA) |
|---|---|---|
| Data fields | 7 | ~17 (10 new, 4 renamed/clarified) |
| Component hash | *recommended* | **required**, with the algorithm as its own field |
| Component license | not required | **required** |
| SBOM document metadata | author + timestamp | author, **author signature**, **tool name**, **data format name + version**, **SBOM version**, **generation context** |
| Depth / coverage | top-level dependencies | **all components, transitively, no depth limit** |
| Known unknowns | "known unknowns" | must **distinguish unknown from withheld**, explicitly |
| Formats | SPDX, CycloneDX, SWID | SPDX, CycloneDX (**SWID dropped**) |
| Scope | software | software **including AI systems, SaaS, open source** |

## 2. Where AIBOM Inspector stood, and what it emits now

Status before this change is against the CycloneDX 1.6 document the exporter
produced previously.

| Element | Origin | Before | Now | How |
|---|---|---|---|---|
| SBOM Author | 2026 renamed | ❌ absent | ✅ / declared | `--sbom-author`, `sbom_author` in `aibom.toml`; declared unknown when unset |
| SBOM Author Signature | 2026 new | ❌ absent | ⚪ declared | The tool emits an **unsigned** document and says so; sign out of band (cosign, `cyclonedx-cli sign`) |
| SBOM Timestamp | 2021 | ✅ | ✅ | `metadata.timestamp` |
| SBOM Version | 2026 new | ✅ implicit | ✅ | `version` + deterministic `serialNumber` |
| SBOM Data Format (name) | 2026 new | ✅ | ✅ | `bomFormat` |
| SBOM Data Format (version) | 2026 new | ✅ | ✅ | `specVersion` |
| SBOM Tool Name | 2026 new | ✅ | ✅ | `metadata.tools.components[]` |
| SBOM Generation Context | 2026 new | ❌ absent | ✅ | `metadata.lifecycles[].phase`, default `pre-build`, `--sbom-lifecycle` to override |
| Component Name | 2021 | ✅ | ✅ | `components[].name` |
| Component Version | 2026 renamed | ⚠️ packages only | ✅ / declared | models now carry their pinned revision; lockfiles resolve ranges to exact pins |
| Component Producer | 2026 renamed | ⚠️ models/datasets only | ⚠️ / declared | model-hub author, lockfile registry, or the configured `--sbom-supplier` for first-party components |
| Software Identifier | 2026 clarified | ⚠️ packages only | ⚠️ / declared | package purls plus `pkg:huggingface/…` for models and datasets, `pkg:github/owner/repo` for the scan target |
| **Component Hash** | **2026 new** | ❌ absent | ⚠️ / declared | lockfile digests (npm SRI decoded to hex, poetry/uv/Pipfile/Cargo/composer, hash-pinned requirements) and the SHA-256 of every prompt |
| **Component Hash Algorithm** | **2026 new** | ❌ absent | ⚠️ / declared | emitted with every digest; a digest whose length does not match a known algorithm is dropped rather than mislabeled |
| **Component License** | **2026 new** | ⚠️ models/datasets only | ⚠️ / declared | plus npm and composer lockfile licenses |
| Component Dependency Relationship | 2026 clarified | ⚠️ non-empty edges only | ✅ | every component gets a `dependencies` entry, including leaves with `dependsOn: []`, rooted at the primary component |
| Known Unknowns | 2026 clarified | ❌ absent | ✅ | `cisa:known-unknown` property naming the field **and the reason** |
| Coverage | 2026 (was depth) | ❌ top level only | ✅ with lockfile / ⚠️ without | `LockfileCollector` resolves the transitive graph; the achieved coverage is declared in `cisa:coverage` |
| Automation Support | 2026 clarified | ✅ | ✅ | CycloneDX 1.6 JSON |

⚪ = not obtainable by this tool, declared. ⚠️ = obtainable for some components,
declared for the rest.

**A declared unknown is conformance, not failure.** The 2026 baseline asks
authors to distinguish data they lack from data they withhold, so the tool
never leaves a required field silently blank: it states which field is missing
and why ("static analysis never downloads weights, so no artifact digest
exists"). A *silent* gap is what the conformance checker fails on.

## 3. What was implemented

### Lockfile resolution (`src/aibom/collectors/lockfiles.py`)

A manifest states what a project asks for; a lockfile states what it gets. This
is the only static source of three 2026 elements at once — Component Hash,
Component Hash Algorithm and transitive Coverage — plus exact Component
Versions and the supplying registry as Component Producer.

Supported: `package-lock.json` (v1 and v2/v3), `Pipfile.lock`, `poetry.lock`,
`uv.lock`, hash-pinned `requirements*.txt`, `Cargo.lock`, `composer.lock`,
`Gemfile.lock`. npm Subresource-Integrity digests are decoded from base64 to
hex so CycloneDX can carry them; where a package ships several artifacts the
sdist digest is preferred and the artifact filename is recorded alongside it.

Lockfile entries merge into the components the manifest collector already
found, so a package declared as a range and locked to a version stays **one**
component that now carries its digest. Turn it off with `--no-lockfiles`.

### Document-level elements (`src/aibom/export/cyclonedx.py`)

`metadata.lifecycles`, `metadata.authors` / `manufacturer`,
`metadata.supplier`, and a **primary component** (`metadata.component`) that
roots the dependency graph, so "all components of *what*" has an answer.

### Conformance checking (`src/aibom/compliance/minimum_elements.py`)

Scores a CycloneDX **document**, not an inventory — so it works on any
CycloneDX SBOM, not only the ones this tool produces:

```bash
# check the SBOM this scan produces
aibom scan . --minimum-elements elements.json

# check someone else's CycloneDX SBOM, and gate CI on silent gaps
aibom conformance third-party-bom.json --fail-on-missing

# supply the document-level facts a scanner cannot know
aibom scan . --sbom-author "Acme Security" \
             --sbom-supplier "Acme Inc" \
             --sbom-lifecycle build \
             --cyclonedx aibom.json
```

Or pin them per repository in `aibom.toml`:

```toml
sbom_author = "Acme Security"
sbom_supplier = "Acme Inc"
sbom_lifecycle = "pre-build"
lockfiles = true
```

The report is also written into the HTML report, the web UI, and the
`minimum_elements` key of the `/api/scan` payload.

## 4. Known limitations

- **No signing.** The tool emits an unsigned document. Implementing JSF
  signing requires RFC 8785 canonicalization; a subtly wrong implementation is
  worse than an honest declaration, so the gap is declared instead.
- **Coverage depends on a committed lockfile.** Without one, only declared
  dependencies are listed and `cisa:coverage` says
  `declared-dependencies-only`. The tool never resolves dependencies over the
  network — that would mean trusting a registry to describe the build.
- **No `yarn.lock` / `pnpm-lock.yaml` / `go.sum`.** The first two need a YAML
  parser this project does not depend on; `go.sum` records module-tree hashes
  rather than artifact digests, which would be misleading in a `hashes` field.
- **Model and dataset digests are never collected.** Static analysis does not
  download weights. A post-build SBOM produced where the artifacts actually
  live is the right place for those digests.
- **Package licenses come only from lockfiles that record them** (npm,
  composer). PyPI, crates.io and RubyGems licenses would require registry
  lookups.
- **SPDX is not evaluated.** The checker reads CycloneDX; an SPDX document is
  rejected with a clear message rather than silently mis-scored.
