"use strict";
const SEV_COLOR = { critical: "#a7333f", high: "#b9582f", medium: "#9b701c", low: "#39745b", info: "#64716a" };
const EXAMPLE_REPO = "https://github.com/openai/openai-quickstart-python";
const $ = (id) => document.getElementById(id);

// The backend serves this page, so the API lives at this page's origin.
// Static hosting (e.g. GitHub Pages) can point elsewhere via ?api=https://host.
const API_BASE_KEY = "aibom.apiBase";

// localStorage throws in some privacy modes; a saved backend is a convenience,
// never a requirement.
function storedApiBase() {
  try {
    return localStorage.getItem(API_BASE_KEY) || "";
  } catch (_) {
    return "";
  }
}

function storeApiBase(value) {
  try {
    if (value) localStorage.setItem(API_BASE_KEY, value);
    else localStorage.removeItem(API_BASE_KEY);
  } catch (_) { /* nothing to do: the address still applies to this page load */ }
}

let apiOverride = new URLSearchParams(location.search).get("api") || storedApiBase();

function apiBase() {
  if (apiOverride) return apiOverride.replace(/\/$/, "");
  return /^https?:$/.test(location.protocol) && location.host
    ? location.origin : "http://localhost:8000";
}

// Raised when the address we are talking to is not an AIBOM Inspector backend
// (a static host answering with HTML, or nothing listening at all). The UI
// reacts by asking for a backend address instead of printing "HTTP 404".
class BackendUnavailable extends Error {}

let lastRequest = null;
let lastResult = null;
let scannerVersion = "";

// Escapes for text *and* quoted attribute values. Scanned repositories control
// names and file paths (a file may be called `a" onfocus="...`), and many of
// them land in attributes, so quotes must be escaped too.
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function esc(s) {
  return (s == null ? "" : String(s)).replace(/[&<>"']/g, (c) => ESC[c]);
}
function evLoc(ev) {
  if (!ev) return "";
  return ev.line_start === ev.line_end ? `${ev.file}:${ev.line_start}`
    : `${ev.file}:${ev.line_start}-${ev.line_end}`;
}

function usageLabel(usage) {
  if (!usage) return "—";
  const states = ["declared", "imported", "instantiated", "invoked"]
    .filter(name => usage[name]);
  states.push("reachable:" + (usage.reachable || "unknown"));
  return states.join(" → ");
}
function setStatus(msg, isErr) {
  const s = $("status"); s.textContent = msg; s.className = isErr ? "err" : "";
}

function repoLabel(repo) {
  // "built-in://impact-demo" is a bundled fixture, not somebody's repository.
  if (typeof repo === "string" && repo.startsWith("built-in://")) {
    return "Bundled sample app (FastAPI + OpenAI Agents fixture)";
  }
  try {
    const url = new URL(repo);
    const parts = url.pathname.replace(/\.git$/, "").split("/").filter(Boolean);
    return parts.length >= 2 ? `${parts[parts.length - 2]} / ${parts[parts.length - 1]}`
      : (parts[0] || url.hostname);
  } catch (_) {
    return repo;
  }
}

function isRepositoryUrl(value) {
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "http:") && Boolean(url.hostname);
  } catch (_) {
    return false;
  }
}

function loadExample() {
  const input = $("repo");
  input.value = EXAMPLE_REPO;
  input.removeAttribute("aria-invalid");
  setStatus("Example URL added. Start the analysis when you are ready.", false);
  input.focus();
}

const ACTION_BUTTONS = ["scan", "runDemo"];
const SCAN_EXPORTS = ["download", "downloadCdx", "downloadSarif", "downloadInventory"];

function setExportsEnabled(enabled) {
  for (const id of SCAN_EXPORTS) $(id).disabled = !enabled;
}

function showResultBody() {
  $("resultsArea").hidden = false;
  $("scanResult").hidden = false;
  for (const id of SCAN_EXPORTS) $(id).hidden = false;
  $("results").hidden = false;
}

// One busy/error/scroll path for every analysis the panel can start. The
// previous result stays on screen until a new one has arrived, and a failed or
// cancelled run never wipes it.
let activeScan = null;

// Stage ids sent by /api/scan/stream, in the order the backend runs them.
const STAGES = {
  clone: "Fetch the repository",
  collect: "Read files and manifests",
  lockfiles: "Resolve lockfiles",
  link: "Link components",
  resolve: "Fetch Hugging Face metadata",
  risk: "Evaluate rules",
  vulns: "Look up known vulnerabilities (OSV)",
  agents: "Analyze agent paths",
  report: "Build the result",
};

// Each reported stage becomes a step; earlier ones are marked done.
function showStage(id, seen) {
  seen.push(id);
  const label = (s) => STAGES[s] || s;
  $("progressStage").textContent = label(id) + "…";
  const list = $("progressSteps");
  list.hidden = false;
  list.innerHTML = seen.map((s, i) => {
    const done = i < seen.length - 1;
    return `<li class="${done ? "done" : "current"}"${done ? "" : ' aria-current="step"'}>`
      + `${done ? "✓ " : ""}${esc(label(s))}</li>`;
  }).join("");
}

async function runAnalysis(button, busyLabel, spec) {
  const original = button.textContent;
  ACTION_BUTTONS.forEach((id) => { $(id).disabled = true; });
  button.textContent = busyLabel;
  $("scanSection").setAttribute("aria-busy", "true");
  const hadResult = !$("results").hidden;
  const stale = $("staleNote");
  stale.hidden = !hadResult;
  stale.textContent = "Showing the previous result while the new analysis runs.";
  setStatus(spec.status, false);
  const controller = new AbortController();
  activeScan = controller;
  const started = Date.now();
  $("progressStage").textContent = spec.progress;
  const seen = [];
  const progress = { streamed: false, stage: (id) => showStage(id, seen) };
  $("progressSteps").hidden = true;
  $("progressSteps").innerHTML = "";
  const tick = () => {
    $("progressElapsed").textContent = Math.floor((Date.now() - started) / 1000) + " s elapsed";
  };
  tick();
  $("progress").hidden = false;
  const timer = setInterval(tick, 1000);
  try {
    const data = await spec.request(controller.signal, progress);
    lastRequest = spec.requestInfo;
    spec.render(data);
    stale.hidden = true;
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? "auto" : "smooth";
    $("results").scrollIntoView({ behavior, block: "start" });
    $("results").focus({ preventScroll: true });
  } catch (e) {
    const keep = hadResult ? " The previous result is still shown below." : "";
    if (e.name === "AbortError") {
      setStatus((progress.streamed
        ? "Cancelled. The backend stops the analysis before its next step."
        : "Cancelled. The page stopped waiting; the backend may still finish and "
          + "discard the work.") + keep, false);
    } else {
      const missing = e instanceof BackendUnavailable;
      setStatus(spec.failure + ": " + e.message + keep, true);
      if (missing) showApiEndpointField();
    }
    stale.textContent = "Showing the previous result: the latest analysis did not complete.";
  } finally {
    clearInterval(timer);
    $("progress").hidden = true;
    $("progressSteps").hidden = true;
    activeScan = null;
    ACTION_BUTTONS.forEach((id) => { $(id).disabled = false; });
    button.textContent = original;
    $("scanSection").removeAttribute("aria-busy");
  }
}

function runDemo() {
  showView("analyze");
  const info = { repo_url: "built-in://impact-demo", resolve: false, api: apiBase(), demo: true };
  return runAnalysis($("runDemo"), "Scanning the sample…", {
    status: "Scanning the bundled sample app (offline)…",
    progress: "Static analysis of the bundled sample (no clone, no network)",
    failure: "The bundled sample scan could not be completed",
    requestInfo: info,
    request: (signal) => postJson(apiBase() + "/api/demo", null, signal),
    render: (data) => {
      renderScan(data);
      setStatus("Sample scanned. Start with the findings at the top of the result.", false);
    },
  });
}

// Proof-of-work line: what the scan actually read, and how long each step took.
function statsLine(repo, st) {
  if (!st) return "Scanned " + repo + ".";
  const kb = st.bytes_scanned >= 1048576
    ? (st.bytes_scanned / 1048576).toFixed(1) + " MB"
    : Math.max(1, Math.round(st.bytes_scanned / 1024)) + " KB";
  let msg = `Read ${st.files_scanned} files (${kb})`;
  if (st.manifests_parsed && st.manifests_parsed.length) {
    msg += ` · manifests: ${st.manifests_parsed.slice(0, 4).join(", ")}`
      + (st.manifests_parsed.length > 4 ? ` +${st.manifests_parsed.length - 4}` : "");
  }
  const parts = [];
  if (st.clone_ms != null) parts.push(`clone ${(st.clone_ms / 1000).toFixed(1)}s`);
  if (st.duration_ms != null) parts.push(`scan ${(st.duration_ms / 1000).toFixed(1)}s`);
  if (parts.length) msg += ` · ${parts.join(" + ")}`;
  return msg;
}

function scan() {
  const repoInput = $("repo");
  const repo = repoInput.value.trim();
  const ref = $("repoRef").value.trim();
  if (!isRepositoryUrl(repo)) {
    repoInput.setAttribute("aria-invalid", "true");
    setStatus(repo
      ? "Enter a complete repository URL, including https://."
      : "Enter a repository URL to start the analysis.", true);
    repoInput.focus();
    return Promise.resolve();
  }
  repoInput.removeAttribute("aria-invalid");
  const info = { repo_url: repo, ref: ref || null, resolve: true, api: apiBase() };
  return runAnalysis($("scan"), "Analyzing…", {
    status: "Analyzing " + repoLabel(repo) + (ref ? " at " + ref : "") + "…",
    progress: "Waiting for the backend",
    failure: "The analysis could not be completed",
    requestInfo: info,
    request: async (signal, progress) => {
      const body = { repo_url: repo, ref: ref || null, resolve: true };
      const streamed = await postStream(apiBase() + "/api/scan/stream", body, signal, progress);
      if (streamed !== NO_STREAM) return streamed;
      // An older backend without the stream endpoint: one request, no stages.
      $("progressStage").textContent = "This backend does not report its steps. It clones "
        + "the repository, reads supported files, looks up advisories and builds the report; "
        + "step timings are shown when it finishes.";
      return postJson(apiBase() + "/api/scan", body, signal);
    },
    render: (data) => {
      renderScan(data);
      setStatus("Analysis complete. " + statsLine(repo, data.stats), false);
    },
  });
}

function renderScan(d) {
  lastResult = d;
  showResultBody();
  setExportsEnabled(true);
  const repo = d.repo_url || (lastRequest && lastRequest.repo_url);
  const demo = typeof repo === "string" && repo.startsWith("built-in://");
  $("resultOverline").textContent = demo ? "Bundled sample · analysis result" : "Analysis result";
  $("resultRepoName").textContent = repoLabel(repo);
  $("resultMeta").textContent = statsLine(repo, d.stats);
  $("resultProvenance").innerHTML = provenanceHtml(d.metadata || {});
  for (const id of ["findingSearch", "inventorySearch", "depsSearch"]) $(id).value = "";
  for (const id of ["severityFilter", "typeFilter", "reachFilter", "depsFilter"]) $(id).value = "all";

  renderSummary(d);
  renderScore(d);
  renderFindings(d);
  renderDependencies(d.dependencies);
  renderGraph(d.graph || { nodes: [], edges: [] }, d.findings || []);
  renderGraphLead(d);
  renderInventory(d);
  renderMinimumElements(d.minimum_elements, d);
  renderAgentSecurity(d.agent_security, d.inventory);
  // Lead with what needs doing: findings when there are any, else the packages.
  selectTab((d.findings || []).length ? "findings" : "deps");
  filterFindings();
  filterInventory();
  filterDeps();
}

function provenanceHtml(meta) {
  const parts = [];
  if (meta.ref) parts.push(`ref <code>${esc(meta.ref)}</code>`);
  if (meta.commit) {
    const tree = meta.source_url_template
      ? meta.source_url_template.replace("{path}", "").replace(/#.*$/, "") : null;
    const short = esc(meta.commit.slice(0, 12));
    parts.push(tree
      ? `commit <a href="${esc(tree)}" target="_blank" rel="noopener noreferrer"><code>${short}</code></a>`
      : `commit <code>${short}</code>`);
  } else if (!String(meta.target || "").startsWith("built-in://")) {
    parts.push("commit not recorded");
  }
  if (meta.tool_version) parts.push(`aibom ${esc(meta.tool_version)}`);
  if (meta.created_at) {
    const when = new Date(meta.created_at);
    parts.push("analyzed " + esc(isNaN(when) ? meta.created_at
      : when.toISOString().replace("T", " ").slice(0, 16) + " UTC"));
  }
  return parts.join(" · ");
}

// A file:line that opens the analyzed commit on the forge, when one is known.
function srcLink(ev) {
  if (!ev) return "";
  const text = evLoc(ev);
  const meta = (lastResult && lastResult.metadata) || {};
  const template = meta.source_url_template;
  if (!template || !ev.file || ev.file.startsWith("<")) return `<code>${esc(text)}</code>`;
  const href = template.replace("{path}", ev.file.split("/").map(encodeURIComponent).join("/"))
    .replace("{line}", String(ev.line_start || 1));
  return `<a class="src" href="${esc(href)}" target="_blank" rel="noopener noreferrer">`
    + `<code>${esc(text)}</code></a>`;
}

const ELEMENT_STATUS = {
  satisfied: { label: "filled", color: "#2e8b57" },
  partial: { label: "partly filled", color: "#b8860b" },
  declared_unknown: { label: "declared unknown", color: "#5a6a82" },
  missing: { label: "missing", color: "#b3123b" },
};
const ELEMENT_ORIGIN = {
  carried_over: "2021", updated_2026: "2026 updated", new_2026: "2026 new",
};

// CISA 2026 SBOM minimum elements: field coverage, declared unknowns and the
// machine check are three different statements, shown apart.
function renderMinimumElements(report, d) {
  const body = document.querySelector("#elements tbody");
  if (!body) return;
  if (!report || !report.elements) {
    $("elementsSummary").innerHTML = "";
    body.innerHTML = `<tr><td colspan="5" class="empty">No SBOM field report was returned.</td></tr>`;
    return;
  }
  const s = report.summary || {};
  const tile = (n, label, cls, note) => `<div class="sum-tile ${cls}"><strong>${n}</strong>`
    + `<span>${esc(label)}</span>${note ? `<small>${esc(note)}</small>` : ""}</div>`;
  const inventory = ((d && d.inventory && d.inventory.entities) || []).length;
  const rows = Math.max(0, ...report.elements.map(el => el.applicable || 0));
  const denominator = rows === inventory + 1
    ? ` Component counts cover ${rows} components: the ${inventory} inventory entries plus the `
      + "scanned repository itself (the SBOM's primary component)."
    : rows ? ` Component counts cover ${rows} components.` : "";
  $("elementsSummary").innerHTML = tile(s.satisfied, "filled", "is-ok", `of ${s.total} fields`)
    + tile(s.partial, "partly filled", s.partial ? "is-warn" : "", "some components only")
    + tile(s.declared_unknown, "declared unknown", "", "stated as unknown in the file")
    + tile(s.missing, "missing", s.missing ? "is-bad" : "", "empty without a declaration")
    + `<p class="elements-note"><strong>Machine check: ${report.conformant ? "passed" : "failed"}.`
    + `</strong> ${report.conformant
      ? "Every field is either filled or explicitly declared unknown in the generated file, "
        + "which is what the 2026 minimum elements require of a generator. That is not "
        + `completeness: ${s.satisfied} of ${s.total} fields are fully filled.`
      : `${s.missing} field(s) are empty without an explicit declaration.`}`
    + `${esc(denominator)}</p>`;
  body.innerHTML = report.elements.map(el => {
    const status = ELEMENT_STATUS[el.status] || ELEMENT_STATUS.missing;
    let coverage = el.applicable > 1 ? `${el.present}/${el.applicable}`
      : (el.present ? "yes" : "no");
    if (el.declared_unknown) coverage += ` <span class="muted">+${el.declared_unknown} declared unknown</span>`;
    const detail = el.status === "satisfied" ? el.description : el.remediation;
    const gaps = (el.undeclared_gaps || []).length
      ? `<br><span class="muted">undeclared: ${esc(el.undeclared_gaps.slice(0, 5).join(", "))}</span>`
      : "";
    return `<tr><td><span class="sev" style="color:${status.color}">`
      + `${esc(status.label)}</span></td>`
      + `<td>${esc(el.name)}<br><span class="muted">${esc(detail)}</span>${gaps}</td>`
      + `<td>${esc(ELEMENT_ORIGIN[el.origin] || el.origin)}</td>`
      + `<td>${coverage}</td><td><code>${esc(el.cyclonedx_path)}</code></td></tr>`;
  }).join("");
}

function renderScore(d) {
  const sc = d.score;
  const scope = d.analysis_scope || {};
  if (!sc || !scope.production_ai_components) {
    $("scoreBrief").textContent = "· not scored: no production AI components";
    $("scoreNum").textContent = "—";
    $("scoreNum").style.color = "";
    $("scoreGrade").textContent = "not scored";
    $("cats").innerHTML = "<span class='muted'>Nothing to score in production code.</span>";
    $("chips").innerHTML = "";
    return;
  }
  const gradeColor = { A: "#2e8b57", B: "#6a9c3a", C: "#b8860b", D: "#d64500", F: "#b3123b" }[sc.grade] || "";
  $("scoreBrief").textContent = `· ${sc.overall} / 100, grade ${sc.grade}`;
  $("scoreNum").textContent = sc.overall;
  $("scoreNum").style.color = gradeColor;
  $("scoreGrade").textContent = `/ 100 · grade ${sc.grade}`;
  $("cats").innerHTML = sc.categories.map(c => {
    const col = c.score >= 75 ? "#2e8b57" : c.score >= 50 ? "#b8860b" : "#b3123b";
    const category = c.category.charAt(0).toUpperCase() + c.category.slice(1);
    return `<div class="cat"><div class="r"><span>${esc(category)}</span>`
      + `<span>${c.score} · ${c.finding_count} finding(s)</span></div>`
      + `<div class="bar"><span style="width:${c.score}%;background:${col}"></span></div></div>`;
  }).join("");
  $("chips").innerHTML = ["critical", "high", "medium", "low", "info"].map(s => {
    const n = sc.severity_counts[s] || 0;
    return n ? `<span class="chip" data-severity="${s}">${n} ${s}</span>` : "";
  }).join("");
}

function advisoryHtml(f) {
  const a = f.advisory;
  const links = (a.urls || []).map(u => `<a href="${esc(u)}" target="_blank" `
    + `rel="noopener noreferrer">${esc(u.split("/").pop())}</a>`).join(", ");
  const linked = new Set((a.urls || []).map(u => u.split("/").pop()));
  const aliases = (a.ids || []).filter(i => !linked.has(i));
  const rated = (a.severity_sources || []).map(s => `${esc(s.advisory_id)}: `
    + `${esc(s.severity || "unrated")} <span class="muted">(${esc(s.source)}`
    + `${s.score != null ? " " + esc(s.score) : ""})</span>`).join(" · ");
  const where = (f.source_evidence || []).slice(0, 2).map(srcLink).join(", ");
  return `<li class="advisory" data-severity="${esc(f.severity)}">${sevTag(f.severity)} `
    + `<strong>${links}</strong>${aliases.length ? ` <span class="muted">also ${esc(aliases.join(", "))}</span>` : ""}`
    + `<p>${esc(f.description)}</p><dl class="adv-facts">`
    + `<dt>Installed</dt><dd><code>${esc(a.installed_version)}</code> (${esc(a.match)})</dd>`
    + `<dt>Affected</dt><dd>${esc((a.affected_ranges || []).join("; ") || "not stated by the advisory")}</dd>`
    + `<dt>Fixed in</dt><dd>${a.fixed_version ? `<code>${esc(a.fixed_version)}</code>`
      : "no fixed release recorded"}</dd>`
    + `<dt>Severity</dt><dd>${esc(a.severity_rule)}: ${rated}</dd>`
    + (a.modified ? `<dt>Updated</dt><dd>${esc(a.modified)}</dd>` : "")
    + (where ? `<dt>Declared at</dt><dd>${where}</dd>` : "")
    + `</dl></li>`;
}

function renderFindings(d) {
  const findings = d.findings || [];
  const byEntity = {};
  for (const f of findings) {
    if (f.advisory) (byEntity[f.entity_id] = byEntity[f.entity_id] || []).push(f);
  }
  const groups = d.vulnerable_packages || [];
  $("vulnPackages").innerHTML = groups.length
    ? `<h3 class="subhead">Vulnerable packages (${groups.length})</h3>` + groups.map(g => {
      const items = (byEntity[g.entity_id] || []).slice().sort((a, b) =>
        (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
      const fixed = items.length - g.without_known_fix;
      const upgrade = g.recommended_version
        ? `Upgrade to <strong><code>${esc(g.recommended_version)}</code></strong> or later: `
          + `clears ${fixed === items.length ? "all " : ""}${fixed} of ${items.length} advisories `
          + `with a known fixed release. Check compatibility before upgrading.`
        : "No fixed release is recorded for these advisories; see each advisory.";
      const none = g.without_known_fix && g.recommended_version
        ? ` ${g.without_known_fix} advisory(ies) have no fixed release recorded.` : "";
      return `<article class="vuln-card" data-row="true" `
        + `data-severities="${esc([...new Set(items.map(i => i.severity))].join(" "))}">`
        + `<header>${sevTag(g.severity)} <strong>${esc(g.package)}</strong> `
        + `<code>${esc(g.installed_version || "")}</code> <span class="muted">`
        + `${items.length} advisor${items.length === 1 ? "y" : "ies"}</span></header>`
        + `<p class="upgrade">${upgrade}${esc(none)}</p>`
        + `<details><summary>Advisory details</summary><ul class="advisories">`
        + items.map(advisoryHtml).join("") + `</ul></details></article>`;
    }).join("")
    : "";
  const lookup = (d.stats && d.stats.vuln_lookup) || {};
  if (!groups.length && lookup.status && lookup.status !== "complete") {
    $("vulnPackages").innerHTML = `<p class="notice">Known-vulnerability lookup: `
      + `${esc(lookup.status.replace("_", " "))}. See Analysis limits above.</p>`;
  }

  const code = findings.filter(f => !f.advisory);
  const fb = $("findings").querySelector("tbody");
  $("findingCount").textContent = findings.length ? "(" + findings.length + ")" : "";
  $("codeFindingsTitle").hidden = !groups.length;
  if (!code.length) {
    const scope = d.analysis_scope || {};
    const why = !scope.production_ai_components
      ? "No AI component was found in production code, so the AI rules had nothing to check."
      : `The ${scope.production_ai_components} AI component(s) in production code matched none `
        + "of the rules. This covers the rules listed in the README, not every possible risk.";
    fb.innerHTML = `<tr><td colspan="4" class="empty">No code or configuration findings. `
      + `${esc(why)}</td></tr>`;
  } else {
    fb.innerHTML = code.slice().sort((a, b) =>
      (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)).map(f => {
      const locs = (f.source_evidence || []).slice(0, 3).map(srcLink).join("<br>") || "—";
      return `<tr data-row="true" data-severity="${esc(f.severity)}">`
        + `<td><span class="sev" data-severity="${esc(f.severity)}">${esc(f.severity)}</span></td>`
        + `<td><code>${esc(f.rule_id)}</code></td>`
        + `<td><strong class="finding-title">${esc(f.title)}</strong>${findingThreeParts(f)}</td>`
        + `<td>${esc(f.entity_name || "—")}<br>${locs}</td></tr>`;
    }).join("");
  }
}

function renderDependencies(dep) {
  const body = $("deps").querySelector("tbody");
  if (!dep) {
    $("depsLead").textContent = "This backend did not return a dependency table.";
    body.innerHTML = "";
    return;
  }
  const s = dep.summary;
  // The graph is drawn when first shown; a new result starts it afresh.
  depsData = dep;
  $("depsGraph").innerHTML = "";
  const graphButton = document.querySelector('[data-deps-view="graph"]');
  graphButton.disabled = !s.edges;
  graphButton.title = s.edges ? "" : "No lockfile records package-to-package dependencies";
  setDepsView(s.edges ? "graph" : "table");
  const byId = Object.fromEntries(dep.packages.map((p, i) => [p.id, { ...p, index: i }]));
  $("depsCount").textContent = `(${s.total})`;
  $("depsLead").textContent = `${s.total} package(s): ${s.direct} direct (declared by the `
    + `project) and ${s.transitive} transitive (resolved by a lockfile); ${s.ai} AI package(s). `
    + "This is the same set the CycloneDX file lists as libraries, test and example "
    + "manifests included. Nothing is filtered or hidden here.";
  const notice = $("depsNotice");
  notice.hidden = !s.total || s.relations_resolved === s.total;
  notice.innerHTML = !s.relations_resolved
    ? `<strong>Dependency relations unresolved:</strong> ${s.total} package(s) detected, but no `
      + "lockfile that records package-to-package dependencies was found (package-lock.json, "
      + "poetry.lock, uv.lock, Cargo.lock, composer.lock, Gemfile.lock). Their own dependencies "
      + "are <em>unknown</em>, not absent, and transitive packages are missing from this list."
    : `Relations are known for ${s.relations_resolved} of ${s.total} package(s), from `
      + `${esc(s.graph_lockfiles.join(", "))}. The rest show “unknown”.`;
  const name = (id) => {
    const p = byId[id];
    return p ? `<button type="button" class="link dep-jump" data-dep="${p.index}">${esc(p.name)}</button>` : esc(id);
  };
  body.innerHTML = dep.packages.length ? dep.packages.map((p, i) => {
    const deps = p.relations === "unknown"
      ? `<span class="muted" title="No edge-recording lockfile covers this package">unknown</span>`
      : (p.depends_on.length ? p.depends_on.map(name).join(", ") : `<span class="muted">none (lockfile)</span>`);
    const req = p.required_by.length ? p.required_by.map(name).join(", ")
      : (p.scope === "direct" ? `<span class="muted">this project</span>` : `<span class="muted">—</span>`);
    const version = p.version
      ? `<code>${esc(p.version)}</code>${p.version_pinned ? "" : ` <span class="muted">declared range</span>`}`
      : `<span class="muted">unknown</span>`;
    const where = [...new Set(p.locations || [])].slice(0, 2).map(loc => {
      const [file, line] = loc.split(/:(?=\d)/);
      return srcLink({ file, line_start: Number(line) || 1, line_end: Number(line) || 1 });
    }).join("<br>");
    const findings = p.finding_count
      ? `<button type="button" class="link dep-findings" data-name="${esc(p.name)}">`
        + `${sevTag(p.severity)} ${p.finding_count}</button>` : `<span class="muted">0</span>`;
    const ctx = p.production ? "" : ` <span class="tag">${esc(p.source_contexts.join(", "))}</span>`;
    return `<tr id="dep-${i}" data-row="true" data-scope="${esc(p.scope)}" data-ai="${p.ai}" `
      + `data-findings="${p.finding_count ? "yes" : "no"}" data-relations="${esc(p.relations)}">`
      + `<td><strong>${esc(p.name)}</strong>${p.ai ? ' <span class="tag ai">AI</span>' : ""}${ctx}`
      + `<br><span class="muted">${esc(p.ecosystem || "")}${p.purl ? " · " + esc(p.purl) : ""}</span></td>`
      + `<td>${version}</td><td>${esc(p.scope)}</td><td>${deps}</td><td>${req}</td>`
      + `<td>${where || "—"}</td><td>${findings}</td></tr>`;
  }).join("") : `<tr><td colspan="7" class="empty">No dependency manifest or lockfile was found.</td></tr>`;
  body.querySelectorAll(".dep-jump").forEach(btn => btn.addEventListener("click", () => {
    $("depsFilter").value = "all"; $("depsSearch").value = ""; filterDeps();
    const row = $("dep-" + btn.dataset.dep);
    row.scrollIntoView({ block: "center" });
    row.classList.add("is-flash");
    setTimeout(() => row.classList.remove("is-flash"), 1600);
  }));
  body.querySelectorAll(".dep-findings").forEach(btn => btn.addEventListener("click", () => {
    showFindingsFor(btn.dataset.name);
  }));
}

function showFindingsFor(name) {
  $("findingSearch").value = name;
  $("severityFilter").value = "all";
  selectTab("findings");
  filterFindings();
}

function filterDeps() {
  const mode = $("depsFilter").value;
  filterRows("deps", "depsSearch", null, null, "No packages match the current filters.", (row) =>
    mode === "all" || (mode === "direct" && row.dataset.scope === "direct")
    || (mode === "transitive" && row.dataset.scope === "transitive")
    || (mode === "ai" && row.dataset.ai === "true")
    || (mode === "findings" && row.dataset.findings === "yes")
    || (mode === "unknown" && row.dataset.relations === "unknown"));
}

function renderGraphLead(d) {
  const nodes = ((d.graph || {}).nodes || []).length;
  const scope = d.analysis_scope || {};
  const total = ((d.inventory || {}).entities || []).length;
  $("graphLead").textContent = `Showing ${nodes} of ${total} components: models, services, `
    + "prompts, tools, agents and AI packages, plus an ordinary package only when it has a "
    + "finding or an AI package depends on it directly. Production code only"
    + (scope.excluded_non_production_entities
      ? ` (${scope.excluded_non_production_entities} test/example/docs component(s) left out)` : "")
    + ". Every line is a relationship a scanned file proves; the full package list is under "
    + "Dependencies.";
}

function renderInventory(d) {
  const allEnts = (d.inventory && d.inventory.entities) || [];
  const ib = $("inventory").querySelector("tbody");
  const ents = allEnts.slice().sort((a, b) => {
    if (a.type !== b.type) return a.type.localeCompare(b.type);
    const aiDiff = (b.ai ? 1 : 0) - (a.ai ? 1 : 0);  // AI packages first
    return aiDiff !== 0 ? aiDiff : a.name.localeCompare(b.name);
  });
  $("invSummary").textContent = "(" +
    Object.entries(d.counts || {}).map(([k, v]) => v + " " + k).join(" · ") + ")";
  ib.innerHTML = ents.length ? ents.map(e => {
    const prov = e.provider || e.source || e.source_kind || e.ecosystem || "—";
    const loc = e.source_evidence && e.source_evidence[0] ? srcLink(e.source_evidence[0]) : "—";
    const contexts = (e.source_contexts || []).join(", ") || "—";
    const detectors = (e.detector_ids || []).join(", ") || "—";
    const typeCell = e.type === "package" && e.ai
      ? "package <span class='tag ai'>AI</span>" : esc(e.type);
    const reach = e.type === "package" ? "n/a" : ((e.usage && e.usage.reachable) || "unknown");
    const version = e.version || e.revision;
    const scope = e.type === "package" && e.dependency_scope ? ` <span class="muted">${esc(e.dependency_scope)}</span>` : "";
    return `<tr data-row="true" data-type="${esc(e.type)}" data-reach="${esc(reach)}" `
      + `data-contexts="${esc((e.source_contexts || []).join(" "))}">`
      + `<td>${typeCell}</td><td>${esc(e.name)}</td>`
      + `<td>${version ? `<code>${esc(version)}</code>` : '<span class="muted">unknown</span>'}${scope}</td>`
      + `<td>${esc(prov)}</td><td>${usageCell(e, reach)}</td>`
      + `<td>${esc(contexts)}</td><td>${loc}<br><span class="muted">${esc(detectors)}</span></td></tr>`;
  }).join("") : `<tr><td colspan="7" class="empty">No components were discovered.</td></tr>`;

  const fill = (id, values, label) => {
    const select = $(id);
    select.innerHTML = `<option value="all">${label}</option>`;
    values.forEach(v => {
      const option = document.createElement("option");
      option.value = v;
      option.textContent = v.charAt(0).toUpperCase() + v.slice(1);
      select.appendChild(option);
    });
  };
  fill("typeFilter", [...new Set(ents.map(e => e.type))].sort(), "All types");
  fill("contextFilter", [...new Set(ents.flatMap(e => e.source_contexts || []))].sort(),
    "All contexts");
}

// The exports re-run the same request as the result on screen (same ref).
function exportRequest() {
  return lastRequest.demo
    ? { method: "POST" }
    : { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: lastRequest.repo_url, ref: lastRequest.ref || null,
          resolve: lastRequest.resolve }) };
}

async function download() {
  if (!lastRequest) return;
  const button = $("download");
  const original = button.innerHTML;
  button.disabled = true;
  button.textContent = "Building report…";
  setStatus("Building the HTML report (the backend re-runs the analysis)…", false);
  try {
    const endpoint = lastRequest.demo ? "/api/demo/report" : "/api/report";
    const resp = await fetch(lastRequest.api + endpoint, exportRequest());
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "aibom-report.html";
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    setStatus("Report downloaded.", false);
  } catch (e) {
    setStatus("Report failed: " + e.message, true);
  } finally {
    button.disabled = false;
    button.innerHTML = original;
  }
}

function downloadCycloneDX() {
  if (!lastResult || !lastResult.cyclonedx) return;
  saveJson(lastResult.cyclonedx, "aibom.cdx.json", "CycloneDX SBOM");
}

function saveJson(payload, filename, label) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  setStatus(label + " downloaded.", false);
}

function downloadInventory() {
  if (!lastResult || !lastResult.inventory) return;
  saveJson(lastResult.inventory, "aibom-inventory.json", "Inventory JSON");
}

// SARIF is built server-side so the file matches `aibom scan --sarif` exactly.
async function downloadSarif() {
  if (!lastRequest) return;
  const button = $("downloadSarif");
  const original = button.innerHTML;
  button.disabled = true;
  button.textContent = "Building SARIF…";
  try {
    const endpoint = lastRequest.demo ? "/api/demo/sarif" : "/api/sarif";
    const resp = await fetch(lastRequest.api + endpoint, exportRequest());
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.detail || ("HTTP " + resp.status));
    saveJson(data, "aibom-findings.sarif", "SARIF log");
  } catch (e) {
    setStatus("SARIF export failed: " + e.message, true);
  } finally {
    button.disabled = false;
    button.innerHTML = original;
  }
}

// POST to an NDJSON endpoint: {"stage": id} lines, then {"result": ...} or
// {"error": detail, "status": code}. Returns NO_STREAM when the backend has no
// such endpoint (404/405) so the caller can fall back to the plain request.
const NO_STREAM = Symbol("no-stream");
async function postStream(url, body, signal, progress) {
  let resp;
  try {
    resp = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body), signal });
  } catch (e) {
    if (e.name === "AbortError") throw e;
    throw new BackendUnavailable("cannot reach " + apiBase() + " (" + e.message + ")");
  }
  if (resp.status === 404 || resp.status === 405) return NO_STREAM;
  const type = resp.headers.get("content-type") || "";
  if (!resp.ok || !type.includes("ndjson") || !resp.body) {
    // A validation error (plain JSON) or a static host (HTML): same handling
    // as a plain request.
    const text = await resp.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch (_) {
      throw new BackendUnavailable("no analysis backend at " + apiBase() + " (HTTP "
        + resp.status + ", and the reply was not JSON)");
    }
    if (!resp.ok) throw new Error(errorDetail(data, resp.status));
    return data;
  }
  progress.streamed = true;
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  for (;;) {
    const { value, done } = await reader.read();
    buffered += decoder.decode(value || new Uint8Array(), { stream: !done });
    let nl;
    while ((nl = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, nl).trim();
      buffered = buffered.slice(nl + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      if (msg.stage) progress.stage(msg.stage);
      else if (msg.error) throw new Error(errorDetail({ detail: msg.error }, msg.status || 500));
      else if (msg.result) return msg.result;
    }
    if (done) throw new Error("the backend closed the connection before sending a result");
  }
}

function errorDetail(data, status) {
  const detail = data && data.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length) return detail.map(d => d.msg || d).join("; ");
  return "HTTP " + status;
}

async function postJson(url, body, signal) {
  const options = body
    ? { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body), signal }
    : { method: "POST", signal };
  let resp;
  try {
    resp = await fetch(url, options);
  } catch (e) {
    if (e.name === "AbortError") throw e;
    // Network-level failure: wrong address, backend down, CORS, offline.
    throw new BackendUnavailable("cannot reach " + apiBase() + " (" + e.message + ")");
  }
  const text = await resp.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    // Not JSON. A static host (GitHub Pages, a CDN) answers every POST with
    // HTML, which is exactly the "nothing happens" case.
    throw new BackendUnavailable(
      "no analysis backend at " + apiBase() + " (HTTP " + resp.status
      + ", and the reply was not JSON)");
  }
  if (!resp.ok) {
    // 404/405 on an API path means this origin serves the page but not the API.
    if (resp.status === 404 || resp.status === 405) {
      throw new BackendUnavailable(
        "no analysis backend at " + apiBase() + " (HTTP " + resp.status + ")");
    }
    throw new Error(data.detail || ("HTTP " + resp.status));
  }
  return data;
}

// --- backend address -------------------------------------------------------

function renderApiLine() {
  const base = apiBase();
  const sameOrigin = base === location.origin;
  $("apiLine").textContent = sameOrigin
    ? "Analysis backend: this server"
    : "Analysis backend: " + base;
}

function showApiEndpointField(message) {
  $("advancedInfo").open = true;
  $("apiEndpoint").value = apiOverride || "";
  if (message) setStatus(message, true);
  $("advancedInfo").scrollIntoView({ block: "nearest" });
  $("apiEndpoint").focus();
}

function saveApiEndpoint() {
  const value = $("apiEndpoint").value.trim().replace(/\/$/, "");
  if (value && !isRepositoryUrl(value)) {
    $("apiEndpoint").setAttribute("aria-invalid", "true");
    setStatus("Enter the backend address, including https://.", true);
    return;
  }
  $("apiEndpoint").removeAttribute("aria-invalid");
  apiOverride = value;
  storeApiBase(value);
  renderApiLine();
  checkBackend({ announce: true });
}

// Ask the backend whether it is there *before* the user clicks anything, so a
// missing backend reads as a setup step rather than a failed analysis.
async function checkBackend(options) {
  const announce = options && options.announce;
  const base = apiBase();
  try {
    const resp = await fetch(base + "/api/health");
    const data = await resp.json();
    if (!resp.ok || data.status !== "ok") throw new Error("HTTP " + resp.status);
    scannerVersion = data.version || "";
    if (announce) setStatus("Backend reachable (aibom " + (data.version || "?") + ").", false);
    return true;
  } catch (_) {
    showApiEndpointField(
      "No analysis backend at " + base + ". This page is only the interface — "
      + "point it at a running backend to analyze anything.");
    return false;
  }
}

// ── dependency graph (dependency-free SVG force layout) ──────────────────────
const SVGNS = "http://www.w3.org/2000/svg";
const TYPE_COLOR = { model:"#3a6ea5", dataset:"#7a5ea5", prompt:"#9c7a2e",
  agent:"#2e7d5b", service:"#556", package:"#8a6d3b", license:"#667", tool:"#a14d6b" };
// Edge styling per relationship type; the arrow points from dependent to dependency.
const EDGE_STYLE = {
  depends_on:  { color: "#7c8593", dash: "",    label: "depends on (package / SDK)" },
  served_by:   { color: "#3a6ea5", dash: "6 3", label: "served by (provider)" },
  invokes:     { color: "#2e7d5b", dash: "",    label: "invokes (tool / server)" },
  flows_to:    { color: "#b0761c", dash: "",    label: "prompt flows to (data flow)" },
  uses_prompt: { color: "#7a5ea5", dash: "2 3", label: "uses prompt" },
};
const EDGE_FALLBACK = { color: "#7c8593", dash: "4 2", label: "related" };
function edgeStyle(type) { return EDGE_STYLE[type] || EDGE_FALLBACK; }
// Endpoints trimmed to the node rims so the arrowhead is not hidden under a circle.
function edgeCoords(l) {
  const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
  const d = Math.sqrt(dx*dx + dy*dy) || 1;
  const rs = (l.s.radius || 8.5) + 1, rt = (l.t.radius || 8.5) + 3;
  return { x1: l.s.x + dx / d * rs, y1: l.s.y + dy / d * rs,
           x2: l.t.x - dx / d * rt, y2: l.t.y - dy / d * rt };
}
function placeEdge(l) {
  const c = edgeCoords(l);
  for (const k in c) l.el.setAttribute(k, c[k]);
}
let graphFindings = [];
let graphExposurePaths = [];
let graphImpactPaths = [];

function nodeColor(n) {
  return n.severity ? SEV_COLOR[n.severity] : (TYPE_COLOR[n.type] || "#6b7280");
}
function svgEl(name, attrs) {
  const el = document.createElementNS(SVGNS, name);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  return el;
}

// Where a graph is drawn. The scan tab owns the impact/exposure path panels;
// the drift and compare demos draw a plain dependency map with its own panel.
const MAIN_GRAPH = { host: "graph", legend: "edgeLegend", detail: "graphDetail", main: true };
const DRIFT_GRAPH = { host: "driftDepGraph", legend: "driftDepLegend", detail: "driftDepDetail" };
const COMPARE_GRAPH = { host: "compareDepGraph", legend: "compareDepLegend", detail: "compareDepDetail" };
// Package -> package dependencies from the lockfile, laid out by depth.
const DEPS_GRAPH = { host: "depsGraph", legend: "depsLegend", detail: "depsDetail",
  layout: "layers", title: "Dependency graph" };

// Columns by dependency depth: each package sits one column to the right of
// the deepest package that depends on it (longest path), so every arrow runs
// left to right and a shared dependency such as typing-extensions ends up at
// the far right instead of pulling arrows backwards. Rows are by name.
function layerLayout(nodes, links, pad) {
  const depth = {};
  nodes.forEach(n => { depth[n.id] = 0; });
  // Relaxation; bounded by the node count, so a cyclic lockfile still ends.
  for (let round = 0; round < nodes.length; round++) {
    let changed = false;
    for (const l of links) {
      if (depth[l.t.id] < depth[l.s.id] + 1 && depth[l.s.id] + 1 < nodes.length) {
        depth[l.t.id] = depth[l.s.id] + 1;
        changed = true;
      }
    }
    if (!changed) break;
  }
  const deepest = Math.max(0, ...Object.values(depth));
  const columns = [];
  nodes.forEach(n => {
    const d = depth[n.id] ?? deepest + 1;
    (columns[d] = columns[d] || []).push(n);
  });
  const COL = 190, ROW = 44;
  const rows = Math.max(...columns.map(c => (c ? c.length : 0)));
  const W = pad * 2 + Math.max(1, columns.length - 1) * COL;
  const H = pad * 2 + Math.max(1, rows - 1) * ROW;
  // Left column by name; every later column by the mean height of the
  // packages that depend on it (barycenter), which removes most crossings.
  const parents = {};
  links.forEach(l => { (parents[l.t.id] = parents[l.t.id] || []).push(l.s); });
  columns.forEach((col, i) => {
    if (!col) return;
    const key = (n) => {
      const ys = (parents[n.id] || []).filter(p => p.y != null && p.x < pad + i * COL);
      return ys.length ? ys.reduce((sum, p) => sum + p.y, 0) / ys.length : Infinity;
    };
    col.sort((a, b) => (i ? key(a) - key(b) : 0) || a.label.localeCompare(b.label));
    const top = (H - (col.length - 1) * ROW) / 2;
    col.forEach((n, j) => { n.x = pad + i * COL; n.y = top + j * ROW; });
  });
  return { W, H };
}

// The dependency table as a graph: one node per package, one edge per
// lockfile-recorded dependency, each citing its lockfile line.
function dependencyGraph(dep) {
  const ids = new Set(dep.packages.map(p => p.id));
  return {
    nodes: dep.packages.map(p => ({
      id: p.id, label: p.name, type: "package", severity: p.severity, direct: p.scope === "direct",
      version: p.version, scope: p.scope, location: (p.locations || [])[0],
      source_contexts: p.source_contexts,
    })),
    edges: dep.packages.flatMap(p => p.depends_on.filter(t => ids.has(t)).map(t => ({
      source: p.id, target: t, type: "depends_on",
      evidence: p.edge_evidence[t] ? [p.edge_evidence[t]] : [],
    }))),
  };
}

let depsData = null;
function setDepsView(mode) {
  const graph = mode === "graph";
  document.querySelectorAll("[data-deps-view]").forEach(b =>
    b.setAttribute("aria-pressed", String(b.dataset.depsView === mode)));
  $("depsMap").hidden = !graph;
  $("depsTable").hidden = graph;
  $("depsToolbar").hidden = graph;
  if (graph) drawDepsGraph();
}

// Drawn only while the Dependencies tab is visible: a hidden host has no
// width, and the zoom would be computed for nothing.
function drawDepsGraph() {
  const host = $("depsGraph");
  if (!depsData || $("depsSection").hidden) return;
  if (!host.querySelector("svg")) {
    renderGraph(dependencyGraph(depsData), lastResult ? lastResult.findings : [], DEPS_GRAPH);
  } else {
    setZoom(host, "default");
  }
}

function renderGraph(graph, findings, view = MAIN_GRAPH) {
  const ctx = { detail: view.detail, findings: findings || [], exposure: graph.exposure_paths || [] };
  if (view.main) {
    graphFindings = ctx.findings;
    graphExposurePaths = ctx.exposure;
    graphImpactPaths = graph.impact_paths || [];
    renderImpactPaths(graphImpactPaths);
    renderExposurePaths(graphExposurePaths);
  }
  const host = $(view.host);
  const grid = host.closest(".graphgrid");
  const tools = graphToolbar(host);
  host.innerHTML = "";
  grid.classList.toggle("is-empty", !graph.nodes.length);
  if (view.main) $("nodeLegend").hidden = !graph.nodes.length;
  if (!graph.nodes.length) {
    // An empty map gets a reason and a next step, not a legend and "select a node".
    host.innerHTML = `<div class="empty-graph"><strong>Nothing to map.</strong> No AI component `
      + "was found in production code, so there is nothing to connect. Every package is "
      + `listed under <button type="button" class="link" data-goto="deps">Dependencies</button>.</div>`;
    tools.hidden = true;
    $(view.detail).innerHTML = "";
    renderEdgeLegend([], view.legend);
    return;
  }
  tools.hidden = false;
  detailReset(ctx);

  let W = 800, H = 520;
  const PAD = 46;
  const nodes = graph.nodes.map((n, i) => {
    const a = (i / graph.nodes.length) * Math.PI * 2;
    return { ...n, x: W/2 + Math.cos(a)*150, y: H/2 + Math.sin(a)*150, vx:0, vy:0 };
  });
  const byId = {}; nodes.forEach(n => byId[n.id] = n);
  const links = graph.edges.map(e => ({ s: byId[e.source], t: byId[e.target], type: e.type,
    evidence: e.evidence || [] })).filter(l => l.s && l.t);
  nodes.forEach(n => { n.radius = n.type === "agent" || n.direct ? 11 : 8.5; });
  const adj = {}; nodes.forEach(n => adj[n.id] = new Set());
  links.forEach(l => { adj[l.s.id].add(l.t.id); adj[l.t.id].add(l.s.id); });

  if (view.layout === "layers") {
    ({ W, H } = layerLayout(nodes, links, PAD));
  } else {
    simulate(nodes, links, W, H);
    fit(nodes, W, H, PAD);
  }

  if (!links.length) {
    const note = document.createElement("p");
    note.className = "notice";
    note.textContent = `No relationship between these ${nodes.length} components could be `
      + "proven from the scanned lines, so they are drawn unconnected. That is not a "
      + "statement that they are unrelated.";
    host.appendChild(note);
  }

  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, role: "group",
    "aria-label": view.title || "AI usage map" });
  const defs = svgEl("defs", {});
  const types = [...new Set(links.map(l => l.type))];
  types.forEach(type => {
    const marker = svgEl("marker", { id: `arrow-${view.host}-${type}`, viewBox: "0 0 10 10", refX: "9", refY: "5",
      markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
    marker.appendChild(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: edgeStyle(type).color }));
    defs.appendChild(marker);
  });
  svg.appendChild(defs);
  const gEdges = svgEl("g", {}), gNodes = svgEl("g", {});
  svg.appendChild(gEdges); svg.appendChild(gNodes);

  const lineEls = links.map(l => {
    const style = edgeStyle(l.type);
    const ln = svgEl("line", { class: "edge", "data-type": l.type, stroke: style.color,
      "marker-end": `url(#arrow-${view.host}-${l.type})` });
    if (style.dash) ln.setAttribute("stroke-dasharray", style.dash);
    const title = svgEl("title", {});
    title.textContent = `${l.s.label} ${style.label} ${l.t.label}`
      + (l.evidence.length ? ` (${l.evidence[0]})` : "");
    ln.appendChild(title);
    gEdges.appendChild(ln); l.el = ln; placeEdge(l); return ln;
  });
  renderEdgeLegend(types, view.legend);

  nodes.forEach(n => {
    const g = svgEl("g", { class: "node", role: "button", tabindex: "0",
      "aria-label": `${n.label}, ${n.type}${n.severity ? `, ${n.severity} severity` : ""}` });
    const r = n.radius;
    const c = svgEl("circle", { r, cx: n.x, cy: n.y, fill: nodeColor(n) });
    const label = n.label.length > 24 ? n.label.slice(0, 23) + "…" : n.label;
    const t = svgEl("text", { x: n.x, y: n.y + r + 13, "text-anchor": "middle" });
    t.textContent = label;
    const full = svgEl("title", {});
    full.textContent = `${n.label} (${n.type})`;
    g.appendChild(full); g.appendChild(c); g.appendChild(t);
    gNodes.appendChild(g);
    n.circle = c; n.text = t; n.g = g;
    g.addEventListener("click", (ev) => { ev.stopPropagation(); selectNode(n, nodes, links, adj, ctx); });
    g.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        ev.stopPropagation();
        selectNode(n, nodes, links, adj, ctx);
      }
    });
    enableDrag(g, n, svg, W, H, links);
  });

  svg.addEventListener("click", () => clearSelection(nodes, lineEls, ctx));
  host.appendChild(svg);
  host._nodes = nodes; host._lines = lineEls; host._links = links;
  host._select = (n) => selectNode(n, nodes, links, adj, ctx);
  host._W = W;
  setZoom(host, "default");
}

// Zoom keeps labels readable on a narrow screen: the map scrolls inside its
// own frame instead of shrinking until the text is illegible.
function setZoom(host, mode) {
  const svg = host.querySelector("svg");
  if (!svg) return;
  const avail = Math.max(host.clientWidth || 0, 280);
  const current = host._zoom || 1;
  const zoom = mode === "fit" ? avail / host._W
    : mode === "in" ? current * 1.25
    : mode === "out" ? current / 1.25
    : Math.max(avail, 640) / host._W;
  host._zoom = Math.min(3, Math.max(0.3, zoom));
  svg.style.width = Math.round(host._W * host._zoom) + "px";
}

function graphToolbar(host) {
  let tools = host.previousElementSibling;
  if (!tools || !tools.classList.contains("graph-tools")) {
    tools = document.createElement("div");
    tools.className = "graph-tools";
    tools.setAttribute("role", "group");
    tools.setAttribute("aria-label", "Map controls");
    host.parentNode.insertBefore(tools, host);
  }
  if (!tools.dataset.ready) {
    tools.dataset.ready = "1";
    tools.innerHTML = `<button type="button" class="ghost small" data-zoom="out" aria-label="Zoom out">−</button>`
      + `<button type="button" class="ghost small" data-zoom="fit">Fit</button>`
      + `<button type="button" class="ghost small" data-zoom="in" aria-label="Zoom in">+</button>`
      + `<input type="search" class="graph-search" placeholder="Find a component" `
      + `aria-label="Find a component in the map">`;
    tools.querySelectorAll("[data-zoom]").forEach(b =>
      b.addEventListener("click", () => setZoom(host, b.dataset.zoom)));
    const search = tools.querySelector(".graph-search");
    const find = (select) => {
      const q = search.value.trim().toLocaleLowerCase();
      const nodes = host._nodes || [];
      const hits = nodes.filter(n => q && n.label.toLocaleLowerCase().includes(q));
      nodes.forEach(n => n.g && n.g.classList.toggle("is-hit", hits.includes(n)));
      if (select && hits.length && host._select) host._select(hits[0]);
    };
    search.addEventListener("input", () => find(false));
    search.addEventListener("keydown", (e) => { if (e.key === "Enter") find(true); });
  }
  return tools;
}

function renderEdgeLegend(types, legendId = "edgeLegend") {
  const host = $(legendId);
  host.hidden = !types.length;
  host.innerHTML = types.map(type => {
    const style = edgeStyle(type);
    return `<span><svg width="26" height="8" aria-hidden="true"><line x1="1" y1="4" x2="25" y2="4"`
      + ` stroke="${style.color}" stroke-width="2"${style.dash ? ` stroke-dasharray="${style.dash}"` : ""}/>`
      + `</svg>${esc(style.label)}</span>`;
  }).join("");
}

function renderImpactPaths(paths) {
  const host = $("impactPaths");
  host.hidden = !paths.length;
  if (!paths.length) {
    host.innerHTML = "";
    return;
  }
  host.innerHTML = paths.map(path => {
    const models = (path.model_names || []).join(", ") || "unresolved model";
    const tools = (path.tool_names || []).join(", ") || "unresolved tool";
    const consequences = [...new Set((path.capabilities || []).map(item => item.impact))].join("; ");
    const route = `${path.source_kind} \u2192 privileged instructions \u2192 ${models} \u2192 ${tools}`;
    const operations = (path.capabilities || []).map(item =>
      `${item.operation}(${(item.controlled_parameters || []).join(", ")})`).join(", ");
    return `<div class="impact-path"><strong>Untrusted input reaches a bound tool \u00b7 ${esc(path.severity)}</strong>`
      + `<span class="impact-route">${esc(route)}</span>`
      + `<span>Could ${esc(consequences)}.</span>`
      + `<span class="muted"> Direct binding + tool-parameter flow \u00b7 ${esc(operations)}`
      + ` \u00b7 confidence ${Number(path.confidence || 0).toFixed(2)}</span></div>`;
  }).join("");
}

function renderExposurePaths(paths) {
  const host = $("exposurePaths");
  host.hidden = !paths.length;
  if (!paths.length) {
    host.innerHTML = "";
    return;
  }
  host.innerHTML = paths.map(path => {
    const models = (path.model_names || []).join(", ") || "unresolved model";
    const label = `${path.source_kind} \u2192 ${path.sink_kind} \u2192 ${models}`;
    const prefix = path.privileged ? "Privileged prompt exposure" : "Expected user-input path";
    const location = (path.source_evidence || []).slice(0, 2).map(evLoc).join(", ");
    return `<div class="exposure-path" data-privileged="${path.privileged ? "true" : "false"}">`
      + `<strong>${esc(prefix)}</strong><code>${esc(label)}</code>`
      + `<span class="muted">${esc(path.trust_boundary)}`
      + `${location ? ` \u00b7 ${esc(location)}` : ""}</span></div>`;
  }).join("");
}

function simulate(nodes, links, W, H) {
  const REP = 2400, SPRING = 0.045, LEN = 92, GRAV = 0.008, DAMP = 0.86;
  for (let it = 0; it < 340; it++) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx*dx + dy*dy || 0.01;
        const f = REP / d2;
        const d = Math.sqrt(d2);
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      }
    }
    for (const l of links) {
      let dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
      const d = Math.sqrt(dx*dx + dy*dy) || 0.01;
      const f = SPRING * (d - LEN);
      const fx = (dx / d) * f, fy = (dy / d) * f;
      l.s.vx += fx; l.s.vy += fy; l.t.vx -= fx; l.t.vy -= fy;
    }
    for (const n of nodes) {
      n.vx += (W/2 - n.x) * GRAV; n.vy += (H/2 - n.y) * GRAV;
      n.vx *= DAMP; n.vy *= DAMP;
      n.x += Math.max(-14, Math.min(14, n.vx));
      n.y += Math.max(-14, Math.min(14, n.vy));
    }
  }
}

function fit(nodes, W, H, pad) {
  const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const sx = (W - 2*pad) / Math.max(1, maxX - minX);
  const sy = (H - 2*pad) / Math.max(1, maxY - minY);
  const s = Math.min(sx, sy, 2.2);
  nodes.forEach(n => {
    n.x = pad + (n.x - minX) * s + (W - 2*pad - (maxX - minX)*s)/2;
    n.y = pad + (n.y - minY) * s + (H - 2*pad - (maxY - minY)*s)/2;
  });
}

function selectNode(node, nodes, links, adj, ctx) {
  const keep = adj[node.id];
  nodes.forEach(n => {
    const on = n.id === node.id || keep.has(n.id);
    n.circle.setAttribute("opacity", on ? 1 : 0.16);
    n.text.setAttribute("opacity", on ? 1 : 0.16);
    if (n.g) n.g.classList.toggle("is-selected", n.id === node.id);
  });
  links.forEach(l => {
    const on = l.s.id === node.id || l.t.id === node.id;
    l.el.setAttribute("stroke-opacity", on ? 0.85 : 0.06);
  });
  detailShow(node, links, ctx);
}

function clearSelection(nodes, lineEls, ctx) {
  nodes.forEach(n => {
    n.circle.setAttribute("opacity", 1); n.text.setAttribute("opacity", 1);
    if (n.g) n.g.classList.remove("is-selected");
  });
  lineEls.forEach(l => l.setAttribute("stroke-opacity", 0.55));
  detailReset(ctx);
}

function enableDrag(g, n, svg, W, H, links) {
  let dragging = false;
  const toSvg = (ev) => {
    const r = svg.getBoundingClientRect();
    return { x: (ev.clientX - r.left) / r.width * W, y: (ev.clientY - r.top) / r.height * H };
  };
  g.addEventListener("pointerdown", (ev) => {
    dragging = true; g.setPointerCapture(ev.pointerId); ev.stopPropagation();
  });
  g.addEventListener("pointermove", (ev) => {
    if (!dragging) return;
    const p = toSvg(ev); n.x = p.x; n.y = p.y;
    n.circle.setAttribute("cx", n.x); n.circle.setAttribute("cy", n.y);
    n.text.setAttribute("x", n.x); n.text.setAttribute("y", n.y + n.radius + 9);
    links.forEach(l => { if (l.s === n || l.t === n) placeEdge(l); });
  });
  g.addEventListener("pointerup", (ev) => { dragging = false; g.releasePointerCapture(ev.pointerId); });
}

function detailReset(ctx) {
  $(ctx ? ctx.detail : "graphDetail").innerHTML =
    "<span class='muted'>Select a component to see its full name, evidence, connections and "
    + "findings.</span>";
}

function connectionsHtml(node, links) {
  const out = links.filter(l => l.s.id === node.id), inc = links.filter(l => l.t.id === node.id);
  if (!out.length && !inc.length) {
    return `<div class="dt-find muted">No proven connections. A component is only linked when a`
      + ` scanned line (import, call, lockfile entry) shows the relationship.</div>`;
  }
  const name = (n) => `<strong>${esc(n.label)}</strong> <span class="muted">(${esc(n.type)})</span>`;
  const cite = (l) => (l.evidence.length ? ` <code>${esc(l.evidence[0])}</code>` : "");
  let html = `<div class="dt-find"><strong>Connections</strong><ul class="dt-links">`;
  // Outgoing reads "this <verb> other"; incoming reads "other <verb> this".
  out.forEach(l => { html += `<li>${esc(edgeStyle(l.type).label)} ${name(l.t)}${cite(l)}</li>`; });
  inc.forEach(l => { html += `<li>${name(l.s)} ${esc(edgeStyle(l.type).label)} this${cite(l)}</li>`; });
  return html + `</ul></div>`;
}

function detailShow(node, links, ctx) {
  ctx = ctx || { detail: "graphDetail", findings: graphFindings, exposure: graphExposurePaths };
  const mine = ctx.findings.filter(f => f.entity_id === node.id);
  const paths = ctx.exposure.filter(path =>
    path.prompt_id === node.id || (path.model_ids || []).includes(node.id));
  let html = `<span class="dt-type">${esc(node.type)} · selected</span>`
    + `<h3 class="dt-name">${esc(node.label)}</h3>`
    + `<button type="button" class="ghost small copy-name">Copy name</button>`;
  if (node.provider) html += `<div class="muted">Provider: ${esc(node.provider)}</div>`;
  if (node.version) html += `<div class="muted">Version: <code>${esc(node.version)}</code></div>`;
  if (node.scope) {
    html += `<div class="muted">${node.scope === "direct" ? "Direct dependency (declared by the "
      + "project)" : "Transitive dependency (resolved by the lockfile)"}</div>`;
  }
  if (node.location) html += `<div class="muted">Location: <code>${esc(node.location)}</code></div>`;
  if (node.usage) html += `<div class="muted">${esc(usageLabel(node.usage))}</div>`;
  if (node.source_contexts && node.source_contexts.length) {
    html += `<div class="muted">Context: ${esc(node.source_contexts.join(", "))}</div>`;
  }
  if (node.detectors && node.detectors.length) {
    html += `<div class="muted">Detectors: ${esc(node.detectors.join(", "))}</div>`;
  }
  html += connectionsHtml(node, links || []);
  for (const path of paths) {
    const models = (path.model_names || []).join(", ") || "unresolved model";
    html += `<div class="dt-find"><strong>${path.privileged ? "Privileged exposure" : "Input path"}</strong>`
      + `<div class="muted">${esc(path.source_kind)} &rarr; ${esc(path.sink_kind)}`
      + ` &rarr; ${esc(models)}</div></div>`;
  }
  if (!mine.length) {
    html += `<div class="dt-find muted">No findings on this component.</div>`;
  } else {
    for (const f of mine.slice(0, 5)) {
      html += `<div class="dt-find"><span class="sev" data-severity="${esc(f.severity)}">`
        + `${esc(f.severity)}</span> <code>${esc(f.rule_id)}</code><br>`
        + `<strong>${esc(f.title)}</strong></div>`;
    }
    if (ctx.detail === "graphDetail") {
      html += `<button type="button" class="link open-findings">Open ${mine.length} finding(s) `
        + `in Findings</button>`;
    }
  }
  const host = $(ctx.detail);
  host.innerHTML = html;
  host.querySelector(".copy-name").addEventListener("click", (ev) => {
    const done = () => { ev.target.textContent = "Copied"; };
    if (navigator.clipboard) navigator.clipboard.writeText(node.label).then(done, () => {});
  });
  const open = host.querySelector(".open-findings");
  if (open) open.addEventListener("click", () => showFindingsFor(node.label));
}

function filterRows(tableId, searchId, selectId, dataKey, emptyMessage, extraMatch) {
  const table = $(tableId);
  const tbody = table.querySelector("tbody");
  tbody.querySelectorAll(".filter-empty").forEach(row => row.remove());
  const rows = [...tbody.querySelectorAll("tr[data-row='true']")];
  const query = $(searchId).value.trim().toLocaleLowerCase();
  const selected = selectId ? $(selectId).value : "all";
  let visible = 0;
  rows.forEach(row => {
    const matchesText = !query || row.textContent.toLocaleLowerCase().includes(query);
    const matchesSelect = selected === "all" || row.dataset[dataKey] === selected;
    const matchesExtra = !extraMatch || extraMatch(row);
    row.hidden = !(matchesText && matchesSelect && matchesExtra);
    if (!row.hidden) visible += 1;
  });
  if (rows.length && visible === 0) {
    const row = document.createElement("tr");
    row.className = "filter-empty";
    const cell = document.createElement("td");
    cell.colSpan = table.querySelectorAll("thead th").length;
    cell.className = "empty";
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    tbody.appendChild(row);
  }
  return { visible, total: rows.length };
}

function filterFindings() {
  const count = filterRows("findings", "findingSearch", "severityFilter", "severity",
    "No code or configuration findings match the current filters.");
  const query = $("findingSearch").value.trim().toLocaleLowerCase();
  const sev = $("severityFilter").value;
  let cards = 0, shown = 0;
  document.querySelectorAll("#vulnPackages .vuln-card").forEach(card => {
    cards += 1;
    const ok = (!query || card.textContent.toLocaleLowerCase().includes(query))
      && (sev === "all" || card.dataset.severities.split(" ").includes(sev));
    card.hidden = !ok;
    if (ok) shown += 1;
  });
  const total = count.total + (lastResult && lastResult.findings
    ? lastResult.findings.filter(f => f.advisory).length : 0);
  if (total) {
    const filtered = query || sev !== "all";
    $("findingCount").textContent = filtered
      ? `(${count.visible} code findings and ${shown} of ${cards} packages shown)` : `(${total})`;
  }
}

function filterInventory() {
  const reach = $("reachFilter").value;
  const context = $("contextFilter").value;
  filterRows("inventory", "inventorySearch", "typeFilter", "type",
    "No components match the current filters.",
    (row) => (reach === "all" || row.dataset.reach === reach)
      && (context === "all" || row.dataset.contexts.split(" ").includes(context)));
}

// The panel has two modes; the steps and empty state describe the active one.
$("scan").addEventListener("click", scan);
$("loadExample").addEventListener("click", loadExample);
$("saveApiEndpoint").addEventListener("click", saveApiEndpoint);
$("apiEndpoint").addEventListener("keydown", (e) => {
  if (e.key === "Enter") saveApiEndpoint();
});
$("runDemo").addEventListener("click", runDemo);
$("download").addEventListener("click", download);
$("downloadCdx").addEventListener("click", downloadCycloneDX);
$("downloadSarif").addEventListener("click", downloadSarif);
$("downloadInventory").addEventListener("click", downloadInventory);
$("repo").addEventListener("input", () => {
  $("repo").removeAttribute("aria-invalid");
});
$("repo").addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });
$("findingSearch").addEventListener("input", filterFindings);
$("severityFilter").addEventListener("change", filterFindings);
$("inventorySearch").addEventListener("input", filterInventory);
$("typeFilter").addEventListener("change", filterInventory);
$("reachFilter").addEventListener("change", filterInventory);

// ── compare revisions ─────────────────────────────────────────────────────────
// Same engine as `aibom diff` and POST /api/diff; this only renders the payload.
const EVIDENCE_LABEL = { proven_static: "Proven statically", potential: "Potential",
  unknown: "Unknown" };
const ROLE_LABEL = { source: "Untrusted input", flow: "Flow", privileged_prompt: "Privileged prompt",
  model: "Model", tool: "Bound tool", operation: "Operation" };
const PATH_KINDS = ["impact_path_added", "impact_path_changed", "impact_path_unresolved",
  "impact_path_removed"];
const COMPARE_BUTTONS = ["compareDemoPy", "compareDemoTs", "compareDemoFix", "compareRun"];
let compareLanguage = "python";
let compareNodes = [];

function setCompareStatus(msg, isErr) {
  const s = $("compareStatus"); s.textContent = msg; s.className = isErr ? "err" : "";
}

function revisionLabel(target) {
  if (typeof target === "string" && target.startsWith("built-in://")) {
    const parts = target.replace("built-in://", "").split("/");
    const language = parts[1] === "typescript" ? "TypeScript" : "Python";
    return `${language} demo · ${parts[2] || "revision"}`;
  }
  return repoLabel(target);
}

async function runCompare(button, busyLabel, status, request, demo) {
  const original = button.textContent;
  COMPARE_BUTTONS.forEach((id) => { $(id).disabled = true; });
  button.textContent = busyLabel;
  $("compareSection").setAttribute("aria-busy", "true");
  $("compareState").textContent = "Comparison in progress";
  setDriftStatus("", false);
  setCompareStatus(status, false);
  try {
    const body = await request();
    renderCompare(body, demo);
    $("compareState").textContent = "Comparison loaded";
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? "auto" : "smooth";
    $("compareResult").scrollIntoView({ behavior, block: "start" });
    $("compareResult").focus({ preventScroll: true });
  } catch (e) {
    setCompareStatus("The comparison could not be completed: " + e.message, true);
    $("compareState").textContent = "Comparison failed";
    if (e instanceof BackendUnavailable) showApiEndpointField();
  } finally {
    COMPARE_BUTTONS.forEach((id) => { $(id).disabled = false; });
    button.textContent = original;
    $("compareSection").removeAttribute("aria-busy");
  }
}

function compareDemo(language, revision) {
  compareLanguage = language;
  const button = revision === "fixed" ? $("compareDemoFix")
    : $(language === "typescript" ? "compareDemoTs" : "compareDemoPy");
  const query = `language=${language}&scenario=cross-file&revision=${revision}`;
  return runCompare(button, "Comparing…",
    revision === "fixed"
      ? "Comparing the vulnerable candidate with the bundled fixed revision (offline demo)…"
      : `Scanning the bundled ${language} baseline and candidate (offline demo)…`,
    () => postJson(apiBase() + "/api/diff/demo?" + query), revision === "fixed" ? "fixed" : "demo");
}

function compareRepo() {
  const repo = $("compareRepo").value.trim();
  const base = $("compareBase").value.trim();
  const head = $("compareHead").value.trim();
  if (!isRepositoryUrl(repo) || !base || !head) {
    setCompareStatus("Enter a repository URL and both refs to compare.", true);
    return Promise.resolve();
  }
  return runCompare($("compareRun"), "Comparing…",
    `Cloning ${repoLabel(repo)} at ${base} and ${head}…`,
    () => postJson(apiBase() + "/api/diff",
      { repo_url: repo, base_ref: base, head_ref: head }), null);
}

function renderCompare(body, demo) {
  const drift = body.drift || {};
  $("privResult").hidden = true;
  $("compareResult").hidden = false;
  $("nodeDetail").hidden = true;
  $("compareOverline").textContent = demo
    ? "Demo result · bundled data" : "Comparison · " + repoLabel(drift.baseline_target || "");
  renderVerdicts(drift, body.agent_privileges, demo);
  renderRevision($("baselineCard"), "Baseline", body.baseline, body.baseline_paths);
  renderRevision($("candidateCard"), demo === "fixed" ? "Bundled fixed revision" : "Candidate",
    body.candidate, body.candidate_paths);
  renderGraph((body.candidate || {}).graph || { nodes: [], edges: [] }, [], COMPARE_GRAPH);
  const changes = drift.changes || [];
  const paths = changes.filter(c => PATH_KINDS.includes(c.kind));
  const others = changes.filter(c => !PATH_KINDS.includes(c.kind));
  compareNodes = [];
  $("pathChanges").innerHTML = paths.length
    ? paths.map((change, index) => pathChangeHtml(change, index)).join("")
    : `<p class="help">No agent capability path was added, changed or removed.</p>`;
  $("pathChanges").querySelectorAll(".path-node").forEach((node) => {
    node.addEventListener("click", () => showNode(node));
  });
  const priv = body.agent_privileges;
  $("comparePrivileges").innerHTML = priv && priv.status === "evaluated"
    ? `<h3 class="subhead">Agent permission changes</h3>`
      + privilegeChangesHtml(priv.report.changes || [], {}) : "";
  const rows = others.map(change => {
    const evidence = (change.after_evidence && change.after_evidence[0])
      || (change.before_evidence && change.before_evidence[0]);
    return `<tr><td>${sevTag(change.severity)}</td><td><code>${esc(change.kind)}</code></td>`
      + `<td><strong>${esc(change.title)}</strong><br>${esc(change.description)}</td>`
      + `<td>${esc(evLoc(evidence))}${change.evidence_level
        ? "<br>" + evidenceTag(change.evidence_level) : ""}</td></tr>`;
  });
  $("otherChanges").querySelector("tbody").innerHTML = rows.length ? rows.join("")
    : `<tr><td colspan="4">No other changes.</td></tr>`;
  setCompareStatus(
    `${changes.length} change(s) between ${revisionLabel(drift.baseline_target)} and `
    + `${revisionLabel(drift.candidate_target)}.`, false);
}

function renderVerdicts(drift, privileges, demo) {
  const bom = drift.bom;
  const bomBox = $("bomVerdict");
  const types = bom ? esc((bom.compared_types || []).join(", ")) : "";
  if (bom && bom.identical) {
    bomBox.className = "verdict ok";
    bomBox.innerHTML = `<p class="verdict-label">COMPONENTS</p>`
      + `<p class="verdict-value">Compared components identical</p><p class="verdict-note">`
      + `${bom.candidate_components} component(s) of type ${types}: names, versions and `
      + `security metadata match. Prompts are not in this comparison; they are compared as `
      + `paths below.</p>`;
  } else if (bom) {
    bomBox.className = "verdict warn";
    const delta = [...bom.added.map(x => "+" + x), ...bom.removed.map(x => "−" + x),
      ...bom.changed.map(x => "~" + x)];
    bomBox.innerHTML = `<p class="verdict-label">COMPONENTS (${types})</p>`
      + `<p class="verdict-value">Changed</p><p class="verdict-note">`
      + `${esc(delta.slice(0, 6).join(", "))}${delta.length > 6 ? ` +${delta.length - 6} more` : ""}</p>`;
  } else {
    bomBox.className = "verdict";
    bomBox.innerHTML = `<p class="verdict-label">COMPONENTS</p><p class="verdict-value">—</p>`;
  }
  const changes = drift.changes || [];
  const added = changes.filter(c => c.kind === "impact_path_added");
  const unresolved = changes.filter(c => c.kind === "impact_path_unresolved");
  const box = $("boundaryVerdict");
  if (drift.security_boundary_changed) {
    const proven = added.filter(c => c.evidence_level === "proven_static").length;
    box.className = "verdict bad";
    box.innerHTML = `<p class="verdict-label">INPUT-TO-TOOL PATHS</p>`
      + `<p class="verdict-value">Changed</p><p class="verdict-note">${added.length} new agent`
      + ` capability path(s), ${proven} proven statically. A static path, not a proven exploit.</p>`;
  } else {
    box.className = unresolved.length ? "verdict warn" : "verdict ok";
    box.innerHTML = `<p class="verdict-label">INPUT-TO-TOOL PATHS</p>`
      + `<p class="verdict-value">Unchanged</p><p class="verdict-note">${unresolved.length
        ? `${unresolved.length} unresolved input(s) to review — not proven either way.`
        : "No new path from untrusted input to privileged instructions or a bound tool."}</p>`;
  }
  const priv = $("privilegeVerdict");
  if (!privileges) {
    priv.className = "verdict";
    priv.innerHTML = `<p class="verdict-label">AGENT PERMISSIONS</p><p class="verdict-value">`
      + `Not in this demo</p><p class="verdict-note">See the “Agent permission change” `
      + `demo.</p>`;
  } else if (privileges.status === "evaluated") {
    const gated = (privileges.report.changes || []).filter(c => c.gates);
    priv.className = "verdict " + (gated.length ? "bad" : "ok");
    priv.innerHTML = `<p class="verdict-label">AGENT PERMISSIONS</p><p class="verdict-value">`
      + `${gated.length ? gated.length + " added" : "No addition"}</p><p class="verdict-note">`
      + "Judged against the identity policies in aibom-identity.yaml only, not AWS effective "
      + "authorization.</p>";
  } else {
    priv.className = "verdict warn";
    priv.innerHTML = `<p class="verdict-label">AGENT PERMISSIONS</p><p class="verdict-value">`
      + `${privileges.status === "failed" ? "Analysis failed" : "Not evaluated"}</p>`
      + `<p class="verdict-note">${esc(privileges.reason || "")}.</p>`;
  }
}

function renderRevision(card, title, summary, paths) {
  if (!summary) { card.innerHTML = ""; return; }
  const counts = Object.entries(summary.counts || {})
    .filter(([kind, count]) => count && kind !== "prompt")
    .map(([kind, count]) => `${count} ${kind}`).join(" · ");
  const impact = (paths && paths.impact) || [];
  const unresolved = (paths && paths.unresolved) || [];
  const items = [...impact.map(p => `<li>${sevTag(p.severity)} ${evidenceTag(p.evidence_level)}`
      + ` ${esc(p.source_kind)} → ${esc(p.tool_names.join(", "))}</li>`),
    ...unresolved.map(p => `<li>${evidenceTag("unknown")} ${esc(p.sink_kind)} → `
      + `${esc(p.tool_names.join(", "))}</li>`)];
  const head = summary.headline || {};
  const score = summary.score || {};
  card.innerHTML = `<h4>${esc(title)}</h4>`
    + `<p class="revision-target">${esc(revisionLabel(summary.target))}</p>`
    + `<div>${esc(counts || "no components")}</div>`
    + `<div><strong>${esc(head.label || "")}</strong> · ${summary.findings} finding(s)`
    + `${score.overall != null ? ` <span class="muted">· hygiene ${score.overall}</span>` : ""}</div>`
    + `<div><strong>${impact.length}</strong> agent capability path(s)</div>`
    + (items.length ? `<ul>${items.join("")}</ul>` : "");
}

function sevTag(severity) {
  return `<span class="sev-tag" style="background:${SEV_COLOR[severity] || "#64716a"}">`
    + `${esc(severity)}</span>`;
}

function evidenceTag(level) {
  const key = EVIDENCE_LABEL[level] ? level : "unknown";
  return `<span class="evidence-tag ${key}">${EVIDENCE_LABEL[key]}</span>`;
}

function pathChangeHtml(change, index) {
  const details = change.details || {};
  const view = details.after || details;
  const nodes = view.nodes || [];
  const graph = nodes.map((node, position) => {
    const id = compareNodes.length;
    compareNodes.push({ node, limitations: view.limitations || [], change });
    const where = node.file ? `${node.file}:${node.line}` : "location unresolved";
    return `<li><button type="button" class="path-node role-${esc(node.role)} ${esc(node.status)}"`
      + ` data-node="${id}" aria-pressed="false"`
      + ` aria-label="${esc((ROLE_LABEL[node.role] || node.role) + ": " + node.label + ", " + where)}">`
      + `${esc(ROLE_LABEL[node.role] || node.role)}: ${esc(node.label)}`
      + `<small>${esc(where)}</small></button></li>`;
  }).join("");
  const consequence = view.potential_consequence
    ? `<p><strong>Potential consequence:</strong> ${esc(view.potential_consequence)}</p>` : "";
  const boundary = view.changed_boundary
    ? `<p><strong>Changed boundary:</strong> ${esc(view.changed_boundary)}</p>` : "";
  return `<article class="path-change" aria-labelledby="pathChange${index}">`
    + `<header>${sevTag(change.severity)} ${evidenceTag(change.evidence_level)}`
    + (view.cross_file ? ` <span class="evidence-tag">cross-file</span>` : "")
    + ` <h4 id="pathChange${index}">${esc(change.title)}</h4></header>`
    + `<p>${esc(change.description)}</p>${boundary}${consequence}`
    + (graph ? `<ol class="path-graph" aria-label="Path nodes">${graph}</ol>` : "")
    + `</article>`;
}

function showNode(button) {
  const entry = compareNodes[Number(button.dataset.node)];
  if (!entry) return;
  $("pathChanges").querySelectorAll(".path-node").forEach((item) => {
    item.setAttribute("aria-pressed", item === button ? "true" : "false");
  });
  const { node, limitations } = entry;
  const detail = $("nodeDetail");
  detail.hidden = false;
  detail.innerHTML = `<h4>${esc(ROLE_LABEL[node.role] || node.role)}: ${esc(node.label)}</h4>`
    + `<dl><dt>Location</dt><dd>${esc(node.file ? node.file + ":" + node.line : "unresolved")}</dd>`
    + `<dt>Evidence</dt><dd>${evidenceTag(node.status)}</dd>`
    + (node.detail ? `<dt>Detail</dt><dd>${esc(node.detail)}</dd>` : "")
    + `</dl>`
    + (limitations.length
      ? `<ul>${limitations.map(item => `<li>${esc(item)}</li>`).join("")}</ul>` : "");
}

$("compareDemoPy").addEventListener("click", () => compareDemo("python", "candidate"));
$("compareDemoTs").addEventListener("click", () => compareDemo("typescript", "candidate"));
$("compareDemoFix").addEventListener("click", () => compareDemo(compareLanguage, "fixed"));
$("compareRun").addEventListener("click", compareRepo);

// ── agent security: agent → MCP server → tool → operation → identity ───────────
// Renders the AgentSecurityReport the backend returns (`aibom scan --agent-security`).
// Nothing here infers anything: verdicts, unknowns and evidence come from the report.
const SEC_COL = { agent: 0, mcp_client: 0, mcp_server: 1, tool: 2, operation: 3, identity: 4 };
const SEC_COL_TITLE = ["AGENT / CLIENT", "MCP SERVER", "TOOL", "CLOUD OPERATION", "IDENTITY"];
const SEC_STRUCT_EDGES = new Set(["BINDS_TOOL", "CONNECTS_MCP", "CONFIGURES_MCP", "EXPOSES_TOOL",
  "REACHES_OPERATION"]);
const VERDICT_RANK = { potentially_allowed: 0, unknown: 1,
  no_matching_allow_in_supplied_policies: 2, explicitly_denied: 3 };
const VERDICT_LABEL = { potentially_allowed: "potentially allowed",
  explicitly_denied: "explicitly denied",
  no_matching_allow_in_supplied_policies: "no matching allow", unknown: "unknown" };
const HAZARD_SEV = { list: "low", read: "medium", write: "high", delete: "high",
  secrets_read: "high", admin: "critical" };
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const UNKNOWN_REASON = {
  identity_unmapped: "Agent has no identity mapping in aibom-identity.yaml, so its cloud "
    + "permissions cannot be evaluated. Verdicts stay Unknown; the role is never guessed.",
  mcp_server_identity_unmapped: "MCP server has no identity mapping, so its tools' cloud "
    + "operations cannot be evaluated.",
  remote_server_tools_unknown: "Remote MCP server (SSE / HTTP): its tools are not in this "
    + "repository and servers are never contacted.",
  server_outside_analyzed_sources: "MCP server launched from outside the repository.",
  mcp_tool_filter_unresolved: "tool_filter is not a literal; every tool is treated as exposed.",
  mcp_servers_not_a_literal_list: "mcp_servers is built dynamically; connections not resolved.",
  delegate_unresolved: "Handoff / agent-as-tool target could not be resolved statically.",
  tool_definition_unresolved: "A tool bound to the agent could not be traced to its code.",
  policy_unparsable: "An identity policy file could not be parsed.",
};

function verdictTag(verdict) {
  return `<span class="verdict-tag v-${esc(verdict)}">${esc(VERDICT_LABEL[verdict] || verdict)}</span>`;
}
function secLoc(ev) {
  if (!ev) return "";
  return ev.file + (ev.line ? ":" + ev.line : "") + (ev.pointer ? "#" + ev.pointer : "");
}
function uniqueLocs(list, limit) {
  return [...new Set((list || []).map(secLoc).filter(Boolean))].slice(0, limit || 6);
}

function findingThreeParts(f) {
  const where = [f.source_kind, f.sink_kind].filter(Boolean).join(" → ");
  const locs = (f.source_evidence || []).slice(0, 3).map(srcLink).join(", ");
  const impact = esc(f.description)
    + (f.trust_boundary ? ` <span class="muted">Trust boundary: ${esc(f.trust_boundary)}.</span>` : "");
  const steps = (f.data_flow_path || []).slice(0, 6).map(step =>
    `${step.operation}${step.symbol ? " " + step.symbol : ""} @ ${step.file}${step.line ? ":" + step.line : ""}`);
  const level = f.evidence_level
    ? evidenceTag(f.evidence_level)
    : `<span class="evidence-tag" title="A deterministic rule matched the code or manifest at these lines">Rule match</span>`;
  const count = (f.source_evidence || []).length;
  const evidence = `${level} ${where ? `<code>${esc(where)}</code> ` : ""}`
    + (steps.length ? `<br><span class="muted">${esc(steps.join(" → "))}</span>`
      : `<span class="muted">matched at ${count} source location(s)${locs ? ": " : ""}</span>${locs}`);
  return `<div class="f3"><span class="f3-label l-impact">Impact</span><div>${impact}</div>`
    + `<span class="f3-label l-evidence">Evidence</span><div>${evidence}</div>`
    + `<span class="f3-label l-fix">Fix</span><div>${esc(f.remediation)}</div></div>`;
}

function usageCell(e, reach) {
  if (reach === "n/a") return `<span class="muted">—</span>`;
  const states = ["declared", "imported", "instantiated", "invoked"]
    .filter(name => e.usage && e.usage[name]);
  const reachText = reach === "unknown"
    ? `<span class="muted" title="Static analysis did not connect this component to a `
      + `production entry point. Unknown is not unreachable.">entry point: unknown</span>`
    : `entry point: ${reach === "true" ? "reachable" : reach === "false" ? "not reachable" : esc(reach)}`;
  return (states.length ? esc(states.join(" → ")) + " → " : "") + reachText;
}

function selectTab(name) {
  document.querySelectorAll(".result-tab").forEach(tab => {
    tab.setAttribute("aria-selected", tab.dataset.tab === name ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.hidden = panel.dataset.panel !== name;
  });
  if (name === "graph") setZoom($("graph"), "default");
  if (name === "deps" && !$("depsMap").hidden) drawDepsGraph();
}
document.querySelectorAll(".result-tab").forEach(tab => {
  tab.addEventListener("click", () => selectTab(tab.dataset.tab));
});

function secModel(report, names) {
  const nodes = new Map(), edges = new Map();
  for (const n of report.nodes || []) {
    if (!(n.kind in SEC_COL)) continue;
    nodes.set(n.id, { id: n.id, kind: n.kind, label: n.label,
      unresolved: n.resolution_status !== "resolved" && n.kind !== "operation",
      evidence: [...(n.evidence || [])], paths: [], record: null, dormant: false });
  }
  const node = (id, kind, label) => {
    if (!nodes.has(id)) {
      nodes.set(id, { id, kind, label, unresolved: false, evidence: [], paths: [], record: null,
        dormant: false });
    }
    return nodes.get(id);
  };
  const edge = (source, target, kind) => {
    if (!nodes.has(source) || !nodes.has(target)) return null;
    const id = source + "→" + target;
    if (!edges.has(id)) edges.set(id, { id, source, target, kind, evidence: [], verdict: null,
      dormant: false });
    return edges.get(id);
  };
  for (const e of report.edges || []) {
    if (!SEC_STRUCT_EDGES.has(e.kind)) continue;
    const made = edge(e.source, e.target, e.kind);
    if (!made) continue;
    made.evidence.push(...(e.evidence || []));
    if (e.kind === "EXPOSES_TOOL" || e.kind === "BINDS_TOOL") {
      nodes.get(e.target).evidence.push(...(e.evidence || []));
    }
  }
  const exposed = new Set();
  for (const a of report.agents || []) {
    const n = node(a.id, "agent", a.display_name || a.source);
    n.record = a;
    (a.tool_ids || []).forEach(id => exposed.add(id));
    (a.mcp_tool_ids || []).forEach(id => exposed.add(id));
  }
  for (const server of report.mcp_servers || []) {
    const n = node(server.id, "mcp_server", server.name || server.file);
    n.record = server;
    for (const tool of server.tools || []) {
      const t = node(tool.tool_id, "tool", tool.name);
      t.record = tool;
      edge(server.id, tool.tool_id, "EXPOSES_TOOL");
    }
  }
  // An MCP tool no analyzed agent is connected to is defined, not exposed.
  for (const e of edges.values()) {
    if (e.kind === "EXPOSES_TOOL" && !exposed.has(e.target)) {
      e.dormant = true;
      nodes.get(e.target).dormant = true;
    }
  }
  for (const op of report.operations || []) {
    const n = node(`operation:${op.action}|${op.resource}`, "operation", `${op.action}`);
    n.op = op;
    n.evidence.push(...(op.evidence || []));
    const e = edge(op.tool_id, n.id, "REACHES_OPERATION");
    if (e && nodes.get(op.tool_id) && nodes.get(op.tool_id).dormant) e.dormant = true;
  }
  for (const p of report.capability_paths || []) {
    const opId = `operation:${p.action}|${p.resource}`;
    const op = node(opId, "operation", p.action);
    const identityId = p.identity_id || "identity:unmapped";
    const identity = node(identityId, "identity", p.identity_id || "unmapped identity");
    if (!p.identity_id) identity.unresolved = true;
    for (const id of [opId, identityId, p.tool_id, p.agent_id, p.mcp_server_id]) {
      if (id && nodes.has(id)) nodes.get(id).paths.push(p);
    }
    const e = edge(opId, identityId, "EVALUATED_AS");
    if (e && (e.verdict == null || VERDICT_RANK[p.verdict] < VERDICT_RANK[e.verdict])) {
      e.verdict = p.verdict;
    }
    if (!op.op) op.hazard = p.hazard;
  }
  for (const n of nodes.values()) {
    if (n.kind === "operation") {
      n.label = n.label.split(" ")[0];
      n.hazard = n.hazard || (n.op && n.op.hazard);
    }
  }
  // The report labels an unresolved tool by its inventory id; show the inventory name.
  for (const n of nodes.values()) {
    if (n.kind === "tool" && names && names[n.id] && n.label === n.id) {
      n.label = names[n.id].split("@")[0];
    }
  }
  // Operation nodes nobody reaches and identities nobody evaluates add only noise.
  for (const [id, n] of nodes) {
    const linked = [...edges.values()].some(e => e.source === id || e.target === id);
    if (!linked && (n.kind === "operation" || n.kind === "identity")) nodes.delete(id);
  }
  return { nodes, edges, report };
}

function secLayout(model) {
  const used = [...new Set([...model.nodes.values()].map(n => SEC_COL[n.kind]))].sort();
  const colOf = (n) => used.indexOf(SEC_COL[n.kind]);
  const W_NODE = 172, H_NODE = 40, X_STEP = 216, Y_STEP = 52, TOP = 34, PAD = 14;
  const columns = used.map(() => []);
  for (const n of model.nodes.values()) columns[colOf(n)].push(n);
  const row = new Map();
  const preds = (n) => [...model.edges.values()].filter(e => e.target === n.id && row.has(e.source));
  columns.forEach((col, ci) => {
    if (ci === 0) {
      col.sort((a, b) => (a.kind === b.kind ? a.label.localeCompare(b.label)
        : a.kind === "agent" ? -1 : 1));
    } else {
      const score = (n) => {
        const ps = preds(n);
        return ps.length ? ps.reduce((sum, e) => sum + row.get(e.source), 0) / ps.length : 1e6;
      };
      col.sort((a, b) => (score(a) - score(b)) || a.label.localeCompare(b.label));
    }
    col.forEach((n, ri) => {
      row.set(n.id, ri);
      n.x = PAD + ci * X_STEP;
      n.y = TOP + ri * Y_STEP;
      n.w = W_NODE; n.h = H_NODE;
    });
  });
  const rows = Math.max(1, ...columns.map(c => c.length));
  return { used, W: PAD * 2 + (used.length - 1) * X_STEP + W_NODE, H: TOP + rows * Y_STEP + 6,
    X_STEP, PAD };
}

function secSub(n) {
  if (n.kind === "agent") {
    const r = n.record || {};
    return r.identity_id ? "runs as " + r.identity_id.split("/").pop() : "identity unmapped";
  }
  if (n.kind === "mcp_server") {
    const r = n.record || {};
    return `${(r.tools || []).length} tool(s) · ${r.status || "defined"}`;
  }
  if (n.kind === "mcp_client") return "client config";
  if (n.kind === "tool") {
    const kinds = (n.record && n.record.capability_kinds) || [];
    if (n.dormant) return "defined, not exposed";
    return kinds.length ? kinds.join(", ") : "tool";
  }
  if (n.kind === "operation") return (n.hazard || "operation") + " · " + (n.op ? n.op.resource : "");
  if (n.kind === "identity") return n.unresolved ? "no manifest mapping" : "identity policy";
  return n.kind;
}

function nodeSeverity(n) {
  if (n.kind === "operation") return HAZARD_SEV[n.hazard] || null;
  if (n.kind === "tool" && n.record && n.record.capability_severity) return n.record.capability_severity;
  return null;
}

// diffBase: an older model; nodes/edges absent from it, newly exposed, or with a
// changed verdict are highlighted.
function renderSecGraph(host, detailHost, model, diffBase) {
  host.innerHTML = "";
  detailHost.innerHTML = `<span class="muted">Select a node to see its file-and-line evidence.</span>`;
  if (!model.nodes.size) {
    host.innerHTML = `<p class="empty-graph">No agent, MCP server or tool was found in production `
      + `code. Agent analysis covers the Python OpenAI Agents SDK and Python MCP servers.</p>`;
    return;
  }
  const L = secLayout(model);
  const changed = new Set();
  if (diffBase) {
    for (const n of model.nodes.values()) {
      const old = diffBase.nodes.get(n.id);
      if (!old || (old.dormant && !n.dormant)) n.isNew = true;
    }
    for (const e of model.edges.values()) {
      const old = diffBase.edges.get(e.id);
      if (!old || (old.dormant && !e.dormant) || (old.verdict !== e.verdict && e.verdict)) {
        e.isNew = true;
        if (old && old.verdict !== e.verdict) changed.add(e.source);
      }
    }
  }
  const svg = svgEl("svg", { viewBox: `0 0 ${L.W} ${L.H}`, role: "group",
    "aria-label": "Agent security graph" });
  // Natural size when it fits; wider graphs scale down rather than clip.
  svg.style.width = "100%";
  svg.style.maxWidth = L.W + "px";
  L.used.forEach((col, ci) => {
    const t = svgEl("text", { x: L.PAD + ci * L.X_STEP, y: 18, class: "sg-col-title" });
    t.textContent = SEC_COL_TITLE[col];
    svg.appendChild(t);
  });
  const gE = svgEl("g", {}), gN = svgEl("g", {});
  svg.appendChild(gE); svg.appendChild(gN);
  const edgeEls = [];
  for (const e of model.edges.values()) {
    const s = model.nodes.get(e.source), t = model.nodes.get(e.target);
    if (!s || !t) continue;
    const x1 = s.x + s.w, y1 = s.y + s.h / 2, x2 = t.x, y2 = t.y + t.h / 2;
    const dx = Math.max(30, (x2 - x1) / 2);
    const cls = ["sg-edge", e.verdict ? "v-" + e.verdict : "", e.dormant ? "is-dormant" : "",
      e.isNew ? "is-new" : ""].filter(Boolean).join(" ");
    const path = svgEl("path", { d: `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`,
      class: cls });
    if (e.verdict) {
      const title = svgEl("title", {});
      title.textContent = VERDICT_LABEL[e.verdict] || e.verdict;
      path.appendChild(title);
    }
    gE.appendChild(path);
    edgeEls.push({ e, el: path });
  }
  const nodeEls = [];
  for (const n of model.nodes.values()) {
    const sev = nodeSeverity(n);
    const cls = ["sg-node", "k-" + n.kind, sev === "critical" || sev === "high" ? "h-" + sev : "",
      n.unresolved ? "is-unresolved" : "", n.dormant ? "is-dormant" : "",
      n.isNew ? "is-new" : ""].filter(Boolean).join(" ");
    const g = svgEl("g", { class: cls, tabindex: "0", role: "button",
      "aria-label": `${n.kind.replace("_", " ")}: ${n.label}` });
    g.appendChild(svgEl("rect", { x: n.x, y: n.y, width: n.w, height: n.h, rx: 6 }));
    const label = n.label.length > 23 ? n.label.slice(0, 22) + "…" : n.label;
    const t1 = svgEl("text", { x: n.x + 9, y: n.y + 16 });
    t1.textContent = label;
    const sub = secSub(n);
    const t2 = svgEl("text", { x: n.x + 9, y: n.y + 31, class: "sg-sub" });
    t2.textContent = sub.length > 30 ? sub.slice(0, 29) + "…" : sub;
    g.appendChild(t1); g.appendChild(t2);
    if (n.isNew || changed.has(n.id)) {
      const badge = svgEl("text", { x: n.x + n.w - 6, y: n.y + 12, "text-anchor": "end",
        class: "sg-badge" });
      badge.textContent = n.isNew ? "NEW" : "CHANGED";
      g.appendChild(badge);
    }
    const choose = (ev) => {
      ev.stopPropagation();
      secSelect(n, model, nodeEls, edgeEls);
      renderSecDetail(detailHost, n, model);
    };
    g.addEventListener("click", choose);
    g.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); choose(ev); }
    });
    gN.appendChild(g);
    nodeEls.push({ n, el: g });
  }
  svg.addEventListener("click", () => secSelect(null, model, nodeEls, edgeEls));
  host.appendChild(svg);
}

function secSelect(node, model, nodeEls, edgeEls) {
  if (!node) {
    nodeEls.forEach(({ el }) => el.classList.remove("is-dim", "is-selected"));
    edgeEls.forEach(({ el }) => el.classList.remove("is-dim"));
    return;
  }
  // Everything upstream and downstream of the node: the paths it takes part in.
  const walk = (forward) => {
    const seen = new Set([node.id]);
    const queue = [node.id];
    while (queue.length) {
      const id = queue.shift();
      for (const e of model.edges.values()) {
        const [from, to] = forward ? [e.source, e.target] : [e.target, e.source];
        if (from === id && !seen.has(to)) { seen.add(to); queue.push(to); }
      }
    }
    return seen;
  };
  const keep = new Set([...walk(true), ...walk(false)]);
  nodeEls.forEach(({ n, el }) => {
    el.classList.toggle("is-dim", !keep.has(n.id));
    el.classList.toggle("is-selected", n.id === node.id);
  });
  edgeEls.forEach(({ e, el }) => el.classList.toggle("is-dim",
    !(keep.has(e.source) && keep.has(e.target))));
}

function renderSecDetail(host, n, model) {
  const rows = [];
  const add = (k, v) => { if (v != null && v !== "") rows.push(`<dt>${esc(k)}</dt><dd>${v}</dd>`); };
  const r = n.record || {};
  if (n.kind === "agent") {
    add("Identity", r.identity_id ? `<code>${esc(r.identity_id)}</code>`
      : `<span class="verdict-tag v-unknown">unmapped</span> add it to aibom-identity.yaml`);
    add("Tools", String((r.tool_ids || []).length + (r.mcp_tool_ids || []).length));
    add("Untrusted input", r.external_input ? "reaches its instructions (proven)" : "not proven");
    add("Registry", esc(r.management_status || "unknown"));
    const delegations = (model.report.delegations || []).filter(d => d.parent_id === n.id);
    if (delegations.length) {
      add("Delegates to", delegations.map(d => `${esc(d.mechanism)} → `
        + `<code>${esc(d.child_id || d.child_ref)}</code>`).join("<br>"));
    }
  } else if (n.kind === "mcp_server") {
    add("File", `<code>${esc(r.file)}</code>`);
    add("Status", esc(r.status));
    add("Runs as", r.identity_id ? `<code>${esc(r.identity_id)}</code>`
      : `<span class="verdict-tag v-unknown">unmapped</span>`);
    add("Tools", (r.tools || []).map(t => esc(t.name)
      + (t.capability_kinds && t.capability_kinds.length
        ? ` <span class="cap-tag">${esc(t.capability_kinds.join(", "))}</span>` : "")).join("<br>"));
  } else if (n.kind === "tool") {
    add("Exposure", n.dormant ? "defined on an MCP server; no analyzed agent is connected"
      : "bound or exposed to an analyzed agent");
    if (r.capability_kinds && r.capability_kinds.length) {
      add("Capability", `<span class="cap-tag">${esc(r.capability_kinds.join(", "))}</span> `
        + esc(r.capability_severity || ""));
    }
  } else if (n.kind === "operation") {
    add("Action", `<code>${esc(n.label)}</code>`);
    if (n.op) add("Resource", `<code>${esc(n.op.resource)}</code>${n.op.resource_resolved ? ""
      : ' <span class="muted">(partially resolved)</span>'}`);
    add("Hazard", esc(n.hazard || "—"));
    if (n.op && n.op.derived_action) add("Note", "IAM action derived from the boto3 API name");
  } else if (n.kind === "identity") {
    const identity = (model.report.identities || []).find(i => i.id === n.id);
    add("Policies", identity ? identity.policies.map(p => `<code>${esc(p)}</code>`).join("<br>")
      : "none: no aibom-identity.yaml mapping");
  }
  let html = `<span class="dt-type">${esc(n.kind.replace("_", " "))}</span><h3>${esc(n.label)}</h3>`
    + (rows.length ? `<dl>${rows.join("")}</dl>` : "");
  const paths = n.paths.slice().sort((a, b) => VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict]);
  if (paths.length) {
    html += `<h4>Capability paths (${paths.length})</h4><ul>` + paths.slice(0, 8).map(p =>
      `<li>${verdictTag(p.verdict)} <code>${esc(p.tool_name)}</code> → <code>${esc(p.action)}</code>`
      + (p.reasons.length ? `<br><span class="muted">${esc(p.reasons.join(", "))}</span>` : "")
      + (p.constraints.length ? `<br><span class="muted">conditions: ${esc(p.constraints.join(", "))}</span>` : "")
      + `</li>`).join("") + `</ul>`;
  }
  const locs = uniqueLocs([...n.evidence, ...paths.flatMap(p => p.evidence || [])], 8);
  html += `<h4>Evidence</h4>` + (locs.length
    ? `<ul>${locs.map(l => `<li><code>${esc(l)}</code></li>`).join("")}</ul>`
    : `<p class="muted">No source location recorded for this node.</p>`);
  host.innerHTML = html;
}

function attackPathCards(report) {
  const agents = Object.fromEntries((report.agents || []).map(a => [a.id, a.display_name || a.source]));
  const servers = Object.fromEntries((report.mcp_servers || []).map(s => [s.id, s.name || s.file]));
  const paths = (report.capability_paths || []).slice().sort((a, b) =>
    (VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict])
    || (SEV_RANK[HAZARD_SEV[a.hazard]] - SEV_RANK[HAZARD_SEV[b.hazard]]));
  const hop = (kind, text) => `<span class="ap-hop k-${kind}">${esc(text)}</span>`;
  const arrow = `<span class="ap-arrow">→</span>`;
  const cards = paths.slice(0, 5).map(p => {
    const sev = HAZARD_SEV[p.hazard] || "info";
    const route = [hop("agent", agents[p.agent_id] || p.agent_id),
      ...(p.via === "mcp" ? [hop("mcp_server", "MCP " + (servers[p.mcp_server_id] || "server"))] : []),
      hop("tool", p.tool_name), hop("operation", `${p.action} ${p.resource}`),
      hop("identity", p.identity_id || "unmapped identity")].join(arrow);
    const why = p.verdict === "potentially_allowed"
      ? `The supplied policy for ${p.identity_id} matches with an Allow.`
      : p.reasons.length ? p.reasons.join(", ") : VERDICT_LABEL[p.verdict];
    return `<article class="attack-path" data-verdict="${esc(p.verdict)}"><header>`
      + `${sevTag(sev)} ${verdictTag(p.verdict)} <strong>${esc(agents[p.agent_id] || p.agent_id)} can reach `
      + `${esc(p.action)}</strong></header><div class="ap-route">${route}</div>`
      + `<div class="ap-meta">${esc(why)} · evidence `
      + uniqueLocs(p.evidence, 3).map(l => `<code>${esc(l)}</code>`).join(" ")
      + `</div></article>`;
  });
  if (paths.length > 5) cards.push(`<p class="field-help">${paths.length - 5} more path(s) in the graph below.</p>`);
  // MCP tools with dangerous capabilities matter even with no agent in the repository.
  for (const server of report.mcp_servers || []) {
    const risky = (server.tools || []).filter(t => (t.capability_kinds || []).length);
    if (!risky.length) continue;
    const worst = risky.map(t => t.capability_severity || "info")
      .sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0];
    const connected = server.status === "connected";
    cards.push(`<article class="attack-path" data-verdict="${connected ? "potentially_allowed" : "unknown"}">`
      + `<header>${sevTag(worst)} <strong>MCP server “${esc(server.name || server.file)}” `
      + `exposes ${(server.tools || []).length} LLM-invokable tool(s)</strong></header>`
      + `<div class="ap-route">${risky.map(t => `${hop("tool", t.name)} <span class="cap-tag">`
        + `${esc(t.capability_kinds.join(", "))}</span>`).join(" ")}</div>`
      + `<div class="ap-meta">${connected ? "An analyzed agent connects to this server."
        : "No analyzed agent connects to it in this repository: any MCP client that launches it "
          + "can call these tools."} · evidence ${uniqueLocs(server.evidence, 2)
        .map(l => `<code>${esc(l)}</code>`).join(" ")}</div></article>`);
  }
  return cards.join("");
}

function unknownsHtml(report) {
  const groups = {};
  for (const u of report.unknowns || []) (groups[u.reason] = groups[u.reason] || []).push(u);
  const reasons = Object.keys(groups);
  if (!reasons.length) return "";
  const items = reasons.map(reason => {
    const subjects = [...new Set(groups[reason].map(u => u.subject))];
    return `<li><strong>${esc(UNKNOWN_REASON[reason] || "Not statically resolvable.")}</strong>`
      + ` <span class="muted">(${esc(reason)}; ${subjects.length} subject(s))</span>`
      + `<br><span class="muted">${esc(subjects.slice(0, 4).join(", "))}`
      + `${subjects.length > 4 ? ` +${subjects.length - 4}` : ""}</span></li>`;
  }).join("");
  const total = (report.unknowns || []).length;
  return `<details open><summary>Unresolved: ${total} item(s) for ${reasons.length} reason(s). `
    + `Shown, never counted as safe.</summary><ul>${items}</ul></details>`;
}

let agentModel = null;
function renderAgentSecurity(report, inventory) {
  const graphHost = $("agentGraph"), detailHost = $("agentDetail");
  const state = agentState(report);
  const status = $("agentStatus");
  status.textContent = state.text;
  status.dataset.state = state.state;
  // A tab for a feature that found nothing to analyze only adds noise.
  $("agentTab").hidden = state.state === "not_detected";
  if (state.state === "failed" || state.state === "not_run" || state.state === "not_detected") {
    agentModel = null;
    $("attackPaths").innerHTML = "";
    $("agentUnknowns").innerHTML = "";
    $("agentGraphGrid").hidden = true;
    graphHost.innerHTML = "";
    detailHost.innerHTML = "";
    return;
  }
  $("agentGraphGrid").hidden = false;
  const names = Object.fromEntries(((inventory && inventory.entities) || []).map(e => [e.id, e.name]));
  agentModel = secModel(report, names);
  $("attackPaths").innerHTML = attackPathCards(report);
  renderSecGraph(graphHost, detailHost, agentModel, null);
  $("agentUnknowns").innerHTML = unknownsHtml(report);
}

// What a reader must see first: the worst-finding status, what was found, and
// what the scan could not see. Zero counts of features that do not apply stay
// out of the way.
function agentState(report) {
  if (!report) return { state: "not_run", text: "Agent analysis was not run." };
  if (report.error) {
    return { state: "failed", text: "Agent analysis failed: " + report.error
      + ". Nothing is inferred about agents in this repository." };
  }
  const agents = (report.agents || []).length;
  const servers = (report.mcp_servers || []).length;
  if (!agents && !servers) {
    return { state: "not_detected", text: "No agent or MCP server was found in production code. "
      + "Supported: Python OpenAI Agents SDK agents and MCP servers/configs; other "
      + "frameworks are not analyzed, so this is not a proof that none exist." };
  }
  const subject = [agents ? `${agents} agent(s)` : "", servers ? `${servers} MCP server(s)` : ""]
    .filter(Boolean).join(" and ");
  if (!(report.scope && report.scope.manifest)) {
    return { state: "not_evaluated", text: `${subject} found. Cloud permissions were not `
      + "evaluated: the repository has no aibom-identity.yaml mapping agents to IAM policies." };
  }
  const allowed = (report.capability_paths || [])
    .filter(p => p.verdict === "potentially_allowed").length;
  return { state: "evaluated", text: `${subject} found; permissions checked against the `
    + `supplied policies: ${allowed} path(s) potentially allowed.` };
}

function renderSummary(d) {
  const h = d.headline || { status: "no_findings", label: "No findings from the applied rules",
    detail: "" };
  const dep = (d.dependencies && d.dependencies.summary) || null;
  const entities = (d.inventory && d.inventory.entities) || [];
  const scope = d.analysis_scope || {};
  const aiTotal = entities.filter(e => e.type !== "package" || e.ai).length;
  const sevs = (d.score && d.score.severity_counts) || {};
  const vuln = d.vulnerable_packages || [];
  const agent = agentState(d.agent_security);
  const impact = (d.graph && d.graph.impact_paths) || [];
  const tile = (n, label, cls, note) => `<div class="sum-tile ${cls || ""}"><strong>${n}</strong>`
    + `<span>${esc(label)}</span>${note ? `<small>${esc(note)}</small>` : ""}</div>`;
  const sevNote = ["critical", "high", "medium", "low"].filter(s => sevs[s])
    .map(s => `${sevs[s]} ${s}`).join(" · ");
  const tiles = [
    tile((d.findings || []).length, "findings",
      h.status === "action_required" ? "is-bad" : h.status === "review" ? "is-warn" : "",
      sevNote || "none from the applied rules"),
  ];
  if (dep) {
    tiles.push(tile(dep.total, "packages",
      "", `${dep.direct} direct · ${dep.transitive} transitive · relations known for `
        + `${dep.relations_resolved}`));
  }
  if (vuln.length) {
    tiles.push(tile(vuln.length, "vulnerable packages", "is-bad",
      `${vuln.filter(v => v.recommended_version).length} with a known fixed release`));
  }
  tiles.push(tile(scope.production_ai_components ?? aiTotal, "AI components in production code",
    "", scope.excluded_non_production_entities
      ? `${scope.excluded_non_production_entities} more in test/example/docs` : ""));
  if (impact.length) {
    tiles.push(tile(impact.length, "input-to-tool paths", "is-bad", "untrusted input reaches a bound tool"));
  }
  if (agent.state !== "not_detected") {
    tiles.push(tile((d.agent_security && d.agent_security.agents || []).length, "agents",
      agent.state === "failed" ? "is-warn" : "", agent.state.replace("_", " ")));
  }

  const contexts = {};
  for (const e of entities) {
    const list = e.source_contexts && e.source_contexts.length ? e.source_contexts : ["unknown"];
    for (const c of list) contexts[c] = (contexts[c] || 0) + 1;
  }
  const contextLine = Object.keys(contexts).length > 1 || !contexts.production
    ? `<p class="sum-contexts">Components by source context: ${Object.entries(contexts)
        .sort((a, b) => b[1] - a[1]).map(([c, n]) => `<button type="button" class="link" `
        + `data-context="${esc(c)}">${esc(c)} ${n}</button>`).join(" · ")}. Risk rules and the `
        + `AI usage map use production code only; the Inventory lists everything.</p>` : "";

  const limits = [...(d.coverage_notes || [])];
  if (agent.state !== "evaluated") limits.push(agent.text);
  const top = (d.findings || []).slice().sort((a, b) =>
    (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9))[0];
  const start = top && h.status !== "no_findings"
    ? `<p class="sum-start">Start with: <button type="button" class="link" data-goto="findings">`
      + `${esc(top.title)}</button> (${esc(top.severity)})</p>` : "";

  $("securitySummary").innerHTML =
    `<div class="headline ${esc(h.status)}"><p class="headline-label">${esc(h.label)}</p>`
    + `<p>${esc(h.detail)}</p>${start}</div>`
    + `<div class="sum-tiles">${tiles.join("")}</div>`
    + contextLine
    + (limits.length ? `<details class="limits" open><summary>Analysis limits (${limits.length})`
      + `</summary><ul>${limits.map(n => `<li>${esc(n)}</li>`).join("")}</ul></details>` : "");
  $("securitySummary").querySelectorAll("[data-context]").forEach(btn => {
    btn.addEventListener("click", () => {
      $("contextFilter").value = btn.dataset.context;
      selectTab("inventory");
      filterInventory();
    });
  });
  $("tabCountFindings").textContent = (d.findings || []).length || "";
  $("tabCountDeps").textContent = dep ? dep.total : "";
  $("tabCountInventory").textContent = entities.length || "";
}

// ── agent privilege drift (Baseline → Candidate → Fixed) ──────────────────────────
const DRIFT_BUTTONS = ["driftDemoPolicy", "driftDemoMcp"];
const DRIFT_TYPE_LABEL = {
  permission_scope_expanded: "Permission scope expanded",
  privilege_path_added: "Privilege path added",
  privileged_identity_binding_added: "Privileged identity binding",
  identity_permission_expanded: "Identity grant expanded (unused)",
  review_required: "Review required",
  potential_privilege_removed: "Privilege removed",
  mcp_tool_exposure_added: "MCP tool newly exposed",
  delegate_path_added: "Delegation path added",
  unregistered_agent_added: "Unregistered agent",
};
let driftBody = null;

function setDriftStatus(msg, isErr) {
  const s = $("driftStatus"); s.textContent = msg; s.className = isErr ? "err" : "";
}

async function runPrivilegeScenario(scenario, button) {
  const original = button.textContent;
  DRIFT_BUTTONS.forEach(id => { $(id).disabled = true; });
  button.textContent = "Scanning 3 bundled revisions…";
  $("driftState").textContent = "Scanning";
  setCompareStatus("", false);
  setDriftStatus("Scanning the bundled baseline, candidate and fixed revisions (offline demo)…", false);
  try {
    const body = await postJson(apiBase() + "/api/agent-drift/demo?scenario=" + encodeURIComponent(scenario));
    renderDrift(body);
    $("driftState").textContent = "Scenario loaded";
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
    $("privResult").scrollIntoView({ behavior, block: "start" });
    $("privResult").focus({ preventScroll: true });
  } catch (e) {
    setDriftStatus("The demo could not be run: " + e.message, true);
    $("driftState").textContent = "Failed";
    if (e instanceof BackendUnavailable) showApiEndpointField();
  } finally {
    DRIFT_BUTTONS.forEach(id => { $(id).disabled = false; });
    button.textContent = original;
  }
}

function driftCard(title, label, report, note) {
  const agents = Object.fromEntries((report.agents || []).map(a => [a.id, a.display_name || a.id]));
  const items = (report.capability_paths || []).slice()
    .sort((a, b) => VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict])
    .map(p => `<li>${verdictTag(p.verdict)} ${esc(agents[p.agent_id] || p.agent_id)} → `
      + `${esc(p.tool_name)} → <code>${esc(p.action)}</code></li>`);
  return `<h4>${esc(title)}</h4><p class="revision-target">${esc(label)}</p>`
    + (note ? `<div>${note}</div>` : "")
    + `<div><strong>${report.capability_paths.length}</strong> capability path(s) · `
    + `${(report.unknowns || []).length} unknown(s)</div>`
    + (items.length ? `<ul>${items.join("")}</ul>` : "");
}

function privilegeChangesHtml(list, toolLabel) {
  const changes = list.slice().sort((a, b) =>
    (b.gates - a.gates) || (SEV_RANK[a.severity] - SEV_RANK[b.severity]));
  if (!changes.length) return `<p class="help">No permission change between the revisions.</p>`;
  return changes.map(c => {
    const rem = c.remediation || {};
    const verdicts = c.before_verdict || c.after_verdict
      ? `${verdictTag(c.before_verdict || "unknown")} → ${verdictTag(c.after_verdict || "unknown")}` : "";
    const subject = [c.agent, toolLabel[c.tool] || c.tool, c.action].filter(Boolean).join(" → ");
    return `<article class="drift-change" data-gates="${c.gates}"><header>${sevTag(c.severity)}`
      + ` <span class="evidence-tag">${esc(DRIFT_TYPE_LABEL[c.type] || c.type)}</span>`
      + ` <span class="evidence-tag" title="Whether aibom diff --agent-privileges --fail-on would fail on it">`
      + `${c.gates ? "can fail CI (--fail-on)" : "review only, never fails CI"}</span>`
      + ` <h4>${esc(subject)}${c.affected_resource ? ` on ${esc(c.affected_resource)}` : ""}</h4></header>`
      + `<div class="f3"><span class="f3-label l-impact">Impact</span><div>`
      + `${esc(rem.why_it_matters || "")} ${verdicts}</div>`
      + `<span class="f3-label l-evidence">Evidence</span><div>certainty: ${esc(c.certainty)}`
      + ` · ${(c.evidence || []).map(e => `<code>${esc(e)}</code>`).join(" ")}`
      + ((rem.conditions || []).length ? `<br><span class="muted">conditions: ${esc(rem.conditions.join(", "))}</span>` : "")
      + `</div><span class="f3-label l-fix">Fix</span><div>`
      + ((rem.recommended_actions || []).length
        ? `<ol>${rem.recommended_actions.map(a => `<li>${esc(a)}</li>`).join("")}</ol>` : "")
      + (rem.retest_command ? `<span class="muted">Retest: <code>${esc(rem.retest_command)}</code></span>` : "")
      + `</div></div></article>`;
  }).join("");
}

function renderDrift(body) {
  driftBody = body;
  const introduced = body.introduced, residual = body.residual;
  const gated = introduced.changes.filter(c => c.gates);
  const remaining = residual.changes.filter(c => c.gates);
  const counts = body.revisions.candidate.counts || {};
  const components = Object.entries(counts).filter(([k, n]) => n && k !== "prompt")
    .map(([k, n]) => `${n} ${k}`).join(", ");
  $("compareResult").hidden = true;
  $("privResult").hidden = false;
  const bom = $("driftBomVerdict");
  bom.className = "verdict " + (introduced.bom_components_unchanged ? "ok" : "warn");
  bom.innerHTML = `<p class="verdict-label">COMPONENTS</p><p class="verdict-value">`
    + `${introduced.bom_components_unchanged ? "Compared components identical" : "Changed"}</p>`
    + `<p class="verdict-note">` + (introduced.bom_components_unchanged
      ? `${esc(components)} in both revisions (prompts not compared as parts). A component `
        + "diff reports nothing."
      : esc(introduced.bom_differences.slice(0, 5).join(", "))) + `</p>`;
  const priv = $("driftPrivVerdict");
  priv.className = "verdict " + (gated.length ? "bad" : "ok");
  priv.innerHTML = `<p class="verdict-label">AGENT PERMISSIONS</p><p class="verdict-value">`
    + `${gated.length ? gated.length + " added" : "No change"}</p><p class="verdict-note">`
    + (gated.length ? esc([...new Set(gated.map(c => DRIFT_TYPE_LABEL[c.type] || c.type))].join(", "))
      + `. Changed file: <code>${esc(body.scenario.changed)}</code>. Judged against the bundled `
      + "identity policies only."
      : "No privilege addition.") + `</p>`;
  const fix = $("driftFixVerdict");
  const unknowns = (body.reports.fixed.unknowns || []).length;
  fix.className = "verdict " + (remaining.length ? "bad" : "ok");
  fix.innerHTML = `<p class="verdict-label">BUNDLED FIXED REVISION (DEMO)</p><p class="verdict-value">`
    + `${remaining.length ? remaining.length + " remain" : "No addition left"}</p><p class="verdict-note">`
    + `${esc(body.scenario.fix)}. Compared with the baseline: ${remaining.length} privilege `
    + `addition(s) remain${unknowns ? `, ${unknowns} unresolved (never counted as fixed)` : ""}. `
    + "This is the fixture shipped with the demo, not a check of your code.</p>";
  $("driftRevisions").innerHTML =
    `<article class="revision">${driftCard("Baseline", "bundled · least privilege", body.reports.baseline)}</article>`
    + `<span class="revision-arrow" aria-hidden="true">→</span>`
    + `<article class="revision">${driftCard("Candidate", "bundled · after the change", body.reports.candidate,
      `<span class="evidence-tag">changed</span> ${esc(body.scenario.change)}`)}</article>`;
  showDriftStage("candidate");
  const toolLabel = Object.fromEntries((body.reports.candidate.nodes || [])
    .filter(n => n.kind === "tool").map(n => [n.id, n.label]));
  $("driftChanges").innerHTML = privilegeChangesHtml(introduced.changes, toolLabel);
  setDriftStatus(`Demo: ${gated.length} privilege addition(s) that \`aibom diff --agent-privileges `
    + `--fail-on\` would fail on; the compared components are `
    + `${introduced.bom_components_unchanged ? "identical" : "changed"}.`, false);
}

function showDriftStage(stage) {
  if (!driftBody) return;
  document.querySelectorAll(".stage-toggle button").forEach(b => {
    b.setAttribute("aria-pressed", b.dataset.stage === stage ? "true" : "false");
  });
  const base = secModel(driftBody.reports.baseline);
  const model = secModel(driftBody.reports[stage]);
  renderSecGraph($("driftGraph"), $("driftDetail"), model, stage === "baseline" ? null : base);
  const revision = (driftBody.revisions || {})[stage] || {};
  $("driftDepTitle").textContent = "AI usage map · "
    + (stage === "fixed" ? "bundled fixed revision" : stage);
  renderGraph(revision.graph || { nodes: [], edges: [] }, [], DRIFT_GRAPH);
}
document.querySelectorAll(".stage-toggle button").forEach(b => {
  b.addEventListener("click", () => showDriftStage(b.dataset.stage));
});

$("driftDemoPolicy").addEventListener("click", () => runPrivilegeScenario("agent-privilege-drift", $("driftDemoPolicy")));
$("driftDemoMcp").addEventListener("click", () => runPrivilegeScenario("mcp-tool-exposure", $("driftDemoMcp")));

// ── views: Analyze (default) and Compare changes ──────────────────────────────
function showView(name) {
  document.querySelectorAll(".view").forEach(v => { v.hidden = v.dataset.view !== name; });
  document.querySelectorAll("[data-view-link]").forEach(a => {
    if (a.getAttribute("href") === "#help") return;
    if (a.dataset.viewLink === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}
function route() {
  const hash = location.hash.replace("#", "");
  if (hash === "compare") {
    showView("compare");
    window.scrollTo(0, 0);
  } else {
    showView("analyze");
    if (hash && hash !== "analyze") {
      const target = document.getElementById(hash);
      if (target) target.scrollIntoView();
    }
  }
}
window.addEventListener("hashchange", route);
route();

document.addEventListener("click", (ev) => {
  const goto = ev.target.closest("[data-goto]");
  if (goto) selectTab(goto.dataset.goto);
  const example = ev.target.closest("[data-example]");
  if (example) {
    if (example.dataset.example === "demo") runDemo();
    else {
      $("repo").value = example.dataset.example;
      $("repoRef").value = "";
      setStatus("Example URL added. Start the analysis when you are ready.", false);
      $("scanSection").scrollIntoView({ block: "start" });
      $("repo").focus();
    }
  }
});
$("cancelScan").addEventListener("click", () => { if (activeScan) activeScan.abort(); });
$("depsSearch").addEventListener("input", filterDeps);
document.querySelectorAll("[data-deps-view]").forEach(b =>
  b.addEventListener("click", () => setDepsView(b.dataset.depsView)));
$("depsFilter").addEventListener("change", filterDeps);
$("contextFilter").addEventListener("change", filterInventory);
$("repoRef").addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });

renderApiLine();

// Shareable demo links: ?repo=https://github.com/owner/repo prefills and scans.
const params = new URLSearchParams(location.search);
const preset = params.get("repo");

// Confirm the backend first: an autostarted analysis against a static host
// would otherwise fail with an error the visitor never asked for.
checkBackend().then((ready) => {
  if (!ready) return;
  if (params.get("demo") === "1") runDemo();
  else if (preset) { $("repo").value = preset; scan(); }
});
