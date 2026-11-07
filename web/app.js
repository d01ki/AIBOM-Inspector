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

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
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

function showWorkspaceState(code, title, copy) {
  $("workspaceStateCode").textContent = code;
  $("workspaceStateTitle").textContent = title;
  $("workspaceStateCopy").textContent = copy;
  $("emptyState").hidden = false;
  const state = $("resultState");
  const states = {
    "READY": ["Waiting for input", "idle"],
    "RUNNING": ["Analysis in progress", "running"],
    "NO RESULT": ["Analysis failed", "error"],
  };
  const next = states[code] || [code, "idle"];
  state.textContent = next[0];
  state.dataset.state = next[1];
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

// Reveal the results area and its exports.
function showResultBody() {
  $("scanResult").hidden = false;
  for (const id of SCAN_EXPORTS) $(id).hidden = false;
  $("emptyState").hidden = true;
  $("results").hidden = false;
}

// One busy/error/scroll path for every analysis the panel can start.
async function runAnalysis(button, busyLabel, spec) {
  const original = button.textContent;
  ACTION_BUTTONS.forEach((id) => { $(id).disabled = true; });
  button.textContent = busyLabel;
  $("scanSection").setAttribute("aria-busy", "true");
  $("results").hidden = true;
  setExportsEnabled(false);
  showWorkspaceState("RUNNING", spec.running[0], spec.running[1]);
  setStatus(spec.status, false);
  try {
    const data = await spec.request();
    spec.render(data);
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? "auto" : "smooth";
    $("results").scrollIntoView({ behavior, block: "start" });
    $("results").focus({ preventScroll: true });
  } catch (e) {
    const missing = e instanceof BackendUnavailable;
    setStatus(spec.failure + ": " + e.message, true);
    showWorkspaceState("NO RESULT", missing ? "No analysis backend" : spec.failure,
      missing
        ? "This page is only the interface. Start a backend with `aibom serve` (or the "
          + "Docker image) and enter its address above — nothing was analyzed."
        : "Review the error above, adjust the input if needed, and try again.");
    if (missing) showApiEndpointField();
  } finally {
    ACTION_BUTTONS.forEach((id) => { $(id).disabled = false; });
    button.textContent = original;
    $("scanSection").removeAttribute("aria-busy");
  }
}

function runDemo() {
  lastRequest = { repo_url: "built-in://impact-demo", resolve: false, api: apiBase(), demo: true };
  lastResult = null;
  return runAnalysis($("runDemo"), "Scanning the sample app…", {
    status: "Scanning the bundled sample app (offline)…",
    running: ["Scanning the bundled sample app",
      "Tracing external input through agent instructions to directly bound tool capabilities."],
    failure: "The bundled sample scan could not be completed",
    request: () => postJson(apiBase() + "/api/demo"),
    render: (data) => {
      renderScan(data);
      setStatus("Sample app scanned. Start with the path from untrusted input to the bound tool.", false);
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
  if (!isRepositoryUrl(repo)) {
    repoInput.setAttribute("aria-invalid", "true");
    setStatus(repo
      ? "Enter a complete repository URL, including https://."
      : "Enter a repository URL to start the analysis.", true);
    repoInput.focus();
    return Promise.resolve();
  }
  repoInput.removeAttribute("aria-invalid");
  lastRequest = { repo_url: repo, resolve: true, api: apiBase() };
  lastResult = null;
  return runAnalysis($("scan"), "Analyzing…", {
    status: "Inspecting " + repoLabel(repo) + "…",
    running: ["Scan in progress",
      "The repository is being cloned and analyzed. Results will replace this message when ready."],
    failure: "The analysis could not be completed",
    request: () => postJson(apiBase() + "/api/scan", { repo_url: repo, resolve: true }),
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
  $("resultOverline").textContent = "SCAN RESULT";
  const sc = d.score;
  const allEnts = (d.inventory && d.inventory.entities) || [];
  // Non-AI packages complete the BOM but don't count as AI usage.
  const totalEntities = allEnts.filter(e => e.type !== "package" || e.ai).length;
  const riskEntities = d.analysis_scope
    ? d.analysis_scope.production_ai_components : totalEntities;
  const excludedEntities = d.analysis_scope
    ? d.analysis_scope.excluded_non_production_entities : 0;
  const plainDeps = allEnts.length - totalEntities;
  $("resultRepoName").textContent = repoLabel(d.repo_url || lastRequest.repo_url);
  const scopeSuffix = excludedEntities
    ? ` \u00b7 ${excludedEntities} test/example/docs component(s) excluded from risk and graph`
    : "";
  $("resultMeta").textContent = statsLine(d.repo_url || lastRequest.repo_url, d.stats)
    + scopeSuffix;
  $("findingTotal").textContent = d.findings.length;
  $("componentTotal").textContent = totalEntities;
  $("fileTotal").textContent = d.stats && d.stats.files_scanned != null
    ? d.stats.files_scanned : "—";
  $("findingSearch").value = "";
  $("severityFilter").value = "all";
  $("inventorySearch").value = "";
  $("typeFilter").value = "all";
  $("reachFilter").value = "all";
  if (!riskEntities) {
    // "Nothing AI found" means exactly that, not "perfectly safe" —
    // don't present a triumphant 100/A over zero evidence.
    $("scoreNum").textContent = "—";
    $("scoreNum").style.color = "";
    $("scoreGrade").textContent = "no production AI components detected";
    $("cats").innerHTML = "<span class='muted'>Nothing to score in production scope."
      + (excludedEntities ? ` ${excludedEntities} test/example/docs component(s) remain `
      + "visible in the inventory but are excluded from risk and graph claims." : "")
      + (plainDeps ? ` ${plainDeps} ordinary dependencies were also catalogued.` : "")
      + "</span>";
  } else {
  $("scoreNum").textContent = sc.overall;
  const gradeColor = { A:"#2e8b57", B:"#6a9c3a", C:"#b8860b", D:"#d64500", F:"#b3123b" }[sc.grade] || "";
  const highestFinding = ["critical", "high", "medium", "low", "info"].find(
    severity => (sc.severity_counts[severity] || 0) > 0);
  const gradeWord = highestFinding === "critical" ? "critical finding present"
    : highestFinding === "high" ? "high finding present"
    : ({ A:"good hygiene", B:"minor issues", C:"needs attention",
         D:"poor hygiene", F:"serious issues" }[sc.grade] || "");
  $("scoreNum").style.color = gradeColor;
  $("scoreGrade").textContent = `/ 100 · grade ${sc.grade} — ${gradeWord}`;

  $("cats").innerHTML = sc.categories.map(c => {
    const col = c.score >= 75 ? "#2e8b57" : c.score >= 50 ? "#b8860b" : "#b3123b";
    const category = c.category.charAt(0).toUpperCase() + c.category.slice(1);
    return `<div class="cat"><div class="r"><span>${esc(category)}</span>`
      + `<span>${c.score} · ${c.finding_count} finding(s)</span></div>`
      + `<div class="bar"><span style="width:${c.score}%;background:${col}"></span></div></div>`;
  }).join("");

  $("chips").innerHTML = ["critical","high","medium","low","info"].map(s => {
    const n = sc.severity_counts[s] || 0;
    return n ? `<span class="chip" data-severity="${s}">${n} ${s}</span>` : "";
  }).join("");
  }
  if (!totalEntities) $("chips").innerHTML = "";

  const fb = $("findings").querySelector("tbody");
  $("findingCount").textContent = d.findings.length ? "(" + d.findings.length + ")" : "";
  if (!d.findings.length) {
    // "No findings" has two very different meanings. Say which one this is,
    // so an empty table is not mistaken for a broken scan.
    const why = !riskEntities
      ? (totalEntities
        ? `This repository's ${totalEntities} AI component(s) were all found in test, `
          + "example, or documentation files, which are deliberately excluded from risk "
          + "rules so a fixture cannot score its own repository. They are listed in the "
          + "Inventory below."
        : "No AI components were detected in this repository, so no AI risk rule applies. "
          + "Ordinary dependencies are still listed in the Inventory below.")
      : `The ${riskEntities} AI component(s) in production code matched none of the risk `
        + "rules. This covers the rules listed in the README — not every possible risk.";
    fb.innerHTML = `<tr><td colspan="4" class="empty empty-state">No findings. ${esc(why)}</td></tr>`;
  } else {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const orderedFindings = d.findings.slice().sort((a, b) =>
      (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
    fb.innerHTML = orderedFindings.map(f => {
      const locs = (f.source_evidence || []).slice(0, 4).map(evLoc).join(", ") || "—";
      return `<tr data-row="true" data-severity="${esc(f.severity)}">`
        + `<td><span class="sev" data-severity="${esc(f.severity)}">${esc(f.severity)}</span></td>`
        + `<td><code>${esc(f.rule_id)}</code></td>`
        + `<td><strong class="finding-title">${esc(f.title)}</strong>${findingThreeParts(f)}</td>`
        + `<td>${esc(f.entity_name || "—")}<br><code>${esc(locs)}</code></td></tr>`;
    }).join("");
  }

  renderGraph(d.graph || { nodes: [], edges: [] }, d.findings || []);

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
    const loc = e.source_evidence && e.source_evidence[0] ? evLoc(e.source_evidence[0]) : "—";
    const contexts = (e.source_contexts || []).join(", ") || "—";
    const detectors = (e.detector_ids || []).join(", ") || "—";
    const typeCell = e.type === "package" && e.ai
      ? "package <strong style='color:var(--accent)'>· AI</strong>"
      : esc(e.type);
    const reach = e.type === "package" ? "n/a" : ((e.usage && e.usage.reachable) || "unknown");
    return `<tr data-row="true" data-type="${esc(e.type)}" data-reach="${esc(reach)}">`
      + `<td>${typeCell}</td><td>${esc(e.name)}</td>`
      + `<td>${esc(prov)}</td><td>${usageCell(e, reach)}</td>`
      + `<td>${esc(contexts)}</td><td><code>${esc(loc)}</code><br>${esc(detectors)}</td></tr>`;
  }).join("") : `<tr><td colspan="6" class="empty empty-state">No components were discovered.</td></tr>`;

  const typeFilter = $("typeFilter");
  typeFilter.innerHTML = `<option value="all">All types</option>`;
  [...new Set(ents.map(e => e.type))].sort().forEach(type => {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type.charAt(0).toUpperCase() + type.slice(1);
    typeFilter.appendChild(option);
  });

  renderMinimumElements(d.minimum_elements);
  renderAgentSecurity(d.agent_security, d.inventory);
  renderSecuritySummary(d);
  selectTab("agent");

  $("resultState").textContent = "Analysis complete";
  $("resultState").dataset.state = "complete";
  filterFindings();
  filterInventory();
}

const ELEMENT_STATUS = {
  satisfied: { label: "verified", color: "#7adbb1" },
  partial: { label: "partial", color: "#efd078" },
  declared_unknown: { label: "unknown", color: "#a4b7ce" },
  missing: { label: "missing", color: "#ff879e" },
};
const ELEMENT_ORIGIN = {
  carried_over: "2021", updated_2026: "2026 updated", new_2026: "2026 new",
};

// CISA 2026 SBOM minimum elements: a declared known unknown is conformance,
// a silent gap is not — so the summary counts them separately.
function renderMinimumElements(report) {
  const body = document.querySelector("#elements tbody");
  if (!body) return;
  if (!report || !report.elements) {
    $("elementsSummary").innerHTML = "";
    body.innerHTML = `<tr><td colspan="5" class="empty empty-state">`
      + `No conformance report was returned.</td></tr>`;
    return;
  }
  const s = report.summary || {};
  const tile = (n, label, cls, note) => `<div class="sum-tile ${cls}"><strong>${n}</strong>`
    + `<span>${esc(label)}</span>${note ? `<small>${esc(note)}</small>` : ""}</div>`;
  $("elementsSummary").innerHTML = tile(s.satisfied, "verified", "is-ok", `of ${s.total} elements`)
    + tile(s.partial, "partial", s.partial ? "is-warn" : "", "some components only")
    + tile(s.declared_unknown, "unknown (declared)", "", "not knowable statically")
    + tile(s.missing, "missing", s.missing ? "is-bad" : "is-ok", "silent gaps")
    + `<p class="elements-note">${report.conformant
      ? `Conformant under the CISA 2026 rule: every element is either populated or explicitly `
        + `declared unknown in the BOM. That is not the same as complete — only `
        + `${s.satisfied} of ${s.total} elements are fully populated.`
      : `Not conformant: ${s.missing} element(s) are missing without an explicit `
        + `declaration.`}</p>`;
  body.innerHTML = report.elements.map(el => {
    const status = ELEMENT_STATUS[el.status] || ELEMENT_STATUS.missing;
    let coverage = el.applicable > 1 ? `${el.present}/${el.applicable}`
      : (el.present ? "yes" : "no");
    if (el.declared_unknown) coverage += ` <span class="muted">+${el.declared_unknown} declared</span>`;
    const detail = el.status === "satisfied" ? el.description : el.remediation;
    const gaps = (el.undeclared_gaps || []).length
      ? `<br><span class="muted">undeclared: ${esc(el.undeclared_gaps.slice(0, 5).join(", "))}</span>`
      : "";
    // .sev renders as an outline chip: the status reads through `color`.
    return `<tr><td><span class="sev" style="color:${status.color}">`
      + `${esc(status.label)}</span></td>`
      + `<td>${esc(el.name)}<br><span class="muted">${esc(detail)}</span>${gaps}</td>`
      + `<td>${esc(ELEMENT_ORIGIN[el.origin] || el.origin)}</td>`
      + `<td>${coverage}</td><td><code>${esc(el.cyclonedx_path)}</code></td></tr>`;
  }).join("");
}

async function download() {
  if (!lastRequest) return;
  const button = $("download");
  button.disabled = true;
  button.textContent = "Building report…";
  setStatus("Building HTML report …", false);
  try {
    const endpoint = lastRequest.demo ? "/api/demo/report" : "/api/report";
    const options = lastRequest.demo
      ? { method: "POST" }
      : {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: lastRequest.repo_url, resolve: lastRequest.resolve }),
      };
    const resp = await fetch(lastRequest.api + endpoint, options);
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
    button.textContent = "HTML report";
  }
}

function downloadCycloneDX() {
  if (!lastResult || !lastResult.cyclonedx) return;
  const blob = new Blob([JSON.stringify(lastResult.cyclonedx, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "aibom.cdx.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  setStatus("CycloneDX AIBOM downloaded.", false);
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
  button.disabled = true;
  button.textContent = "Building SARIF…";
  try {
    const endpoint = lastRequest.demo ? "/api/demo/sarif" : "/api/sarif";
    const options = lastRequest.demo
      ? { method: "POST" }
      : {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: lastRequest.repo_url, resolve: lastRequest.resolve }),
      };
    const resp = await fetch(lastRequest.api + endpoint, options);
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.detail || ("HTTP " + resp.status));
    saveJson(data, "aibom-findings.sarif", "SARIF log");
  } catch (e) {
    setStatus("SARIF export failed: " + e.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "SARIF";
  }
}

async function postJson(url, body) {
  const options = body
    ? { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) }
    : { method: "POST" };
  let resp;
  try {
    resp = await fetch(url, options);
  } catch (e) {
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
  const block = $("apiEndpointBlock");
  block.hidden = false;
  $("apiEndpoint").value = apiOverride || "";
  if (message) setStatus(message, true);
  block.scrollIntoView({ block: "nearest" });
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
    $("apiEndpointBlock").hidden = true;
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
  depends_on:  { color: "#7c8593", dash: "",    label: "depends on" },
  served_by:   { color: "#3a6ea5", dash: "6 3", label: "served by" },
  invokes:     { color: "#2e7d5b", dash: "",    label: "invokes" },
  flows_to:    { color: "#b0761c", dash: "",    label: "prompt flows to" },
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
  host.innerHTML = "";
  detailReset(ctx);
  grid.classList.toggle("is-empty", !graph.nodes.length);
  if (!graph.nodes.length) {
    host.innerHTML = "<p class='muted'>No components to graph.</p>";
    renderEdgeLegend([], view.legend);
    return;
  }

  const W = 800, H = 520, PAD = 46;
  const nodes = graph.nodes.map((n, i) => {
    const a = (i / graph.nodes.length) * Math.PI * 2;
    return { ...n, x: W/2 + Math.cos(a)*150, y: H/2 + Math.sin(a)*150, vx:0, vy:0 };
  });
  const byId = {}; nodes.forEach(n => byId[n.id] = n);
  const links = graph.edges.map(e => ({ s: byId[e.source], t: byId[e.target], type: e.type,
    evidence: e.evidence || [] })).filter(l => l.s && l.t);
  nodes.forEach(n => { n.radius = n.type === "agent" ? 11 : 8.5; });
  const adj = {}; nodes.forEach(n => adj[n.id] = new Set());
  links.forEach(l => { adj[l.s.id].add(l.t.id); adj[l.t.id].add(l.s.id); });

  simulate(nodes, links, W, H);
  fit(nodes, W, H, PAD);

  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, role: "group",
    "aria-label": "AI dependency graph" });
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
    const label = n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label;
    const t = svgEl("text", { x: n.x, y: n.y + r + 9, "text-anchor": "middle" });
    t.textContent = label;
    g.appendChild(c); g.appendChild(t);
    gNodes.appendChild(g);
    n.circle = c; n.text = t;
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
  });
  links.forEach(l => {
    const on = l.s.id === node.id || l.t.id === node.id;
    l.el.setAttribute("stroke-opacity", on ? 0.85 : 0.06);
  });
  detailShow(node, links, ctx);
}

function clearSelection(nodes, lineEls, ctx) {
  nodes.forEach(n => { n.circle.setAttribute("opacity", 1); n.text.setAttribute("opacity", 1); });
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
    "<span class='muted'>Select a node to inspect its evidence and related findings.</span>";
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
  let html = `<span class="dt-type">${esc(node.type)}</span><h3>${esc(node.label)}</h3>`;
  if (node.provider) html += `<div class="muted">Provider: ${esc(node.provider)}</div>`;
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
    for (const f of mine) {
      const loc = (f.source_evidence || []).slice(0, 3).map(evLoc).join(", ");
      html += `<div class="dt-find"><span class="sev" data-severity="${esc(f.severity)}">`
        + `${esc(f.severity)}</span> <code>${esc(f.rule_id)}</code><br>`
        + `<strong>${esc(f.title)}</strong><div class="muted">${esc(loc)}</div></div>`;
    }
  }
  $(ctx.detail).innerHTML = html;
}

function filterRows(tableId, searchId, selectId, dataKey, emptyMessage, extraMatch) {
  const table = $(tableId);
  const tbody = table.querySelector("tbody");
  tbody.querySelectorAll(".filter-empty").forEach(row => row.remove());
  const rows = [...tbody.querySelectorAll("tr[data-row='true']")];
  const query = $(searchId).value.trim().toLocaleLowerCase();
  const selected = $(selectId).value;
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
    cell.className = "empty empty-state";
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    tbody.appendChild(row);
  }
  return { visible, total: rows.length };
}

function filterFindings() {
  const count = filterRows("findings", "findingSearch", "severityFilter", "severity",
    "No findings match the current filters.");
  if (count.total) {
    $("findingCount").textContent = count.visible === count.total
      ? `(${count.total})` : `(${count.visible} of ${count.total})`;
  }
}

function filterInventory() {
  const reach = $("reachFilter").value;
  filterRows("inventory", "inventorySearch", "typeFilter", "type",
    "No components match the current filters.",
    (row) => reach === "all" || row.dataset.reach === reach);
}

// The panel has two modes; the steps and empty state describe the active one.
$("scan").addEventListener("click", scan);
$("loadExample").addEventListener("click", loadExample);
$("saveApiEndpoint").addEventListener("click", saveApiEndpoint);
$("apiEndpoint").addEventListener("keydown", (e) => {
  if (e.key === "Enter") saveApiEndpoint();
});
$("toggleApiEndpoint").addEventListener("click", () => {
  const block = $("apiEndpointBlock");
  if (block.hidden) showApiEndpointField();
  else block.hidden = true;
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

async function runCompare(button, busyLabel, status, request) {
  const original = button.textContent;
  COMPARE_BUTTONS.forEach((id) => { $(id).disabled = true; });
  button.textContent = busyLabel;
  $("compareSection").setAttribute("aria-busy", "true");
  $("compareState").textContent = "Comparison in progress";
  setCompareStatus(status, false);
  try {
    const body = await request();
    renderCompare(body);
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
      ? "Rescanning the fixed revision against the vulnerable candidate (offline)…"
      : `Scanning the ${language} baseline and candidate revisions (offline)…`,
    () => postJson(apiBase() + "/api/diff/demo?" + query));
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
      { repo_url: repo, base_ref: base, head_ref: head }));
}

function renderCompare(body) {
  const drift = body.drift || {};
  $("compareResult").hidden = false;
  $("nodeDetail").hidden = true;
  renderVerdicts(drift);
  renderRevision($("baselineCard"), "Baseline", body.baseline, body.baseline_paths);
  renderRevision($("candidateCard"), "Candidate", body.candidate, body.candidate_paths);
  renderGraph((body.candidate || {}).graph || { nodes: [], edges: [] }, [], COMPARE_GRAPH);
  const changes = drift.changes || [];
  const paths = changes.filter(c => PATH_KINDS.includes(c.kind));
  const others = changes.filter(c => !PATH_KINDS.includes(c.kind));
  compareNodes = [];
  $("pathChanges").innerHTML = paths.length
    ? paths.map((change, index) => pathChangeHtml(change, index)).join("")
    : `<p class="field-help">No agent capability path was added, changed or removed.</p>`;
  $("pathChanges").querySelectorAll(".path-node").forEach((node) => {
    node.addEventListener("click", () => showNode(node));
  });
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

function renderVerdicts(drift) {
  const bom = drift.bom;
  const bomBox = $("bomVerdict");
  if (bom && bom.identical) {
    bomBox.className = "verdict ok";
    bomBox.innerHTML = `<p class="verdict-label">COMPONENT BOM</p>`
      + `<p class="verdict-value">Unchanged</p><p class="verdict-note">${bom.candidate_components}`
      + ` components compared (${esc((bom.compared_types || []).join(", "))}): names, versions`
      + ` and security metadata are identical. Prompts are compared as paths, not as parts.</p>`;
  } else if (bom) {
    bomBox.className = "verdict warn";
    const delta = [...bom.added.map(x => "+" + x), ...bom.removed.map(x => "−" + x),
      ...bom.changed.map(x => "~" + x)];
    bomBox.innerHTML = `<p class="verdict-label">COMPONENT BOM</p>`
      + `<p class="verdict-value">Changed</p><p class="verdict-note">`
      + `${esc(delta.slice(0, 6).join(", "))}${delta.length > 6 ? ` +${delta.length - 6} more` : ""}</p>`;
  } else {
    bomBox.className = "verdict";
    bomBox.innerHTML = `<p class="verdict-label">COMPONENT BOM</p><p class="verdict-value">—</p>`;
  }
  const changes = drift.changes || [];
  const added = changes.filter(c => c.kind === "impact_path_added");
  const unresolved = changes.filter(c => c.kind === "impact_path_unresolved");
  const box = $("boundaryVerdict");
  if (drift.security_boundary_changed) {
    const proven = added.filter(c => c.evidence_level === "proven_static").length;
    box.className = "verdict bad";
    box.innerHTML = `<p class="verdict-label">SECURITY BOUNDARY</p>`
      + `<p class="verdict-value">Changed</p><p class="verdict-note">${added.length} new agent`
      + ` capability path(s), ${proven} proven statically. A static path, not a proven exploit.</p>`;
  } else {
    box.className = unresolved.length ? "verdict warn" : "verdict ok";
    box.innerHTML = `<p class="verdict-label">SECURITY BOUNDARY</p>`
      + `<p class="verdict-value">Unchanged</p><p class="verdict-note">${unresolved.length
        ? `${unresolved.length} unresolved input(s) to review — not proven either way.`
        : "No new path from untrusted input to privileged instructions or a bound tool."}</p>`;
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
  const score = summary.score || {};
  card.innerHTML = `<h4>${title}</h4>`
    + `<p class="revision-target">${esc(revisionLabel(summary.target))}</p>`
    + `<div>${esc(counts || "no components")}</div>`
    + `<div>${summary.findings} finding(s) · score ${score.overall ?? "–"}`
    + `${score.grade ? " (" + esc(score.grade) + ")" : ""}</div>`
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
  const impact = esc(f.description)
    + (f.trust_boundary ? ` <span class="muted">Trust boundary: ${esc(f.trust_boundary)}.</span>` : "");
  const steps = (f.data_flow_path || []).slice(0, 6).map(step =>
    `${step.operation}${step.symbol ? " " + step.symbol : ""} @ ${step.file}${step.line ? ":" + step.line : ""}`);
  const level = f.evidence_level
    ? evidenceTag(f.evidence_level)
    : `<span class="evidence-tag">Rule match</span>`;
  const count = (f.source_evidence || []).length;
  const evidence = `${level} ${where ? `<code>${esc(where)}</code> ` : ""}`
    + (steps.length ? `<br><span class="muted">${esc(steps.join(" → "))}</span>`
      : `<span class="muted">${count} source location(s)</span>`);
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
      + `production entry point. Unknown is not unreachable.">reachable: unknown</span>`
    : `reachable: ${esc(reach)}`;
  return (states.length ? esc(states.join(" → ")) + " → " : "") + reachText;
}

function selectTab(name) {
  document.querySelectorAll(".result-tab").forEach(tab => {
    tab.setAttribute("aria-selected", tab.dataset.tab === name ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.hidden = panel.dataset.panel !== name;
  });
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
    return `<li><code>${esc(reason)}</code> ×${groups[reason].length} — `
      + `${esc(UNKNOWN_REASON[reason] || "Not statically resolvable.")}`
      + `<br><span class="muted">${esc(subjects.slice(0, 4).join(", "))}`
      + `${subjects.length > 4 ? ` +${subjects.length - 4}` : ""}</span></li>`;
  }).join("");
  const manifest = report.scope && report.scope.manifest
    ? "" : `<li>No <code>aibom-identity.yaml</code> in this repository, so no agent has a known `
      + `identity. Add one to turn Unknown verdicts into policy-checked ones.</li>`;
  return `<details open><summary>Unknown — ${(report.unknowns || []).length} item(s) not `
    + `resolved statically (shown, never counted as safe)</summary><ul>${manifest}${items}</ul></details>`;
}

let agentModel = null;
function renderAgentSecurity(report, inventory) {
  const graphHost = $("agentGraph"), detailHost = $("agentDetail");
  if (!report || report.error) {
    agentModel = null;
    $("attackPaths").innerHTML = "";
    $("agentUnknowns").innerHTML = "";
    graphHost.innerHTML = `<p class="empty-graph">Agent security analysis is unavailable for this `
      + `scan${report && report.error ? ": " + esc(report.error) : "."}</p>`;
    detailHost.innerHTML = "";
    return;
  }
  const names = Object.fromEntries(((inventory && inventory.entities) || []).map(e => [e.id, e.name]));
  agentModel = secModel(report, names);
  $("attackPaths").innerHTML = attackPathCards(report);
  renderSecGraph(graphHost, detailHost, agentModel, null);
  $("agentUnknowns").innerHTML = unknownsHtml(report);
}

function renderSecuritySummary(d) {
  const report = d.agent_security && !d.agent_security.error ? d.agent_security : null;
  const sc = d.score || { severity_counts: {} };
  const impact = (d.graph && d.graph.impact_paths) || [];
  const paths = report ? report.capability_paths : [];
  const allowed = paths.filter(p => p.verdict === "potentially_allowed");
  const unknownPaths = paths.filter(p => p.verdict === "unknown");
  const servers = report ? report.mcp_servers : [];
  const mcpTools = servers.flatMap(s => s.tools || []);
  const exposedIds = new Set(report ? report.agents.flatMap(a => a.mcp_tool_ids || []) : []);
  const riskyTools = mcpTools.filter(t => (t.capability_kinds || []).length);
  const critHigh = (sc.severity_counts.critical || 0) + (sc.severity_counts.high || 0);
  let headline;
  if (impact.length) {
    const p = impact[0];
    headline = `Untrusted ${p.source_kind} input reaches tool ${(p.tool_names || []).join(", ")}`
      + ` (${(p.capabilities || []).map(c => c.operation).join(", ") || "capability"}) — `
      + `${p.severity}, ${p.evidence_level === "proven_static" ? "proven statically" : "potential"}.`;
  } else if (allowed.length) {
    const top = allowed.slice().sort((a, b) =>
      SEV_RANK[HAZARD_SEV[a.hazard]] - SEV_RANK[HAZARD_SEV[b.hazard]])[0];
    headline = `${top.agent_id} can reach ${top.action} via ${top.tool_name}; the supplied `
      + `policy for ${top.identity_id} potentially allows it.`;
  } else if (riskyTools.length) {
    headline = `${riskyTools.length} MCP tool(s) with ${[...new Set(riskyTools.flatMap(t =>
      t.capability_kinds))].join(", ")} are exposed to any LLM client that launches the server.`;
  }
  const tile = (n, label, cls, note) => `<div class="sum-tile ${cls || ""}"><strong>${n}</strong>`
    + `<span>${esc(label)}</span>${note ? `<small>${esc(note)}</small>` : ""}</div>`;
  $("securitySummary").innerHTML =
    (headline ? `<p class="sum-headline">${esc(headline)}</p>`
      : `<p class="sum-headline is-quiet">No path from an agent or untrusted input to a dangerous `
        + `operation was found. Unknowns below are not counted as safe.</p>`)
    + tile(report ? report.agents.length : "—", "agents")
    + tile(mcpTools.length ? `${exposedIds.size}/${mcpTools.length}` : "0", "MCP tools exposed",
      riskyTools.length ? "is-warn" : "", riskyTools.length ? `${riskyTools.length} with dangerous capability` : "")
    + tile(report ? report.operations.length : "—", "cloud operations in tool code")
    + tile(allowed.length + impact.length, "dangerous paths", allowed.length + impact.length ? "is-bad" : "is-ok",
      `${impact.length} from untrusted input · ${allowed.length} policy-allowed`)
    + tile(unknownPaths.length + (report ? report.unknowns.length : 0), "unknown",
      unknownPaths.length || (report && report.unknowns.length) ? "is-warn" : "", "unresolved, not safe")
    + tile(critHigh, "critical / high findings", critHigh ? "is-bad" : "is-ok");
}

// ── agent privilege drift (Baseline → Candidate → Fixed) ──────────────────────────
const DRIFT_BUTTONS = ["driftDemoPolicy", "driftDemoMcp", "heroDrift", "heroMcp"];
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
  button.textContent = "Scanning 3 revisions…";
  $("driftState").textContent = "Scanning";
  $("driftState").dataset.state = "running";
  setDriftStatus("Scanning baseline, candidate and fixed revisions offline…", false);
  try {
    const body = await postJson(apiBase() + "/api/agent-drift/demo?scenario=" + encodeURIComponent(scenario));
    renderDrift(body);
    $("driftState").textContent = "Scenario loaded";
    $("driftState").dataset.state = "complete";
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
    $("privResult").scrollIntoView({ behavior, block: "start" });
    $("privResult").focus({ preventScroll: true });
  } catch (e) {
    setDriftStatus("The drift scenario could not be run: " + e.message, true);
    $("driftState").textContent = "Failed";
    $("driftState").dataset.state = "error";
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

function renderDrift(body) {
  driftBody = body;
  const introduced = body.introduced, residual = body.residual;
  const gated = introduced.changes.filter(c => c.gates);
  const remaining = residual.changes.filter(c => c.gates);
  const counts = body.revisions.candidate.counts || {};
  const components = Object.entries(counts).filter(([k, n]) => n && k !== "prompt")
    .map(([k, n]) => `${n} ${k}`).join(", ");
  $("privResult").hidden = false;
  const bom = $("driftBomVerdict");
  bom.className = "verdict " + (introduced.bom_components_unchanged ? "ok" : "warn");
  bom.innerHTML = `<p class="verdict-label">COMPONENT BOM</p><p class="verdict-value">`
    + `${introduced.bom_components_unchanged ? "Unchanged" : "Changed"}</p><p class="verdict-note">`
    + (introduced.bom_components_unchanged
      ? `${esc(components)}: identical in both revisions. An SBOM diff reports nothing.`
      : esc(introduced.bom_differences.slice(0, 5).join(", "))) + `</p>`;
  const priv = $("driftPrivVerdict");
  priv.className = "verdict " + (gated.length ? "bad" : "ok");
  priv.innerHTML = `<p class="verdict-label">AGENT PRIVILEGE</p><p class="verdict-value">`
    + `${gated.length ? gated.length + " new" : "No change"}</p><p class="verdict-note">`
    + (gated.length ? esc([...new Set(gated.map(c => DRIFT_TYPE_LABEL[c.type] || c.type))].join(", "))
      + `. Changed file: <code>${esc(body.scenario.changed)}</code>.`
      : "No privilege addition.") + `</p>`;
  const fix = $("driftFixVerdict");
  const unknowns = (body.reports.fixed.unknowns || []).length;
  fix.className = "verdict " + (remaining.length ? "bad" : "ok");
  fix.innerHTML = `<p class="verdict-label">VERIFY FIX (BASELINE vs FIXED)</p><p class="verdict-value">`
    + `${remaining.length ? remaining.length + " remain" : "Fixed"}</p><p class="verdict-note">`
    + `${esc(body.scenario.fix)}. ${remaining.length} privilege addition(s) remain`
    + `${unknowns ? `, ${unknowns} unknown(s) (never counted as fixed)` : ""}.</p>`;
  $("driftRevisions").innerHTML =
    `<article class="revision">${driftCard("Baseline", "least privilege", body.reports.baseline)}</article>`
    + `<span class="revision-arrow" aria-hidden="true">→</span>`
    + `<article class="revision">${driftCard("Candidate", "after the change", body.reports.candidate,
      `<span class="evidence-tag">changed</span> ${esc(body.scenario.change)}`)}</article>`;
  showDriftStage("candidate");
  const toolLabel = Object.fromEntries((body.reports.candidate.nodes || [])
    .filter(n => n.kind === "tool").map(n => [n.id, n.label]));
  const changes = introduced.changes.slice().sort((a, b) =>
    (b.gates - a.gates) || (SEV_RANK[a.severity] - SEV_RANK[b.severity]));
  $("driftChanges").innerHTML = changes.length ? changes.map(c => {
    const rem = c.remediation || {};
    const verdicts = c.before_verdict || c.after_verdict
      ? `${verdictTag(c.before_verdict || "unknown")} → ${verdictTag(c.after_verdict || "unknown")}` : "";
    const subject = [c.agent, toolLabel[c.tool] || c.tool, c.action].filter(Boolean).join(" → ");
    return `<article class="drift-change" data-gates="${c.gates}"><header>${sevTag(c.severity)}`
      + ` <span class="evidence-tag">${esc(DRIFT_TYPE_LABEL[c.type] || c.type)}</span>`
      + ` <span class="evidence-tag">${c.gates ? "gates CI" : "review only"}</span>`
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
  }).join("") : `<p class="field-help">No privilege change between baseline and candidate.</p>`;
  setDriftStatus(`${gated.length} privilege addition(s) gate CI; the component BOM is `
    + `${introduced.bom_components_unchanged ? "unchanged" : "changed"}.`, false);
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
  $("driftDepTitle").textContent = "Dependency map \u00b7 " + stage;
  renderGraph(revision.graph || { nodes: [], edges: [] }, [], DRIFT_GRAPH);
}
document.querySelectorAll(".stage-toggle button").forEach(b => {
  b.addEventListener("click", () => showDriftStage(b.dataset.stage));
});

function heroDemo(scenario, button) {
  const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
  $("driftSection").scrollIntoView({ behavior, block: "start" });
  return runPrivilegeScenario(scenario, button);
}
$("driftDemoPolicy").addEventListener("click", () => runPrivilegeScenario("agent-privilege-drift", $("driftDemoPolicy")));
$("driftDemoMcp").addEventListener("click", () => runPrivilegeScenario("mcp-tool-exposure", $("driftDemoMcp")));
$("heroDrift").addEventListener("click", () => heroDemo("agent-privilege-drift", $("heroDrift")));
$("heroMcp").addEventListener("click", () => heroDemo("mcp-tool-exposure", $("heroMcp")));

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
