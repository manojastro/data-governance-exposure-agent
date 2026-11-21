/* Data Access Governance Agent SPA. Vanilla ES module, no dependencies.
   All data comes from the local FastAPI backend (/api/v1/...). */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* keep */ }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}
const post = (path, body) => api(path, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body || {}),
});

function toast(msg, ok = true) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden", "err", "ok");
  t.classList.add(ok ? "ok" : "err");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add("hidden"), 4200);
}

/* ------------------------------------------------------------ meta/boot */

async function loadMeta() {
  try {
    const m = await api("/api/v1/meta");
    $("mock-badge").classList.toggle("hidden", !m.mock_mode);
    $("llm-badge").textContent = `LLM: ${m.llm_mode || "?"}${m.llm_model ? " / " + m.llm_model : ""}`;
    $("db-label").textContent = `db: ${(m.database || "?").replace(/^.*[\\/]/, "")}`;
    $("health-dot").className = "health-dot up";
  } catch {
    $("health-dot").className = "health-dot down";
    throw new Error("backend unreachable");
  }
}

/* ---------------------------------------------------------------- KPIs */

const KPI_DEFS = [
  ["sensitive_assets_discovered", "sensitive assets", ""],
  ["classification_coverage_pct", "classified", "%"],
  ["policy_coverage_pct", "policy coverage", "%"],
  ["excess_privilege_count", "excess privileges", "", "alert"],
  ["stale_permission_count", "stale permissions", "", "alert"],
  ["high_risk_access_paths", "high-risk paths", "", "alert"],
  ["ai_identity_violations", "AI violations", "", "alert"],
  ["open_findings", "open findings", "", "alert"],
];

function renderKpis(m) {
  $("kpis").innerHTML = KPI_DEFS.map(([k, label, unit, tone]) => {
    const v = m[k];
    const cls = tone === "alert" && Number(v) > 0 ? "kpi alert" : "kpi";
    return `<div class="${cls}"><b>${esc(v)}${unit}</b><span>${label}</span></div>`;
  }).join("");
  setBar("cov-class", m.classification_coverage_pct);
  setBar("cov-policy", m.policy_coverage_pct);
}

function setBar(id, pct) {
  const el = $(id);
  el.style.width = `${Math.min(100, Number(pct) || 0)}%`;
  el.className = Number(pct) < 70 ? "warn" : "";
  $(`${id}-v`).textContent = `${Number(pct).toFixed(1)}%`;
}

/* ------------------------------------------------------------- findings */

let ALL_FINDINGS = [];

async function loadFindings() {
  const sev = $("finding-sev").value;
  const st = $("finding-status").value;
  const qs = new URLSearchParams({ limit: "200" });
  if (sev) qs.set("severity", sev);
  if (st) qs.set("status", st);
  const data = await api(`/api/v1/findings?${qs}`);
  ALL_FINDINGS = data.findings || [];
  $("findings-count").textContent = `(${data.count})`;
  $("findings-table").querySelector("tbody").innerHTML = ALL_FINDINGS.map((f) => `
    <tr>
      <td><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td class="mono">${esc(f.type)}</td>
      <td class="mono">${esc(f.principal_name || "-")}${f.asset_ref ? "<br>" + esc(f.asset_ref) : ""}</td>
      <td>${esc(f.title)}</td>
    </tr>`).join("");
  renderHighRisk();
}

const HIGH_RISK_TYPES = {
  PUBLIC_SHARE_ON_SENSITIVE: "public share",
  EXTERNAL_SHARE_RESTRICTED: "external share",
  CREDENTIAL_EXPOSURE: "credential exposure",
  UNMASKED_PII_EXPOSURE: "unmasked PII",
  STALE_ELEVATED_ACCESS: "stale elevated",
};

function renderHighRisk() {
  const rows = [];
  for (const f of ALL_FINDINGS) {
    const kind = HIGH_RISK_TYPES[f.type];
    if (!kind || f.status === "remediated") continue;
    rows.push(`<tr>
      <td><span class="sev sev-${esc(f.severity)}">${kind}</span></td>
      <td class="mono">${esc(f.principal_name || f.asset_ref || "-")}</td>
      <td>${esc(f.title)}</td></tr>`);
  }
  $("highrisk-table").querySelector("tbody").innerHTML =
    rows.join("") || `<tr><td colspan="3" class="dim pad">no high-risk permissions open</td></tr>`;
}

/* ----------------------------------------------------------- access graph */

const KIND_FILL = {
  USER: "#4da3ff", GROUP: "#2f7fd4", ROLE: "#77aaee",
  SERVICE_ACCOUNT: "#9fb8d8", AI_AGENT: "#e8b64c",
  TABLE: "#ff9040", VIEW: "#ff7a6b", MODEL: "#ffb340",
  COLUMN: "#8b98a9", DATA_SHARE: "#b085f5",
};
const IDENTITY_KINDS = new Set(["USER", "GROUP", "ROLE", "SERVICE_ACCOUNT", "AI_AGENT"]);

async function loadGraph() {
  const g = await api("/api/v1/graph");
  $("graph-meta").textContent =
    `${(g.nodes || []).length} nodes / ${(g.edges || []).length} edges shown`;
  renderGraphSvg(g.nodes || [], g.edges || []);
}

function renderGraphSvg(nodes, edges) {
  const W = 900, H = 560, R = 225;
  const ids = nodes.map((n) => n.id);
  const left = ids.filter((id) => {
    const n = nodes.find((x) => x.id === id);
    return IDENTITY_KINDS.has(n.kind);
  });
  const right = ids.filter((id) => !left.includes(id));
  const pos = {};
  left.forEach((id, i) => {
    const a = Math.PI * (0.08 + 0.84 * (i / Math.max(left.length - 1, 1)));
    pos[id] = [60 + R * 0.62 * Math.cos(a), H / 2 - R * Math.sin(a)];
  });
  right.forEach((id, i) => {
    const a = Math.PI * (0.92 - 0.84 * (i / Math.max(right.length - 1, 1)));
    pos[id] = [W - 60 - R * 0.62 * Math.cos(a), H / 2 - R * Math.sin(a)];
  });

  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const edgeLines = edges.map((e) => {
    const p1 = pos[e.source], p2 = pos[e.target];
    if (!p1 || !p2) return "";
    const color = e.risky ? "#ff4d4d" : e.type === "DERIVES_FROM" ? "#7a5cff" : "#33465e";
    const dash = e.type === "DERIVES_FROM" ? ' stroke-dasharray="4 3"' : "";
    const width = e.risky ? 2 : 1;
    return `<line x1="${p1[0]}" y1="${p1[1]}" x2="${p2[0]}" y2="${p2[1]}"
      stroke="${color}" stroke-width="${width}" opacity="0.75"${dash}>
      <title>${esc(e.source)} -[${esc(e.type)}]-&gt; ${esc(e.target)}</title></line>`;
  }).join("");

  const dots = nodes.map((n) => {
    const p = pos[n.id];
    if (!p) return "";
    const fill = KIND_FILL[n.kind] || "#8b98a9";
    const r = IDENTITY_KINDS.has(n.kind) ? 6 : n.level === "credential" ? 9 : 7;
    return `<circle cx="${p[0]}" cy="${p[1]}" r="${r}" fill="${fill}" stroke="#0d1117">
      <title>${esc(n.id)}
kind: ${esc(n.kind)}  level: ${esc(n.level || "-")}</title></circle>`;
  }).join("");

  $("graph-wrap").innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="access graph">
      ${edgeLines}${dots}</svg>`;
}

/* ---------------------------------------------------------- ai identities */

async function loadAgents() {
  const d = await api("/api/v1/ai-identities");
  $("agents-count").textContent = `(${d.noncompliant}/${d.total} non-compliant)`;
  $("agents-list").innerHTML = (d.agents || []).map((a) => {
    const acc = a.accessible_datasets, need = a.task_required_datasets;
    const over = acc > need;
    return `<div class="agent-card">
      <h3>${esc(a.agent)}<span class="flag ${a.compliant ? "good" : "bad"}">
        ${a.compliant ? "COMPLIANT" : "SCOPE VIOLATION"}</span></h3>
      <div class="abar">accessible ${acc}<span class="track">
        <span class="fill${over ? " over" : ""}" style="width:${Math.min(100, acc * 4)}%"></span>
      </span></div>
      <div class="abar">task needs ${need}<span class="track">
        <span class="fill" style="width:${Math.min(100, need * 4)}%"></span>
      </span></div>
      <div class="dim" style="font-size:11px;margin-top:4px">
        gap score ${a.least_privilege_gap_score} &middot; scope: ${esc(a.declared_scope.join(", ") || "-")}
        &middot; task: ${esc(a.task || "-")}</div>
      ${a.pii_or_restricted_reachable.length ? `<div class="agent-tags">
        PII reachable: ${a.pii_or_restricted_reachable.map((x) => `<span class="tagchip">${esc(x)}</span>`).join("")}
      </div>` : ""}
    </div>`;
  }).join("") || '<div class="dim pad">no AI agent identities in estate</div>';
}

/* -------------------------------------------------------------- inventory */

async function loadAssets() {
  const q = $("asset-q").value.trim();
  const d = await api(`/api/v1/assets?q=${encodeURIComponent(q)}&level_min=internal`);
  $("assets-count").textContent = `(${d.count})`;
  $("assets-table").querySelector("tbody").innerHTML = (d.assets || []).map((a) => `
    <tr><td class="mono">${esc(a.fqn)}</td><td>${esc(a.level)}</td>
    <td>${a.tags.map((t) => `<span class="tagchip">${esc(t)}</span>`).join("")}</td>
    <td>${a.masked_columns}/${a.columns}</td></tr>`).join("");
}

async function loadShares() {
  const d = await api("/api/v1/shares");
  const interesting = (d.shares || []).filter((s) => s.external || s.is_public);
  $("shares-table").querySelector("tbody").innerHTML = (interesting.length
    ? interesting : (d.shares || [])).map((s) => `
    <tr><td class="mono">${esc(s.share_name)}</td><td class="mono">${esc(s.dataset)}</td>
    <td>${esc(s.recipient)}${s.external ? ' <span class="sev sev-critical">external</span>' : ""}
        ${s.is_public ? ' <span class="sev sev-high">public</span>' : ""}</td>
    <td class="st-${esc(s.status)}">${esc(s.status)}</td></tr>`).join("");
}

/* --------------------------------------------------------------- lineage */

async function loadLineage() {
  const d = await api("/api/v1/lineage");
  const nodes = (d.nodes || []).map((n) => n.id);
  const edges = d.edges || [];
  // depth layering via longest-path from roots (iterative relaxation)
  const depth = Object.fromEntries(nodes.map((n) => [n, 0]));
  for (let i = 0; i < nodes.length; i++) {
    for (const e of edges) {
      if ((depth[e.target] ?? 0) <= (depth[e.source] ?? 0)) depth[e.target] = depth[e.source] + 1;
    }
  }
  const layers = {};
  for (const n of nodes) (layers[depth[n]] ||= []).push(n);
  const colW = 190, rowH = 46, W = (Object.keys(layers).length + 0.4) * colW;
  const maxRows = Math.max(...Object.values(layers).map((l) => l.length));
  const H = maxRows * rowH + 20;
  const pos = {};
  for (const [lv, list] of Object.entries(layers)) {
    list.forEach((n, i) => {
      pos[n] = [40 + Number(lv) * colW, (H - list.length * rowH) / 2 + i * rowH];
    });
  }
  const lines = edges.map((e) => {
    const p1 = pos[e.source], p2 = pos[e.target];
    if (!p1 || !p2) return "";
    const x1 = p1[0] + 78, x2 = p2[0];
    const y1 = p1[1] + 14, y2 = p2[1] + 14;
    return `<path d="M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}"
      fill="none" stroke="#33465e" stroke-width="1.4"/>`;
  }).join("");
  const boxes = nodes.map((n) => {
    const p = pos[n];
    if (!p) return "";
    const short = n.length > 24 ? n.slice(0, 23) + ".." : n;
    return `<g><rect x="${p[0]}" y="${p[1]}" rx="6" width="150" height="28"
      fill="#131a23" stroke="#2f4258"/>
      <text x="${p[0] + 8}" y="${p[1] + 18}" fill="#dce3ec" font-size="10.5"
      font-family="Consolas, monospace">${esc(short)}</text>
      <title>${esc(n)}</title></g>`;
  }).join("");
  $("lineage-wrap").innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" width="100%" aria-label="lineage">${lines}${boxes}</svg>`;
}

/* ------------------------------------------------------------- proposals */

async function loadProposals() {
  const d = await api("/api/v1/proposals?limit=200");
  const open = (d.proposals || []).filter(
    (p) => ["proposed", "approved"].includes(p.status));
  $("proposals-count").textContent = `(${open.length} active / ${d.count} total)`;
  $("proposals-table").querySelector("tbody").innerHTML = (open.length ? open : d.proposals)
    .slice(0, 120).map((p) => `
    <tr>
      <td class="mono">${esc(p.signature)}${p.finding ? `<br><span class="dim">for ${esc(p.finding.severity || "")} ${esc(p.finding.scenario_key || "")}</span>` : ""}</td>
      <td>${esc(p.risk_level)}</td>
      <td class="st-${esc(p.status)}">${esc(p.status)}</td></tr>`).join("")
    || '<tr><td colspan="3" class="dim pad">no proposals yet - run an investigation</td></tr>';
}

async function loadApprovals() {
  const d = await api("/api/v1/approvals");
  const pending = (d.approvals || []).find((a) => a.status === "pending");
  $("pending-approval").textContent = pending
    ? `pending approval #${pending.id} (investigation #${pending.investigation_id}, ${pending.note})`
    : "no pending approval";
  $("btn-approve").disabled = !pending;
  $("btn-reject").disabled = !pending;
  $("btn-approve").dataset.id = pending ? pending.id : "";
  $("btn-reject").dataset.id = pending ? pending.id : "";
  return pending || null;
}

/* ------------------------------------------------------------- validation */

async function loadValidations() {
  const d = await api("/api/v1/validations");
  const v = (d.validations || [])[0];
  const box = $("validation-latest");
  if (!v) { box.textContent = "no validation yet"; box.className = "verdict-box dim"; return; }
  box.className = `verdict-box ${v.passed ? "pass" : "fail"}`;
  box.innerHTML = `<b>shadow validation #${v.id}</b> (investigation #${v.investigation_id})
    ${v.passed ? "PASS" : "FAIL"} &middot; exposure ${esc(v.exposure_before)} -> ${esc(v.exposure_after)}
    &middot; legitimate workflows ${v.legit_passed}/${v.legit_passed + v.legit_failed} preserved
    <br><span class="dim">${esc(v.verdict || "")}</span>`;
}

async function loadLegitTests() {
  const d = await api("/api/v1/legitimate-access-tests");
  $("legit-table").querySelector("tbody").innerHTML = (d.tests || []).map((t) => `
    <tr><td>${esc(t.name)}</td><td class="mono">${esc(t.principal)}</td>
    <td class="mono">${esc(t.operation)} ${esc(t.asset)}</td></tr>`).join("");
}

/* -------------------------------------------------------- events + tools */

async function loadEvents() {
  const d = await api("/api/v1/events?limit=60");
  $("events-list").innerHTML = (d.events || []).map((e) => `
    <div class="event-item sev-${esc(e.severity)}">
      <span class="when">${esc(String(e.created_at).replace("T", " ").slice(0, 19))}</span>
      <b class="mono"> ${esc(e.kind)}</b> ${esc(e.message)}</div>`).join("")
    || '<div class="dim pad">no events</div>';
}

async function loadToolCalls() {
  const d = await api("/api/v1/tool-calls?limit=60");
  $("tools-note").textContent = `(last ${(d.tool_calls || []).length})`;
  $("toolcalls-table").querySelector("tbody").innerHTML = (d.tool_calls || []).map((t) => `
    <tr><td class="mono">${esc(t.tool)}</td><td class="mono">${esc(t.caller)}</td>
    <td>${esc(t.risk_level)}</td><td class="st-${esc(t.status)}">${esc(t.status)}</td>
    <td class="mono">${t.duration_ms}</td></tr>`).join("")
    || '<tr><td colspan="5" class="dim pad">no tool calls yet</td></tr>';
}

/* --------------------------------------------------------- investigations */

async function loadInvestigations() {
  const d = await api("/api/v1/investigations");
  const sel = $("inv-select");
  const current = sel.value;
  sel.innerHTML = `<option value="">investigation: none</option>` +
    (d.investigations || []).map((i) =>
      `<option value="${i.id}">#${i.id} ${esc(i.status)} ${esc(i.title.slice(0, 42))}</option>`).join("");
  sel.value = current;
  const invId = sel.value || (d.investigations || [])[0]?.id;
  if (!invId) { setInvChip(null); return null; }
  const inv = await api(`/api/v1/investigations/${invId}`);
  setInvChip(inv);
  return inv;
}

function setInvChip(inv) {
  const chip = $("inv-status");
  if (!inv) { chip.textContent = "idle"; chip.className = "chip chip-idle"; return; }
  chip.textContent = `#${inv.id} ${inv.status}`;
  const s = inv.status;
  const cls = ["AWAITING_APPROVAL"].includes(s) ? "chip-wait"
    : ["COMPLETED"].includes(s) ? "chip-done"
    : ["REJECTED", "FAILED", "ROLLED_BACK"].includes(s) ? "chip-bad"
    : ["APPROVED", "EXECUTING", "VERIFYING"].includes(s) ? "chip-run" : "chip-run";
  chip.className = `chip ${cls}`;
}

/* ---------------------------------------------------------------- actions */

async function actionSeed() {
  try {
    const r = await post("/api/v1/simulator/seed", { seed: 42, reset: true });
    toast(`estate seeded (${r.datasets} datasets, ${r.principals} principals, ${r.grants} grants)`);
    refreshAll();
  } catch (e) { toast(`seed failed: ${e.message}`, false); }
}

async function actionScan() {
  try {
    const r = await post("/api/v1/scans/discovery", {});
    toast(`discovery scan: ${r.stats?.columns_scanned ?? "?"} columns scanned`);
    refreshAll();
  } catch (e) { toast(`scan failed: ${e.message}`, false); }
}

async function actionInvestigate() {
  try {
    const inv = await post("/api/v1/investigations",
      { title: `UI investigation ${new Date().toISOString().slice(0, 16)}`, trigger: "ui" });
    $("inv-select").value = String(inv.id);
    setInvChip(inv);
    toast(`investigation #${inv.id} running...`, true);
    const summary = await post(`/api/v1/investigations/${inv.id}/run`, {});
    toast(`pipeline done: ${summary.findings} findings, ${summary.proposed_changes} changes, `
      + `shadow ${summary.shadow_passed ? "PASS" : "FAIL"}, awaiting approval`);
    refreshAll();
  } catch (e) { toast(`investigation failed: ${e.message}`, false); }
}

async function actionApprove() {
  const id = $("btn-approve").dataset.id;
  if (!id) return;
  try {
    const r = await post(`/api/v1/approvals/${id}/approve`,
      { approver: $("approver").value || "operator", note: "approved from UI" });
    const ex = r.execution || {};
    toast(`applied ${ex.applied ?? 0} changes; verification `
      + `${ex.verification?.ok ? "OK" : "FAILED"}; status ${r.investigation_status}`);
    refreshAll();
  } catch (e) { toast(`approve failed: ${e.message}`, false); }
}

async function actionReject() {
  const id = $("btn-reject").dataset.id;
  if (!id) return;
  try {
    const r = await post(`/api/v1/approvals/${id}/reject`,
      { approver: $("approver").value || "operator", note: "rejected from UI" });
    toast(r.investigation_status === "REJECTED"
      ? "rejected - nothing was applied" : `status ${r.investigation_status}`);
    refreshAll();
  } catch (e) { toast(`reject failed: ${e.message}`, false); }
}

/* ----------------------------------------------------------------- cycle */

async function refreshAll() {
  await loadMeta();
  const [metrics] = await Promise.all([api("/api/v1/metrics/summary")]);
  renderKpis(metrics);
  await Promise.allSettled([
    loadFindings(), loadGraph(), loadAgents(), loadAssets(),
    loadShares(), loadLineage(), loadProposals(), loadApprovals(),
    loadValidations(), loadLegitTests(), loadEvents(), loadToolCalls(),
    loadInvestigations(),
  ]);
}

function wireUi() {
  $("btn-seed").addEventListener("click", actionSeed);
  $("btn-scan").addEventListener("click", actionScan);
  $("btn-investigate").addEventListener("click", actionInvestigate);
  $("btn-approve").addEventListener("click", actionApprove);
  $("btn-reject").addEventListener("click", actionReject);
  $("finding-sev").addEventListener("change", loadFindings);
  $("finding-status").addEventListener("change", loadFindings);
  let qTimer;
  $("asset-q").addEventListener("input", () => {
    clearTimeout(qTimer);
    qTimer = setTimeout(loadAssets, 250);
  });
  setInterval(() => {
    if ($("auto-refresh").checked && !document.hidden) refreshAll().catch(() => {});
  }, 6000);
}

async function main() {
  wireUi();
  try { await refreshAll(); }
  catch (e) { toast(`startup: ${e.message}`, false); }
}

main();
