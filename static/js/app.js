/* SPY-THREAT-HUNT V2 — app logic */
(function () {
  "use strict";

  const $ = (sel, ctx) => (ctx || document).querySelector(sel);
  const $$ = (sel, ctx) => Array.from((ctx || document).querySelectorAll(sel));

  // ------------------------------------------------------------- boot seq
  const BOOT_LINES = [
    "SPY-THREAT-HUNT V2 :: local intelligence node",
    "> initializing extraction engine ......... [ OK ]",
    "> loading pattern library (12 IOC types) .. [ OK ]",
    "> mounting local SQLite ledger ............ [ OK ]",
    "> hunt-forge platforms: splunk/sigma/kql",
    "         /elastic/wazuh/yara .............. [ OK ]",
    "> network: no outbound telemetry .......... [ SECURE ]",
    "",
    "developed by SPYDIRBYTE — idea created by hAckDHD",
    "",
    "> establishing session...",
  ];

  function runBoot() {
    const el = $("#boot-text");
    let i = 0;
    function typeLine() {
      if (i >= BOOT_LINES.length) {
        setTimeout(() => {
          $("#boot-screen").classList.add("fade-out");
          $("#app").classList.remove("hidden");
          setTimeout(() => $("#boot-screen").remove(), 550);
          init();
        }, 250);
        return;
      }
      const line = BOOT_LINES[i];
      let cls = "";
      if (line.includes("[ OK ]")) cls = "ok";
      else if (line.includes("[ SECURE ]")) cls = "ok";
      else if (line.startsWith(">")) cls = "dim";
      const span = document.createElement("div");
      span.className = cls;
      span.textContent = line;
      el.appendChild(span);
      i++;
      setTimeout(typeLine, line ? 90 : 40);
    }
    typeLine();
  }

  // -------------------------------------------------------------- toasts
  function toast(msg, isError) {
    const stack = $("#toast-stack");
    const t = document.createElement("div");
    t.className = "toast" + (isError ? " error" : "");
    t.textContent = msg;
    stack.appendChild(t);
    setTimeout(() => {
      t.classList.add("fade-out");
      setTimeout(() => t.remove(), 300);
    }, 3200);
  }

  // ---------------------------------------------------------------- clock
  function tickClock() {
    const el = $("#clock");
    if (!el) return;
    const now = new Date();
    el.textContent = now.toTimeString().slice(0, 8);
  }

  // ------------------------------------------------------------ tab logic
  function initTabs() {
    $$(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".tab-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const tab = btn.dataset.tab;
        $$(".panel").forEach((p) => p.classList.add("hidden"));
        $("#tab-" + tab).classList.remove("hidden");
        if (tab === "ledger") loadLedger();
      });
    });
  }

  // --------------------------------------------------------------- stats
  async function refreshStats() {
    try {
      const res = await fetch("/api/stats");
      const data = await res.json();
      animateNumber("#stat-total", data.total || 0);
      animateNumber("#stat-malicious", data.byClassification.malicious || 0);
      animateNumber("#stat-suspicious", data.byClassification.suspicious || 0);
      animateNumber("#stat-unknown", data.byClassification.unknown || 0);
      animateNumber("#stat-types", Object.keys(data.byType || {}).length);
    } catch (e) { /* silent */ }
  }

  function animateNumber(sel, target) {
    const el = $(sel);
    if (!el) return;
    const start = parseInt(el.textContent, 10) || 0;
    if (start === target) return;
    const dur = 500;
    const t0 = performance.now();
    function frame(t) {
      const p = Math.min(1, (t - t0) / dur);
      const val = Math.round(start + (target - start) * (1 - Math.pow(1 - p, 3)));
      el.textContent = val.toLocaleString();
      if (p < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  // ------------------------------------------------------------- ingest ui
  function initIngestModes() {
    $$(".mode-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".mode-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const mode = btn.dataset.mode;
        $$(".ingest-body").forEach((b) => b.classList.add("hidden"));
        $("#mode-" + mode).classList.remove("hidden");
        if (mode === "feed" && !$("#feed-list-picker").dataset.loaded) {
          $("#feed-list-picker").dataset.loaded = "1";
          loadFeedPicker();
        }
      });
    });

    const dz = $("#dropzone");
    const fileInput = $("#file-input");
    dz.addEventListener("click", () => fileInput.click());
    dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag-over"); });
    dz.addEventListener("dragleave", () => dz.classList.remove("drag-over"));
    dz.addEventListener("drop", (e) => {
      e.preventDefault();
      dz.classList.remove("drag-over");
      if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        dz.querySelector(".dz-text").textContent = e.dataTransfer.files[0].name;
      }
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) dz.querySelector(".dz-text").textContent = fileInput.files[0].name;
    });
  }

  async function loadFeedPicker() {
    const el = $("#feed-list-picker");
    try {
      const res = await fetch("/api/feeds");
      const feeds = await res.json();
      el.innerHTML = Object.entries(feeds).map(([id, f]) => `
        <div class="feed-item-row">
          <div class="fi-info">
            <div class="fi-name">${escapeHtml(f.name)} <span class="fi-badge ${f.configured ? "ready" : "needs-key"}">${f.configured ? "ready" : "needs key"}</span></div>
            <div class="fi-desc">${escapeHtml(f.description)}</div>
            <div class="fi-cost">${escapeHtml(f.cost)}</div>
          </div>
          <button class="feed-pull-btn" data-feed="${id}" ${f.configured ? "" : "disabled"}>Pull</button>
        </div>
      `).join("");
      $$(".feed-pull-btn", el).forEach((btn) => btn.addEventListener("click", () => pullFeed(btn.dataset.feed, btn)));
    } catch (e) {
      el.innerHTML = `<div class="empty-state">Couldn't load feed list — check your connection.</div>`;
    }
  }

  async function pullFeed(feedId, btn) {
    const original = btn.textContent;
    btn.textContent = "Pulling...";
    btn.disabled = true;
    try {
      const res = await fetch(`/api/feeds/${feedId}/pull`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ huntName: $("#hunt-name-input") ? $("#hunt-name-input").value.trim() : null }),
      });
      const data = await res.json();
      if (!res.ok) { toast(data.error || "Feed pull failed.", true); return; }
      showExtractResult(data);
      prependFeed(data.iocs);
      refreshStats();
      toast(`Pulled ${data.extracted} indicator(s) from feed — ${data.inserted} new.`);
    } catch (e) {
      toast("Feed pull failed: " + e.message, true);
    } finally {
      btn.textContent = original;
      btn.disabled = false;
    }
  }

  function initCustomFeed() {
    $("#btn-pull-custom-feed").addEventListener("click", async () => {
      const url = $("#custom-feed-url").value.trim();
      const apiKey = $("#custom-feed-key").value.trim();
      if (!url) { toast("Enter a feed URL first.", true); return; }
      const btn = $("#btn-pull-custom-feed");
      btn.textContent = "Pulling...";
      btn.disabled = true;
      try {
        const res = await fetch("/api/feeds/custom/pull", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, apiKey }),
        });
        const data = await res.json();
        if (!res.ok) { toast(data.error || "Custom feed pull failed.", true); return; }
        showExtractResult(data);
        prependFeed(data.iocs);
        refreshStats();
        toast(`Pulled ${data.extracted} indicator(s) — ${data.inserted} new.`);
      } catch (e) {
        toast("Custom feed pull failed: " + e.message, true);
      } finally {
        btn.textContent = "Pull";
        btn.disabled = false;
      }
    });
  }

  function activeMode() {
    return $(".mode-btn.active").dataset.mode;
  }

  async function runExtraction() {
    const mode = activeMode();
    const btn = $("#btn-extract");
    btn.classList.add("loading");
    const includeHostnames = $("#opt-hostnames").checked;

    try {
      let res, data;
      if (mode === "paste") {
        const text = $("#paste-input").value;
        if (!text.trim()) { toast("Paste some text first.", true); return; }
        res = await fetch("/api/extract/paste", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text, includeHostnames }),
        });
      } else if (mode === "url") {
        const url = $("#url-input").value.trim();
        if (!url) { toast("Enter a URL first.", true); return; }
        res = await fetch("/api/extract/url", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });
      } else {
        const fileInput = $("#file-input");
        if (!fileInput.files.length) { toast("Choose a file first.", true); return; }
        const fd = new FormData();
        fd.append("file", fileInput.files[0]);
        res = await fetch("/api/extract/file", { method: "POST", body: fd });
      }
      data = await res.json();
      if (!res.ok) { toast(data.error || "Extraction failed.", true); return; }

      showExtractResult(data);
      prependFeed(data.iocs);
      refreshStats();
      toast(`Extracted ${data.extracted} indicator(s) — ${data.inserted} new.`);
    } catch (e) {
      toast("Extraction failed: " + e.message, true);
    } finally {
      btn.classList.remove("loading");
    }
  }

  function showExtractResult(data) {
    const el = $("#extract-result");
    const rows = Object.entries(data.byType || {}).sort((a, b) => b[1] - a[1])
      .map(([t, c]) => `${t}: ${c}`).join("  ·  ");
    el.innerHTML = `<strong>${data.extracted}</strong> extracted, <strong>${data.inserted}</strong> new, ${data.duplicates} duplicate(s)<br>${rows || "—"}`;
    el.classList.remove("hidden");
  }

  function prependFeed(iocs) {
    const list = $("#feed-list");
    if (list.querySelector(".empty-state")) list.innerHTML = "";
    iocs.slice(0, 40).forEach((ioc) => {
      const item = document.createElement("div");
      item.className = "feed-item";
      item.innerHTML = `
        <span class="badge type">${ioc.type}</span>
        <span class="feed-value" title="${escapeHtml(ioc.value)}">${escapeHtml(ioc.value)}</span>
        <span class="badge ${ioc.classification}">${ioc.classification}</span>
      `;
      list.prepend(item);
    });
    while (list.children.length > 80) list.removeChild(list.lastChild);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // -------------------------------------------------------------- ledger
  let ledgerCache = [];
  let selectedIds = new Set();

  async function loadLedger() {
    const type = $("#ledger-type-filter").value;
    const cls = $("#ledger-class-filter").value;
    const huntStatus = $("#ledger-hunt-status-filter").value;
    const search = $("#ledger-search").value;
    const params = new URLSearchParams();
    if (type) params.set("type", type);
    if (cls) params.set("classification", cls);
    if (huntStatus) params.set("huntStatus", huntStatus);
    if (search) params.set("search", search);
    params.set("limit", "1000");

    const res = await fetch("/api/iocs?" + params.toString());
    const data = await res.json();
    ledgerCache = data.iocs;
    renderLedger();
    populateTypeFilter();
  }

  function populateTypeFilter() {
    const sel = $("#ledger-type-filter");
    if (sel.dataset.populated) return;
    const types = [...new Set(ledgerCache.map((i) => i.type))].sort();
    types.forEach((t) => {
      const opt = document.createElement("option");
      opt.value = t; opt.textContent = t;
      sel.appendChild(opt);
    });
    sel.dataset.populated = "1";
  }

  function renderLedger() {
    const body = $("#ledger-body");
    $("#ledger-count").textContent = `${ledgerCache.length} indicators`;
    if (!ledgerCache.length) {
      body.innerHTML = `<tr><td colspan="7"><div class="empty-state">No indicators match this filter.</div></td></tr>`;
      return;
    }
    body.innerHTML = ledgerCache.map((ioc) => `
      <tr data-id="${ioc.id}">
        <td><input type="checkbox" class="row-chk" data-id="${ioc.id}" ${selectedIds.has(ioc.id) ? "checked" : ""}></td>
        <td class="val-cell" title="${escapeHtml(ioc.value)}">${escapeHtml(ioc.value)}</td>
        <td>${ioc.type}</td>
        <td>
          <select class="class-select" data-id="${ioc.id}">
            ${["malicious", "suspicious", "unknown", "internal", "external"].map(c =>
              `<option value="${c}" ${c === ioc.classification ? "selected" : ""}>${c}</option>`).join("")}
          </select>
        </td>
        <td>
          <select class="hunt-status-select" data-id="${ioc.id}">
            ${["unconfirmed", "found", "not_found"].map(s =>
              `<option value="${s}" ${s === (ioc.hunt_status || "unconfirmed") ? "selected" : ""}>${s === "not_found" ? "not found" : s}</option>`).join("")}
          </select>
        </td>
        <td>${ioc.source}</td>
        <td>${(ioc.extracted_at || "").slice(0, 19).replace("T", " ")}</td>
        <td><button class="row-del" data-id="${ioc.id}" title="delete">✕</button></td>
      </tr>
    `).join("");

    $$(".hunt-status-select", body).forEach((sel) => sel.addEventListener("change", async () => {
      await fetch(`/api/iocs/${sel.dataset.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hunt_status: sel.value }),
      });
      toast("Hunt status updated.");
    }));

    $$(".row-chk", body).forEach((chk) => chk.addEventListener("change", () => {
      if (chk.checked) selectedIds.add(chk.dataset.id); else selectedIds.delete(chk.dataset.id);
      updateSelectedCount();
    }));
    $$(".class-select", body).forEach((sel) => sel.addEventListener("change", async () => {
      await fetch(`/api/iocs/${sel.dataset.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ classification: sel.value }),
      });
      refreshStats();
      toast("Classification updated.");
    }));
    $$(".row-del", body).forEach((btn) => btn.addEventListener("click", async () => {
      await fetch(`/api/iocs/${btn.dataset.id}`, { method: "DELETE" });
      ledgerCache = ledgerCache.filter((i) => i.id !== btn.dataset.id);
      selectedIds.delete(btn.dataset.id);
      renderLedger();
      updateSelectedCount();
      refreshStats();
    }));
  }

  function updateSelectedCount() {
    $("#ledger-selected-count").textContent = `${selectedIds.size} selected`;
  }

  function initLedger() {
    $("#btn-refresh-ledger").addEventListener("click", loadLedger);
    $("#ledger-search").addEventListener("input", debounce(loadLedger, 300));
    $("#ledger-type-filter").addEventListener("change", loadLedger);
    $("#ledger-class-filter").addEventListener("change", loadLedger);
    $("#ledger-hunt-status-filter").addEventListener("change", loadLedger);
    $("#ledger-check-all").addEventListener("change", (e) => {
      ledgerCache.forEach((i) => e.target.checked ? selectedIds.add(i.id) : selectedIds.delete(i.id));
      renderLedger();
      updateSelectedCount();
    });
    $("#btn-clear-all").addEventListener("click", async () => {
      if (!confirm("Purge ALL stored indicators? This cannot be undone.")) return;
      await fetch("/api/iocs/clear", { method: "POST" });
      ledgerCache = []; selectedIds.clear();
      renderLedger(); updateSelectedCount(); refreshStats();
      toast("Ledger purged.");
    });
    $("#btn-send-to-forge").addEventListener("click", () => {
      if (!selectedIds.size) { toast("Select some indicators first.", true); return; }
      $('.tab-btn[data-tab="forge"]').click();
      $("#forge-hint").textContent = `Using ${selectedIds.size} selected indicator(s) from Ledger.`;
    });
  }

  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  // --------------------------------------------------------------- forge
  let activePlatform = "splunk";

  function initForge() {
    $$(".plat-btn").forEach((btn) => btn.addEventListener("click", () => {
      $$(".plat-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activePlatform = btn.dataset.platform;
    }));
    $("#btn-forge-generate").addEventListener("click", generateQueries);
  }

  async function generateQueries() {
    const timeRange = $("#forge-timerange").value || null;
    const body = { platform: activePlatform, timeRange };
    if (selectedIds.size) body.iocIds = Array.from(selectedIds);

    const res = await fetch("/api/hunt", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    renderQueries(data.queries);
  }

  function renderQueries(queries) {
    const el = $("#query-results");
    if (!queries.length) {
      el.innerHTML = `<div class="empty-state">No compatible IOCs found for this platform. Try a different platform or extract more indicators.</div>`;
      return;
    }
    el.innerHTML = queries.map((q, idx) => `
      <div class="query-block">
        <div class="query-block-head">
          <span class="qb-desc">${escapeHtml(q.description)}</span>
          <button class="copy-btn" data-idx="${idx}">Copy</button>
        </div>
        <pre>${escapeHtml(q.query)}</pre>
      </div>
    `).join("");
    $$(".copy-btn", el).forEach((btn, idx) => btn.addEventListener("click", () => {
      navigator.clipboard.writeText(queries[idx].query).then(() => {
        btn.textContent = "Copied ✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
      });
    }));
  }

  // ------------------------------------------------------------- reports
  function initReports() {
    const nameInput = $("#hunt-name-input");
    const saved = localStorage.getItem("spyhunt_hunt_name");
    if (saved) nameInput.value = saved;
    nameInput.addEventListener("input", () => {
      localStorage.setItem("spyhunt_hunt_name", nameInput.value);
    });

    $("#btn-gen-exec").addEventListener("click", async () => {
      const name = nameInput.value.trim();
      const url = "/api/report/exec" + (name ? "?name=" + encodeURIComponent(name) : "");
      const res = await fetch(url);
      const rep = await res.json();
      renderExecReport(rep);
    });
    $("#btn-gen-analyst").addEventListener("click", async () => {
      const name = nameInput.value.trim();
      const url = "/api/report/analyst" + (name ? "?name=" + encodeURIComponent(name) : "");
      const res = await fetch(url);
      const rep = await res.json();
      renderAnalystReport(rep);
    });
  }

  function renderExecReport(rep) {
    const el = $("#exec-report");
    const sevColor = { critical: "critical", high: "high", medium: "medium", low: "low" }[rep.severity] || "low";
    const titleHtml = rep.huntName ? `<span class="report-hunt-title">${escapeHtml(rep.huntName)}</span>` : "";
    el.innerHTML = `
      ${titleHtml}
      <div><span class="severity-tag ${sevColor}">${rep.severity}</span> &nbsp; ${rep.totalIOCs} total indicators, ${rep.criticalCount} confirmed malicious</div>
      <h3>Business Impact</h3>
      <p>${escapeHtml(rep.businessImpact.estimatedImpact)}</p>
      <ul>
        <li>Users at risk: ${rep.businessImpact.usersAtRisk}</li>
        <li>External communications observed: ${rep.businessImpact.externalCommunications ? "Yes" : "No"}</li>
        <li>Geographic spread: ${rep.businessImpact.geographicSpread.join(", ") || "Unknown"}</li>
      </ul>
      <h3>Timeline</h3>
      ${rep.timeline.slice(0, 10).map(t => `
        <div class="timeline-item">
          <span class="timeline-dot" style="background:${{critical:"var(--crimson)",medium:"var(--amber)",low:"var(--green-ok)"}[t.severity] || "var(--text-dim)"}"></span>
          <span>${(t.timestamp || "").slice(0,19).replace("T"," ")} — ${escapeHtml(t.event)}</span>
        </div>`).join("")}
      <h3>Recommendations</h3>
      <ul>${rep.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
    `;
  }

  function renderAnalystReport(rep) {
    const el = $("#analyst-report");
    const typeRows = Object.entries(rep.iocsByType).map(([t, arr]) => `<li>${t}: ${arr.length}</li>`).join("");
    const titleHtml = rep.huntName ? `<span class="report-hunt-title">${escapeHtml(rep.huntName)}</span>` : "";
    el.innerHTML = `
      ${titleHtml}
      <div>Enrichment: ${rep.enrichmentSummary.enriched} enriched / ${rep.enrichmentSummary.pending} pending</div>
      <h3>Indicators by Type</h3>
      <ul>${typeRows}</ul>
      <h3>Threat Actor Hypotheses</h3>
      <ul>${rep.threatActorHypotheses.map(h => `<li>${escapeHtml(h)}</li>`).join("")}</ul>
      <h3>Detection Opportunities</h3>
      <ul>${rep.detectionOpportunities.map(d => `<li>${escapeHtml(d)}</li>`).join("")}</ul>
      <h3>Hunt Queries Generated</h3>
      <p>${rep.huntQueries.length} ready-to-run queries across Splunk / Sigma / KQL — see Hunt Forge tab.</p>
    `;
  }

  // -------------------------------------------------------------- export
  function initExport() {
    const toggle = $("#btn-export-toggle");
    const menu = $("#export-menu");
    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      menu.classList.toggle("hidden");
    });
    document.addEventListener("click", () => menu.classList.add("hidden"));
    $$("button", menu).forEach((btn) => btn.addEventListener("click", () => {
      const fmt = btn.dataset.fmt;
      const ids = selectedIds.size ? Array.from(selectedIds).join(",") : "";
      const url = "/api/export/" + fmt + (ids ? "?ids=" + encodeURIComponent(ids) : "");
      window.open(url, "_blank");
      menu.classList.add("hidden");
      toast(`Exporting ${selectedIds.size ? selectedIds.size : "all"} indicator(s) as ${fmt.toUpperCase()}.`);
    }));
  }

  // ------------------------------------------------------------- enrich
  function initEnrich() {
    $("#btn-enrich-selected").addEventListener("click", async () => {
      if (!selectedIds.size) { toast("Select some indicators to enrich first.", true); return; }
      const btn = $("#btn-enrich-selected");
      btn.textContent = "Enriching...";
      btn.disabled = true;
      try {
        const res = await fetch("/api/enrich", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ iocIds: Array.from(selectedIds) }),
        });
        const data = await res.json();
        toast(`Enriched ${data.enriched} of ${data.results.length} selected indicator(s).${data.enriched === 0 ? " (No API keys configured — see .env.example)" : ""}`, data.enriched === 0);
        loadLedger();
        refreshStats();
      } catch (e) {
        toast("Enrichment failed: " + e.message, true);
      } finally {
        btn.textContent = "Enrich Selected ⟡";
        btn.disabled = false;
      }
    });
  }

  // --------------------------------------------------------- bulk actions
  function initBulkActions() {
    $("#btn-bulk-tag").addEventListener("click", async () => {
      const tag = $("#bulk-tag-input").value.trim();
      if (!tag) { toast("Enter a tag first.", true); return; }
      if (!selectedIds.size) { toast("Select some indicators first.", true); return; }
      await fetch("/api/iocs/bulk", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iocIds: Array.from(selectedIds), fields: { tagsAdd: tag } }),
      });
      toast(`Tagged ${selectedIds.size} indicator(s) with "${tag}".`);
      $("#bulk-tag-input").value = "";
    });

    $("#btn-bulk-tlp").addEventListener("click", async () => {
      const tlp = $("#bulk-tlp-select").value;
      if (!tlp) { toast("Choose a TLP level first.", true); return; }
      if (!selectedIds.size) { toast("Select some indicators first.", true); return; }
      await fetch("/api/iocs/bulk", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iocIds: Array.from(selectedIds), fields: { tlp } }),
      });
      toast(`Set TLP:${tlp.toUpperCase()} on ${selectedIds.size} indicator(s).`);
    });

    $("#btn-bulk-whitelist").addEventListener("click", async () => {
      if (!selectedIds.size) { toast("Select some indicators first.", true); return; }
      await fetch("/api/iocs/bulk", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iocIds: Array.from(selectedIds), fields: { classification: "external" } }),
      });
      toast(`Whitelisted ${selectedIds.size} indicator(s).`);
      loadLedger();
      refreshStats();
    });
  }

  // --------------------------------------------------------- attack summary
  function initAttackSummary() {
    $("#btn-gen-attack").addEventListener("click", async () => {
      const res = await fetch("/api/attack-summary");
      const data = await res.json();
      const el = $("#attack-summary");
      if (!data.techniques.length) {
        el.innerHTML = `<div class="empty-state">No indicators to analyze yet.</div>`;
        return;
      }
      el.innerHTML = data.techniques.map(t => `
        <div class="attack-tile">
          <span class="at-count">${t.count}×</span>
          <div class="at-id">${t.id}</div>
          <div class="at-name">${escapeHtml(t.name)}</div>
        </div>
      `).join("");
    });
  }

  // ------------------------------------------------------------- tutorial
  const TUTORIAL_STEPS = [
    { title: "Welcome to SPY-THREAT-HUNT V2", body: "This is a local IOC intelligence workspace — extract indicators from threat intel, classify them, generate hunt queries, and report on what you find. Nothing leaves your machine. Let's walk through the four tabs.", target: null },
    { title: "1. Extract", body: "Paste a threat report, point at a URL to scrape, or upload a file (.txt, .pdf, .docx, .csv, .html). The engine pulls out IPs, domains, hashes, CVEs, emails, and more — even de-fanged ones like hxxp:// or evil[.]com.", target: "#tab-extract .glass-card:first-child" },
    { title: "2. Ledger", body: "Every extracted indicator lands here. Search, filter, reclassify, tag, set TLP labels, whitelist false positives, or enrich against VirusTotal/AbuseIPDB/Shodan if you've added API keys to .env.", target: '.tab-btn[data-tab="ledger"]' },
    { title: "3. Hunt Forge", body: "Select indicators in the Ledger (or leave nothing selected to use everything), pick a platform, and generate ready-to-paste detection queries for Splunk, Sigma, KQL, Elastic, Wazuh, or YARA.", target: '.tab-btn[data-tab="forge"]' },
    { title: "4. Reports", body: "Generate an executive brief (severity, business impact, recommendations) or a technical analyst report (hypotheses, detection opportunities, MITRE ATT&CK technique coverage) from whatever's currently in your ledger.", target: '.tab-btn[data-tab="reports"]' },
    { title: "You're set", body: "Everything is stored locally in SQLite — export to CSV, JSON, or a STIX 2.1 bundle any time from the Ledger. Click the ? button in the bottom-left corner to replay this tour.", target: null },
  ];
  let tutStep = 0;

  function initTutorial() {
    $("#tutorial-step-total").textContent = TUTORIAL_STEPS.length;
    $("#help-fab").addEventListener("click", () => startTutorial());
    $("#tutorial-skip").addEventListener("click", closeTutorial);
    $("#tutorial-next").addEventListener("click", () => {
      if (tutStep >= TUTORIAL_STEPS.length - 1) { closeTutorial(); return; }
      tutStep++; renderTutorialStep();
    });
    $("#tutorial-back").addEventListener("click", () => {
      if (tutStep === 0) return;
      tutStep--; renderTutorialStep();
    });

    if (!localStorage.getItem("spyhunt_tutorial_done")) {
      setTimeout(startTutorial, 600);
    }
  }

  function startTutorial() {
    tutStep = 0;
    $("#tutorial-overlay").classList.remove("hidden");
    renderTutorialStep();
  }

  function closeTutorial() {
    clearSpotlight();
    $("#tutorial-overlay").classList.add("hidden");
    localStorage.setItem("spyhunt_tutorial_done", "1");
  }

  function clearSpotlight() {
    $$(".spotlight-target").forEach((el) => el.classList.remove("spotlight-target"));
  }

  function renderTutorialStep() {
    clearSpotlight();
    const step = TUTORIAL_STEPS[tutStep];
    $("#tutorial-step-num").textContent = tutStep + 1;
    $("#tutorial-title").textContent = step.title;
    $("#tutorial-body").textContent = step.body;
    $("#tutorial-progress").style.setProperty("--pct", `${((tutStep + 1) / TUTORIAL_STEPS.length) * 100}%`);
    $("#tutorial-back").style.visibility = tutStep === 0 ? "hidden" : "visible";
    $("#tutorial-next").textContent = tutStep === TUTORIAL_STEPS.length - 1 ? "Finish" : "Next";
    if (step.target) {
      const el = $(step.target);
      if (el) el.classList.add("spotlight-target");
    }
  }

  // ------------------------------------------------------------------ init
  function init() {
    initTabs();
    initIngestModes();
    initLedger();
    initForge();
    initReports();
    initExport();
    initEnrich();
    initBulkActions();
    initAttackSummary();
    initCustomFeed();
    initTutorial();
    $("#btn-extract").addEventListener("click", runExtraction);
    refreshStats();
    tickClock();
    setInterval(tickClock, 1000);
  }

  document.addEventListener("DOMContentLoaded", runBoot);
})();
