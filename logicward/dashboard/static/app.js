/* Vigilo SOC dashboard — polling + rendering + role-gated actions */
/* Modified by Komal & Antigravity (Adani Project RBAC Fixes) */
(function () {
  "use strict";
  const role = document.body.dataset.role || "operator";
  // capability-based RBAC (6 roles) — the server sends this user's capabilities
  const caps = (document.body.dataset.caps || "").split(",").filter(Boolean);
  const hasCap = (c) => caps.includes(c);
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  // per-role view — which tabs a role sees + its default landing (least-privilege UX)
  const ROLE_VIEWS = {
    operator:         { tabs: ["plant", "alerts"], home: "plant" },
    control_engineer: { tabs: ["overview", "plant", "diff", "insider", "alerts"], home: "diff" },
    network_engineer: { tabs: ["overview", "alerts", "plant"], home: "alerts" },
    soc_analyst:      { tabs: ["overview", "plant", "diff", "alerts", "evidence"], home: "overview" },
    vendor:           { tabs: ["plant", "diff"], home: "plant" },
    ciso:             { tabs: ["overview", "alerts", "evidence", "roles"], home: "overview" },
  };
  const ALL_TABS = ["overview", "plant", "diff", "insider", "alerts", "roles", "evidence"];

  let cursor = 0;
  const events = [];
  const seen = new Set();
  let activeTab = "overview";
  let paused = false;
  const acked = new Set();
  const expanded = new Set();   // event_ids whose Wazuh-style log detail is expanded
  let catFilter = "all";        // Alerts category filter: all | external | internal | mistake
  const CAT_LABEL = { external: "EXTERNAL", internal: "INTERNAL", mistake: "MISTAKE" };

  // ---- multi-site ----
  let activeSite = "thermal-pi";          // "thermal-pi" | "grfics-chem" | "all"
  let chemAvailable = false;
  let chemFrameLoaded = false;
  const SITE_META = {
    "thermal-pi": { name: "Thermal Power Plant", icon: "⚡" },
    "grfics-chem": { name: "GRFICS Chemical Reactor", icon: "⚗️" },
    "all": { name: "All Sites", icon: "🌐" },
  };
  const eventSite = (e) => (e.details && e.details.site) || "thermal-pi";
  const siteVisible = (e) => activeSite === "all" || eventSite(e) === activeSite;
  const siteLabel = (id) => (SITE_META[id] ? SITE_META[id].name : id);

  const $ = (s, r) => (r || document).querySelector(s);
  const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
  const pretty = (t) => (t || "").replace(/_/g, " ");
  const fmt = (n) => (typeof n === "number" ? (Number.isInteger(n) ? n : n.toFixed(1)) : n);
  const jpost = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) }).then(r => r.json());

  // ---- theme (Vigilo light/dark, default light, persisted) ----
  (function initTheme() {
    const root = document.documentElement;
    const apply = (t) => {
      root.setAttribute("data-theme", t);
      try { localStorage.setItem("lw_theme", t); } catch (e) {}
      const btn = $("#theme-toggle");
      if (btn) btn.textContent = (t === "dark" ? "☀" : "☾");
    };
    let saved = "light";
    try { if (localStorage.getItem("lw_theme") === "dark") saved = "dark"; } catch (e) {}
    apply(saved);
    const btn = $("#theme-toggle");
    if (btn) btn.addEventListener("click", () =>
      apply(root.getAttribute("data-theme") === "dark" ? "light" : "dark"));
  })();

  function toast(msg) {
    const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
    clearTimeout(t._h); t._h = setTimeout(() => t.classList.add("hidden"), 2600);
  }

  // capability-gate action controls: remove any control this role can't use
  document.querySelectorAll("[data-cap]").forEach(e => {
    if (!hasCap(e.dataset.cap)) e.remove();
  });

  // tabs
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      activeTab = item.dataset.tab;
      setView(activeTab);
      document.querySelectorAll(".panel").forEach(p => p.classList.add("hidden"));
      $("#tab-" + activeTab).classList.remove("hidden");
      if (activeTab === "diff") { if (activeSite === "grfics-chem") loadChemDiff(); else loadDiff(); }
      if (activeTab === "alerts" || activeTab === "evidence") render();
      if (activeTab === "overview") renderOverviewCards();
    });
  });

  // ---- site selector ----
  const SITE_SHORT = { "thermal-pi": "⚡ Thermal", "grfics-chem": "⚗️ Chemical", "all": "🌐 All" };
  const SITE_TAB_META = {
    "thermal-pi": ["Thermal plant", "var(--accent)"],
    "grfics-chem": ["Chemical reactor", "var(--crit)"],
    "all": ["All sites", "var(--muted)"],
  };

  function buildSiteTabs(list) {
    const box = $("#siteTabs"); if (!box) return;
    const ids = ["thermal-pi"];
    (list || []).forEach(s => { if (s.site_id === "grfics-chem" && s.available) chemAvailable = true; });
    if (chemAvailable) { ids.push("grfics-chem"); ids.push("all"); }
    box.innerHTML = "";
    ids.forEach(id => {
      const meta = SITE_TAB_META[id] || [id, "var(--muted)"];
      const b = el("button", "site-tab" + (id === activeSite ? " active" : ""));
      const dot = el("span", "st-dot"); dot.style.background = meta[1]; b.appendChild(dot);
      b.appendChild(el("span", null, meta[0]));
      b.dataset.site = id;
      b.onclick = () => setSite(id);
      box.appendChild(b);
    });
  }

  function setSite(id) {
    activeSite = id;
    document.querySelectorAll("#siteTabs .site-tab").forEach(b => b.classList.toggle("active", b.dataset.site === id));
    const t = $("#site-title"); if (t) t.textContent = siteLabel(id);
    const showChem = id === "grfics-chem";
    const pt = $("#plant-thermal"), pc = $("#plant-chem");
    if (pt) pt.classList.toggle("hidden", showChem);
    if (pc) pc.classList.toggle("hidden", !showChem);
    const dt = $("#diff-thermal"), dc = $("#diff-chem-note");
    if (dt) dt.classList.toggle("hidden", showChem);
    if (dc) dc.classList.toggle("hidden", !showChem);
    if (activeTab === "diff") { if (showChem) loadChemDiff(); else loadDiff(); }
    // lazy-load the 200 MB 3D scene only when the chemical site is first opened
    if (showChem && !chemFrameLoaded) { const f = $("#chem-frame"); if (f) { f.src = "/viz/"; chemFrameLoaded = true; } }
    const pdfHref = "/api/evidence/report.pdf" + (id === "all" ? "" : "?site=" + id);
    ["#btn-pdf", "#btn-pdf-2", "#ra-pdf"].forEach(sel => { const p = $(sel); if (p) p.href = pdfHref; });
    render();
  }

  fetch("/api/sites").then(r => r.json()).then(d => buildSiteTabs(d.sites)).catch(() => {});

  // ---- chemical site: gauges + attacks ----
  function setCG(vid, mid, val, unit, max, warn, crit) {
    const v = $("#" + vid), m = $("#" + mid);
    if (v) v.innerHTML = (val == null ? "—" : val.toFixed(1)) + ' <span class="cg-u">' + unit + "</span>";
    if (m && val != null) {
      m.style.width = Math.max(0, Math.min(100, (val / max) * 100)) + "%";
      m.style.background = val >= crit ? "var(--crit)" : val >= warn ? "var(--med)" : "var(--ok, #37d67a)";
    }
  }
  function pollChem() {
    if (!chemAvailable || paused) return;
    fetch("/api/site-b/state").then(r => r.json()).then(s => {
      const o = s.feed.outputs, st = s.feed.state;
      setCG("cg-press", "cgm-press", o.pressure, "kPa", 4000, 2600, 3200);
      setCG("cg-level", "cgm-level", o.liquid_level, "%", 120, 85, 100);
      setCG("cg-f1", "cgm-f1", st.f1_valve_pos, "%", 100, 101, 101);
      setCG("cg-f2", "cgm-f2", st.f2_valve_pos, "%", 100, 101, 101);
      setCG("cg-purge", "cgm-purge", st.purge_valve_pos, "%", 100, 101, 101);
      setCG("cg-product", "cgm-product", st.product_valve_pos, "%", 100, 101, 101);
      const esd = $("#cg-esd");
      if (esd) {
        if (st.e_stop) { esd.className = "pill bad"; esd.textContent = "Reactor: EMERGENCY SHUTDOWN"; }
        else { esd.className = "pill ok"; esd.textContent = "Reactor: RUNNING"; }
      }
    }).catch(() => {});
  }
  document.querySelectorAll(".chem-atk[data-atk]").forEach(b => {
    b.addEventListener("click", () => {
      b.disabled = true;
      jpost("/api/site-b/attack/" + b.dataset.atk).then(r => toast("Chemical: " + (r.note || r.attack || "attack fired")))
        .finally(() => setTimeout(() => (b.disabled = false), 500));
    });
  });
  const chemReset = $("#chem-reset"); if (chemReset) chemReset.addEventListener("click", () =>
    jpost("/api/site-b/reset").then(() => toast("Chemical plant restored to baseline")));

  // topbar actions
  const lockBtn = $("#btn-lock"); if (lockBtn) lockBtn.addEventListener("click", () =>
    jpost("/api/baseline/lock").then(r => toast("Baseline re-locked · " + (r.hash || "").slice(7, 19))));
  const restoreBtn = $("#btn-restore"); if (restoreBtn) restoreBtn.addEventListener("click", () =>
    jpost("/api/response/restore").then(() => toast("Approved baseline restored")));
  const clearLogsBtn = $("#btn-clear-logs"); if (clearLogsBtn) clearLogsBtn.addEventListener("click", () =>
    jpost("/api/alerts/clear").then(() => { toast("All alerts cleared"); setTimeout(() => window.location.reload(), 500); }));
  // Alert-feed card-header actions (mirror the topbar controls)
  const ackAllBtn = $("#btn-ack-all"); if (ackAllBtn) ackAllBtn.addEventListener("click", () =>
    jpost("/api/alerts/clear").then(() => { toast("All alerts cleared"); setTimeout(() => window.location.reload(), 500); }));
  const restoreAlertsBtn = $("#btn-restore-alerts"); if (restoreAlertsBtn) restoreAlertsBtn.addEventListener("click", () =>
    jpost("/api/response/restore").then(() => toast("Approved baseline restored")));
  // pause live updates + "view all" jump
  const pauseBtn = $("#btn-pause");
  if (pauseBtn) pauseBtn.addEventListener("click", () => {
    paused = !paused;
    pauseBtn.textContent = paused ? "Resume" : "Pause";
    pauseBtn.classList.toggle("primary", paused);
    toast(paused ? "Live updates paused" : "Live updates resumed");
  });
  const viewAllBtn = $("#ov-viewall");
  if (viewAllBtn) viewAllBtn.addEventListener("click", () => { const n = document.querySelector('.nav-item[data-tab="alerts"]'); if (n) n.click(); });
  // alerts category filter (all / external / internal / mistake)
  document.querySelectorAll("#cat-filter button").forEach(b => b.addEventListener("click", () => {
    catFilter = b.dataset.cat;
    document.querySelectorAll("#cat-filter button").forEach(x => x.classList.toggle("active", x === b));
    render();
  }));

  // ---- role quick-action bar (each button is capability-gated in the template) ----
  const gotoAlerts = () => { const n = document.querySelector('.nav-item[data-tab="alerts"]'); if (n) n.click(); };
  const raAck = $("#ra-ack"); if (raAck) raAck.addEventListener("click", () =>
    jpost("/api/alerts/clear").then(() => { toast("All alerts acknowledged"); setTimeout(() => window.location.reload(), 500); }));
  const raLock = $("#ra-lock"); if (raLock) raLock.addEventListener("click", () =>
    jpost("/api/baseline/lock").then(r => toast("Baseline re-locked · " + (r.hash || "").slice(7, 19))));
  const raRestore = $("#ra-restore"); if (raRestore) raRestore.addEventListener("click", () =>
    jpost("/api/response/restore").then(() => toast("Approved baseline restored")));
  const raQuar = $("#ra-quar"); if (raQuar) raQuar.addEventListener("click", () => {
    const rogue = events.filter(e => e.type === "physical.rogue_device").sort((a, b) => b.seq - a.seq)[0];
    if (rogue) jpost("/api/response/quarantine", { mac: rogue.details.mac, ip: rogue.details.ip, ref: rogue.event_id }).then(() => toast("Rogue device quarantined"));
    else { toast("No rogue device active — opening alerts"); gotoAlerts(); }
  });
  const raSafe = $("#ra-safe"); if (raSafe) raSafe.addEventListener("click", () => {
    const sc = events.filter(e => e.details && e.details.safety_critical && (e.type || "").startsWith("cyber.")).sort((a, b) => b.seq - a.seq)[0];
    if (sc) jpost("/api/response/safe_state", { rung_id: sc.details.rung_id, ref: sc.event_id }).then(() => toast("Safe-state recommended"));
    else { toast("No safety-critical drift active — opening alerts"); gotoAlerts(); }
  });
  const raComp = $("#ra-comp"); if (raComp) raComp.addEventListener("click", () => {
    const o = lastOverview || {};
    toast("Compliance posture · risk " + (o.risk_score != null ? o.risk_score : "—") + " " + (o.risk_band || "") + " · baseline " + (o.baseline_integrity || "—"));
  });
  // vendor (no caps): hide the "Your actions" label, show the read-only notice
  const raLabel = $("#ra-label"), roNote = $("#ro-note");
  if (raLabel) raLabel.style.display = caps.length ? "" : "none";
  if (roNote) roNote.style.display = caps.length ? "none" : "";

  // ---- polling ----
  function pollEvents() {
    if (paused) return;
    fetch("/api/events?since=" + cursor).then(r => r.json()).then(d => {
      cursor = d.cursor;
      let newCrit = false;
      (d.events || []).forEach(e => {
        if (seen.has(e.event_id)) return;
        seen.add(e.event_id); events.push(e);
        if (e.severity === "critical") newCrit = true;
      });
      if (newCrit) { toast("⚠ Critical drift detected"); }
      render();
    }).catch(() => {});
  }

  let lastOverview = null, lastPlant = null, lastChem = null;

  function pollOverview() {
    if (paused) return;
    fetch("/api/overview").then(r => r.json()).then(o => {
      lastOverview = o;
      $("#side-hash").textContent = (o.baseline_hash || "").slice(0, 30) + "…";
      const sp = $("#side-integrity");
      if (sp) { sp.textContent = o.baseline_integrity; sp.className = "pill " + (o.baseline_integrity === "VALID" ? "ok" : "bad"); }
      updateThreatHealth();
      renderOverviewCards();
    }).catch(() => {});
    if (chemAvailable) fetch("/api/site-b/state").then(r => r.json()).then(s => { lastChem = s; renderOverviewCards(); }).catch(() => {});
  }

  // ---- topbar: view title, threat banner, health indicator ----
  const VIEW_META = {
    overview: ["Overview", "Live plant status · impact-ranked detections"],
    plant: ["Live plant", "SCADA mimic · live process + controller load"],
    diff: ["Baseline vs current", "Signed L5X · structural + register diff"],
    insider: ["Insider actions", "Engineering-workstation attack surface (program plane)"],
    alerts: ["Alerts", "Three detection planes · severity ranked"],
    evidence: ["Evidence log", "Append-only forensic record · who · when · what"],
    roles: ["Roles & access", "OT/ICS functional roles + monitored scopes"],
  };
  function setView(tab) {
    const m = VIEW_META[tab] || [tab, ""];
    const t = $("#view-title"), s = $("#view-sub");
    if (t) t.textContent = m[0];
    if (s) s.textContent = m[1];
  }
  // least-privilege UX: show only this role's tabs and land it on its home tab
  function applyRoleView() {
    const view = ROLE_VIEWS[role] || { tabs: ALL_TABS, home: "overview" };
    document.querySelectorAll(".nav-item").forEach(n => {
      n.style.display = view.tabs.includes(n.dataset.tab) ? "" : "none";
    });
    const homeNav = document.querySelector('.nav-item[data-tab="' + view.home + '"]');
    if (homeNav) homeNav.click(); else setView(activeTab);
  }
  function updateThreatHealth() {
    const c = (lastOverview && lastOverview.severity_counts) || {};
    const crit = c.critical || 0, high = c.high || 0, med = c.medium || 0;
    const banner = $("#threat-banner");
    if (banner) {
      const open = crit + high;
      if (open > 0) {
        banner.classList.remove("hidden");
        const cnt = $("#tb-count"); if (cnt) cnt.textContent = open;
        const latest = events.filter(e => e.severity === "critical" || e.severity === "high").sort((a, b) => b.seq - a.seq)[0];
        const lt = $("#tb-latest"); if (lt) lt.textContent = latest ? ((latest.details && latest.details.reason) || pretty(latest.type)) : "";
      } else banner.classList.add("hidden");
    }
    const hi = $("#health-ind"), txt = $("#hi-text");
    if (hi && txt) {
      let state = "ok", label = "All nominal";
      if (crit > 0) { state = "crit"; label = "Attention required"; }
      else if (high > 0) { state = "high"; label = "Elevated"; }
      else if (med > 0) { state = "med"; label = "Advisory"; }
      hi.className = "health-ind " + state; txt.textContent = label;
    }
  }

  // ---- overview cards: KPIs, site cards, detection planes ----
  const _val = (v) => v ? (fmt(v.eng) + " " + v.unit) : "—";
  const _num = (v, u) => (v == null ? "—" : (Math.round(v * 10) / 10) + " " + u);

  function kpiCard(icon, label, val, unit, tone, meterW, sub) {
    const card = el("div", "kpi ov-kpi");
    const head = el("div", "kpi-head");
    head.appendChild(el("span", "kpi-icon tone-" + tone, icon));
    head.appendChild(el("span", "kpi-label", label));
    card.appendChild(head);
    const vrow = el("div", "kpi-valrow");
    vrow.appendChild(el("span", "kpi-val tone-" + tone, val));
    if (unit) vrow.appendChild(el("span", "kpi-unit", unit));
    card.appendChild(vrow);
    const meter = el("div", "kpi-meter"); const fill = el("i", "tone-" + tone);
    fill.style.width = Math.max(0, Math.min(100, meterW)) + "%"; meter.appendChild(fill); card.appendChild(meter);
    card.appendChild(el("div", "kpi-sub", sub));
    return card;
  }
  function renderKpis() {
    const box = $("#kpi-row"); if (!box) return;
    const o = lastOverview || {}, c = o.severity_counts || {};
    const ir = (lastPlant && lastPlant.input_registers) || {};
    const chemO = (lastChem && lastChem.feed && lastChem.feed.outputs) || {};
    const chemHold = (lastChem && lastChem.snapshot && lastChem.snapshot.holding_registers) || {};
    const cards = [];
    const valid = o.baseline_integrity === "VALID";
    cards.push(kpiCard("🛡", "Baseline integrity", valid ? "INTACT" : "TAMPERED", "", valid ? "ok" : "bad",
      valid ? 100 : 12, valid ? "HMAC signature valid" : "signature broken — investigate"));
    const mw = ir.Generator_MW, rpm = ir.Turbine_Speed;
    if (mw) cards.push(kpiCard("⚡", "Unit output", fmt(mw.eng), "MW", "accent",
      mw.eng / 300 * 100, (rpm ? fmt(rpm.eng) + " rpm · " + (rpm.eng / 60).toFixed(2) + " Hz" : "—")));
    else cards.push(kpiCard("⚡", "Unit output", "—", "MW", "accent", 0, "awaiting plant data"));
    const pr = chemO.pressure, lvl = chemO.liquid_level, hh = chemHold.Pressure_HH_SP;
    if (pr != null) { const hhv = hh ? Math.round(hh.eng) : 3000;
      cards.push(kpiCard("◎", "Reactor pressure", Math.round(pr), "kPa", pr >= hhv ? "bad" : "accent",
        pr / (hhv * 1.4) * 100, "level " + (lvl != null ? lvl.toFixed(1) : "—") + "% · HH " + hhv));
    } else cards.push(kpiCard("◎", "Reactor pressure", "—", "kPa", "accent", 0, "site offline"));
    const crit = c.critical || 0, high = c.high || 0, med = c.medium || 0, open = crit + high + med;
    cards.push(kpiCard("⚠", "Open detections", String(open), "", open ? (crit ? "bad" : "warn") : "ok",
      open * 20, crit + " critical · " + high + " high · " + med + " medium"));
    box.innerHTML = ""; cards.forEach(cN => box.appendChild(cN));
  }
  function siteHeader(icon, name, proto, pill, tone, openLabel, onOpen) {
    const h = el("div", "ov-site-h");
    h.appendChild(el("span", "ov-site-icon", icon));
    h.appendChild(el("span", "ov-site-name", name));
    h.appendChild(el("span", "ov-site-proto mono", proto));
    h.appendChild(el("span", "ov-site-pill tone-" + tone, pill));
    const btn = el("button", "ov-open", openLabel); btn.onclick = onOpen; h.appendChild(btn);
    return h;
  }
  function siteRows(rows, alarmKeys) {
    const g = el("div", "ov-site-rows");
    rows.forEach(([k, v]) => {
      const r = el("div", "ov-site-cell");
      r.appendChild(el("span", "ov-rk", k));
      r.appendChild(el("span", "ov-rv" + (alarmKeys.indexOf(k) >= 0 ? " alarm" : ""), v));
      g.appendChild(r);
    });
    return g;
  }
  function gotoPlant(site) {
    setSite(site);
    const nav = document.querySelector('.nav-item[data-tab="plant"]'); if (nav) nav.click();
  }
  function renderSiteCards() {
    const ir = (lastPlant && lastPlant.input_registers) || {};
    const coils = (lastPlant && lastPlant.coils) || {};
    const tcard = $("#ov-site-thermal");
    if (tcard) {
      const trips = Object.entries(coils).filter(([t, on]) => /_trip$/i.test(t) && on).length;
      tcard.innerHTML = "";
      tcard.appendChild(siteHeader("◈", "Thermal power plant", "Modbus TCP :5020 · PLC-01",
        trips ? "TRIP" : "ONLINE", trips ? "bad" : "ok", "Open live", () => gotoPlant("thermal-pi")));
      tcard.appendChild(siteRows([
        ["Turbine", _val(ir.Turbine_Speed)], ["Output", _val(ir.Generator_MW)], ["Main steam", _val(ir.Steam_Pressure)],
        ["Drum level", _val(ir.Drum_Level)], ["Vibration", _val(ir.Bearing_Vibration)], ["Trips", trips ? (trips + " tripped") : "clear"],
      ], trips ? ["Trips"] : []));
    }
    const ccard = $("#ov-site-chem");
    if (ccard) {
      if (!chemAvailable) { ccard.classList.add("hidden"); return; }
      ccard.classList.remove("hidden");
      const o = (lastChem && lastChem.feed && lastChem.feed.outputs) || {};
      const st = (lastChem && lastChem.feed && lastChem.feed.state) || {};
      const esd = st.e_stop;
      ccard.innerHTML = "";
      ccard.appendChild(siteHeader("◎", "Chemical reactor", "Modbus TCP :5021 · GRFICS",
        esd ? "ESD" : "ONLINE", esd ? "bad" : "ok", "Open live 3D", () => gotoPlant("grfics-chem")));
      ccard.appendChild(siteRows([
        ["Pressure", _num(o.pressure, "kPa")], ["Level", _num(o.liquid_level, "%")], ["Feed 1", _num(st.f1_valve_pos, "%")],
        ["Purge", _num(st.purge_valve_pos, "%")], ["Agitator", esd ? "stopped" : "running"], ["ESD", esd ? "TRIPPED" : "armed"],
      ], esd ? ["ESD"] : []));
    }
  }
  const PLANE_DEFS = [
    ["cyber.", "cyber.*", "accent", "L5X structural diff + Modbus register diff on the laptop engine."],
    ["physical.", "physical.*", "high", "Pi agent: link carrier, ARP allowlist, GPIO enclosure switch."],
    ["resource.", "resource.*", "warn", "Pi agent: CPU / RAM sampling — DDoS impact signal."],
  ];
  function renderPlanes() {
    const box = $("#ov-planes"); if (!box) return;
    const vis = events.filter(siteVisible);
    box.innerHTML = "";
    PLANE_DEFS.forEach(([prefix, name, tone, desc]) => {
      const cnt = vis.filter(e => (e.type || "").startsWith(prefix)).length;
      const row = el("div", "ov-plane");
      const top = el("div", "ov-plane-top");
      top.appendChild(el("span", "ov-plane-name tone-" + tone, name));
      top.appendChild(el("span", "ov-plane-cnt tone-" + tone, String(cnt)));
      row.appendChild(top);
      row.appendChild(el("div", "ov-plane-desc", desc));
      box.appendChild(row);
    });
  }
  function ovFeedRow(e) {
    const row = el("div", "ovf-row" + (e.severity === "critical" ? " critical" : ""));
    const s = el("div"); s.appendChild(el("span", "sev " + e.severity, e.severity)); row.appendChild(s);
    row.appendChild(el("div", "cell-time", timeOf(e)));
    const det = el("div");
    const title = el("div", "det-title", (e.details && e.details.reason) || pretty(e.type));
    if (e.category) title.appendChild(el("span", "category-chip " + e.category, CAT_LABEL[e.category] || e.category));
    det.appendChild(title);
    if (e.details && e.details.command) det.appendChild(el("div", "det-detail", e.details.command));
    row.appendChild(det);
    const mt = el("div");
    if (e.mitre && e.mitre.technique_id) {
      mt.appendChild(el("div", "mitre-id", e.mitre.technique_id));
      if (e.mitre.technique_name) mt.appendChild(el("div", "mitre-name", e.mitre.technique_name));
    }
    row.appendChild(mt);
    return row;
  }
  function renderOverviewCards() {
    if (activeTab !== "overview") return;
    renderKpis(); renderSiteCards(); renderPlanes();
    const o = lastOverview || {};
    const valid = o.baseline_integrity === "VALID";
    const dot = $("#ov-lock-dot"), lt = $("#ov-lock-text"), lh = $("#ov-lock-hash");
    if (dot) dot.className = "ov-lock-dot" + (valid ? "" : " bad");
    if (lt) { lt.textContent = valid ? "Signature valid" : "Signature broken"; lt.style.color = valid ? "var(--good)" : "var(--crit)"; }
    if (lh) lh.textContent = "HMAC-SHA256 · " + (o.baseline_hash || "").replace(/^sha256:/, "").slice(0, 16);
    const vis = events.filter(siteVisible);
    const crit = vis.filter(e => e.severity === "critical").length;
    const sum = $("#ov-feed-sum"); if (sum) sum.textContent = vis.length ? (vis.length + " open · " + crit + " critical") : "no alerts";
    const feed = $("#ov-alerts");
    if (feed) {
      feed.innerHTML = "";
      sortedEvents(vis).slice(0, 5).forEach(e => feed.appendChild(ovFeedRow(e)));
      if (!vis.length) feed.appendChild(el("div", "dtbl-empty", "No drift. Live program and registers match the signed baseline."));
    }
  }

  // ---- risk score / system health / rollback (production-grade) ----
  const RISK_COLOR = { LOW: "var(--good)", MODERATE: "var(--warn)", ELEVATED: "var(--serious)", HIGH: "var(--crit)", CRITICAL: "var(--crit)" };
  function renderRisk(score, band) {
    if (score == null) return;
    const s = $("#risk-score"); if (s) s.textContent = score;
    const b = $("#risk-band"); if (b) { b.textContent = band || "—"; b.style.color = RISK_COLOR[band] || "var(--muted)"; }
    const f = $("#risk-bar-fill"); if (f) { f.style.width = score + "%"; f.style.background = RISK_COLOR[band] || "var(--accent)"; }
  }
  function renderHealth(sites) {
    const box = $("#site-health"); if (!box) return;
    box.innerHTML = "";
    sites.forEach(s => {
      const row = el("div", "health-row");
      row.appendChild(el("span", "health-dot " + (s.online ? "up" : "down")));
      const main = el("div", "health-main");
      main.appendChild(el("div", "health-name", (s.icon || "") + " " + s.name));
      main.appendChild(el("div", "health-sub", (s.online ? "online" : "offline") + " · " + s.events + " events"));
      row.appendChild(main);
      row.appendChild(el("span", "health-status st-" + (s.status || "").toLowerCase(), s.status || ""));
      box.appendChild(row);
    });
  }
  function renderRollback(rb) {
    const box = $("#rollback-status"); if (!box) return;
    box.innerHTML = "";
    const mk = (label, val, ok) => {
      const r = el("div", "rb-row");
      r.appendChild(el("span", "rb-label", label));
      r.appendChild(el("span", "rb-val " + (ok ? "ok" : "bad"), val));
      box.appendChild(r);
    };
    mk("Baseline integrity", rb.baseline_integrity || "—", rb.baseline_integrity === "VALID");
    mk("Program vs baseline", rb.program_in_sync ? "IN SYNC" : ((rb.drifted_rungs || 0) + " rung(s) drifted"), !!rb.program_in_sync);
    mk("Rollback", rb.restorable ? "restore available" : "not needed", !rb.restorable);
  }
  function renderTimeline(evs) {
    const box = $("#timeline"); if (!box) return;
    if (!evs.length) { box.innerHTML = '<div class="muted tiny" style="padding:14px">No events yet.</div>'; return; }
    const recent = evs.slice().sort((a, b) => a.seq - b.seq).slice(-48);
    box.innerHTML = "";
    recent.forEach(e => {
      const tick = el("div", "tl-tick " + e.severity);
      const sid = (typeof eventSite === "function") ? eventSite(e) : "thermal-pi";
      const sname = (typeof SITE_SHORT !== "undefined" && SITE_SHORT[sid]) || sid;
      tick.title = sname + " · " + e.type + " · " + (e.timestamp || "").slice(11, 19);
      box.appendChild(tick);
    });
  }

  function pollPlant() {
    if (paused) return;
    fetch("/api/plant").then(r => r.json()).then(p => { lastPlant = p; renderPlant(p); renderOverviewCards(); }).catch(() => {});
  }

  // ---- host telemetry (CPU / RAM / temp) — makes the DDoS impact visible ----
  const TLM_MAX = 40;                 // ~60 s of history at the 1.5 s cadence
  const tlmCpu = [];
  function pollTelemetry() {
    if (paused) return;
    fetch("/api/telemetry").then(r => r.json()).then(t => renderTelemetry(t)).catch(() => {});
  }
  function tlmBand(v, warn, crit) { return v == null ? "" : v >= crit ? " crit" : v >= warn ? " warn" : ""; }
  function renderTelemetry(t) {
    const setStat = (id, val, warn, crit, scale) => {
      const b = $("#tlm-" + id), bar = $("#tlm-" + id + "-bar"), box = $("#tlm-" + id + "-box");
      if (b) b.textContent = (val == null ? "n/a" : val);
      if (bar) bar.style.width = (val == null ? 0 : Math.max(0, Math.min(100, val * (scale || 1)))) + "%";
      if (box) box.className = "tlm-stat" + tlmBand(val, warn, crit);
    };
    setStat("cpu", t.cpu, 70, 85, 1);
    setStat("mem", t.mem, 80, 90, 1);
    setStat("temp", t.temp, 70, 80, 100 / 90);      // bar scaled to a 0–90 °C range
    const host = $("#tlm-host");
    if (host) host.textContent = (t.host || "—") + (t.source === "pi" ? " · Pi" : "");
    const src = $("#tlm-src");
    if (src) { src.textContent = t.source === "pi" ? "from Pi agent" : "local psutil"; src.className = "tlm-src" + (t.source === "pi" ? " pi" : ""); }
    if (t.cpu != null) { tlmCpu.push(t.cpu); if (tlmCpu.length > TLM_MAX) tlmCpu.shift(); }
    const line = $("#tlm-cpu-line");
    if (line && tlmCpu.length) {
      const n = tlmCpu.length;
      line.setAttribute("points", tlmCpu.map((v, i) =>
        (n === 1 ? 0 : i / (n - 1) * 100).toFixed(1) + "," + (30 - v / 100 * 30).toFixed(2)).join(" "));
      const last = tlmCpu[n - 1];
      line.setAttribute("class", last >= 85 ? "crit" : last >= 70 ? "warn" : "");
    }
  }

  // ---- rendering ----
  function alertActions(e) {
    const wrap = el("div", "alert-actions");
    const mk = (label, fn) => { const b = el("button", "mini-btn", label); b.onclick = fn; wrap.appendChild(b); };
    if (hasCap("ack"))
      mk("Ack", () => { acked.add(e.event_id); flagMimic(); jpost("/api/response/ack", { ref: e.event_id }).then(() => toast("Acknowledged")); });
    if (hasCap("network_response") && e.type === "physical.rogue_device")
      mk("Quarantine", () => jpost("/api/response/quarantine", { mac: e.details.mac, ip: e.details.ip, ref: e.event_id }).then(() => toast("Device quarantined")));
    if (hasCap("safe_state") && e.details && e.details.safety_critical && e.type.startsWith("cyber."))
      mk("Safe-state", () => jpost("/api/response/safe_state", { rung_id: e.details.rung_id, ref: e.event_id }).then(() => toast("Safe-state recommended")));
    return wrap;
  }

  function alertRow(e, withActions) {
    const row = el("div", "alert-row");
    row.appendChild(el("span", "sev " + e.severity, e.severity));
    const main = el("div", "alert-main");
    main.appendChild(el("div", "alert-type", e.type));
    main.appendChild(el("div", "alert-reason", (e.details && e.details.reason) || ""));
    const cmd = e.details && e.details.command;
    if (cmd) {
      const c = el("div", "alert-cmd");
      c.appendChild(el("span", "cmd-label", "HOW"));
      c.appendChild(el("code", null, cmd));
      main.appendChild(c);
    }
    const meta = el("div", "alert-meta");
    const sid = eventSite(e);
    meta.appendChild(el("span", "site-chip s-" + sid, (SITE_SHORT[sid] || sid)));
    if (e.mitre && e.mitre.technique_id) {
      const m = el("span", "mitre-tag", e.mitre.technique_id + " " + e.mitre.technique_name);
      meta.appendChild(m);
    }
    const who = e.identity && e.identity.who;
    if (who && who !== "unknown") meta.appendChild(el("span", "who-chip", "by " + who));
    meta.appendChild(el("span", null, "src: " + e.source));
    if (e.identity && e.identity.channel) meta.appendChild(el("span", null, "via: " + e.identity.channel));
    const d = new Date(e.timestamp); meta.appendChild(el("span", null, isNaN(d) ? (e.timestamp || "").slice(11, 19) : d.toLocaleTimeString([], {hour12: false})));
    main.appendChild(meta);
    row.appendChild(main);
    row.appendChild(el("span", null, ""));
    if (withActions) row.appendChild(alertActions(e)); else row.appendChild(el("span"));
    return row;
  }

  function sortedEvents(list) {
    return (list || events).slice().sort((a, b) =>
      (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.seq - a.seq));
  }

  // ---- Alerts + Evidence tables (mockup layout) ----
  const SITE_NAME_SHORT = { "thermal-pi": "Thermal plant", "grfics-chem": "Chemical reactor", "all": "All sites" };
  function timeOf(e) { const d = new Date(e.timestamp); return isNaN(d) ? (e.timestamp || "").slice(11, 19) : d.toLocaleTimeString([], { hour12: false }); }

  function respCell(e) {
    const c = el("div", "resp-cell");
    const mk = (label, cls, fn) => { const b = el("div", "resp-btn" + (cls ? " " + cls : ""), label); b.onclick = fn; c.appendChild(b); };
    if (hasCap("ack"))
      mk("Acknowledge", "primary", () => { acked.add(e.event_id); flagMimic(); jpost("/api/response/ack", { ref: e.event_id }).then(() => toast("Acknowledged")); render(); });
    if (hasCap("network_response") && e.type === "physical.rogue_device")
      mk("Quarantine", null, () => jpost("/api/response/quarantine", { mac: e.details.mac, ip: e.details.ip, ref: e.event_id }).then(() => toast("Device quarantined")));
    if (hasCap("safe_state") && e.details && e.details.safety_critical && e.type.startsWith("cyber."))
      mk("Safe state", null, () => jpost("/api/response/safe_state", { rung_id: e.details.rung_id, ref: e.event_id }).then(() => toast("Safe-state recommended")));
    if (!c.children.length) c.appendChild(el("span", "cell-sub", "—"));
    return c;
  }

  // ---- Wazuh-style expandable log detail (click a row to open) ----
  function toggleExpand(id) {
    if (expanded.has(id)) expanded.delete(id); else expanded.add(id);
    render();
  }
  function logDetail(e) {
    const d = el("div", "dtbl-detail");
    const grid = el("div", "ld-grid");
    const kv = (k, v, cls) => {
      if (v == null || v === "") return;
      const r = el("div", "ld-kv");
      r.appendChild(el("span", "ld-k", k));
      r.appendChild(el("span", "ld-v" + (cls ? " " + cls : ""), String(v)));
      grid.appendChild(r);
    };
    const det = e.details || {}, id = e.identity || {}, m = e.mitre || {};
    kv("Event ID", e.event_id);
    kv("Type", e.type);
    kv("Severity", (e.severity || "").toUpperCase(), e.severity);
    kv("Category", e.category, e.category);
    kv("Time (UTC)", e.timestamp);
    kv("Received", e.received_at);
    kv("Seq", e.seq);
    kv("Source", e.source);
    kv("Site", det.site || "thermal-pi");
    kv("Identity · who", id.who);
    kv("Identity · MAC", id.mac);
    kv("Identity · channel", id.channel);
    kv("MITRE · tactic", m.tactic);
    kv("MITRE · technique", m.technique_id ? (m.technique_id + " " + (m.technique_name || "")) : null);
    kv("Reason", det.reason);
    if (det.command) kv("Command", det.command, "mono");
    kv("Tag", det.tag); kv("Coil", det.coil); kv("Rung", det.rung_id);
    if (det.baseline != null) kv("Baseline", det.baseline);
    if (det.current != null) kv("Current", det.current);
    if (det.safety_critical) kv("Safety-critical", "YES", "crit");
    d.appendChild(el("div", "ld-head", "Decoded event"));
    d.appendChild(grid);
    d.appendChild(el("div", "ld-head", "Full event (JSON)"));
    const pre = el("pre", "log-json"); pre.textContent = JSON.stringify(e, null, 2);
    d.appendChild(pre);
    return d;
  }
  function expandableItem(row, e, ignoreSel) {
    const item = el("div", "dtbl-item" + (expanded.has(e.event_id) ? " open" : ""));
    row.classList.add("clickable");
    row.addEventListener("click", (ev) => { if (ignoreSel && ev.target.closest(ignoreSel)) return; toggleExpand(e.event_id); });
    item.appendChild(row);
    if (expanded.has(e.event_id)) item.appendChild(logDetail(e));
    return item;
  }

  function alertsTableRow(e) {
    const row = el("div", "dtbl-row");
    if (acked.has(e.event_id)) row.classList.add("acked");
    const sev = el("div"); sev.appendChild(el("span", "sev " + e.severity, e.severity)); row.appendChild(sev);
    row.appendChild(el("div", "cell-time", timeOf(e)));
    const sid = eventSite(e);
    const pl = el("div");
    pl.appendChild(el("div", "plane-type", e.type));
    pl.appendChild(el("div", "cell-sub", SITE_NAME_SHORT[sid] || siteLabel(sid)));
    if (e.category) pl.appendChild(el("span", "category-chip " + e.category, CAT_LABEL[e.category] || e.category));
    row.appendChild(pl);
    const det = el("div");
    det.appendChild(el("div", "det-title", (e.details && e.details.reason) || pretty(e.type)));
    if (e.details && e.details.command) det.appendChild(el("div", "det-detail", e.details.command));
    const who = e.identity && e.identity.who, ch = e.identity && e.identity.channel;
    const hasWho = who && who !== "unknown";
    const attr = (hasWho ? "by " + who : "") + (ch ? ((hasWho ? " · " : "") + "via " + ch) : "");
    if (attr) det.appendChild(el("div", "det-sub", attr));
    row.appendChild(det);
    const mt = el("div");
    if (e.mitre && e.mitre.technique_id) {
      mt.appendChild(el("div", "mitre-id", e.mitre.technique_id));
      if (e.mitre.technique_name) mt.appendChild(el("div", "mitre-name", e.mitre.technique_name));
      if (e.mitre.tactic) mt.appendChild(el("div", "mitre-tactic", e.mitre.tactic));
    } else { mt.appendChild(el("div", "cell-sub", "N/A")); }
    row.appendChild(mt);
    row.appendChild(respCell(e));
    return expandableItem(row, e, ".resp-cell");
  }

  function evidenceTableRow(e) {
    const row = el("div", "dtbl-row");
    row.appendChild(el("div", "ev-seq", e.seq != null ? String(e.seq) : "—"));
    row.appendChild(el("div", "cell-time", timeOf(e)));
    const who = (e.identity && e.identity.who && e.identity.who !== "unknown") ? e.identity.who : (e.source || "—");
    row.appendChild(el("div", "ev-who", who));
    row.appendChild(el("div", "ev-what", (e.details && e.details.reason) || pretty(e.type)));
    const id = e.event_id || "";
    row.appendChild(el("div", "ev-id", id ? (id.slice(0, 13) + "…") : "—"));
    return expandableItem(row, e, null);
  }

  function render() {
    const vis = events.filter(siteVisible);
    const crit = vis.filter(e => e.severity === "critical").length;
    const badge = $("#alert-badge"); badge.textContent = vis.length;
    badge.style.background = crit ? "var(--crit)" : "var(--muted-2)";

    if (activeTab === "alerts") {
      const box = $("#alerts-table"); box.innerHTML = "";
      const list = sortedEvents(vis).filter(e => catFilter === "all" || e.category === catFilter);
      list.forEach(e => box.appendChild(alertsTableRow(e)));
      if (!list.length) box.appendChild(el("div", "dtbl-empty",
        vis.length ? ("No " + catFilter + "-category alerts.") : "No drift. Live program and registers match the signed baseline on both sites."));
      const sum = $("#alerts-summary");
      if (sum) {
        const byCat = (c) => vis.filter(e => e.category === c).length;
        sum.textContent = vis.length
          ? (vis.length + " open · " + crit + " critical · " + byCat("external") + " ext / " + byCat("internal") + " int / " + byCat("mistake") + " mistake")
          : "no alerts";
      }
    }
    if (activeTab === "evidence") {
      const box = $("#evidence-table"); box.innerHTML = "";
      const list = vis.slice().sort((a, b) => b.seq - a.seq);
      list.forEach(e => box.appendChild(evidenceTableRow(e)));
      if (!list.length) box.appendChild(el("div", "dtbl-empty", "No evidence recorded yet."));
    }
    renderTimeline(vis);
    flagMimic();
    updateThreatHealth();
    renderOverviewCards();
  }

  function renderPlant(p) {
    const vg = $("#plant-values"); if (vg) {
      vg.innerHTML = "";
      Object.entries(p.input_registers || {}).forEach(([tag, v]) => {
        const d = el("div", "v");
        d.appendChild(el("div", "v-label", pretty(tag)));
        const num = el("div", "v-num"); num.textContent = fmt(v.eng);
        num.appendChild(el("span", "v-unit", v.unit)); d.appendChild(num);
        vg.appendChild(d);
      });
    }
    const sg = $("#plant-setpoints"); if (sg) {
      sg.innerHTML = "";
      Object.entries(p.holding_registers || {}).forEach(([tag, v]) => {
        const d = el("div", "v");
        d.appendChild(el("div", "v-label", pretty(tag)));
        const num = el("div", "v-num"); num.textContent = fmt(v.eng);
        num.appendChild(el("span", "v-unit", v.unit)); d.appendChild(num);
        sg.appendChild(d);
      });
    }
    const tg = $("#plant-trips"); if (tg) {
      tg.innerHTML = "";
      Object.entries(p.coils || {}).filter(([t]) => /trip|alarm/i.test(t)).forEach(([tag, on]) => {
        const d = el("div", "trip");
        d.appendChild(el("span", null, pretty(tag)));
        d.appendChild(el("span", "st " + (on ? "tripped" : "clear"), on ? "TRIPPED" : "CLEAR"));
        tg.appendChild(d);
      });
    }
    const mp = $("#ov-plant"); if (mp) {
      mp.innerHTML = "";
      const keys = ["Generator_MW", "Steam_Pressure", "Drum_Level", "Turbine_Speed", "Condenser_Vacuum", "Bearing_Vibration"];
      keys.forEach(k => {
        const v = (p.input_registers || {})[k]; if (!v) return;
        const d = el("div", "mp");
        d.appendChild(el("span", "muted", pretty(k)));
        d.appendChild(el("b", null, fmt(v.eng) + " " + v.unit));
        mp.appendChild(d);
      });
    }
    renderTrends(p);
    updateMimic(p);
  }

  // ---- live trend sparklines ----
  const TREND_KEYS = ["Generator_MW", "Steam_Pressure", "Main_Steam_Temp", "Drum_Level",
                      "Turbine_Speed", "Condenser_Vacuum", "Bearing_Vibration"];
  const trendHist = {};
  const TREND_MAX = 60;
  const SVGNS = "http://www.w3.org/2000/svg";

  function renderTrends(p) {
    const box = $("#plant-trends"); if (!box) return;
    const ir = p.input_registers || {};
    TREND_KEYS.forEach(k => {
      const v = ir[k]; if (!v) return;
      (trendHist[k] = trendHist[k] || []).push(v.eng);
      if (trendHist[k].length > TREND_MAX) trendHist[k].shift();
    });
    box.innerHTML = "";
    TREND_KEYS.forEach(k => {
      const v = ir[k]; if (!v) return;
      const d = el("div", "trend");
      const head = el("div", "trend-head");
      head.appendChild(el("span", "trend-label", pretty(k)));
      const cur = el("span", "trend-cur", fmt(v.eng));
      cur.appendChild(el("span", "trend-unit", " " + v.unit));
      head.appendChild(cur);
      d.appendChild(head);
      d.appendChild(sparkline(trendHist[k] || []));
      box.appendChild(d);
    });
  }

  function sparkline(vals) {
    const w = 170, h = 34, pad = 3;
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    svg.setAttribute("class", "spark");
    if (vals.length < 2) return svg;
    let lo = Math.min(...vals), hi = Math.max(...vals);
    if (hi - lo < 1e-6) hi = lo + 1;
    const x = i => pad + i * (w - 2 * pad) / (vals.length - 1);
    const y = val => h - pad - (val - lo) / (hi - lo) * (h - 2 * pad);
    const rising = vals[vals.length - 1] >= vals[vals.length - 2];
    const stroke = rising ? "var(--accent)" : "var(--serious)";
    const poly = document.createElementNS(SVGNS, "polyline");
    poly.setAttribute("points", vals.map((v, i) => x(i).toFixed(1) + "," + y(v).toFixed(1)).join(" "));
    poly.setAttribute("fill", "none");
    poly.setAttribute("stroke", stroke);
    poly.setAttribute("stroke-width", "1.6");
    poly.setAttribute("vector-effect", "non-scaling-stroke");
    svg.appendChild(poly);
    const dot = document.createElementNS(SVGNS, "circle");
    dot.setAttribute("cx", x(vals.length - 1)); dot.setAttribute("cy", y(vals[vals.length - 1]));
    dot.setAttribute("r", "2.2"); dot.setAttribute("fill", stroke);
    svg.appendChild(dot);
    return svg;
  }

  // ---- live SCADA mimic ----
  const fmtOrDash = (n) => (n == null ? "—" : fmt(n));
  const TAG_NODE = {
    Drum_Level: "n-drum", Drum_Level_LL_SP: "n-drum", Drum_Level_Sensor_OK: "n-drum",
    Feedwater_Trip: "r-feedwater", Feedwater_Pump_1: "n-fwp", Feedwater_Pump_2: "n-fwp",
    Steam_Pressure: "n-msv", Main_Steam_Temp: "n-msv", Steam_Press_HH_SP: "n-msv",
    Main_Steam_Valve_Open: "n-msv", Main_Steam_Trip: "r-steam",
    Turbine_Speed: "n-turbine", Turbine_Overspeed_SP: "n-turbine", Turbine_Trip: "r-turbine",
    Bearing_Vibration: "n-turbine", Bearing_Vib_HI_SP: "n-turbine", Vibration_Alarm: "r-turbine",
    Generator_MW: "n-gen", Load_Setpoint_MW: "n-gen", Generator_Breaker_Closed: "n-gcb",
    Condenser_Vacuum: "n-cond", Condenser_Vac_LO_SP: "n-cond", Condenser_Trip: "r-cond", Vacuum_Sensor_OK: "n-cond",
    Fuel_Valve_Open: "n-fuel", Fuel_Trip: "r-fuel", Flame_Detected: "n-furnace",
  };
  const TYPE_NODE = {
    "physical.enclosure_open": "n-plc", "physical.link_down": "n-grid", "physical.link_up": "n-grid",
    "physical.rogue_device": "n-net", "resource.cpu_spike": "n-plc", "resource.mem_spike": "n-plc",
    "cyber.baseline_tamper": "n-plc",
  };
  const RUNG_NODE = { Rung0: "n-drum", Rung1: "n-msv", Rung2: "n-turbine", Rung3: "n-furnace", Rung4: "n-cond", Rung5: "n-turbine" };

  function setNodeState(valId, on, onLabel, offLabel, nodeId) {
    const v = $("#" + valId); if (v) v.textContent = on ? onLabel : offLabel;
    if (nodeId) { const n = $("#" + nodeId); if (n) n.classList.toggle("off", !on); }
  }
  function relayState(id, tripped) { const n = $("#" + id); if (n) n.classList.toggle("tripped", !!tripped); }

  function updateMimic(p) {
    const ir = p.input_registers || {}, co = p.coils || {}, di = p.discrete_inputs || {};
    const g = (k) => (ir[k] ? ir[k].eng : null);
    const set = (id, v) => { const e = $("#" + id); if (e) e.textContent = v; };
    set("v-drum", fmtOrDash(g("Drum_Level")));
    set("v-steamp", fmtOrDash(g("Steam_Pressure")));
    set("v-steamt", fmtOrDash(g("Main_Steam_Temp")));
    set("v-turb", fmtOrDash(g("Turbine_Speed")));
    set("v-vib", fmtOrDash(g("Bearing_Vibration")));
    set("v-cond", fmtOrDash(g("Condenser_Vacuum")));
    set("v-gen", fmtOrDash(g("Generator_MW")));
    const rpm = g("Turbine_Speed"); set("v-freq", rpm != null ? (rpm / 60).toFixed(2) : "—");
    setNodeState("s-fuel", co.Fuel_Valve_Open, "OPEN", "SHUT", "n-fuel");
    setNodeState("s-flame", di.Flame_Detected, "FLAME OK", "NO FLAME", "n-furnace");
    setNodeState("s-fwp", co.Feedwater_Pump_1 || co.Feedwater_Pump_2, "RUNNING", "STOPPED", "n-fwp");
    setNodeState("s-msv", co.Main_Steam_Valve_Open, "OPEN", "SHUT", "n-msv");
    setNodeState("s-gcb", co.Generator_Breaker_Closed, "CLOSED", "OPEN", "n-gcb");
    relayState("r-feedwater", co.Feedwater_Trip);
    relayState("r-fuel", co.Fuel_Trip);
    relayState("r-steam", co.Main_Steam_Trip);
    relayState("r-turbine", co.Turbine_Trip || co.Vibration_Alarm);
    relayState("r-cond", co.Condenser_Trip);
  }

  function nodesForEvent(e) {
    const ids = new Set();
    if (TYPE_NODE[e.type]) ids.add(TYPE_NODE[e.type]);
    const blob = (e.type || "") + " " + JSON.stringify(e.details || {});
    Object.keys(TAG_NODE).forEach(name => { if (blob.indexOf(name) >= 0) ids.add(TAG_NODE[name]); });
    const rid = e.details && e.details.rung_id;
    if (rid) Object.keys(RUNG_NODE).forEach(rk => { if (rid.indexOf(rk) >= 0) ids.add(RUNG_NODE[rk]); });
    return [...ids];
  }

  function flagMimic() {
    if (!$("#mimic")) return;
    document.querySelectorAll("#mimic .pin").forEach(p => p.remove());
    document.querySelectorAll("#mimic .attacked").forEach(n => { n.classList.remove("attacked"); n.onclick = null; });
    const per = {};
    events.forEach(e => {
      if (acked.has(e.event_id)) return;
      nodesForEvent(e).forEach(id => {
        const r = per[id] || (per[id] = { sev: "info", mitre: null, ids: [] });
        r.ids.push(e.event_id);
        if (SEV_RANK[e.severity] >= SEV_RANK[r.sev]) { r.sev = e.severity; r.mitre = e.mitre; }
      });
    });
    Object.entries(per).forEach(([id, r]) => {
      const n = $("#" + id); if (!n) return;
      n.classList.add("attacked");
      const tech = (r.mitre && r.mitre.technique_id && r.mitre.technique_id !== "N/A") ? r.mitre.technique_id : r.sev.toUpperCase();
      n.appendChild(el("div", "pin " + r.sev, tech));
      n.onclick = () => {
        r.ids.forEach(x => acked.add(x));
        jpost("/api/response/ack", { ref: r.ids[0] }).catch(() => {});
        flagMimic();
        toast("Acknowledged · " + id.replace(/^[nr]-/, ""));
      };
    });
  }

  function loadDiff() {
    fetch("/api/diff").then(r => r.json()).then(d => {
      $("#diff-bhash").textContent = (d.baseline_hash || "").slice(7, 19);
      $("#diff-lhash").textContent = (d.live_hash || "").slice(7, 19);
      const s = d.summary || {};
      $("#diff-summary").textContent = d.changed === 0 ? "identical to baseline"
        : `${s.changed} changed · ${s.added} added · ${s.removed} removed`;
      const body = $("#diff-body"); body.innerHTML = "";
      (d.rows || []).forEach(row => {
        const r = el("div", "diff-row " + row.type);
        r.appendChild(segCell(row.left_seg));
        r.appendChild(segCell(row.right_seg));
        body.appendChild(r);
      });
    }).catch(() => {});
  }

  function segCell(segs) {
    const c = el("div", "diff-cell");
    (segs || []).forEach(s => {
      if (s.hl) { const sp = el("span", "hl", s.text); c.appendChild(sp); }
      else c.appendChild(document.createTextNode(s.text));
    });
    return c;
  }

  function loadChemDiff() {
    fetch("/api/site-b/diff").then(r => r.json()).then(d => {
      const sum = $("#chem-diff-summary");
      if (sum) sum.textContent = d.changed ? (d.changed + " register(s) drifted") : "all registers match the signed baseline";
      const body = $("#chem-diff-body"); if (!body) return;
      body.innerHTML = "";
      const fmtv = (v) => (v === true ? "ON" : v === false ? "OFF" : v == null ? "—" : fmt(v));
      (d.rows || []).forEach(r => {
        const row = el("div", "dtbl-row" + (r.drift ? " chem-drift" : ""));
        const tag = el("div"); tag.appendChild(el("div", "plane-type", r.tag));
        if (r.safety) tag.appendChild(el("div", "cell-sub", "safety-critical"));
        row.appendChild(tag);
        row.appendChild(el("div", "cell-time", r.addr));
        row.appendChild(el("div", "chem-base", fmtv(r.baseline) + (r.unit ? " " + r.unit : "")));
        const live = el("div", "chem-live" + (r.drift ? " drift" : ""));
        live.textContent = fmtv(r.current) + (r.unit ? " " + r.unit : "");
        row.appendChild(live);
        row.appendChild(el("span", "st " + (r.drift ? "tripped" : "clear"), r.drift ? "DRIFTED" : "MATCH"));
        body.appendChild(row);
      });
      if (!(d.rows || []).length) body.appendChild(el("div", "dtbl-empty", "No writable registers to diff."));
    }).catch(() => {});
  }

  // ---- Insider tab: engineering-workstation attacks + scoped terminal ----
  function insOut(text, cls) {
    const o = $("#ins-out"); if (!o) return;
    o.appendChild(el("div", "gt-line " + (cls || ""), text));
    o.scrollTop = o.scrollHeight;
  }
  function insiderInit() {
    const box = $("#insider-attacks");
    if (box && hasCap("baseline")) {
      fetch("/api/insider/attacks").then(r => r.json()).then(d => {
        box.innerHTML = "";
        (d.attacks || []).forEach(a => {
          const c = el("div", "insider-atk");
          c.appendChild(el("div", "ins-name", a.id));
          c.appendChild(el("div", "ins-desc", a.desc));
          const btn = el("button", "btn danger", "Push to PLC");
          btn.onclick = () => {
            btn.disabled = true;
            jpost("/api/insider/attack/" + a.id).then(r => {
              if (r.cmd) insOut("engineer@ews:~$ " + r.cmd, "gt-cmd");
              insOut(r.ok ? ("[+] " + a.id + " delivered — insider drift now in the alert feed") : ("[!] " + (r.output || "failed")), r.ok ? "gt-ok" : "gt-err");
              toast(r.ok ? ("Insider push: " + a.id) : "Push failed");
            }).finally(() => setTimeout(() => (btn.disabled = false), 700));
          };
          c.appendChild(btn);
          box.appendChild(c);
        });
      }).catch(() => {});
    }
    const inp = $("#ins-input"), run = $("#ins-run");
    const runIns = () => {
      const cmd = (inp.value || "").trim(); if (!cmd) return;
      insOut("engineer@ews:~$ " + cmd, "gt-cmd"); inp.value = "";
      jpost("/api/insider/exec", { cmd }).then(d => {
        (d.output || "").split("\n").forEach(line => insOut(line, d.ok ? "gt-out" : "gt-err"));
      }).catch(e => insOut(e.message, "gt-err"));
    };
    if (run) run.addEventListener("click", runIns);
    if (inp) inp.addEventListener("keydown", e => { if (e.key === "Enter") runIns(); });
  }

  // ---- loops ----
  applyRoleView();
  insiderInit();
  pollEvents(); pollOverview(); pollPlant(); pollTelemetry();
  setInterval(pollEvents, 1000);
  setInterval(pollOverview, 2000);
  setInterval(() => { pollPlant(); if (activeTab === "diff") { if (activeSite === "grfics-chem") loadChemDiff(); else loadDiff(); } }, 1500);
  setInterval(pollTelemetry, 1500);
  setInterval(() => { if (activeSite === "grfics-chem") pollChem(); }, 700);
})();
