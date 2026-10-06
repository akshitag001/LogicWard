(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const jpost = (url) => fetch(url, { method: "POST" }).then((r) => r.json());

  // ---- live process gauges ----
  function setGauge(vid, mid, val, unit, max, warn, crit) {
    const v = $(vid), m = $(mid);
    if (v) v.innerHTML = (val).toFixed(1) + ' <small>' + unit + '</small>';
    if (m) {
      const pct = Math.max(0, Math.min(100, (val / max) * 100));
      m.style.width = pct + "%";
      m.style.background = val >= crit ? "var(--crit)" : val >= warn ? "var(--med)" : "var(--ok)";
    }
  }

  function pollState() {
    fetch("/api/site-b/state").then((r) => r.json()).then((s) => {
      const o = s.feed.outputs, st = s.feed.state;
      setGauge("g-press", "m-press", o.pressure, "kPa", 4000, 2600, 3200);
      setGauge("g-level", "m-level", o.liquid_level, "%", 120, 85, 100);
      setGauge("g-f1", "m-f1", st.f1_valve_pos, "%", 100, 101, 101);
      setGauge("g-purge", "m-purge", st.purge_valve_pos, "%", 100, 101, 101);
      const esd = $("esd");
      if (st.e_stop) { esd.className = "pill trip"; esd.textContent = "Reactor: EMERGENCY SHUTDOWN"; }
      else { esd.className = "pill run"; esd.textContent = "Reactor: RUNNING"; }
    }).catch(() => {});
  }

  // ---- detection feed ----
  let cursor = 0, total = 0;
  const feed = $("feed");
  function pollEvents() {
    fetch("/api/site-b/events?since=" + cursor).then((r) => r.json()).then((d) => {
      cursor = d.cursor;
      if (!d.events.length) return;
      if (total === 0) feed.innerHTML = "";
      d.events.forEach((e) => {
        total++;
        const el = document.createElement("div");
        el.className = "ev " + e.severity;
        const mi = e.mitre && e.mitre.technique_id
          ? '<div class="mi">MITRE ATT&CK ICS · ' + e.mitre.technique_id + ' ' + (e.mitre.technique_name || "") + '</div>' : "";
        el.innerHTML =
          '<div class="h"><span class="sev ' + e.severity + '">' + e.severity + '</span>' +
          '<span class="ty">' + e.type + '</span></div>' +
          '<div class="rs">' + (e.details.reason || "") + '</div>' + mi;
        feed.insertBefore(el, feed.firstChild);
      });
      $("evcount").textContent = total + (total === 1 ? " event" : " events");
    }).catch(() => {});
  }

  // ---- attacks ----
  document.querySelectorAll("[data-atk]").forEach((b) => {
    b.addEventListener("click", () => {
      b.disabled = true;
      jpost("/api/site-b/attack/" + b.dataset.atk).finally(() => setTimeout(() => (b.disabled = false), 400));
    });
  });
  const rundemo = $("rundemo");
  if (rundemo) rundemo.addEventListener("click", async () => {
    rundemo.disabled = true;
    for (const a of ["quality-sabotage", "pressure-redline", "overfill"]) {
      await jpost("/api/site-b/attack/" + a);
      await new Promise((r) => setTimeout(r, 3000));
    }
    setTimeout(() => (rundemo.disabled = false), 800);
  });
  const resetBtn = $("reset");
  if (resetBtn) resetBtn.addEventListener("click", () => {
    jpost("/api/site-b/reset").then(() => {
      feed.innerHTML = '<div class="empty">Baseline restored — plant matches approved config.</div>';
      total = 0; $("evcount").textContent = "0 events";
      $("integrity").textContent = "baseline: LOCKED";
    });
  });

  setInterval(pollState, 500);
  setInterval(pollEvents, 1000);
  pollState(); pollEvents();
})();
