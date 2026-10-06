/* ═══════════════════════════════════════════════════════════════════════════
   Vigilo Red Team Console — frontend logic
   ═══════════════════════════════════════════════════════════════════════════ */

function ts() {
  return new Date().toLocaleTimeString([], { hour12: false });
}

function log(msg, cls = "system") {
  const c = document.getElementById("logContainer");
  const d = document.createElement("div");
  d.className = "log-line " + cls;
  d.innerHTML = `<span class="timestamp">[${ts()}]</span> ${msg}`;
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
}

function esc(s) {
  return String(s).replace(/[&<>]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[ch]));
}

/* Log the exact wire commands an attack sent (the literal Modbus / program ops). */
function logCommands(cmds) {
  if (!Array.isArray(cmds)) return;
  for (const cmd of cmds) {
    const c = document.getElementById("logContainer");
    const d = document.createElement("div");
    d.className = "log-line command";
    d.innerHTML = `<span class="timestamp">[${ts()}]</span> <span class="cmd-arrow">&raquo;</span> <code>${esc(cmd)}</code>`;
    c.appendChild(d);
    c.scrollTop = c.scrollHeight;
  }
}

/* ── Fire an attack ───────────────────────────────────────────────────── */
async function fireAttack(id, btn) {
  const card = btn.closest(".attack-card");
  const result = card.querySelector(".card-result");

  btn.classList.add("loading");
  card.classList.remove("success", "failed");
  card.classList.add("firing");
  result.textContent = "";
  result.className = "card-result";

  log(`EXECUTING attack: <strong>${id}</strong>`, "attack");

  let payload = { id: id };
  if (id === "ddos") {
    const slider = document.getElementById("ddos-slider");
    if (slider) payload.count = parseInt(slider.value, 10);
  }

  try {
    const resp = await fetch("/api/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();

    if (data.status === "success") {
      card.classList.remove("firing");
      card.classList.add("success");
      result.textContent = "✓ " + (data.detail || "OK");
      result.className = "card-result ok";
      log(`✓ ${id}: ${data.detail || "success"}`, "success");
      logCommands(data.commands);
    } else {
      card.classList.remove("firing");
      card.classList.add("failed");
      result.textContent = "✗ " + (data.detail || "failed");
      result.className = "card-result fail";
      log(`✗ ${id}: ${data.detail || "failed"}`, "error");
      logCommands(data.commands);
    }
  } catch (err) {
    card.classList.remove("firing");
    card.classList.add("failed");
    result.textContent = "✗ " + err.message;
    result.className = "card-result fail";
    log(`✗ ${id}: ${err.message}`, "error");
  }

  btn.classList.remove("loading");

  // Reset card glow after 4s
  setTimeout(() => card.classList.remove("success", "failed"), 4000);
}

/* ── Fire a utility action ────────────────────────────────────────────── */
async function fireUtility(id, btn) {
  btn.classList.add("loading");
  log(`Running utility: <strong>${id}</strong>`, "utility");

  try {
    const resp = await fetch("/api/utility", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    const data = await resp.json();

    if (data.status === "success") {
      log(`✓ ${id} complete`, "success");
      if (data.detail) log(data.detail.replace(/\n/g, "<br>"), "system");
    } else {
      log(`✗ ${id}: ${data.detail || "failed"}`, "error");
    }
  } catch (err) {
    log(`✗ ${id}: ${err.message}`, "error");
  }

  btn.classList.remove("loading");
}

/* ── Connection check on load ─────────────────────────────────────────── */
(async function checkTarget() {
  const dot = document.getElementById("statusDot");
  try {
    const r = await fetch("/api/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: "__ping__" }),
    });
    // Even a 400 means our server is alive; the Pi connectivity
    // is tested when an actual attack is fired.
    dot.classList.add("online");
    dot.title = "Console online";
    log("Console ready. Select an attack to execute.", "system");
  } catch {
    dot.classList.add("offline");
    dot.title = "Console offline";
    log("WARNING: Could not reach attacker backend.", "error");
  }
})();

/* ── Guided attack terminal (⌨ GUIDED) — show + run the real command ─────── */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let gtCurrent = null;

function cliCommand(id, scope) {
  const r = window.RT || {};
  if (scope === "chem")
    return "python -m logicward.sites.grfics.attacks --host " + (r.chemHost || "127.0.0.1") +
           " --port " + (r.chemPort || "5021") + " " + id;
  return "python -m logicward.attacker.attacks --host " + (r.thermalHost || "127.0.0.1") +
         " --modbus-port " + (r.modbusPort || "5020") + " " + id;
}

function gtWrite(html, cls) {
  const t = document.getElementById("gtTerm");
  const d = document.createElement("div");
  d.className = "gt-line " + (cls || "");
  d.innerHTML = html;
  t.appendChild(d);
  t.scrollTop = t.scrollHeight;
}

function guidedAttack(id, name, scope) {
  gtCurrent = { id, name, scope, cmd: cliCommand(id, scope) };
  document.getElementById("gtTitle").textContent = "Guided attack · " + name;
  document.getElementById("gtTerm").innerHTML = "";
  const run = document.getElementById("gtRun");
  run.disabled = false; run.querySelector(".btn-label").textContent = "RUN COMMAND";
  gtWrite("# " + esc(name), "gt-comment");
  gtWrite("# Step 1 — from the attacker workstation, run the exploit against the live target:", "gt-comment");
  gtWrite('<span class="gt-prompt">attacker@redteam:~$</span> ' + esc(gtCurrent.cmd), "gt-cmd");
  gtWrite("", "");
  gtWrite("Press RUN COMMAND to execute now, or copy it and run in a real terminal.", "gt-dim");
  document.getElementById("gtOverlay").classList.add("open");
}

function closeGuided() { document.getElementById("gtOverlay").classList.remove("open"); }

function guidedCopy() {
  if (!gtCurrent) return;
  navigator.clipboard.writeText(gtCurrent.cmd).then(() => log("Command copied to clipboard", "system"));
}

async function guidedRun() {
  if (!gtCurrent) return;
  const run = document.getElementById("gtRun");
  run.disabled = true; run.querySelector(".btn-label").textContent = "RUNNING…";
  gtWrite('<span class="gt-prompt">attacker@redteam:~$</span> ' + esc(gtCurrent.cmd), "gt-cmd");
  const payload = { id: gtCurrent.id };
  if (gtCurrent.id === "ddos") { const s = document.getElementById("ddos-slider"); if (s) payload.count = parseInt(s.value, 10); }
  try {
    const resp = await fetch("/api/attack", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    const data = await resp.json();
    const cmds = Array.isArray(data.commands) ? data.commands : [];
    for (let i = 0; i < cmds.length; i++) { await sleep(240); gtWrite("  &raquo; " + esc(cmds[i]), "gt-out"); }
    await sleep(200);
    if (data.status === "success") {
      gtWrite("[+] " + esc(data.detail || "attack delivered"), "gt-ok");
      log("✓ (guided) " + gtCurrent.id + ": " + (data.detail || "success"), "success");
      logCommands(data.commands);
    } else {
      gtWrite("[!] " + esc(data.detail || "failed"), "gt-err");
      log("✗ (guided) " + gtCurrent.id + ": " + (data.detail || "failed"), "error");
    }
    gtWrite('<span class="gt-prompt">attacker@redteam:~$</span> <span class="gt-cursor">&#9613;</span>', "gt-cmd");
  } catch (err) {
    gtWrite("[!] " + esc(err.message), "gt-err");
  }
  run.disabled = false; run.querySelector(".btn-label").textContent = "RUN AGAIN";
}

/* ── light / dark theme ──────────────────────────────────────────────────── */
function toggleRtTheme() {
  const root = document.documentElement;
  const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
  root.setAttribute("data-theme", next);
  try { localStorage.setItem("rt_theme", next); } catch (e) {}
  const b = document.getElementById("rtTheme"); if (b) b.textContent = next === "light" ? "☾" : "☀";
}
(function initRtTheme() {
  const root = document.documentElement;
  let t = "dark"; try { if (localStorage.getItem("rt_theme") === "light") t = "light"; } catch (e) {}
  root.setAttribute("data-theme", t);
  const b = document.getElementById("rtTheme"); if (b) b.textContent = t === "light" ? "☾" : "☀";
})();

/* ── scoped terminal ─────────────────────────────────────────────────────── */
function termWrite(html, cls) {
  const o = document.getElementById("termOut");
  const d = document.createElement("div");
  d.className = "gt-line " + (cls || "");
  d.innerHTML = html;
  o.appendChild(d); o.scrollTop = o.scrollHeight;
}
async function termRun() {
  const inp = document.getElementById("termInput");
  const cmd = (inp.value || "").trim(); if (!cmd) return;
  termWrite('<span class="gt-prompt">attacker@redteam:~$</span> ' + esc(cmd), "gt-cmd");
  inp.value = "";
  const btn = document.getElementById("termRun"); btn.disabled = true;
  try {
    const r = await fetch("/api/terminal", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cmd }) });
    const d = await r.json();
    (d.output || "").split("\n").forEach(line => termWrite(esc(line), d.ok ? "gt-out" : "gt-err"));
    log((d.ok ? "⌨ " : "✗ ") + "terminal: " + cmd, d.ok ? "success" : "error");
  } catch (err) { termWrite("[!] " + esc(err.message), "gt-err"); }
  btn.disabled = false; inp.focus();
}
(function wireTerm() {
  const inp = document.getElementById("termInput");
  if (inp) inp.addEventListener("keydown", (e) => { if (e.key === "Enter") termRun(); });
})();
