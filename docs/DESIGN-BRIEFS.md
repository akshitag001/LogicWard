# LogicWard — Page-by-Page Design Briefs (for Claude / any designer)

This document contains a **ready-to-use design prompt for every screen** in LogicWard. Each brief
is self-contained: paste the **Global Design System** section (once) plus any single **Page** section
into Claude and ask it to design/build that page as an HTML or React artifact.

LogicWard is a **multi-site OT (industrial control) security monitoring platform**. It has two faces:

- **Blue team — SOC Dashboard** (`:8080`, professional, **light** theme): monitors two industrial
  plants and shows drift/attack detections.
- **Red team — Attacker Console** (`:9090`, hacker aesthetic, **dark** theme): launches attacks
  against both plants.

There are two monitored **sites**: **Thermal Power Plant** (Site A — a Raspberry Pi PLC) and the
**GRFICS Chemical Reactor** (Site B — a live Unity **3D** scene). Both feed one alert timeline.

---

## GLOBAL DESIGN SYSTEM

> Paste this block first, then a page block.

**Product:** LogicWard — live OT drift-detection & incident-response console for industrial plants.
**Audience:** control-room operators, control engineers, and SOC analysts at a power/chemical utility.
**Tone:** calm, authoritative, "mission-control" — trustworthy enough to run a live plant, not flashy.
Think Bloomberg terminal × modern SOC (e.g. a refined Grafana/Splunk), not consumer SaaS.

### Two themes

**A. SOC Dashboard — LIGHT, corporate control-room**
```
--page:      #eef0f4   (app background)
--surface:   #ffffff   (cards)
--border:    #dbe0e8   --hair: #eef1f5   (dividers)
--navy:      #14304f   (brand / headers)      --navy-2: #0f2440
--ink:       #1f2937   (primary text)         --ink-2:  #374151
--muted:     #5b6b80   --muted-2: #8494a8     (secondary text)
--accent:    #3987e5   (interactive blue)
Severity:  critical #c02626 · high #c05621 · medium #a16207 · low #0e7a0e · info #5b6b80
           each has a soft bg: crit #fbe8e8 · high #fbeee6 · med #fdf4e3 · low #e6f4ea
Fonts:  UI = system-ui / "Segoe UI" / Roboto;  data/mono = "Cascadia Code"/Consolas
Radius: cards 12px, chips/pills 20px, buttons 8px.  Shadows: subtle (0 1px 2px navy@12%).
```

**B. Attacker Console — DARK, red-team hacker terminal**
```
Background: near-black (#0a0b0e–#111318), subtle CRT scanline overlay, faint grid.
Accent: aggressive RED (#ff3b47 / #e5484d) for "critical/execute"; amber for "high".
Text: bright #e8eef6 on dark; dim #48484a for secondary.
Fonts:  headings/data = "JetBrains Mono";  body = "Inter".
Motif: ⚔️ sword logo, "RED TEAM" wordmark, terminal/log panel, glowing card borders on hover.
Severity chips: critical (red), high (amber), Modbus vs Program-Download category tags.
```

**C. 3D scene panel** (embedded in the SOC dashboard's chemical view): a dark video-like canvas
(#05080c) showing the Unity reactor; the surrounding UI stays light. Treat it like an embedded
live-camera feed.

### Cross-cutting rules
- **Severity is the primary visual language** everywhere — color-code by the 5 levels above.
- **Site identity**: every alert/row carries a **site badge** — *⚡ Thermal* (blue chip #3987e5) or
  *⚗️ Chemical* (amber chip #a16207).
- **MITRE ATT&CK for ICS** technique IDs (e.g. `T0836`, `T0855`, `T0889`) appear as small tags on
  alerts and attack cards — they are a trust signal; make them legible, not decorative.
- **Live data**: pages poll every ~1s. Design explicit **states**: loading, nominal/empty,
  live-updating, and "under attack" (pulsing red). No layout shift when data arrives.
- **Responsive**: works on a 1280–1920px control-room monitor first; degrade gracefully to laptop.
- **Accessibility**: don't rely on color alone (pair with labels/icons); AA contrast; keyboard-focus
  rings on all controls.

---

## PAGE 1 — Login (SOC Dashboard)

**Route:** `GET /login` · Theme A (light).
**One-line prompt:** *Design a professional OT SOC login screen for "LogicWard — SOC Console" with a
username/password form and a demo-credentials quick-fill panel.*

**Purpose:** authenticate one of three role accounts before entering the control-room dashboard.

**Layout:** centered card on the `--page` background. Optional left brand rail (LogicWard mark +
"OT Drift Detection & Incident Response"). Card ≤ 420px wide.

**Components & data**
| Component | Detail |
|-----------|--------|
| Brand | Square gradient mark (navy→accent) + "LogicWard" / "SOC Console" subtitle |
| Form | `username` text, `password` password, "Sign in" primary button (navy). POSTs to `/login` |
| Error | Red inline banner "Invalid credentials" (bg `--crit-bg`, text `--crit`) on 401 |
| Demo credentials panel | Three selectable rows the user can click to auto-fill: `operator/operator123` (Operator), `engineer/engineer123` (Engineer), `soc/soc123` (SOC Analyst). Show role + mono id. Selected row highlights with accent ring. |

**States:** default, focus (accent outline), invalid (error banner + shake optional), submitting.
**Notes:** this is the first impression — quietly premium. No marketing copy. Footer line: "Demo-grade
credentials — change for production."

---

## PAGE 2 — Dashboard Shell (chrome shared by all SOC tabs)

**Route:** `GET /dashboard` · Theme A. **This is the frame** that Pages 3–8 render inside.
**One-line prompt:** *Design the shell for an OT SOC dashboard: a left icon+label sidebar, a top bar
with a site selector and severity counters, and a content area that swaps between tabs.*

**Layout:** full-height flex — fixed **left sidebar** (~230px) + **main** column (topbar + scrolling
content).

**Left sidebar**
| Region | Content |
|--------|---------|
| Brand | LogicWard mark + "SOC Console" |
| Nav (tabs) | **Overview**, **Live Plant**, **Program Diff**, **Alerts** (with a live count badge), **Evidence**. Active item highlighted. |
| Approved baseline | "Approved baseline" kicker + short mono hash + an integrity **pill**: `VALID` (green) or `TAMPERED` (red) |
| User | Signed-in name, role, "Sign out" link |

**Top bar**
| Region | Content / data |
|--------|----------------|
| Title | ● live-dot + **site title** (changes with selected site) + "— {controller name}" |
| **Site selector** | Segmented control: **⚡ Thermal**, **⚗️ Chemical**, **🌐 All** (from `GET /api/sites`; Chemical/All only if Site B is up). Selecting a site swaps the Live Plant view, filters the feed, and retitles. |
| Severity chips | `CRIT n` (red) · `HIGH n` (orange) · `MED n` (amber) — platform-wide counts |
| Actions | "Re-lock baseline" & "Restore baseline" (engineer+), "Export PDF" (SOC only) — role-gated (hidden if the user's role is too low) |

**States:** the site selector's active pill; alert badge turns red when criticals exist; role-gating
removes buttons the user can't use. **RBAC ranks:** operator < engineer < soc_analyst.

---

## PAGE 3 — Overview tab

**Route:** `/dashboard` → Overview · Theme A.
**One-line prompt:** *Design the landing "situation overview" for an OT SOC: four KPI tiles, a
plant-at-a-glance mini panel, and a recent-alerts feed.*

**Purpose:** 5-second health read of the selected site (or all sites).

**Components & data** (from `GET /api/overview` + the client event list)
| Component | Data |
|-----------|------|
| KPI row (4 tiles) | **Baseline integrity** (VALID/TAMPERED, green/red) · **Program vs baseline** (IN SYNC/DRIFTED) · **Critical alerts** (count) · **Total events** (count) |
| Plant at a glance | Compact list of key live values (thermal: Generator MW, Steam Pressure, Drum Level, Turbine Speed, Condenser Vacuum, Bearing Vibration) |
| Recent alerts | The 6 most recent, severity-ranked; each = severity chip + type + one-line reason + **site badge** + MITRE tag + time. Empty state: "No drift detected — plant nominal." |

**Notes:** KPI tiles use big numbers + tiny labels; color the value (green good / red bad). This tab
is glanceable — generous whitespace, no dense tables.

---

## PAGE 4 — Live Plant: Thermal (SCADA mimic)

**Route:** `/dashboard` → Live Plant, when **⚡ Thermal** is selected · Theme A.
**One-line prompt:** *Design an animated single-line SCADA mimic of a thermal power plant that turns
components red and pins a MITRE badge on them when they're under attack.*

**Purpose:** show the live thermal process as an interactive P&ID/single-line diagram that reacts to
detections in real time.

**The mimic** — an SVG flow left→right with labeled nodes and connecting "pipes" (color-coded:
water/blue, fuel/amber, steam/orange, electrical/yellow, control/dashed):
`FUEL VALVE → FURNACE → BOILER DRUM → MAIN STEAM → HP TURBINE → GENERATOR → GEN CB → GSU T1 → 115kV GRID`,
with **FEEDWATER PUMPS**, **CONDENSER**, a **SAFETY PLC** (Modbus :5020, "No Auth" warning tag) and
**OT NETWORK** node. Each protective function shows a **relay chip**: FW TRIP, MS TRIP, TURB TRIP,
FUEL TRIP, COND TRIP.

**Live values on nodes** (from `GET /api/plant`): Drum Level (mm), Steam Pressure (bar) + temp (°C),
Turbine Speed (rpm) + vibration (mm/s), Condenser Vacuum (mbar), Generator MW + Hz, plus on/off states
for valves, pumps, breaker, flame.

**Under-attack behavior:** when an event maps to a node, that node gets an **`attacked` state**
(pulsing red outline) with a pinned **MITRE technique badge**; clicking it **acknowledges** the alert.
Relays flip to **TRIPPED** (red) when their trip coil is set.

**Supporting cards below:** *Trip & alarm status* grid, *Setpoints (holding registers)* grid, *All
process values* grid.

**Legend:** running / stopped / tripped / under-attack. **States:** nominal (calm), tripped (relay
red), under attack (node pulsing + badge). This is the visual centerpiece — make it feel like a real
control-room wallboard.

---

## PAGE 5 — Live Plant: Chemical Reactor 3D (Site B)

**Route:** `/dashboard` → Live Plant, when **⚗️ Chemical** is selected · Theme A shell + Theme C panel.
**One-line prompt:** *Design a monitoring panel that puts a live 3D chemical-reactor scene beside live
process gauges and a one-click attack panel, so an attack visibly hits the plant while an alert fires.*

**Purpose:** the "winning" single-screen moment — the real GRFICS Unity reactor reacting to attacks,
next to the detection.

**Layout:** two columns — **left (large):** the 3D scene; **right (~380px):** gauges + attacks.

**Components & data**
| Component | Data / source |
|-----------|---------------|
| 3D stage | An `<iframe>` of the live Unity reactor (`/viz/`), dark canvas, header "Live 3D process — GRFICS chemical reactor · Modbus :5021 · unauthenticated". Lazy-loads on first open (~200 MB). |
| Live gauges (from `GET /api/site-b/state`) | **Reactor pressure** (kPa, redline ≥3200) · **Liquid level** (%, warn ≥85, over ≥100) · **Feed-1 valve** (%) · **Purge valve** (%). Each = big value + a thin meter bar that turns amber→red as it climbs. |
| Reactor status pill | `Reactor: RUNNING` (green) or `EMERGENCY SHUTDOWN` (red) from the ESD state. |
| Attack panel (engineer+) | Buttons: **Defeat protection**, **Valve override**, **Overfill tank**, **E-stop injection**, **Feed pump kill**, and a green **Restore baseline**. Each has a title + tiny "consequence" caption. POST to `/api/site-b/attack/<id>` and `/api/site-b/reset`. |

**The demo beat:** click *Defeat protection* then *Valve override* → the 3D reactor's pressure gauge
climbs into the red and the scene visibly stresses, while the alert feed (Page 7) fills with
chemical-tagged detections. Gauges must update smoothly (~1–2 Hz). Design the attack buttons as
clearly **dangerous** (red-outlined) but controlled.

---

## PAGE 6 — Program Diff

**Route:** `/dashboard` → Program Diff · Theme A.
**One-line prompt:** *Design a GitHub-style side-by-side diff of a PLC's approved baseline program vs
its live running program, with changed lines highlighted red/green.*

**Thermal (⚡):** header "Baseline vs running program" + a change **summary** (`n changed · n added ·
n removed`) + two mono hashes (baseline / live). Body = two-column diff rows: **left = baseline**,
**right = live**; changed/removed cells tinted red, added tinted green, with inline highlighted spans
on the exact changed tokens. Data from `GET /api/diff`. Empty/clean state: "identical to baseline"
(green).

**Chemical (⚗️):** the reactor has no L5X program, so show an **honest info card**: "Program
monitoring — GRFICS chemical reactor. This site is monitored on the **register plane** (Modbus
holding registers & coils diffed vs the signed baseline). The OpenPLC controller runs **Structured
Text**, not Rockwell L5X, so the rung-level diff doesn't apply. A Structured-Text program-drift parser
is on the roadmap." Design it as a calm explanatory panel, not an error.

---

## PAGE 7 — Alerts (unified timeline)

**Route:** `/dashboard` → Alerts · Theme A.
**One-line prompt:** *Design a severity-ranked, multi-site alert feed for an OT SOC — each row shows
severity, event type, plain-English reason, site badge, MITRE technique, source, and response
actions.*

**Purpose:** the common detection timeline across both plants.

**Row anatomy** (repeated, sorted by severity then recency; from `GET /api/events`):
- **Severity chip** (color-coded, uppercase) at the left edge (also a colored left border).
- **Event type** (e.g. `cyber.setpoint_drift`, `cyber.register_change`, `physical.rogue_device`).
- **Reason** — one plain sentence ("Safety setpoint Pressure_HH_SP changed 3000 → 4100 kPa over Modbus
  — protection weakened").
- **Meta line:** **site badge** (⚡/⚗️) · **MITRE tag** (`T0855 Unauthorized Command Message`) · `src: …`
  · `via: modbus-write` · timestamp.
- **Actions** (role-gated): **Ack** (all), **Quarantine** (SOC, for rogue-device), **Safe-state**
  (SOC, for safety-critical).

**Behavior:** the site selector (Page 2) filters this feed to Thermal / Chemical / All. New criticals
trigger a toast. **Empty state:** "No drift detected — plant nominal." Design for density but keep it
scannable — severity color first, reason second.

---

## PAGE 8 — Evidence (forensic log + report)

**Route:** `/dashboard` → Evidence · Theme A.
**One-line prompt:** *Design a forensic evidence log for an OT SOC — a chronological, exportable record
of every detection with who/when/what and its MITRE mapping, per site.*

**Purpose:** the audit trail an analyst hands to an investigator.

**Components**
| Component | Detail |
|-----------|--------|
| Header | "Evidence log — who · when · what · MITRE ATT&CK for ICS" |
| Rows | Same row format as Alerts (severity, type, reason, site badge, MITRE, source, time) but **chronological** (most recent first) and read-only. Data from `GET /api/evidence` (supports `?site=`). |
| Export | "Export PDF" (SOC role) → `GET /api/evidence/report.pdf?site=<id>` produces a **signed forensic report** (severity summary table + full event timeline + baseline hash/integrity). Per-site or all-sites. |

**Notes:** emphasize completeness and integrity (show the baseline hash + VALID/TAMPERED). The PDF is a
real deliverable — the on-screen view should read like the report's source.

---

## PAGE 9 — Attacker Console (Red Team, both sites)

**Route:** `GET /` on `:9090` · **Theme B (dark hacker terminal).**
**One-line prompt:** *Design a red-team attack console with a dark terminal aesthetic: two
target-grouped grids of attack cards (a thermal power plant and a 3D chemical reactor), a Pi-utilities
row, and a live scrolling operation log.*

**Purpose:** launch real attacks against both monitored plants during a demo.

**Layout:** top bar → two attack sections → utilities → operation log. Card grid, responsive.

**Top bar:** ⚔️ "LogicWard **RED TEAM**"; target readouts **TARGET** (Pi host), **MODBUS** (:5020),
**PROGRAM** (:8081); a connection **status dot**.

**Attack sections (two):**
1. **⚡ Thermal Power Plant** — subtitle "Raspberry Pi · {host}:5020". Cards: **Setpoint Drift**
   (T0836), **Logic Inversion** (T0889), **Condition Stripping** (T0889), **Coil Hijack** (T0889),
   **Rung Injection** (T0843), **Force Coil** (T0855), **DDoS Flood** (T0814, with an **intensity
   slider** 1k–250k packets).
2. **⚗️ GRFICS Chemical Reactor** — subtitle "3D model · {host}:5021". Cards: **Defeat Protection**
   (T0836), **Valve Override** (T0855), **Tank Overfill** (T0855), **E-Stop Injection** (T0855,
   critical), **Feed Pump Kill** (T0855).

**Attack card anatomy:** big emoji icon; category chip (`Modbus` / `Program Download`); severity chip
(HIGH/CRITICAL); title; MITRE line; 1–2 sentence description of the real-world effect; **EXECUTE**
button (with spinner); inline result "✓ …/✗ …". POSTs `{id}` to `/api/attack`.

**Pi Utilities row:** Reset to Baseline, Restart Pi Services, Verify Pi State, Clear SOC Alerts
(each a compact card + RUN button → `/api/utility`).

**Operation log:** a terminal-style panel, newest at bottom, timestamped colored lines
(attack/success/error/system). This is where the "hacker" feel lives — monospace, green/red log lines,
subtle glow.

**States:** card firing (pulse), success (green flash + ✓), failed (red + ✗); status dot online/offline.
Make executing an attack feel weighty and deliberate.

---

## PAGE 10 — Standalone Site B Dashboard (optional)

**Route:** `GET /` on `:8095` (`python -m logicward.sites.grfics.app`) · **Theme C (dark).**
**One-line prompt:** *Design a single-screen "digital twin" console for a chemical reactor: a large
live 3D scene on the left, and on the right live gauges, one-click attacks, and a live detection feed —
all on one dark page.*

**Purpose:** a focused, self-contained chemical-plant demo (no login), used when you want only Site B.

**Layout:** top brand bar ("LogicWard · Site B — GRFICS Chemical Reactor", Modbus :5021 badge,
"Restore baseline" button) → two-column body: **left** the 3D `/viz/` iframe (full-height), **right** a
scrolling column of: **Live process** gauges (pressure, level, feed-1, purge + Reactor RUNNING/ESD
pill), **Attacks** card (the 5 attacks + a "▶ Run scripted demo" that chains Defeat-protection →
Valve-override), and **Detection feed** (live, severity-colored cards with MITRE badges from
`/api/site-b/events`).

**Theme C palette:** bg #0b0f14, panels #0f1722, Fortiphyd **gold** accent #d7b114; severity
crit #ff4d4f / high #ff8c42 / med #ffd166 / low #4dabf7. Alerts animate in (pop). This is the
"wow" single-screen: 3D on the left reacting, alerts lighting up on the right.

---

## Quick reference — pages → routes → data

| Page | Route | Theme | Primary data source(s) |
|------|-------|-------|------------------------|
| 1 Login | `/login` (:8080) | Light | `POST /login` |
| 2 Shell | `/dashboard` | Light | `/api/sites`, `/api/overview` |
| 3 Overview | Overview tab | Light | `/api/overview`, `/api/events` |
| 4 Live Plant — Thermal | Live Plant (⚡) | Light | `/api/plant`, `/api/events` |
| 5 Live Plant — Chemical | Live Plant (⚗️) | Light + 3D | `/viz/`, `/api/site-b/state`, `/api/site-b/attack/*` |
| 6 Program Diff | Diff tab | Light | `/api/diff` |
| 7 Alerts | Alerts tab | Light | `/api/events` |
| 8 Evidence | Evidence tab | Light | `/api/evidence`, `/api/evidence/report.pdf` |
| 9 Attacker Console | `/` (:9090) | Dark | `/api/attack`, `/api/utility` |
| 10 Standalone Site B | `/` (:8095) | Dark | `/viz/`, `/api/site-b/*` |

> Full endpoint details are in **[09-API.md](09-API.md)**; the live data shapes are in
> **[06-SITES.md](06-SITES.md)** and **[07-DETECTION.md](07-DETECTION.md)**.
