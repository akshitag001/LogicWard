# LogicWard — Live OT Drift-Detection Appliance

**Detect unauthorized PLC logic changes on a thermal power plant before they become operational risk.**

Version 1.0 · Design & Engineering Specification · 2026-07-27

---

## 0 · Executive summary

**LogicWard** is a live Operational-Technology (OT) security appliance that continuously verifies a Programmable Logic Controller (PLC) against a **cryptographically hashed, approved baseline** and raises severity-ranked, MITRE-mapped alerts the instant the running logic or process state drifts from that baseline.

The demonstration models a **thermal power plant**. A **Raspberry Pi** acts as the PLC, running a Modbus TCP server plus a thin edge sensor agent. A **second machine** acts as the attacker. A **laptop** runs the detection engine and a professional Flask dashboard with role-based access control.

The core insight of the design: **a PLC "program" is data, not something we execute.** LogicWard does *not* build a ladder-logic interpreter. It treats the approved rung set as structured data to baseline, and it treats the PLC's live Modbus registers as ground-truth reality. Detection is a continuous **diff** of live-vs-baseline across two surfaces — the structural program and the live register state.

Everything in the system speaks **one event contract**. Three detection planes (cyber, physical, resource) all emit the same `Event` object onto a single **event bus**, which enriches each event with attacker identity and a MITRE ATT&CK for ICS technique, appends it to a tamper-evident evidence log, and streams it to the dashboard.

### What a judge sees in 8 minutes
1. A quiet, professional SOC dashboard showing a live thermal plant running normally.
2. An attacker on a second machine drifts the PLC — changing a safety setpoint, inverting trip logic, injecting a rogue rung, hijacking an output coil.
3. LogicWard lights up in real time: a side-by-side baseline-vs-current diff with the exact changes highlighted, a severity-ranked alert feed, each alert mapped to a named MITRE ATT&CK for ICS technique.
4. Physical-tampering and resource-exhaustion (DDoS) attacks are caught by the same fabric.
5. One click exports a signed PDF forensic report: who, when, what changed, and the ICS technique used.

---

## 0.1 · Implementation update (v1.1 — as built & verified)

The system described below is **built and passing 98 automated checks across 7 test suites**. Three design decisions were upgraded after the v1.0 draft; this section is the authoritative delta — read it alongside the original sections.

**Changed from the v1.0 draft:**
- **Program format is now real Rockwell L5X XML, not JSON.** The PLC program is a genuine `.L5X` export (`plant/program/ThermalPlant_baseline.L5X`). The engine parses it with `lxml`, **canonicalizes** it (strips volatile `ExportDate`/`EditedDate`/revisions/CRC and non-logic comments), and diffs canonical rung structure. A date-only re-export or a comment edit yields an **identical structural hash** (no false positives); an operator flip / setpoint drift / coil hijack changes it. Neutral-text ladder (`XIC(..)[LES(..)]OTE(..);`) is parsed into instruction/operand structs so all six mutations are still named.
- **Baseline lock is HMAC-SHA256 signed.** Locking captures the L5X + register snapshot into a manifest signed with HMAC-SHA256; editing the locked baseline on disk breaks the signature (`engine/baseline.py`). Honest framing: integrity (tamper-without-key), not access control.
- **Passive FIM via `watchdog`** watches **both** files (`agent/sensors/fim_watch.py`): the Pi's running `live.L5X` (out-of-band program tamper → `cyber.program_file_modified`, a second attack channel beyond the download API) and the laptop's signed baseline (change → HMAC re-verify → `cyber.baseline_tamper` critical, or `cyber.baseline_relocked` info).
- **GitHub-style side-by-side diff** (`engine/l5x_diff.py`, `difflib`): the dashboard renders baseline-vs-live rungs with row-level and word-level red/green highlighting.
- **SIEM-ready JSONL** — already satisfied by the evidence log; documented as such.
- **Docker: deliberately not included** (hardware-coupled Pi sensors + live-demo robustness). Revisit only if time allows.

**Added event types** beyond §3.2: `cyber.program_file_modified`, `cyber.baseline_tamper`, `cyber.baseline_relocked` (FIM); `response.*` actions are live.

**As-built module map** (all under `logicward/`): `engine/{events,server,mitre_map,l5x,l5x_diff,baseline,drift,response,sources,modbus_client}.py` · `plant/{modbus_server,logic_store,rung_to_register}.py` + `program/ThermalPlant_baseline.L5X` · `agent/{forwarder,agent}.py` + `sensors/{link_watch,arp_watch,gpio_tamper,resource,fim_watch}.py` · `dashboard/{app,evidence}.py` + `templates/` + `static/` · `attacker/{attacks,demo_sequence}.py` · `tests/smoke_*.py`.

**Verification (98/98):** `smoke_bus` 15 · `smoke_l5x` 16 · `smoke_plant` 14 · `smoke_drift` 18 · `smoke_agent` 10 · `smoke_dashboard` 15 · `smoke_attacker` 10. Run any with `python -m logicward.tests.<name>`.

**Run it:** dashboard `python -m logicward.dashboard.app` (login `soc/soc123`); one-command live show `python -m logicward.attacker.demo_sequence` (brings up the whole stack, opens on a URL, runs normal → attack → detection). Single-machine by default (embedded plant); set `LOGICWARD_EMBED_PLANT=0` for the real Pi split.

---

## 1 · Problem statement & scope

### 1.1 The problem
In OT/ICS environments, an attacker (or a malicious insider) who can reach a PLC can silently alter its control logic or setpoints. Because Modbus TCP is unauthenticated and PLCs rarely log write operations, such a change can persist undetected until it causes a physical incident — a boiler over-pressure, a turbine overspeed, a safety interlock that no longer trips. The problem statement: **detect unauthorized PLC logic changes before they become operational risk.**

### 1.2 In scope
- A realistic, vulnerable-by-design Modbus TCP PLC simulating a thermal power plant.
- A structured representation of the PLC "program" (ladder-logic rungs as JSON data).
- A hashed baseline of the approved program + register state.
- A structural + register **drift engine** detecting six named mutation classes.
- Three detection planes (cyber / physical / resource) unified on one event bus.
- Attacker tooling that performs each named mutation, plus DDoS and rogue-device.
- A professional Flask dashboard with RBAC, a live plant view, a baseline-vs-current visual diff, a severity-ranked alert feed, and an evidence log.
- MITRE ATT&CK **for ICS** mapping (rule-based, explainable).
- Exportable PDF forensic report.
- A scripted `normal ops → attack → detection` demo sequence.

### 1.3 Explicitly out of scope (anti-over-engineering guardrail)
- **No ladder-logic execution engine.** Rungs are data to baseline, mutate, and diff. The Pi's Modbus registers provide the live reality underneath. Building an interpreter that *runs* the rungs is the single biggest trap to avoid and is deliberately excluded.
- No ML/AI black boxes in the detection path — detection is rule-based and explainable end to end.
- No production identity provider — RBAC is a demo-grade session/role gate.

---

## 2 · System architecture

### 2.1 Split deployment topology

LogicWard runs across three hosts. The attacker only ever touches the Pi — which mirrors reality: an adversary attacks the PLC, and the monitor observes it remotely.

```
┌──────────────────── RASPBERRY PI  (the PLC + edge agent) ─────────────────────┐
│  plant/modbus_server.py     Modbus TCP :502   ← attacker writes registers      │
│  plant/logic_store  (HTTP)  GET /program · POST /program/download              │
│                                     ↑ attacker's simulated "program download"  │
│  agent/agent.py             reads eth0 carrier · GPIO · ARP · CPU/RAM          │
│                             → POSTs Event JSON outbound to the laptop          │
└───────────┬──────────────────────────────────────────────┬────────────────────┘
   Modbus poll (laptop → Pi)                     Event POST (Pi → laptop) + program pull
            │                                                │
┌───────────▼────────────────────────────────────────────────▼──────────────────┐
│ LAPTOP  (detection engine + dashboard)                                          │
│  engine/events.py  ── THE BUS ──  ingest  POST /api/ingest  ← agent             │
│  engine/drift.py   polls Pi Modbus + pulls GET /program → cyber events → bus    │
│  engine/{baseline, mitre_map, response}.py                                      │
│  dashboard/app.py  (RBAC, live view, diff, evidence, PDF)                       │
│  dashboard poll    GET /api/events?since=N                                      │
└─────────────────────────────────────────────────────────────────────────────────┘

ATTACKER  (2nd machine) → targets the Pi only:
   Modbus register/coil writes · POST /program/download · DDoS flood · rogue ARP presence
```

### 2.2 Responsibility split

| Host | Runs | Why here |
|---|---|---|
| **Raspberry Pi** | Modbus server (PLC), logic-store program endpoints, edge sensor agent | The agent must read local hardware — `/sys/class/net/eth0/carrier`, GPIO, ARP table, CPU/RAM — so it lives next to the hardware. The PLC is the thing being attacked. |
| **Laptop** | Event bus, ingest endpoint, drift engine, baseline, MITRE map, response, evidence log, Flask dashboard | All analytical/heavy work and the UI. Polls the Pi's Modbus remotely; receives physical events from the agent. |
| **Attacker machine** | `attacks.py`, `demo_sequence.py` | Isolated adversary. Reaches the Pi over the LAN. |

### 2.3 Data & control flows

1. **Register truth (laptop ← Pi):** `drift.py` polls the Pi's Modbus holding/input registers and coils on an interval. It compares them to the baseline snapshot → emits `cyber.setpoint_drift` and `cyber.register_change` events.
2. **Program truth (laptop ← Pi):** `drift.py` pulls `GET /program` (the live rung set) and diffs it structurally against the baseline rung set → emits `cyber.logic_inversion`, `cyber.condition_stripping`, `cyber.coil_hijack`, `cyber.rung_injection`.
3. **Physical/resource truth (laptop ← Pi agent):** the agent samples hardware locally and POSTs `physical.*` and `resource.*` events to the laptop's `/api/ingest`.
4. **Attacker → Pi:** register/coil mutations over Modbus; structural mutations via `POST /program/download`; DDoS via Modbus flood; rogue device by simply appearing on the LAN.
5. **Bus → everywhere:** every event, wherever born, lands on the single bus which enriches (identity + MITRE), logs (evidence), and serves (dashboard poll).

---

## 3 · The event bus — the spine (build this first)

Everything depends on the bus, so it is implemented and verified before any detector.

### 3.1 The Event contract

One object, every plane, every host:

```json
{
  "event_id":  "3f9c1b7e-…  (uuid4)",
  "type":      "cyber.setpoint_drift",
  "timestamp": "2026-07-27T18:22:04.517Z",
  "source":    "drift_engine",
  "severity":  "high",
  "details": {
    "rung_id": "R07_DRUM_LOW_TRIP",
    "field": "threshold",
    "baseline": 220,
    "current": 40,
    "safety_critical": true
  }
}
```

**Core fields (set by the emitter):**

| Field | Type | Meaning |
|---|---|---|
| `event_id` | string (uuid4) | Stable unique id — used for evidence, dedup, and dashboard keys. |
| `type` | string | Namespaced event type (see §3.2). |
| `timestamp` | string | ISO-8601 UTC, millisecond precision. |
| `source` | string | The detector/sensor that emitted it (`drift_engine`, `arp_watch`, `link_watch`, `gpio_tamper`, `resource`, `attacker_sim`, …). |
| `severity` | enum | `info` \| `low` \| `medium` \| `high` \| `critical`. |
| `details` | object | Type-specific payload. Always includes enough to render a human explanation. |

**Bus-enriched fields (added on arrival, never by the emitter):**

| Field | Type | Meaning |
|---|---|---|
| `identity` | object | `{ who, mac, channel }` — best-known attacker identity (source IP, MAC if known, and the channel used: `modbus-write`, `program-download`, `network`, `physical`). |
| `mitre` | object | `{ tactic, technique_id, technique_name }` — ATT&CK for ICS mapping from `mitre_map.py`. |
| `received_at` | string | ISO-8601 UTC when the bus accepted it (may differ from `timestamp` for buffered remote events). |
| `seq` | integer | Monotonic bus sequence number — the cursor the dashboard polls against. |

### 3.2 Event type namespaces

| Namespace | Emitted by | Examples |
|---|---|---|
| `cyber.*` | `drift_engine` (laptop) | `cyber.setpoint_drift`, `cyber.register_change`, `cyber.logic_inversion`, `cyber.condition_stripping`, `cyber.coil_hijack`, `cyber.rung_injection` |
| `physical.*` | agent (Pi) | `physical.link_down`, `physical.link_up`, `physical.rogue_device`, `physical.enclosure_open` |
| `resource.*` | agent (Pi) | `resource.cpu_spike`, `resource.mem_spike` |
| `response.*` | `response.py` (laptop) | `response.quarantine_device`, `response.operator_ack`, `response.recommend_safe_state`, `response.restore_baseline` |

### 3.3 Severity model (explainable, Prahari-derived)

Severity is computed, not hand-set, so it is defensible. Each event type has a **base weight**; `safety_critical` context multiplies it. The numeric score maps to the enum band.

```
score = base_weight(type) × (SAFETY_MULTIPLIER if safety_critical else 1.0)

band:   score ≥ 85 → critical
        score ≥ 65 → high
        score ≥ 40 → medium
        score ≥ 20 → low
        else       → info
```

Indicative base weights (tunable in one table):

| Event type | Base | Rationale |
|---|---|---|
| `cyber.condition_stripping` (safety input removed) | 80 | Removing a safety interlock is the most dangerous single change. |
| `cyber.logic_inversion` (operator flipped) | 75 | A trip that now fires backwards. |
| `cyber.coil_hijack` (output repointed) | 70 | Control redirected to the wrong actuator. |
| `cyber.rung_injection` (new unauthorized rung) | 70 | Foreign logic added to the program. |
| `cyber.setpoint_drift` (threshold changed) | 55 | Dangerous when on a safety rung; moderate otherwise. |
| `cyber.register_change` (raw value) | 35 | Could be process noise or an attack; corroborated by other signals. |
| `physical.enclosure_open` | 60 | Physical access to the cabinet. |
| `physical.rogue_device` | 50 | Unknown MAC on the OT segment. |
| `physical.link_down` | 45 | Cable pull / network isolation. |
| `resource.cpu_spike` / `resource.mem_spike` | 40 | Consistent with DDoS impact. |

`SAFETY_MULTIPLIER ≈ 1.25`, capped so score never exceeds 100. All weights live in a single constants block for judge-time tuning.

### 3.4 Bus internals

`engine/events.py` implements a thread-safe in-process publish/subscribe bus (a `deque` history + a list of subscriber callbacks — the same collector pattern proven in PiSentinel). On every `emit(event)`:

1. **Validate** the core schema; reject malformed events.
2. **Enrich** — assign `seq`, `received_at`; call `mitre_map.map(event)`; attach best-known `identity`.
3. **Score** — if the emitter did not set severity, compute it (§3.3).
4. **Sink 1 — Evidence log:** append to an append-only store (JSONL, upgradeable to SQLite) for the forensic report.
5. **Sink 2 — Dashboard buffer:** append to the bounded history `deque` the poll endpoint reads.
6. **Sink 3 — Subscribers:** invoke any registered live subscribers (e.g. the response engine's auto-mitigation hooks).

Two emit paths converge on the same `emit()`:
- **Local:** `drift.py`, `response.py` call `bus.emit()` directly.
- **Remote:** the agent POSTs to `/api/ingest`; the ingest handler validates the token + schema, then calls `bus.emit()` per event.

### 3.5 Agent → engine forwarding protocol

The physical/resource sensors run on the Pi but their events must reach the bus on the laptop. The wire format **is** the Event object.

```
POST  http://<laptop-ip>:8080/api/ingest
Headers:
    Content-Type: application/json
    X-LogicWard-Token: <shared secret from config.py>
Body:
    { "events": [ <Event>, <Event>, … ] }      # batch of 1 or more

Responses:
    200  { "accepted": N }
    401  invalid or missing token
    422  schema validation failed  { "errors": [...] }
```

**Reliability:** the agent buffers events in a local `deque`, flushes on a short interval or immediately on emit, and **retries with exponential backoff**, keeping the buffer if the laptop is briefly unreachable — so physical events are never silently lost. `event_id` makes ingest idempotent (duplicates from a retry are dropped by id).

**Security:** the shared token stops any other host on the LAN from injecting forged events. It is a config value, not a secret-management system — appropriate for the demo, and clearly documented as such.

### 3.6 Program channel (the structural surface)

The Pi exposes the PLC "program" — a real Rockwell **L5X** — over HTTP, mirroring how an engineering workstation reads/writes a PLC:

```
GET   /program                     → { "l5x": "<RSLogix5000Content…>", "hash": "sha256:…",
                                        "controller": …, "rung_count": … }
POST  /program/download            → replaces the running L5X (the attacker's structural channel)
        body: { "l5x": "<…L5X XML…>" }   (in a real PLC, this is a program download)
```

- The **laptop** `drift.py` pulls `GET /program` each cycle, parses + canonicalizes the returned L5X, and diffs it against the baseline → structural mutation events.
- The **attacker** performs structural mutations by `POST /program/download` with a tampered L5X.
- The running program is persisted to `live.L5X` on the Pi so the passive **FIM** sensor can also catch out-of-band file tampering (a second structural channel).
- **Setpoints/registers need no special channel** — the attacker writes them over Modbus, and the engine reads them over Modbus (the register surface).

### 3.7 Dashboard consumption

```
GET  /api/events?since=<seq>   → { "events": [ … seq > since … ], "cursor": <latest seq> }
```

A `since`-cursor poll (PiSentinel's proven pattern) rather than WebSockets — deliberately chosen for demo robustness (no socket reconnect fragility on stage). Poll cadence ~1 s gives a live feel.

---

## 4 · The L5X logic model — how a "program" is represented and diffed

This is the heart of the cyber plane and the answer to *"how does an attacker change logic, and how do we see it, without executing anything?"*

### 4.1 The program is a real Rockwell L5X

The approved program is a genuine Studio 5000 export, `plant/program/ThermalPlant_baseline.L5X`. The engine parses it with `lxml` and **canonicalizes** it — stripping volatile export/edit timestamps, software/firmware revisions, CRCs, and free-text comments — so a re-export with no logic change yields an *identical* structural hash (no false positives). Rungs are **data**, parsed and compared, **never executed**.

Each rung's neutral-text ladder is parsed into instruction/operand structs:

```xml
<Rung Number="0" Type="N">
  <Comment><![CDATA[SIL-2  Boiler drum level low-low -> trip feedwater]]></Comment>
  <Text><![CDATA[XIC(Plant_Running)[LES(Drum_Level,Drum_Level_LL_SP)]OTE(Feedwater_Trip);]]></Text>
</Rung>
```

parses to: input contact `XIC(Plant_Running)`, compare `LES(Drum_Level, Drum_Level_LL_SP)`, output coil `OTE(Feedwater_Trip)`. `safety_critical` is derived from the output-coil name (a `*_Trip` coil is safety-critical). Setpoints (`*_SP` tags) carry values in the L5X and are mirrored into Modbus holding registers.

### 4.2 The two detection surfaces

| Surface | Lives in | Mutation observed by |
|---|---|---|
| Setpoint values (`*_SP` tags) | L5X tag values, **mirrored** into Modbus holding registers | **Register diff** (Modbus live-vs-baseline) *and* **structural diff** (L5X tag value) |
| `operator`/instructions, inputs, `output_coil`, rung existence | The L5X program (`GET /program`) | **Structural diff** — canonical L5X rung comparison vs baseline |

The engine canonicalizes and diffs the L5X program (structural mutations) and independently diffs live Modbus registers/coils (setpoint writes + unauthorized commands). A setpoint change is thus corroborated on both surfaces; volatile noise shows up on neither. Both detection paths have real teeth.

### 4.3 The six named mutation classes

| Mutation | What the attacker changes | Where | Detected as | Default severity |
|---|---|---|---|---|
| **Setpoint drift** | A `*_SP` setpoint value | Modbus HR (+ mirrored L5X tag) | `cyber.setpoint_drift` | high on safety rung |
| **Logic inversion** | A compare op flipped (`LES`↔`GRT`) or a contact toggled (`XIC`↔`XIO`) | L5X program | `cyber.logic_inversion` | high |
| **Condition stripping** | A safety input instruction removed from a rung | L5X program | `cyber.condition_stripping` | critical (safety) |
| **Coil hijack** | A rung's `OTE`/`OTL`/`OTU` output coil repointed | L5X program | `cyber.coil_hijack` | high |
| **Rung injection** | A new, unapproved rung added | L5X program | `cyber.rung_injection` | high |
| **Raw register change** | A holding register or control coil forced with no matching approved change | Modbus | `cyber.register_change` | medium |

### 4.4 `rung_to_register.py` — the cross-check map

Maps each rung's contacts/coils/thresholds to concrete Modbus addresses. This lets the engine (a) know which live register backs each setpoint, and (b) cross-check that a rung's declared output coil actually corresponds to real coil behaviour — catching a coil hijack even before the physical effect manifests.

---

## 5 · Detection planes

### 5.1 Cyber plane (`engine/`, laptop) — the core

- **`baseline.py`** — captures the approved state: the L5X program, its structural hash, the setpoints, and a register/coil snapshot, then signs the manifest with **HMAC-SHA256**. Editing the locked baseline on disk breaks the signature. Re-baselining is an Engineer/SOC-Analyst privileged action, logged as evidence.
- **`drift.py`** — the diff loop. Each cycle: pull `GET /program`; poll Modbus registers/coils; run the canonical L5X structural diff and the register diff; emit one event per detected mutation with a precise `details` payload (rung id, field, baseline value, current value, `safety_critical`). Idempotent — a persistent mutation is reported once (by content key), not every cycle.
- **Severity** by criticality: safety-critical rungs escalate (§3.3).

### 5.2 Physical plane (Pi agent) — three independent sensors

- **`link_watch.py`** — reads `/sys/class/net/eth0/carrier`; `0` = cable pulled → `physical.link_down` (and `physical.link_up` on restore).
- **`arp_watch.py`** — reuses PiSentinel ARP discovery + an **allowlist**; any MAC not on the allowlist → `physical.rogue_device` with vendor lookup. The allowlist is captured alongside the baseline.
- **`gpio_tamper.py`** — enclosure-open switch via `gpiozero`, **with a software-simulation fallback** so the whole pipeline works with no hardware attached (a simulated toggle emits the identical `physical.enclosure_open` event). This keeps the demo runnable on any laptop.

### 5.3 Resource plane (Pi agent) — bonus

- **`resource.py`** — reuses PiSentinel's psutil/`/proc` sampling for CPU/RAM. Sustained spikes above a threshold → `resource.cpu_spike` / `resource.mem_spike`, demonstrating the operational impact of a DDoS flood against the Modbus server.

---

## 6 · Cross-cutting concerns

### 6.1 Evidence log & PDF forensic report (`dashboard/evidence.py`)
Every event records **who** (source identity — attacker IP/MAC/channel), **when** (timestamp), and **what** (the drift details). The log is append-only. A SOC Analyst exports a **PDF forensic report**: an incident header, a chronological event table, the baseline-vs-current diffs for each cyber event, and the MITRE technique per event — the artifact a real SOC hands to an investigator.

### 6.2 MITRE ATT&CK for ICS mapping (`engine/mitre_map.py`)
A **rule-based, explainable** table maps each event type to a technique in the **ATT&CK for ICS** matrix (the OT matrix, *not* enterprise ATT&CK). No ML — a judge can read the mapping. Technique IDs, names, and tactics were **verified 2026-07-28 against the live matrix** (attack.mitre.org/matrices/ics):

| Event type | Tactic (ICS) | Technique | ID |
|---|---|---|---|
| `cyber.setpoint_drift` | Impair Process Control | Modify Parameter | `T0836` |
| `cyber.logic_inversion` / `cyber.condition_stripping` / `cyber.coil_hijack` | Persistence | Modify Program | `T0889` |
| `cyber.rung_injection` | Lateral Movement | Program Download | `T0843` |
| `cyber.register_change` | Impair Process Control | Unauthorized Command Message | `T0855` |
| `cyber.program_file_modified` | Persistence | Modify Program | `T0889` |
| `physical.rogue_device` | Initial Access | Rogue Master | `T0848` |
| `physical.link_down` / `resource.cpu_spike` | Inhibit Response Function | Denial of Service | `T0814` |
| `physical.enclosure_open` | Initial Access | *physical cabinet tamper — no direct ICS technique* | `N/A` |
| `cyber.baseline_tamper` | — | *detector-evidence tamper — no direct ICS technique* | `N/A` |

> Each mapping carries a `verified: true` flag; the two honest `N/A` rows (physical enclosure tamper, baseline-integrity tamper) have no direct ATT&CK-for-ICS technique and are deliberately **not** assigned a fabricated ID.

### 6.3 RBAC (`dashboard/app.py`)
Three roles, session-based, enforced server-side:

| Role | Can see | Can do |
|---|---|---|
| **Operator** | Live plant view, alert feed | Acknowledge alerts (`response.operator_ack`) |
| **Engineer** | + baseline & diff detail | Capture/re-baseline the approved program, restore baseline |
| **SOC Analyst** | Everything | Evidence log, PDF export, run demo sequence, all mitigation actions |

### 6.4 Simulated mitigation (`engine/response.py`)
Per the chosen response posture — **detect *and* simulate mitigation** — the dashboard offers non-destructive response actions, each of which itself emits a `response.*` event and is logged as evidence:
- **Quarantine rogue device** (from an `arp_watch` alert) — simulated segment isolation.
- **Recommend safe-state** — on a safety-critical cyber drift, surfaces the recommended safe action (does not command the PLC).
- **Restore baseline** — Engineer pushes the approved program back (simulated program download to the PLC).
- **Operator acknowledge** — human-in-the-loop clearing of an alert.

---

## 7 · Dashboard (Flask, laptop)

Built on **PiSentinel's server-rendered Jinja shell** dressed with **Prahari's SOC design language** (navy sidebar, graded severity palette, insider/severity badge tokens). Views:

| View | Contents |
|---|---|
| **Overview** | Live plant status, impact metrics strip, severity-ranked alert feed, LIVE indicator. |
| **Live Plant** | Thermal-plant mimic: boiler drum level, main steam temp/pressure, turbine speed, generator MW, feedwater pumps, trip coils — driven by live Modbus reads. |
| **Baseline vs Current** | Side-by-side rung + register diff, changed fields highlighted, per-change severity + MITRE technique. |
| **Alerts** | Full severity/plane-coded feed, flashes on arrival. |
| **Evidence** | The forensic log + one-click PDF export. |
| **Demo** (SOC Analyst) | Buttons to run the scripted scenarios. |

Live data via `GET /api/events?since=N` + `GET /api/plant` (current register snapshot) polled ~1 s.

---

## 8 · Attacker (2nd machine)

### 8.1 `attacker/attacks.py`
Built on OT_SECURITY's `modisy.py` raw Modbus client. Commands:

| Attack | Mechanism | Triggers |
|---|---|---|
| Setpoint drift | Modbus FC06 write to a threshold HR | `cyber.setpoint_drift` |
| Logic inversion | `POST /program/download` with flipped operator | `cyber.logic_inversion` |
| Condition stripping | `POST /program/download` removing a safety input | `cyber.condition_stripping` |
| Coil hijack | `POST /program/download` repointing an output coil | `cyber.coil_hijack` |
| Rung injection | `POST /program/download` adding a rung | `cyber.rung_injection` |
| Raw register change | Modbus FC06/FC16 write to a live register | `cyber.register_change` |
| DDoS | Modbus request flood | `resource.cpu_spike` |
| Rogue device | Appear on the LAN (new MAC) | `physical.rogue_device` |

### 8.2 `attacker/demo_sequence.py`
Reuses Prahari's timed choreography: **normal ops → attack → detection**, driving the attacks in a scripted order with pauses so a live audience can follow each detection as it lands on the dashboard. Ordered so severities build to a climax (safety-critical condition-strip last).

---

## 9 · Repository layout

```
logicward/
├── plant/                     # ── on the Pi ──
│   ├── modbus_server.py       # OT_SECURITY server, re-themed to a thermal plant
│   ├── program/
│   │   └── ThermalPlant_baseline.L5X   # approved program (real Rockwell L5X) — DATA, never executed
│   ├── logic_store.py         # serves GET /program + POST /program/download; persists live.L5X
│   └── rung_to_register.py    # L5X tag ↔ Modbus address map
├── agent/                     # ── on the Pi ──
│   ├── forwarder.py           # buffered/retrying HTTP POST client to /api/ingest
│   ├── agent.py               # runs sensors locally; forwards Events to the laptop
│   └── sensors/
│       ├── link_watch.py      # /sys/class/net/eth0/carrier (+ sim)
│       ├── arp_watch.py       # PiSentinel ARP allowlist diff
│       ├── gpio_tamper.py     # gpiozero + software-sim fallback
│       ├── resource.py        # PiSentinel CPU/RAM sampling
│       └── fim_watch.py       # watchdog FIM: live.L5X + signed baseline
├── engine/                    # ── on the laptop ──
│   ├── events.py              # ★ THE BUS + severity + evidence sink
│   ├── server.py              # /api/ingest + /api/events blueprint
│   ├── l5x.py                 # L5X parse + canonicalize + structural hash
│   ├── l5x_diff.py            # GitHub-style side-by-side diff
│   ├── baseline.py            # HMAC-SHA256 signed baseline lock
│   ├── drift.py               # canonical L5X diff + register diff (6 mutations)
│   ├── mitre_map.py           # event type → ATT&CK for ICS (verified)
│   ├── response.py            # simulated mitigation actions
│   ├── sources.py             # EmbeddedPlant (dev) / RemotePlant (Pi)
│   └── modbus_client.py       # laptop reads the Pi PLC
├── dashboard/                 # ── on the laptop ──
│   ├── app.py                 # Flask + RBAC; mounts ingest/poll; drift loop; baseline FIM
│   ├── evidence.py            # who/when/what log → reportlab PDF forensic export
│   ├── templates/             # login + SOC dashboard
│   └── static/                # style.css + app.js (poll, live view, red/green diff)
├── attacker/                  # ── on the 2nd machine ──
│   ├── attacks.py             # the 6 mutations + DDoS + rogue device (Modbus + program download)
│   └── demo_sequence.py       # scripted normal → attack → detection (self-contained)
├── tests/                     # smoke_{bus,l5x,plant,drift,agent,dashboard,attacker}.py
├── config.py                  # Pi IP, ingest URL, token, HMAC key, poll intervals
├── requirements.txt
└── README.md
```

---

## 10 · Reuse map — what is lifted from where

| Source repo | Lifted asset | Becomes |
|---|---|---|
| **OT_SECURITY** | `plc_simulator.py` raw Modbus TCP server (MBAP framing, FC 01–11/2B, threaded sim) | `plant/modbus_server.py` (re-themed thermal) |
| **OT_SECURITY** | `modisy.py` raw client (scan/dump/write/estop/flood/replay) | `attacker/attacks.py` |
| **PiSentinel** | `app.py` Flask polling shell + collector pattern | `dashboard/app.py`, bus poll model |
| **PiSentinel** | `network_trace.py` ARP discovery + known/new tagging | `agent/sensors/arp_watch.py` |
| **PiSentinel** | psutil/`/proc` system stats | `agent/sensors/resource.py` |
| **PiSentinel** | `static/style.css` + Jinja templates | dashboard shell |
| **Prahari** | `score.py` / `rules.py` scoring philosophy | severity model in `events.py` |
| **Prahari** | `attack.py` + `DEMO_SCRIPT.md` choreography | `attacker/demo_sequence.py` |
| **Prahari** | auth (sessions + roles) | `dashboard/app.py` RBAC |
| **Prahari** | `index.css` design tokens (navy/severity/badges) | dashboard styling |

---

## 11 · Locked design decisions

1. **Logic model = real Rockwell L5X.** The program is a genuine `.L5X` export, parsed + canonicalized (volatile dates/revisions/CRC/comments stripped) and diffed structurally; setpoints mirror into Modbus registers for corroboration. Rungs are data — no interpreter.
2. **Baseline = HMAC-SHA256 signed lock** — tamper breaks the signature; a passive `watchdog` FIM watches both the live program and the signed baseline.
3. **RBAC = Operator / Engineer / SOC Analyst.**
4. **Response = detect + simulate mitigation** (non-destructive actions, each logged as evidence).
5. **Split architecture.** Pi = Modbus PLC + edge sensor agent + L5X program endpoints. Laptop = engine + dashboard, polls Modbus remotely, ingests physical events over HTTP.
6. **Transport = HTTP.** Agent→engine = `POST /api/ingest` (batched Event objects, token auth, retry/buffer). Dashboard = `GET /api/events?since=N` polling.
7. **MITRE = ATT&CK for ICS**, rule-based, technique IDs verified against the live matrix.
8. **Docker deliberately not included** (hardware-coupled Pi sensors + live-demo robustness).

---

## 12 · Build plan (staged, verify at each gate)

| Stage | Deliverable | Status / verified by |
|---|---|---|
| **0** | This document (MD + LaTeX + PDF) | ✅ delivered (v1.1) |
| **1** | Scaffold + `config.py` | ✅ delivered |
| **2** | `engine/events.py` + `server.py` bus, `/api/ingest`, `/api/events`, evidence | ✅ `smoke_bus` 15/15 |
| **3** | `agent/` forwarder + sensors (sim fallbacks) + `fim_watch` | ✅ `smoke_agent` 10/10 |
| **4** | `plant/` thermal Modbus server + `ThermalPlant_baseline.L5X` + program endpoints; `engine/l5x` | ✅ `smoke_plant` 14/14, `smoke_l5x` 16/16 |
| **5** | `engine/baseline.py` (HMAC) + `engine/drift.py` | ✅ `smoke_drift` 18/18 (all 6 mutations) |
| **6** | `engine/mitre_map.py` (verified) + `engine/response.py` + `l5x_diff` | ✅ folded into suites |
| **7** | `dashboard/` (RBAC, live view, GitHub diff, alert feed, evidence, PDF) | ✅ `smoke_dashboard` 20/20 |
| **8** | `attacker/attacks.py` + `demo_sequence.py` | ✅ `smoke_attacker` 10/10 + live demo |
| **9** | Two-host integration on real Pi + laptop | ✅ verified on a Raspberry Pi 4 + laptop over Wi-Fi (cyber detection + agent event-forwarding live end-to-end) |
| **10** | Chemical Site B + unified two-site SOC + attack categorization | ✅ `smoke_grfics` 39/39 · `smoke_multisite` 20/20 · `smoke_classify` 20/20 |

**Delivered: 183/183 checks across 10 suites, plus a verified real-hardware two-machine run.**

---

## Appendix A · Glossary
- **PLC** — Programmable Logic Controller; the industrial computer running control logic.
- **OT / ICS** — Operational Technology / Industrial Control Systems.
- **Modbus TCP** — a common, unauthenticated industrial protocol. Coils (RW bits), discrete inputs (RO bits), input registers (RO 16-bit), holding registers (RW 16-bit).
- **Ladder logic / rung** — the graphical PLC programming model; a rung is one logical statement (inputs → operator → output coil).
- **Setpoint** — a configured threshold the control logic compares against.
- **Baseline** — the hashed, approved snapshot of program + register state that live reality is diffed against.
- **Drift** — any deviation of live state from the baseline.
- **ATT&CK for ICS** — MITRE's adversary technique matrix specific to industrial control systems.
