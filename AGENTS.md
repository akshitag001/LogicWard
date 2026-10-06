# AGENTS.md — LogicWard developer context

Single onboarding document for **any** coding agent (or human) picking up LogicWard. Read this
first, then the deeper docs it points to. It tells you what the system is, the invariants you must
not break, the exact contracts, and where to make the common changes.

> Companion docs — **[DESIGN.md](DESIGN.md)** (architecture, the authoritative spec) · **[USAGE.md](USAGE.md)** (run/demo/deploy how-to) · **[README.md](README.md)** (overview) · **[CLAUDE.md](CLAUDE.md)** (same guidance, Claude-Code-flavored). This file is the vendor-neutral superset for orientation.

---

## 1 · What LogicWard is

A live **OT (operational-technology) drift-detection appliance** for a hackathon. It watches a
simulated **thermal power plant** PLC and raises severity-ranked, MITRE-mapped alerts the instant the
running control logic or live process state drifts from a cryptographically signed **approved
baseline**. Pure Python package under `logicward/` (Flask + raw-socket Modbus + `lxml`). **No build
step.**

**Status: built and green — 98/98 automated checks across 7 suites; verified end-to-end on a real
Raspberry Pi 4 ↔ laptop over Wi-Fi.** Only optional polish remains (see §11).

---

## 2 · The prime directive (do not violate)

**The PLC "program" is a real Rockwell `.L5X` file that is DATA — parsed, canonicalized, hashed, and
diffed. It is NEVER executed.** Do not add a ladder-logic interpreter that runs the rungs. The Pi's
live Modbus registers provide the "reality" underneath the logic. This is the single biggest
architectural constraint; preserve it above all else.

Other invariants:
- **One `Event` contract** for everything (§5). Every detector/sensor emits it; the bus enriches it.
- **`engine/sources.py` is the single embedded-vs-real-Pi seam.** The engine only needs
  `program_source() -> L5X bytes` and `register_source() -> {holding, coils}`. Keep detection logic
  transport-agnostic — do not reach into Modbus or HTTP from `drift.py`.
- **Sensors degrade gracefully.** `psutil`/`scapy`/`gpiozero`/`watchdog` are imported defensively and
  every sensor has a simulation hook (`set_sim`/`trigger_sim`/`observe`) so the whole pipeline runs
  hardware-free. Never make a sensor hard-require its hardware library.
- **Detection is rule-based and explainable.** No ML in the detection path.
- **Commits carry no AI attribution** — plain author, **no** `Co-Authored-By` / "Generated with…"
  trailers. (Owner preference; applies to every commit and PR in this repo.)

---

## 3 · Fast orientation (run it in 60 seconds)

```bash
pip install -r requirements.txt          # flask, requests, lxml, watchdog, reportlab (+psutil)

# SOC dashboard, everything in-process (embedded plant — no Pi needed):
python -m logicward.dashboard.app                 # http://localhost:8080/   login soc/soc123

# One-command live show: stack up + drive normal -> attack -> detection with narration:
python -m logicward.attacker.demo_sequence        # ~90s   (--fast ~15s)

# Fire one attack at a running stack:
python -m logicward.attacker.attacks [--host H] [--modbus-port P] [--count N] <command>
#   setpoint-drift | force-coil | ddos | rogue | logic-inversion |
#   condition-stripping | coil-hijack | rung-injection | program-setpoint
```

Dashboard logins (roles gate what's visible/actionable, enforced server-side):
`operator/operator123` · `engineer/engineer123` · `soc/soc123`.

**Tests** — no pytest. Each suite is a standalone script printing `RESULT: N/N checks passed`,
non-zero exit on failure:
```bash
python -m logicward.tests.smoke_drift    # one of: bus l5x plant drift agent dashboard attacker grfics multisite classify
```
Run all (183 checks): loop `for t in bus l5x plant drift agent dashboard attacker grfics multisite classify; do python -m logicward.tests.smoke_$t; done`.

---

## 4 · Architecture on one screen

Three hosts; the attacker only ever touches the Pi (mirrors reality). Single-machine dev collapses
all of it in-process via the embedded plant.

```
Raspberry Pi   plant/modbus_server (Modbus TCP :5020) · plant/logic_store (program HTTP :8081)
               agent/agent + sensors/* -> POST events to laptop
Laptop         engine/{events(bus),server,drift,baseline,l5x,mitre_map,response,sources}
               dashboard/app (Flask :8080, RBAC) — polls Pi Modbus, ingests agent events
Attacker box   Modbus writes · POST /program/download · DDoS flood · rogue ARP
```

**The event bus is the spine (`engine/events.py`).** On every `emit()` it: validates → enriches
(computes `severity` from `BASE_WEIGHTS`×safety multiplier; attaches MITRE via `mitre_map`; adds
`identity`, `seq`, `received_at`) → is idempotent by `event_id` → fans out to three sinks: the
append-only JSONL evidence log, the dashboard poll buffer, and live subscribers.

**Two emit paths converge on the same bus:** local detectors (`drift.py`, `response.py`) call
`bus.emit()` directly; remote Pi sensors POST the same Event JSON to `POST /api/ingest`
(token-authed, batched, retry/buffered in `agent/forwarder.py`), which calls `bus.emit()`. The wire
format **is** the Event.

**Detection has two surfaces** (`engine/drift.py`, `DriftEngine.run_once()` in a ~1 s loop):
- *Structural* — pull live L5X, canonicalize (`engine/l5x.py`: strip volatile
  `ExportDate`/`EditedDate`/revisions/CRC/comments; parse neutral-text ladder into
  instruction/operand structs; `structural_hash`), diff canonical rungs vs baseline.
- *Register* — read live Modbus holding registers + control coils, diff vs the baseline snapshot.
  (Input registers are deliberately **not** diffed — they carry live process noise.
  `PLANT_DRIVEN_COILS` are excluded too — the plant sets its own trips.)

---

## 5 · The contracts (respect these when extending)

### Event object
```jsonc
{ "event_id": "<uuid4>", "type": "cyber.setpoint_drift",   // cyber.* | physical.* | resource.* | response.*
  "timestamp": "ISO-8601Z", "source": "drift_engine",
  "severity": "info|low|medium|high|critical",             // omit -> bus computes it
  "details": { ... type-specific, include safety_critical when relevant ... },
  // --- bus adds on emit (never set by emitter): ---
  "identity": {"who","mac","channel"}, "mitre": {"tactic","technique_id","technique_name","verified"},
  "received_at": "ISO-8601Z", "seq": <int> }
```
Build with `logicward.engine.events.new_event(type, source, details, ...)`; the agent uses the same
factory so `event_id` makes ingest idempotent.

### HTTP endpoints
- **Ingest/poll** (`engine/server.py`, mounted on the dashboard app): `POST /api/ingest`
  (`X-LogicWard-Token`, body `{"events":[...]}` → `{accepted,errors}`, 401/422 on failure);
  `GET /api/events?since=<seq>` → `{events, cursor}`; `GET /health`.
- **Program channel** (`plant/logic_store.py`, Pi :8081): `GET /program` → `{l5x,hash,controller,rung_count}`;
  `GET /program/raw` (xml); `GET /program/hash`; `POST /program/download` (replace running `live.L5X` — the attacker's structural channel).
- **Dashboard** (`dashboard/app.py` :8080): `/login /logout / /dashboard`; `GET /api/overview /api/plant /api/diff /api/evidence /api/evidence/report.pdf`; `POST /api/baseline/lock` and `/api/response/{ack,quarantine,safe_state,restore}` (role-gated).

### Baseline (`engine/baseline.py`)
`capture(l5x_bytes, registers) -> signed{manifest:{l5x,structural_hash,registers,...}, signature}`,
signed with **HMAC-SHA256** (`config.HMAC_KEY`). `verify(signed)->bool`, `save/load`. Editing the
locked manifest breaks the signature; `agent/sensors/fim_watch.py` watches both the live program file
and the signed baseline.

### The six named mutations (event `type` → how detected)
`cyber.setpoint_drift` (compare-operand / `*_SP` tag value) · `cyber.logic_inversion`
(`XIC↔XIO`/compare-op flip, see `INVERSE_OP`) · `cyber.condition_stripping` (input instruction
removed) · `cyber.coil_hijack` (`OTE/OTL/OTU` target changed) · `cyber.rung_injection` (new rung) —
all structural; plus `cyber.register_change` (Modbus). FIM adds `cyber.program_file_modified`,
`cyber.baseline_tamper`, `cyber.baseline_relocked`.

### MITRE (`engine/mitre_map.py`)
Rule-based table, **verified 2026-07-28** against the live ATT&CK-for-ICS matrix; each mapping carries
`verified: true`. Physical enclosure tamper and baseline-integrity tamper are honestly `N/A` (no
matching ICS technique) — never fabricate an ID.

---

## 6 · As-built module map

| File | Responsibility | Host |
|---|---|---|
| `engine/events.py` | **The bus** + `Event`/`new_event`, `BASE_WEIGHTS` severity, `EvidenceLog` | laptop |
| `engine/server.py` | `/api/ingest` + `/api/events` + `/health` blueprint | laptop |
| `engine/l5x.py` | L5X parse + canonicalize (strip volatile) + neutral-text rung parser + `structural_hash` | laptop |
| `engine/l5x_diff.py` | GitHub-style side-by-side red/green rung diff (`difflib`) | laptop |
| `engine/baseline.py` | HMAC-SHA256 signed baseline capture / verify / load | laptop |
| `engine/drift.py` | `DriftEngine` — structural + register diff → the 6 mutations | laptop |
| `engine/mitre_map.py` | event type → ATT&CK-for-ICS technique (verified) | laptop |
| `engine/response.py` | simulated mitigations → `response.*` events | laptop |
| `engine/sources.py` | `EmbeddedPlant` / `RemotePlant` — the one embed-vs-Pi seam | laptop |
| `engine/modbus_client.py` | raw-socket Modbus reads of the Pi PLC | laptop |
| `plant/modbus_server.py` | raw-socket Modbus TCP PLC (thermal register model) | Pi |
| `plant/logic_store.py` | program HTTP endpoints; persists `live.L5X` | Pi |
| `plant/rung_to_register.py` | L5X tag ↔ Modbus address/scale bridge | both |
| `plant/program/ThermalPlant_baseline.L5X` | the approved program (real L5X) | — |
| `agent/forwarder.py` | buffered, retrying, idempotent HTTP POST to `/api/ingest` | Pi |
| `agent/agent.py` | wires sensors + FIM → forwarder; poll loop | Pi |
| `agent/sensors/{link_watch,arp_watch,gpio_tamper,resource,fim_watch}.py` | physical/resource/FIM sensors (all with sim hooks) | Pi |
| `dashboard/app.py` | Flask app: RBAC, mounts ingest/poll, drift loop, animated SCADA mimic, baseline FIM | laptop |
| `dashboard/evidence.py` | evidence log → reportlab PDF forensic report | laptop |
| `attacker/attacks.py` | Modbus + program-download mutations, DDoS, rogue (`MUTATORS` + `main()`) | 2nd box |
| `attacker/demo_sequence.py` | self-contained `normal → attack → detection` choreography | 2nd box |
| `tests/smoke_*.py` | integration-style suites (real servers, ephemeral ports) | — |
| `config.py` | all deployment values, each `LOGICWARD_*`-overridable | — |
| `deploy/{pi_bootstrap.sh,run_pi.sh,run_laptop.ps1}` | two-host deploy scripts | — |

---

## 7 · Configuration (`logicward/config.py`, all `LOGICWARD_*`-overridable)

| Value | Default | Notes |
|---|---|---|
| `INGEST_PORT` | `8080` | dashboard + ingest/poll |
| `INGEST_URL` | `http://127.0.0.1:8080/api/ingest` | on the Pi, set to `http://<laptop-ip>:8080/api/ingest` |
| `TOKEN` | `logicward-dev-token-change-me` | `X-LogicWard-Token`, demo-grade static token |
| `PI_HOST` | `127.0.0.1` | where the engine reads Modbus/program in remote mode |
| `MODBUS_PORT` | `5020` | 502 needs root; 5020 for dev |
| `PROGRAM_PORT` | `8081` | program HTTP endpoints |
| `HMAC_KEY` | `logicward-baseline-signing-key-change-me` | signs the baseline manifest |
| `POLL_INTERVAL` / `AGENT_FLUSH_INTERVAL` | `1.0` | seconds |
| `DATA_DIR` / `EVIDENCE_PATH` / `BASELINE_MANIFEST` | under `logicward/data/` | **generated, gitignored** |
| `LOGICWARD_EMBED_PLANT` | `1` | `0` = real Pi (`dashboard/app.py` reads it) |

**Runtime state is generated and gitignored:** `logicward/data/` (evidence + signed baseline) and
`logicward/plant/program/live.L5X`. The pristine approved program is `ThermalPlant_baseline.L5X`;
`live.L5X` is created from it and is what the attacker's download mutates.

---

## 8 · How to make the common changes (where each touches)

- **Add a new event type** → three places: `engine/events.py` `BASE_WEIGHTS` (severity),
  `engine/mitre_map.py` (technique or honest `N/A`), and — if it should light up the mimic —
  `dashboard/static/app.js` (`TAG_NODE`/`TYPE_NODE`/`RUNG_NODE`). Then extend the matching smoke suite
  and keep the printed `N/N` total honest.
- **Add a structural mutation detector** → `engine/drift.py` (`_structural`), reuse the parsed
  `l5x.Rung` structs and `INVERSE_OP`; add the attacker mutator to `attacker/attacks.py` `MUTATORS`;
  extend `smoke_drift`.
- **Add a sensor** → new module in `agent/sensors/`, expose `scan()`/`observe()` + a sim hook, wire it
  in `agent/agent.py`; extend `smoke_agent`.
- **Add an attacker command** → `attacker/attacks.py` (`MUTATORS` for program mutations, or a Modbus
  action + a `main()` subcommand).
- **Add a dashboard view/action** → route in `dashboard/app.py` (respect RBAC), poll data via
  `GET /api/...`, render in `templates/` + `static/app.js`.

---

## 9 · Testing conventions

Suites are standalone scripts (not unit tests): they spin up **real** servers on ephemeral ports and
exercise real HTTP paths. Each prints `RESULT: N/N checks passed` and exits non-zero on failure. The
full set is **183 checks** (bus 15, l5x 16, plant 14, drift 18, agent 11, dashboard 20, attacker 10,
grfics 39, multisite 20, classify 20).
When you add a detector/mutation/sensor, extend the matching suite and keep the total honest.

---

## 10 · Gotchas

- **Ports:** 8080 dashboard+ingest, 8081 program, 5020 Modbus. Change via env, not hardcode.
- **Embedded vs remote is the only deployment switch** (`LOGICWARD_EMBED_PLANT`). Almost all dev is
  embedded; the split changes nothing about detection logic.
- **Private GitHub remote** (`positromen/Adani-Project`) → the Pi can't `git clone`; the deploy path
  copies the working tree over SSH (see USAGE.md §7).
- **Campus/enterprise Wi-Fi often blocks device-to-device** (client isolation) → use a phone hotspot
  for the two-host demo.
- **Input registers are not integrity-checked** (live process noise) — only holding registers +
  operator coils are. Don't "fix" this into false positives.
- **Docs are source-of-truth and kept in sync:** if architecture changes, update `DESIGN.md`,
  `USAGE.md`, and the `.tex`→`.pdf` pair (`pdflatex <file>.tex` twice, then delete `*.aux *.log *.out
  *.toc`).

---

## 11 · What's left / good next tasks

The appliance is feature-complete and verified. Sensible next work, roughly in priority order:
1. **Harden the two-host demo** — a preflight check script (ports reachable, token match, clock skew),
   and auto-recover if the agent's laptop link blips.
2. **A tiny test aggregator** (`tests/run_all.py`) that loops the 7 suites and prints a combined
   `98/98` — today it's a manual shell loop.
3. **Resource plane realism** — wire the real DDoS flood (`attacks.py ddos`) to a measured CPU spike on
   the Pi rather than the simulated hook.
4. **Dashboard polish** — a severity-over-time sparkline and a MITRE-technique tally on Overview
   (data already in the evidence log). Follow the `dataviz` conventions if adding charts.
5. **Screenshots/GIF** for the README and demo guide.
6. **Optional** — Docker for the laptop-side services only (engine+dashboard); the Pi sensors stay
   native. Deliberately deferred (hardware coupling + live-demo robustness).

Keep every change behind a passing smoke suite, respect the prime directive (§2), and keep commits
free of AI attribution.
