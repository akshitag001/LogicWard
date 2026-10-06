# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**LogicWard** — a live OT (operational-technology) drift-detection appliance for a hackathon. It watches a simulated **thermal power plant** PLC and raises severity-ranked, MITRE-mapped alerts the instant the running control logic or live process state drifts from a cryptographically signed approved baseline. Everything is a Python package under `logicward/` (Flask + raw-socket Modbus + `lxml`); there is no build step.

**The prime architectural constraint:** the PLC "program" (a real Rockwell `.L5X`) is **DATA to baseline, mutate, and diff — it is never executed.** Do not add a ladder-logic interpreter that runs the rungs; the Pi's live Modbus registers provide the "reality" underneath. This is the single biggest thing to preserve.

## Commands

```bash
pip install -r requirements.txt        # flask, requests, lxml, watchdog, reportlab, psutil (+ scapy/gpiozero on the Pi)

# Run the whole appliance on ONE machine (embedded in-process plant, no Pi needed):
python -m logicward.dashboard.app                     # http://localhost:8080/  (logins below)

# One-command live demo — brings up dashboard + embedded PLC + program endpoints and drives
# the full attack catalogue with narration while you watch detections land:
python -m logicward.attacker.demo_sequence            # ~90s
python -m logicward.attacker.demo_sequence --fast     # ~15s

# Fire individual attacks (see attacker/attacks.py MUTATORS + main() for the command list):
python -m logicward.attacker.attacks [--host H] [--modbus-port P] [--count N] <command>
#   commands: setpoint-drift | force-coil | ddos | rogue |
#             logic-inversion | condition-stripping | coil-hijack | rung-injection | program-setpoint
```

Dashboard logins: `operator/operator123`, `engineer/engineer123`, `soc/soc123` (roles gate what's visible/actionable, enforced server-side in `dashboard/app.py`).

### Tests

There is **no pytest / test runner** — each suite is a standalone script that prints `RESULT: N/N checks passed` and exits non-zero on failure. Run a single suite:

```bash
python -m logicward.tests.smoke_bus        # one of: bus l5x plant drift agent dashboard attacker
```

Run all (there's no aggregator; loop them):
```bash
for t in bus l5x plant drift agent dashboard attacker grfics multisite classify; do python -m logicward.tests.smoke_$t; done
```

Suites spin up real servers on ephemeral ports and exercise real HTTP paths (they are integration-style, not unit tests). The full set is **183 checks** across 10 suites (adds `grfics`, `multisite`, `classify` beyond the seven above). When you add a detector/mutation, extend the matching suite and keep the printed total honest.

### Docs

`DESIGN.md` (architecture) and `USAGE.md` (how-to) are the source of truth; `LogicWard_Design.tex` / `LogicWard_Demo_Guide.tex` compile to committed PDFs via `pdflatex <file>.tex` (run twice for the TOC; delete `*.aux *.log *.out *.toc` after). Keep the `.md`, `.tex`, and `.pdf` in sync when architecture changes.

## Architecture (the parts that span files)

**The event bus is the spine — build/understand it first** (`engine/events.py`). One `Event` contract: `{event_id, type, timestamp, source, severity, details}`. On every `emit()` the bus **enriches** (computes `severity` from `BASE_WEIGHTS` × a safety-critical multiplier; attaches MITRE via `mitre_map.map_event`; adds `identity`, `seq`, `received_at`), is **idempotent by `event_id`**, and fans out to three sinks: the append-only JSONL evidence log, the dashboard poll buffer, and live subscribers. `type` is namespaced `cyber.* | physical.* | resource.* | response.*`.

**Two emit paths converge on the same bus.** Local detectors (`engine/drift.py`, `engine/response.py`) call `bus.emit()` directly. Remote sensors on the Pi (`agent/`) POST the same Event JSON to `POST /api/ingest` (token-authed, batched, retry/buffered in `agent/forwarder.py`), which calls `bus.emit()`. The wire format **is** the Event object.

**Single-machine vs real-Pi is one seam:** `engine/sources.py`. The engine is transport-agnostic — it only needs `program_source() -> L5X bytes` and `register_source() -> {holding, coils}`. `EmbeddedPlant` starts an in-process Modbus PLC (everything on the laptop); `RemotePlant` reads a real Pi over Modbus + HTTP. The switch is `LOGICWARD_EMBED_PLANT` (default `1`; `0` = real Pi via `LOGICWARD_PI_HOST`). Almost all dev happens embedded; the split deployment changes nothing about detection logic.

**Detection has two surfaces** (`engine/drift.py`, run in a 1 s loop by the dashboard):
- *Structural* — pull the live L5X, canonicalize it (`engine/l5x.py`: strips volatile `ExportDate`/`EditedDate`/revisions/CRC/comments, parses neutral-text ladder like `XIC(..)[LES(..)]OTE(..);` into instruction/operand structs, produces a `structural_hash`), and diff canonical rungs vs the signed baseline. This is *why there are no false positives* — a harmless re-export with new timestamps hashes identically; a real logic change does not.
- *Register* — read live Modbus holding registers/coils and diff vs the baseline snapshot.

These produce the **six named mutations**: `setpoint_drift`, `logic_inversion`, `condition_stripping`, `coil_hijack`, `rung_injection` (structural), and `register_change` (Modbus).

**The baseline is HMAC-SHA256 signed** (`engine/baseline.py`): editing the locked manifest breaks the signature (a `watchdog` FIM in `agent/sensors/fim_watch.py` watches both the live program file and the signed baseline). It's integrity, not access control.

**`plant/rung_to_register.py` is the L5X-tag ↔ Modbus-address bridge** — the register diff, the live-plant mimic, and the plant simulation all depend on this mapping (tag name, area IR/HR/C/DI, address, engineering scale). The Modbus server (`plant/modbus_server.py`) is a **raw-socket** implementation reused from prior work (no `pymodbus`).

**Dashboard** (`dashboard/app.py`): Flask app that mounts the `engine/server.py` blueprint (so `/api/ingest` + `/api/events` live on the same port `8080` as the UI), owns the `Dashboard` object (bus + plant + baseline + drift loop + response engine + baseline FIM), and enforces RBAC. Data reaches the browser by **polling** `GET /api/events?since=<cursor>` and `GET /api/plant` (~1 s) — deliberately no WebSockets, for demo robustness. The **animated SCADA mimic** (`static/app.js` + `templates/dashboard.html`) maps each event to a diagram component via `TAG_NODE`/`TYPE_NODE`/`RUNG_NODE` (by scanning the event's `details`/`type`) and redlines it with a pinned MITRE badge; clicking acknowledges.

**MITRE mapping** (`engine/mitre_map.py`) is a rule-based, explainable table of ATT&CK **for ICS** techniques, verified against the live matrix. Where no technique fits (physical enclosure tamper, baseline-integrity tamper) it is honestly `N/A`, never a fabricated ID.

## Conventions & gotchas

- **Adding a new event type** means touching three places: `engine/events.py` `BASE_WEIGHTS` (severity), `engine/mitre_map.py` (technique or honest `N/A`), and — if it should light up the mimic — `dashboard/static/app.js` (`TAG_NODE`/`TYPE_NODE`). Then extend the relevant smoke suite.
- **Sensors degrade gracefully.** `psutil`, `scapy`, `gpiozero` are imported defensively and every sensor has a simulation hook (`set_sim`, `trigger_sim`, `observe`) so the whole pipeline runs hardware-free — this is what lets the tests and the embedded demo run anywhere. Don't make a sensor hard-require its hardware library.
- **Config is env-driven** (`config.py`): every value is overridable via a `LOGICWARD_*` variable. Modbus is on **5020** (not 502) to avoid needing root. Ports: 8080 dashboard+ingest, 8081 program endpoints. The default token/HMAC key/passwords are intentionally demo-grade and documented as such.
- **Runtime state is generated and gitignored:** `logicward/data/` (evidence log + signed baseline) and `logicward/plant/program/live.L5X`. The pristine approved program is `logicward/plant/program/ThermalPlant_baseline.L5X`; `live.L5X` is created from it and is what the attacker's program-download mutates.
- **Git:** the GitHub remote is **private** (`positromen/Adani-Project-OT`), so the Pi can't clone it — the deploy path copies the tree over SSH (see `USAGE.md` §7). Per the owner's preference, **commits in this repo carry no AI/Claude attribution** (plain author, no `Co-Authored-By`).
