# VIGILO — How it works, and where

A one-page map of what runs where and how a detection flows end to end.

## Where things run

```
┌──────────────── RASPBERRY PI (the plant edge) ────────────────┐      ┌──────────────── LAPTOP / SOC ────────────────┐
│  Thermal PLC (real Rockwell L5X + Modbus)                     │      │  SOC dashboard  :8080                        │
│   • Modbus TCP        :5020   (registers/coils = ground truth)│◄─────┤   • UI + RBAC + role-curated views           │
│   • Program HTTP      :8081   (GET /program  L5X)             │ poll │   • Drift Engine (pull)                       │
│   • Write-attrib HTTP :5024   (GET /writes = "by whom")       │◄─────┤   • Signed baseline + FIM                    │
│  Edge agent (sensors)                                          │      │   • /api/ingest  (push listener)             │
│   • link / ARP / GPIO / CPU-RAM  ──── push events ───────────►│──────►│   • Chemical Site B (3D) Modbus :5021        │
└───────────────────────────────────────────────────────────────┘      │  Attacker console :9090  (red team)          │
                                                                        └──────────────────────────────────────────────┘
```

- **Pi = the plant.** Real PLC program (L5X) + live Modbus, plus an edge agent for the physical/host plane.
- **Laptop = the SOC.** Runs the detection engine, the signed baseline, the dashboard, and (laptop-hosted) the
  chemical 3D site. The attacker console is separate, on `:9090`.
- **Single-machine dev:** set `LOGICWARD_EMBED_PLANT=1` (default) and the laptop runs an in-process PLC too — same code, no Pi.

## Two detection paths, one event bus
1. **Pull — cyber drift (laptop → Pi).** Every ~1 s the Drift Engine (`engine/drift.py`) reads the Pi's Modbus
   registers/coils and pulls the live L5X, canonicalizes it, and diffs **both** against the HMAC-signed baseline
   (`engine/baseline.py`). Any delta → a `cyber.*` event. *The program is data we diff — never executed.*
2. **Push — physical/resource (Pi → laptop).** The edge agent (`agent/`) samples link/ARP/GPIO/CPU-RAM and POSTs
   batched events to `POST /api/ingest` (token-authed). Those become `physical.*` / `resource.*` events.

Both converge on the **Event Bus** (`engine/events.py`), the spine. On every `emit()` it **enriches** — computes
severity, maps MITRE ATT&CK for ICS, attaches `identity` (who/mac/channel) and `category` (mistake/internal/external)
— then fans out to three sinks: the **append-only `evidence.jsonl`** (SIEM-ready log), the dashboard poll buffer, and
live subscribers (the response engine).

## How the screen updates
The browser **polls** (no WebSockets, for demo robustness):
`GET /api/events?since=` (1 s), `/api/overview` (2 s), `/api/plant` (1.5 s), `/api/telemetry`, `/api/site-b/state`.
Each event is mapped to a SCADA-mimic node and redlined with a pinned MITRE badge; clicking acknowledges.

## Security model (secure by design)
- **RBAC is server-enforced** (`dashboard/app.py`: `ROLE_CAPS` + `@require_cap`), not just UI hiding. See `docs/ROLES.md`.
- **Least-privilege visibility:** each role gets only its tabs + its own landing + its own action buttons.
- **Baseline integrity:** HMAC-SHA256 signed; a `watchdog` FIM watches the live program and the signed manifest.
- **No baseline upload:** the approved logic comes from the vendor's engineering tool, then VIGILO **captures + signs**
  it from the verified running plant — never a dashboard file upload (that would be a poisoning vector).

## Deploy / run (real Pi)
1. `python deploy/pi_tools/bootstrap_pi.py --pi-ip <PI> --laptop-ip <LAPTOP>`  → starts Pi services + points ingest at the laptop.
2. `.\deploy\run_laptop.ps1 -PiHost <PI>`  → SOC dashboard in RemotePlant mode (reads the Pi; chemical Site B stays local).
3. `python -m logicward.attacker.dashboard --host <PI>`  → red-team console (thermal → Pi, chemical → laptop).

Full procedure: `STARTUP_MANUAL.md`. Deep architecture: `DESIGN.md`. Roles: `docs/ROLES.md`.
