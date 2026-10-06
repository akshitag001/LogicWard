# Vigilo — Deployment, scale & real-world FAQ

Answers to the "will this work in a real plant?" questions. See `docs/HOW-IT-WORKS.md`
for the end-to-end flow and `docs/ROLES.md` for RBAC.

## Is a "SOC listener" needed? Where do the logs come from?
Events come from **two paths** that both land on one **Event Bus** and are written append-only to
`evidence.jsonl` (the SIEM-ready log):

1. **Pull — cyber drift (no listener needed).** The Drift Engine on the SOC host polls each PLC's Modbus
   registers + program and diffs them against the signed baseline. This is a *client* to the plant, so it
   needs no inbound listener.
2. **Push — physical/resource (listener needed).** Edge agents POST their events to `POST /api/ingest`
   (token-authed). **That ingest endpoint *is* the SOC listener.**

So the listener is required **only for the push path** (link/ARP/GPIO/CPU-RAM sensors). A pure pull-only
deployment works without it but loses physical-plane + DDoS-impact detection. **Keep it** — it is also the
**horizontal-scale ingestion point**: many edge sensors → one listener → one bus/SIEM.

## The whole flow, in one line
`PLC (Modbus + program) ──poll──► Drift Engine ─┐                         ┌─► evidence.jsonl (SIEM log)`
`Edge sensors ──POST /api/ingest──► listener ───┴─► Event Bus (enrich) ───┼─► dashboard (poll)`
`                                                                          └─► response engine`
Enrichment adds: severity, MITRE ATT&CK-for-ICS, identity (who/mac/channel), and **attack category**
(external / internal / mistake).

## Can it deploy in a real plant? Yes — this is a prototype of a real architecture.
The design is already split the way a real deployment is: **edge (Pi/plant) vs SOC (laptop/server)**,
transport-agnostic engine (`engine/sources.py`), one normalized event contract, and a multi-site registry.
What a production rollout adds is **coverage**, not a redesign.

## Multiple / different-OEM PLCs — will it work?
Yes, by extension, because everything normalizes into one event contract:

- **Register / config plane is protocol-agnostic** once a *collector* exists. Modbus TCP today; add
  **S7comm (Siemens), EtherNet/IP–CIP (Rockwell), OPC-UA, DNP3** collectors and they emit the same events.
- **Program / logic plane needs one parser per vendor.** We ship a Rockwell **`.L5X`** parser (rung-level
  structural diff) and OpenPLC **Structured-Text** on the register plane. Siemens `.s7p`, Schneider, etc.
  are **additive parsers** — the diff engine, baseline signing, MITRE mapping, RBAC, and UI are unchanged.
- **Onboarding a new OEM = add a parser + a collector.** Not a new product.

## Scaling — the OT-correct model (passive first)
OT is **passive-first**: never inject traffic that could disturb a PLC.

1. **Passive sensor per switch/cell** — a **SPAN/mirror port or hardware TAP** feeds a sensor that sniffs
   Modbus/S7/CIP and detects register drift, unauthorized writes, and rogue devices **without touching the
   PLCs**. One sensor covers many controllers.
2. **Baseline the program off-band** — diff against the engineering-workstation project repo, or capture
   program-downloads seen on the SPAN.
3. **Active scanning = opt-in, read-only, maintenance-window only** — light FC03 reads where passive is
   insufficient; gated, rate-limited, human-authorized. Default **off**.
4. **Fleet** — many passive sensors → central **collector** (`/api/ingest`; add MQTT/Kafka for volume) →
   one SOC / SIEM. This is exactly today's `agent → ingest → bus`, scaled horizontally. Vigilo's own
   dashboard is the analyst view; `evidence.jsonl` is drop-in **SIEM-forwardable** (syslog/CEF/Wazuh JSON).

## Prototype → product (the honest line)
- **Prototype (this repo):** live drift engine (6 named mutations + register diff), signed baseline + FIM,
  MITRE-for-ICS, attacker attribution, attack categorization, forensic PDF, multi-site SOC, red-team console.
- **Product:** passive SPAN/TAP sensors per cell → central collector → SIEM-forwardable, plus per-OEM
  parsers and protocol collectors to widen coverage.
