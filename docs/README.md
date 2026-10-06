# LogicWard — Documentation

**LogicWard** is a live, multi-site **OT drift-detection & incident-response platform**. It
monitors two industrial plants through one SOC console and raises severity-ranked, MITRE-mapped,
evidence-backed alerts the instant control logic or process state drifts from a signed baseline.

| Site | Plant | Hardware | Program | Visualization |
|------|-------|----------|---------|---------------|
| **A** | Thermal Power Plant | Raspberry Pi (real) | Rockwell **L5X** | Animated SCADA mimic |
| **B** | GRFICS Chemical Reactor | Laptop (sim) | OpenPLC **Structured Text** | Live **Unity 3D** twin |

---

## Documents in this folder

| File | What it is | Use for |
|------|-----------|---------|
| **[LogicWard_Technical_Report.pdf](LogicWard_Technical_Report.pdf)** | Deep 9-page technical report — architecture, data-flow, ER model, detection engine, attack catalogue, RBAC, MITRE mapping, deployment, verification (with diagrams) | Judges' technical read, pitch-deck source material, engineering reference |
| **[LogicWard_Pitch_Deck.pdf](LogicWard_Pitch_Deck.pdf)** | 15-slide presentation (16:9) — problem → solution → architecture → attacks → 3D demo → dashboard → RBAC → verification → why-we-win → roadmap | The live presentation / pitch |
| **[DESIGN-BRIEFS.md](DESIGN-BRIEFS.md)** | Page-by-page UI design briefs (design system + every screen) | Handing any page to a designer/Claude to (re)build as an artifact |

The `.tex` sources sit beside each PDF — rebuild with `pdflatex <file>.tex` (run twice for the
TOC/refs). The report uses `tikz` + `tcolorbox`; the deck uses `beamer` — both are in the repo's
MiKTeX install.

---

## Diagrams in the Technical Report
- **System architecture** — attack channels → two sites → drift engine → event bus → dashboard/evidence
- **Attack lifecycle** — the 10 stages every attack follows (Execution → … → Rollback)
- **Entity–Relationship** — Event · Site · Baseline · User → Role → Capability
- **Deployment topology** — laptop (SOC + attacker + chemical 3D) ↔ Raspberry Pi (thermal PLC)
- Plus tables: 6 PLC mutations, 12-attack catalogue, RBAC capability matrix, MITRE ATT&CK-for-ICS map, 154-check verification matrix

---

## Run the demo (what the docs describe)
```bash
python -m logicward.dashboard.app          # SOC dashboard  → http://localhost:8080/
python -m logicward.attacker.dashboard     # Red-team console → http://localhost:9090/
```
Logins (6 OT/ICS roles): `operator` · `engineer` · `netsec` · `soc` · `vendor` · `ciso`
(password = `<user>123`). Fire the 5 chemical attacks in order in the console — the blast is last.
