# VIGILO — Roles & Access (RBAC)

Six OT/ICS roles. Access is **capability-based and enforced server-side** in
`logicward/dashboard/app.py` (`ROLE_CAPS`, `require_cap`), not just hidden in the UI.
On login each role also gets a **curated dashboard** — only its relevant tabs, its own
landing page, and its own quick-action buttons (least privilege = least visibility).

## Capabilities
| Capability | What it allows |
| :-- | :-- |
| `ack` | Acknowledge a single alert (per-row) |
| `ack_all` | Acknowledge / clear the whole alert feed |
| `baseline` | Re-lock and restore the signed approved baseline |
| `network_response` | Quarantine a rogue device |
| `safe_state` | Recommend a safe-state on a safety-critical alert |
| `evidence` | Export the signed forensic PDF / view the evidence log |
| `compliance` | CISO oversight — cross-role posture / incident command |

## Role → view + capabilities + actions

| Role (login) | Lands on | Tabs it sees | Capabilities | Quick-action buttons |
| :-- | :-- | :-- | :-- | :-- |
| **Operator** (Control Room)<br>`operator / operator123` | Live Plant | Live Plant · Alerts | ack, ack_all | Acknowledge all |
| **C&I / Control Engineer**<br>`engineer / engineer123` | Program Diff | Overview · Live Plant · Program Diff · **Insider** · Alerts | ack, ack_all, **baseline**, **safe_state** | Acknowledge all · Re-lock baseline · Restore baseline · Recommend safe-state |
| **OT Network / Security Eng.**<br>`netsec / netsec123` | Alerts | Overview · Alerts · Live Plant | ack, ack_all, **network_response** | Acknowledge all · Quarantine rogue |
| **SOC Analyst**<br>`soc / soc123` | Overview | Overview · Live Plant · Program Diff · Alerts · Evidence | ack, ack_all, network_response, safe_state, **evidence** | Acknowledge all · Quarantine rogue · Recommend safe-state · Export forensic PDF |
| **Vendor / OEM Contractor**<br>`vendor / vendor123` | Live Plant | Live Plant · Program Diff *(read-only)* | *(none)* | *Read-only session · all actions monitored* |
| **CISO / Plant Cyber Head**<br>`ciso / ciso123` | Overview | Overview · Alerts · Evidence · Roles & Access | **all** | Acknowledge all · Re-lock · Restore · Quarantine · Safe-state · Export PDF · Compliance posture |

## Where it's enforced
- **Server (authoritative):** `logicward/dashboard/app.py` — `ROLE_CAPS`, `caps_for()`, and the
  `@require_cap(...)` decorator gate every state-changing API route (`/api/baseline/lock`,
  `/api/response/*`, `/api/alerts/clear`, `/api/evidence/report.pdf`, …). A role without the
  capability gets **403** even if it forges the request.
- **Client (UX):** `logicward/dashboard/static/app.js` — `ROLE_VIEWS` picks each role's tabs +
  landing; every `data-cap="…"` control is removed for roles that lack the capability.

## Baseline change lifecycle — who accepts a new baseline?
1. An **approved** logic change is made in the vendor's engineering tool (Studio 5000 / TIA Portal) under
   Management-of-Change and downloaded to the PLC.
2. Vigilo sees the live program no longer matches the signed baseline → **raises a drift alert**
   (attributed with who / when / what).
3. An authorized owner must then **accept the new state as the new signed baseline** — the **"Re-lock
   baseline"** action, gated to the **`baseline` capability = C&I / Control Engineer** (the program owner),
   with **CISO** cross-role oversight. Re-locking re-signs (HMAC-SHA256) and clears the drift.
4. **The failure mode = a `mistake`:** if the approver *rubber-stamps* a **drifted / unreviewed** program as
   the new baseline, they have effectively blessed an unauthorized change. This is the "mistake" attack
   category — a change-management error, not a network intrusion.

## Attack surfaces → categories (how the three classes are produced)
- **External** — the standalone **Red-Team console (`:9090`)**: unauthenticated Modbus register/coil forces,
  rogue device, DDoS. Classified `external`.
- **Internal** — the **Insider tab** inside the SOC, shown only to the **C&I / Control Engineer**: one-click
  program-logic pushes + a **scoped terminal** (runs only the Vigilo attack CLI, no open shell). Program
  downloads through the engineering channel → classified `internal`.
- **Mistake** — the **baseline-approval error**: if an approver **re-locks a *drifted* program** (accepts an
  unreviewed / hacked version as the new signed baseline), Vigilo emits a `mistake`-category governance event.
- Both terminals are deliberately **scoped** (`logicward/attacker/terminal.py`): only
  `python -m logicward.attacker.attacks …` / `…sites.grfics.attacks …` run, shell metacharacters are
  rejected, and there is a hard timeout — real commands + live output, never an open remote shell.

## Design note (secure by design)
Least privilege is applied to **visibility**, not only actions: an Operator never sees the
forensic/evidence surface, a Vendor gets a read-only, monitored session with no action buttons,
and only the CISO sees Roles & Access governance. This narrows each user's attack surface and
keeps the console legible for the job at hand.
