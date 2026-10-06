# Changelog

All notable changes to LogicWard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — Portfolio hardening

### Detection
- **AND/OR branch structure is now part of the program hash.** Rungs are parsed into
  an AND/OR logic tree (`[a,b]` = OR, series = AND); flipping `A·B` to `A+B` changes
  the structural hash and raises `cyber.branch_restructure` (MITRE T0889), while
  whitespace- and timestamp-only re-exports still hash identically.
- **Rungs are aligned by content, not by `Number`.** Inserting one rung at the top
  no longer renumbers every rung into ~20 false alerts — a single insert now produces
  exactly one `cyber.rung_injection`. The diff view aligns the same way.
- **State-based drift dedup.** An attack that is restored and then re-applied alerts
  again; a drift that returns to baseline emits an informational `cyber.drift_cleared`.

### Security
- **"Acknowledge All" no longer deletes evidence.** It marks alerts acknowledged
  (hidden from the active feed) and records a `response.operator_ack`; the append-only
  evidence log is never truncated. `POST /api/alerts/clear` now returns 410 Gone.
- **Baselines fail closed.** A saved baseline that fails HMAC verification at startup is
  quarantined (not overwritten), raises a critical `cyber.baseline_tamper`, pauses
  detection, and requires an engineer/CISO re-lock with confirmation.
- **No hardcoded secrets.** Demo mode generates an ephemeral session key; production
  mode (`LOGICWARD_DEMO_MODE=0`) refuses to start without strong `LOGICWARD_SECRET`,
  `LOGICWARD_TOKEN`, and `LOGICWARD_HMAC_KEY`. Added `.env.example`.
- **Auth + CSRF.** `/api/events` requires a session; passwords are stored as PBKDF2
  hashes; browser state-changing POSTs require a per-session CSRF token; session cookies
  are HttpOnly/SameSite=Lax with a 30-minute lifetime; 5-failures/minute login limiting;
  login success/failure is logged as events.

### Engineering
- Added `pyproject.toml`, a `pytest` runner over every smoke suite, `ruff`, and a
  GitHub Actions matrix (Python 3.10–3.12 on Ubuntu and Windows) running lint +
  tests + coverage.
- Single-machine simulation is the primary presentation; Raspberry Pi split-mode code
  is retained and documented under `docs/DEPLOYMENT.md`.

## [1.0.0] — Hackathon build

### Added
- Event bus with one `Event` contract, severity scoring, rule-based MITRE ATT&CK for
  ICS mapping, append-only JSONL evidence log, and a PDF forensic report.
- Real Rockwell **L5X** parser/canonicalizer — the PLC program is data, never executed.
- Two detection surfaces: structural (L5X) and register (Modbus holding registers/coils),
  producing the named mutations (setpoint drift, logic inversion, condition stripping,
  coil hijack, rung injection, raw register change).
- HMAC-SHA256 signed baseline with a `watchdog` file-integrity monitor.
- Flask SOC dashboard (branded **Vigilo**) with an animated SCADA mimic, GitHub-style
  program diff, alert feed, and evidence view; capability-based RBAC across six OT roles
  (operator, control engineer, network engineer, SOC analyst, vendor, CISO).
- Attacker toolkit (unauthenticated Modbus writes + program downloads) and a scripted
  demo sequence; a separate red-team console.
- Second monitored site (GRFICS chemical reactor) sharing the same bus and dashboard.
- Raspberry Pi edge agent (network/host/physical sensors) with simulation fallbacks.
