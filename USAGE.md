# LogicWard — Complete Usage Guide

Everything you need to install, run, demo, and deploy LogicWard — the live OT
drift-detection appliance for a simulated thermal power plant.

> Design & architecture: **[DESIGN.md](DESIGN.md)** · shareable **[LogicWard_Design.pdf](LogicWard_Design.pdf)** · presenter **[LogicWard_Demo_Guide.pdf](LogicWard_Demo_Guide.pdf)**
> Repo: **https://github.com/positromen/Adani-Project-OT**
>
> **Status:** built and passing 98/98 automated checks across 7 suites, **and verified end-to-end on real hardware** (Raspberry Pi 4 PLC ↔ laptop SOC over Wi-Fi).

**Contents**
1. [What it does](#1-what-it-does)
2. [Prerequisites & install](#2-prerequisites--install)
3. [Quick start — one-command live demo](#3-quick-start--one-command-live-demo)
4. [Manual single-machine run](#4-manual-single-machine-run)
5. [The dashboard — every view explained](#5-the-dashboard--every-view-explained)
6. [The attacker toolkit — every command](#6-the-attacker-toolkit--every-command)
7. [Two-machine deployment on a real Raspberry Pi](#7-two-machine-deployment-on-a-real-raspberry-pi)
8. [Configuration reference](#8-configuration-reference)
9. [How detection works (quick reference)](#9-how-detection-works-quick-reference)
10. [Verification — the test suites](#10-verification--the-test-suites)
11. [Troubleshooting](#11-troubleshooting)
12. [Demo script & judge talking points](#12-demo-script--judge-talking-points)

---

## 1. What it does

A **Raspberry Pi** runs a Modbus TCP PLC (a thermal power plant) plus a thin sensor
**agent**. A second machine is the **attacker**. A **laptop** runs the detection
**engine** and a Flask **SOC dashboard**. Every detector across three planes
(**cyber**, **physical**, **resource**) emits one common event onto a single **event
bus**, which enriches each event with attacker identity + a verified MITRE ATT&CK for
ICS technique, logs it as tamper-evident evidence, and streams it to the dashboard.

The PLC "program" is a real **Rockwell L5X** file — **data to baseline and diff,
never executed**. Detection is a continuous live-vs-baseline diff across two surfaces:
the structural program (canonicalized L5X) and the live Modbus register state, all
checked against an **HMAC-SHA256-signed baseline**.

You can run the whole thing **on one machine** (an embedded plant — no Pi needed) or
**split across a real Pi + laptop**. Both are covered below.

---

## 2. Prerequisites & install

- **Python 3.11+** (developed on 3.14; the Pi ships 3.11 on Bookworm).
- Git.
- A modern browser for the dashboard.

```bash
git clone https://github.com/positromen/Adani-Project-OT.git
cd Adani-Project-OT
python -m venv .venv

# activate the venv:
#   Windows PowerShell:  .\.venv\Scripts\Activate.ps1
#   Windows Git Bash:    source .venv/Scripts/activate
#   Linux / macOS / Pi:  source .venv/bin/activate

pip install -r requirements.txt
```

`requirements.txt` installs everything the single-machine appliance needs (Flask,
requests, lxml, watchdog, reportlab, psutil). `scapy` and `gpiozero` are **optional
Pi-only** extras (real ARP sweep + GPIO tamper switch); every sensor has a simulation
fallback, so the full pipeline runs without them.

---

## 3. Quick start — one-command live demo

This is the showpiece. One process brings up the SOC dashboard + an embedded thermal
PLC + the program endpoints, then drives the **entire attack catalogue** with live
narration while you watch detections land on the dashboard in real time.

```bash
python -m logicward.attacker.demo_sequence          # ~90s, watchable pacing
python -m logicward.attacker.demo_sequence --fast    # ~15s, quick flow
```

Then open **http://localhost:8080/** and log in as **`soc` / `soc123`**. Switch
between **Alerts**, **Program Diff**, and **Live Plant** as the acts run:

| Act | What the attacker does | What you see detected |
|---|---|---|
| 1 · Normal ops | nothing | plant nominal, baseline HMAC-locked, program in sync, no alerts |
| 2 · Recon | rogue laptop joins the OT segment | `physical.rogue_device` (Rogue Master, T0848) |
| 3 · Logic tamper | setpoint drift + 4 program downloads | `setpoint_drift` (T0836), `logic_inversion`/`condition_stripping`/`coil_hijack` (Modify Program, T0889), `rung_injection` (Program Download, T0843) — each also raises an FIM `program_file_modified` |
| 4 · Process impact | force a control coil + Modbus DDoS flood | `register_change` (T0855), `resource.cpu_spike` (Denial of Service, T0814) |
| 5 · Physical tamper | cable pull + enclosure door | `physical.link_down` + `physical.enclosure_open` |

A verified run produces **14 events (4 critical, 2 high, 3 medium, 5 low)**. When it
finishes, the dashboard stays live — export the **signed PDF forensic report** from the
Evidence view. Press `Ctrl+C` in the terminal to stop.

---

## 4. Manual single-machine run

Run the dashboard and fire attacks yourself, at your own pace.

**Terminal 1 — the SOC dashboard (with an embedded plant):**
```bash
python -m logicward.dashboard.app
# http://localhost:8080/   logins:  operator/operator123 · engineer/engineer123 · soc/soc123
```

**Terminal 2 — the program endpoints** (needed so the attacker's program-download
mutations reach the same running program the dashboard reads):
```bash
python -m logicward.plant.logic_store        # GET/POST /program on :8081
```

**Terminal 3 — fire individual attacks** (see §6 for the full list):
```bash
python -m logicward.attacker.attacks logic-inversion
python -m logicward.attacker.attacks setpoint-drift
python -m logicward.attacker.attacks ddos --count 800
```

> For register/Modbus attacks against a manually-launched dashboard, prefer the
> `demo_sequence` (it wires the embedded plant's Modbus port to the attacker
> automatically). The `logic_store` + program-download mutations work in the manual
> setup above because both processes share the same `live.L5X` file.

---

## 5. The dashboard — every view explained

Open **http://localhost:8080/** and log in. Three roles, enforced server-side:

| Login | Role | Can see / do |
|---|---|---|
| `operator` / `operator123` | Operator | live plant + alert feed; **acknowledge** alerts |
| `engineer` / `engineer123` | Engineer | + baseline & diff detail; **lock/restore baseline** |
| `soc` / `soc123` | SOC Analyst | everything; **evidence log, PDF export, all response actions** |

**Views:**

- **Overview** — plant status, baseline integrity (`VALID`/`TAMPERED`), whether the
  live program is in sync with the baseline, a severity-ranked count strip, and the
  live event total. A `LIVE` indicator confirms polling.
- **Live Plant** — the thermal-plant mimic driven by live Modbus reads: boiler drum
  level, main steam pressure/temperature, turbine speed, generator MW, condenser
  vacuum, feedwater/trip coils.
- **Program Diff** — the **GitHub-style side-by-side red/green diff** of the baseline
  L5X vs the running L5X, with word-level highlights on each changed rung, plus the
  per-change severity and MITRE technique. This is the "exact logic flip" view.
- **Alerts** — the full severity/plane-coded event feed; new alerts flash on arrival.
  Each carries its `who / when / channel` identity and ATT&CK-for-ICS technique.
- **Evidence** — the append-only forensic log, with a one-click **signed PDF report**
  download (`/api/evidence/report.pdf`).

**Response actions** (role-gated, each logged as a `response.*` evidence event):
acknowledge an alert, quarantine a rogue device, recommend a safe-state on a
safety-critical drift, and restore the approved baseline program.

---

## 6. The attacker toolkit — every command

```bash
python -m logicward.attacker.attacks [--host H] [--modbus-port P] [--count N] <command>
```

- `--host` — target PLC (default `127.0.0.1`; use the Pi's IP in a split deployment)
- `--modbus-port` — Modbus port (default `5020`)
- `--count` — flood size for `ddos` (default `500`)

| Command | Channel | Triggers |
|---|---|---|
| `setpoint-drift` | Modbus FC06 write | `cyber.setpoint_drift` (Modify Parameter, T0836) |
| `logic-inversion` | program download | `cyber.logic_inversion` (Modify Program, T0889) |
| `condition-stripping` | program download | `cyber.condition_stripping` (Modify Program, T0889) |
| `coil-hijack` | program download | `cyber.coil_hijack` (Modify Program, T0889) |
| `rung-injection` | program download | `cyber.rung_injection` (Program Download, T0843) |
| `program-setpoint` | program download | setpoint drift via the L5X program surface |
| `force-coil` | Modbus FC05 write | `cyber.register_change` (Unauthorized Command Message, T0855) |
| `ddos --count N` | Modbus flood | `resource.cpu_spike` (Denial of Service, T0814) |
| `rogue` | ARP announce | `physical.rogue_device` (Rogue Master, T0848) |

Each program-download mutation also trips the passive FIM sensor
(`cyber.program_file_modified`).

Examples:
```bash
python -m logicward.attacker.attacks --host siddhesh.local logic-inversion
python -m logicward.attacker.attacks --host 10.119.190.53 --modbus-port 5020 force-coil
python -m logicward.attacker.attacks --host 10.119.190.53 ddos --count 1000
```

---

## 7. Two-machine deployment on a real Raspberry Pi

Topology: **Pi** = the PLC + sensor agent; **laptop** = engine + dashboard; **attacker**
= any box on the LAN (can be the laptop). All three must be on the **same network**
(the Pi here is on Wi-Fi `Noone`, so is `wlan0`).

> **Network tip (verified):** campus/enterprise Wi-Fi often enables **client isolation**,
> which blocks the laptop↔Pi traffic this needs. A **phone hotspot** is the reliable
> fallback — connect *both* devices to it. Confirm reachability first: from the laptop
> `ping siddhesh.local`, and from the Pi `ping <laptop-ip>`.

### 7.1 On the Pi (hostname `siddhesh`, user `siddhesh`)

SSH in from the laptop (Raspberry Pi OS advertises `siddhesh.local` over mDNS):
```bash
ssh siddhesh@siddhesh.local            # password: the one set in Pi Imager
# re-flashed the Pi? clear the stale host key first:
#   ssh-keygen -R siddhesh.local
```

Get the project onto the Pi, then bootstrap (venv + deps incl. scapy/gpiozero, writes
the ingest URL). Pass the **laptop's** LAN IP (find it with `ipconfig`):
```bash
# If the repo is PUBLIC:
git clone https://github.com/positromen/Adani-Project-OT.git && cd Adani-Project-OT

# If the repo is PRIVATE (the Pi can't clone it) — copy the tree from the laptop instead.
# Run this ON THE LAPTOP from the project folder:
#   tar czf - --exclude=.git --exclude=logicward/data --exclude=.venv logicward deploy requirements.txt \
#     | ssh siddhesh@siddhesh.local "mkdir -p ~/Adani-Project-OT && tar xzf - -C ~/Adani-Project-OT"
# then back on the Pi:  cd ~/Adani-Project-OT

bash deploy/pi_bootstrap.sh 10.119.190.79        # <- your laptop's IP
bash deploy/run_pi.sh                             # PLC :5020 + program :8081 + agent (wlan0)
#   SUDO_AGENT=1 bash deploy/run_pi.sh            # run agent as root for a live ARP sweep
```
Note the Pi's own IP: `hostname -I`.

### 7.2 On the laptop

One-time — allow the Pi agent to reach the ingest port. In an **admin Command Prompt**:
```
netsh advfirewall firewall add rule name="LogicWard" dir=in action=allow protocol=TCP localport=8080
```
(or, in an **admin PowerShell**: `New-NetFirewallRule -DisplayName LogicWard -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow`)

Start the dashboard in **remote** mode (reads the real Pi):
```powershell
.\deploy\run_laptop.ps1 -PiHost siddhesh.local
# or by IP:  .\deploy\run_laptop.ps1 -PiHost 10.119.190.53
```
Open **http://localhost:8080/** (login `soc/soc123`). The Live Plant now reflects the
Pi's real Modbus registers; the Pi agent's physical/resource/FIM events stream in.

### 7.3 From the attacker box (or the laptop)

```bash
python -m logicward.attacker.attacks --host siddhesh.local logic-inversion
python -m logicward.attacker.attacks --host siddhesh.local ddos --count 800
```

To fire the **physical** plane for real, the Pi needs a wired `eth0` (pull the cable →
`link_down`) and a GPIO tamper switch (open the case → `enclosure_open`); on a Wi-Fi-only
Pi those sensors run in fallback while the **cyber + resource** planes are fully live.

---

## 8. Configuration reference

Every value lives in [`logicward/config.py`](logicward/config.py) and is overridable
with a `LOGICWARD_*` environment variable.

| Env var | Default | Meaning |
|---|---|---|
| `LOGICWARD_EMBED_PLANT` | `1` | `1` = embedded in-process plant (single machine); `0` = read a real Pi |
| `LOGICWARD_PI_HOST` | `127.0.0.1` | Pi address the laptop reads (remote mode) |
| `LOGICWARD_MODBUS_PORT` | `5020` | Modbus TCP port (502 needs root; 5020 doesn't) |
| `LOGICWARD_PROGRAM_PORT` | `8081` | `logic_store` HTTP port (GET/POST `/program`) |
| `LOGICWARD_INGEST_PORT` | `8080` | dashboard + `/api/ingest` + `/api/events` port |
| `LOGICWARD_INGEST_URL` | `http://127.0.0.1:8080/api/ingest` | where the Pi agent POSTs events |
| `LOGICWARD_TOKEN` | `logicward-dev-token-change-me` | shared ingest token (agent ↔ dashboard) |
| `LOGICWARD_HMAC_KEY` | `logicward-baseline-signing-key-change-me` | baseline signing key |
| `LOGICWARD_IFACE` | `wlan0` (Pi) | interface the agent watches (Wi-Fi = `wlan0`, wired = `eth0`) |
| `LOGICWARD_POLL_INTERVAL` | `1.0` | drift-loop / agent poll seconds |
| `LOGICWARD_SECRET` | `logicward-dev-secret` | Flask session secret |
| `LOGICWARD_DATA_DIR` | `logicward/data` | evidence log + signed baseline location |

> The default token, HMAC key, session secret, and dashboard passwords are
> **demo-grade** and documented as such. Override them for anything beyond a demo.

---

## 9. How detection works (quick reference)

**Event contract** (one shape for every plane): `event_id, type, timestamp, source,
severity, details{}` — the bus enriches each with `identity{who,mac,channel}`, a
`mitre{tactic,technique_id,technique_name}` mapping, `seq`, and `received_at`.

**The six named cyber mutations:**

| Mutation | What changes | Surface |
|---|---|---|
| Setpoint drift | a `*_SP` setpoint value | Modbus register + mirrored L5X tag |
| Logic inversion | compare op (`LES`↔`GRT`) or contact (`XIC`↔`XIO`) | L5X program |
| Condition stripping | a safety input removed from a rung | L5X program |
| Coil hijack | a rung's output coil repointed | L5X program |
| Rung injection | a new unauthorized rung added | L5X program |
| Raw register change | a holding register / control coil forced | Modbus |

Plus the physical plane (`link_down`, `rogue_device`, `enclosure_open`), the resource
plane (`cpu_spike`/`mem_spike`), and the FIM signals (`program_file_modified`,
`baseline_tamper`). Severity is computed from a per-type base weight × a
safety-critical multiplier (safety-critical rungs escalate). MITRE IDs are verified
against the live ATT&CK-for-ICS matrix; see [DESIGN.md §6.2](DESIGN.md).

---

## 10. Verification — the test suites

Ten self-checking smoke suites, **183/183 checks**:

```bash
python -m logicward.tests.smoke_bus         # 15/15  event bus, ingest, poll, evidence
python -m logicward.tests.smoke_l5x         # 16/16  L5X parse/canonicalize/hash
python -m logicward.tests.smoke_plant       # 14/14  Modbus PLC + program endpoints
python -m logicward.tests.smoke_drift       # 18/18  baseline HMAC + all 6 mutations
python -m logicward.tests.smoke_agent       # 11/11  sensors + FIM + agent wiring
python -m logicward.tests.smoke_dashboard   # 20/20  RBAC, views, diff, PDF, telemetry
python -m logicward.tests.smoke_attacker    # 10/10  attacker -> detection
python -m logicward.tests.smoke_grfics      # 39/39  chemical Site B plant + attacks
python -m logicward.tests.smoke_multisite   # 20/20  unified two-site SOC + console
python -m logicward.tests.smoke_classify    # 20/20  attack categorization (ext/int/mistake)
```

Each prints `RESULT: N/N checks passed` and exits non-zero on any failure.

---

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `pip install` fails on the Pi with "externally-managed-environment" | Use the venv (Bookworm/PEP 668): `python3 -m venv .venv && source .venv/bin/activate`. `pi_bootstrap.sh` does this for you. |
| Dashboard shows no Pi data in remote mode | Same Wi-Fi? Pi services running (`bash deploy/run_pi.sh`)? Try the Pi's IP instead of `.local`. Check `LOGICWARD_PI_HOST`. |
| Pi agent events never appear | Windows Firewall — allow inbound TCP 8080 (§7.2). Confirm `LOGICWARD_INGEST_URL` points at the laptop IP and the `LOGICWARD_TOKEN` matches both sides. |
| `siddhesh.local` won't resolve on Windows | Install Bonjour, or use the Pi's numeric IP (`hostname -I` on the Pi). |
| Laptop & Pi can't reach each other on campus Wi-Fi | Client isolation — switch both to a phone hotspot (§7). |
| Pi can't `git clone` (asks for username) | The repo is private — copy the tree from the laptop instead (§7.1), or make the repo public. |
| Rogue-device (ARP) sensor never fires | The live ARP sweep needs root: `SUDO_AGENT=1 bash deploy/run_pi.sh`. |
| Port 502 permission denied | Use the default 5020 (non-root), or run the Modbus server with `sudo`. |
| Port 8080 already in use | A previous dashboard/demo is still running — stop it, or change `LOGICWARD_INGEST_PORT`. |
| Baseline shows TAMPERED at startup | The signed baseline on disk was edited (that's the point of the FIM demo). Delete `logicward/data/baseline.signed.json` to re-lock a fresh one. |

---

## 12. Demo script & judge talking points

**Open:** dashboard on the big screen (`soc/soc123`), Overview tab — quiet, baseline
`VALID`, program in sync. *"This is a thermal power plant PLC, continuously verified
against a cryptographically signed approved program."*

**Run the show:** `python -m logicward.attacker.demo_sequence` on the attacker
terminal. As each act fires, switch tabs:
- **Program Diff** on the logic mutations — *"here's the exact logic flip: the drum-low
  trip compare inverted from LES to GRT — the interlock now fires backwards."*
- **Alerts** — *"every detection is severity-ranked and mapped to a MITRE ATT&CK for ICS
  technique, with who/when/how."*
- **Evidence → PDF** — *"one click produces a signed forensic report for the incident."*

**Key lines:**
- *"The program is a real Rockwell L5X. We don't execute it — we canonicalize and diff
  it, so a harmless re-export with new timestamps never false-alarms, but a single
  inverted instruction is caught instantly."*
- *"The baseline is HMAC-signed; tampering the approved copy breaks the signature and
  raises a critical alert on its own."*
- *"One event contract, three planes — cyber, physical, resource — on one bus. The same
  fabric catches a logic edit, a pulled cable, and a DDoS flood."*
- *"98 automated checks; runs on one laptop for judging, or split across a real Pi and
  an attacker box over Wi-Fi."*
