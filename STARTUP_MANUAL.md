# LogicWard Demo - Manual Startup Guide

If the IP address of the Raspberry Pi changes (e.g., when the Mobile Hotspot restarts), follow these manual steps to start the demo.

### Prerequisites
1. Turn on your Mobile Hotspot.
2. Plug in the Raspberry Pi and wait ~60 seconds for it to boot.
3. Find the Pi's new IP address in your Mobile Hotspot settings (e.g., `192.168.137.129`).
4. Note your laptop's IP address on the hotspot network (usually `192.168.137.1`).

### Step 1: Bootstrap the Pi (Terminal 1)
Run this command to cleanly restart the Pi services and point it to your laptop's new IP:
```powershell
python deploy/pi_tools/bootstrap_pi.py --pi-ip <PI_IP> --laptop-ip <LAPTOP_IP>
```
*Example: `python deploy/pi_tools/bootstrap_pi.py --pi-ip 192.168.137.129 --laptop-ip 192.168.137.1`*

### Step 2: Start the SOC Dashboard (Terminal 1)
Once the Pi is bootstrapped, start the SOC dashboard:
```powershell
.\deploy\run_laptop.ps1 -PiHost <PI_IP>
```
*Example: `.\deploy\run_laptop.ps1 -PiHost 192.168.137.129`*

### Step 3: Start the Attacker Console (Terminal 2)
Open a new terminal and start the Red Team console:
```powershell
python -m logicward.attacker.dashboard --host <PI_IP>
```
*Example: `python -m logicward.attacker.dashboard --host 192.168.137.129`*

---

## Two-laptop attacker setup (real "by whom" attribution)

Run the attacker console on a **separate laptop** so every attack lands from a
**real remote IP**. That IP is then captured at the write layer and shown as
**"by whom"** on the SOC alert feed, the mimic badge, and the signed forensic PDF
— the exact "what changed, when, and by whom" the problem statement asks for.

**Three machines, one LAN/hotspot:** the **Pi** (thermal plant), the **SOC laptop**
(dashboard + chemical Site B), and the **attacker laptop**.

**How "who" is captured**
- **Thermal (Pi):** the Pi's Modbus server records the client IP of every write and
  serves it on `GET :5024/writes`; the program store records the downloader's IP on
  `GET :8081/program/downloader`. The SOC dashboard reads both and fills in `who`.
- **Chemical (Site B):** the writes arrive *into* the SOC laptop's Site B Modbus
  server, which sees the attacker's IP directly — no extra endpoint needed.

**1 · Pi (Terminal 1 on the Pi)** — start the plant services (already expose
Modbus :5020, program :8081, write-attribution :5024):
```bash
bash deploy/run_pi.sh
```

**2 · SOC laptop** — start the dashboard and expose chemical Site B to the LAN:
```powershell
# one-time firewall (admin): allow the attacker laptop in
New-NetFirewallRule -DisplayName "LogicWard SOC"   -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LogicWard SiteB" -Direction Inbound -LocalPort 5021 -Protocol TCP -Action Allow

.\deploy\run_laptop.ps1 -PiHost <PI_IP> -OpenChemToLan
```

**3 · Attacker laptop** — point the console at the Pi (thermal) and the SOC laptop
(chemical):
```powershell
.\deploy\run_attacker.ps1 -PiHost <PI_IP> -SocHost <SOC_LAPTOP_IP>
```
Open `http://localhost:9090/`, fire any attack, and watch the SOC dashboard: the
alert now reads **"by <attacker-laptop-IP>"**, the **HOW** line shows the literal
Modbus/program op, and — if you run a DDoS — the **Controller host** panel on the
Live Plant tab spikes. Export the PDF (SOC/CISO login) to see the attacker IP in
the evidence trail.

> Same-machine demo? Just use Step 3 above (`--host 127.0.0.1`); "who" resolves to
> `127.0.0.1`. The two-laptop setup only changes the address, not the pipeline.
