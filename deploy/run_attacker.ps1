# ─────────────────────────────────────────────────────────────────────────────
# LogicWard — Red-Team ATTACKER CONSOLE on a SECOND laptop.
#
# Runs the attacker console remotely so every attack lands from this laptop's
# REAL IP — which then shows up as "by whom" on the SOC dashboard, the alert
# feed, and the signed forensic PDF (that is the whole point of running it here
# instead of on the SOC laptop).
#
#   .\deploy\run_attacker.ps1 -PiHost 192.168.137.129 -SocHost 192.168.137.1
#
#   -PiHost   the Raspberry Pi (thermal plant): Modbus :5020, program :8081,
#             write-attribution :5024
#   -SocHost  the SOC laptop (chemical Site B lives inside the SOC dashboard):
#             chemical Modbus :5021
#
# Targets:
#   Thermal (Pi)  -> setpoint-drift · force-coil · ddos · logic-inversion ·
#                    condition-stripping · coil-hijack · rung-injection
#   Chemical (3D) -> quality-sabotage · pump-starve · overfill · estop-injection ·
#                    pressure-redline (BLAST)
#
# PREREQUISITES (one-time):
#   * SOC laptop must publish Site B on all interfaces, not just localhost:
#       $env:LOGICWARD_GRFICS_MODBUS_HOST = "0.0.0.0"   # before run_laptop.ps1
#     and allow inbound TCP 5021 (+ 8080) through its firewall (run as admin):
#       New-NetFirewallRule -DisplayName "LogicWard SiteB" -Direction Inbound -LocalPort 5021 -Protocol TCP -Action Allow
#       New-NetFirewallRule -DisplayName "LogicWard SOC"   -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
#   * Pi must allow inbound 5020 / 8081 / 5024 (default on a fresh Pi firewall).
#   * All three machines on the same LAN / hotspot.
# ─────────────────────────────────────────────────────────────────────────────
param(
  [Parameter(Mandatory = $true)][string]$PiHost,
  [Parameter(Mandatory = $true)][string]$SocHost,
  [int]$Port = 9090
)

Write-Host "Vigilo ATTACKER CONSOLE (2nd laptop)" -ForegroundColor Red
Write-Host "  Console       : http://localhost:$Port/"
Write-Host "  Thermal (Pi)  : $PiHost   (Modbus :5020, program :8081, writes :5024)"
Write-Host "  Chemical (3D) : $SocHost  (Site B Modbus :5021 on the SOC laptop)"
Write-Host "  -> attacks land from THIS laptop's IP; the SOC shows it as 'by whom'."
Write-Host ""
python -m logicward.attacker.dashboard `
  --host $PiHost --modbus-port 5020 --program-port 8081 `
  --chem-host $SocHost --chem-port 5021 --port $Port
