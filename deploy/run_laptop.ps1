# ─────────────────────────────────────────────────────────────────────────────
# LogicWard — launch the SOC dashboard on the laptop, reading the REAL Pi.
#
#   .\deploy\run_laptop.ps1                       # Pi at siddhesh-pi.local
#   .\deploy\run_laptop.ps1 -PiHost 192.168.1.42  # or an explicit IP
#
# The dashboard also hosts /api/ingest, so the Pi agent POSTs its events here.
# One-time: allow inbound TCP 8080 through Windows Firewall (run as admin):
#   New-NetFirewallRule -DisplayName LogicWard -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
#
# For the TWO-LAPTOP attacker demo add -OpenChemToLan so the chemical Site B
# Modbus (:5021) accepts attacks from the second laptop (also open 5021 in the
# firewall). See STARTUP_MANUAL.md "Two-laptop attacker setup".
# ─────────────────────────────────────────────────────────────────────────────
param(
  [string]$PiHost = "siddhesh.local",
  [string]$Token  = "logicward-dev-token-change-me",
  [switch]$OpenChemToLan
)

$env:LOGICWARD_EMBED_PLANT = "0"        # read the real Pi, not an in-process plant
$env:LOGICWARD_PI_HOST     = $PiHost    # PROGRAM_URL derives from this automatically
$env:LOGICWARD_TOKEN       = $Token     # must match the token on the Pi agent
if ($OpenChemToLan) {
  $env:LOGICWARD_GRFICS_MODBUS_HOST = "0.0.0.0"   # expose Site B to the attacker laptop
}

Write-Host "Vigilo SOC dashboard" -ForegroundColor Cyan
Write-Host "  URL      : http://localhost:8080/   (login soc/soc123)"
Write-Host "  Reading  : PLC at $PiHost  (Modbus :5020, program :8081)"
Write-Host "  Ingest   : POST http://<this-laptop>:8080/api/ingest  (Pi agent -> here)"
if ($OpenChemToLan) { Write-Host "  Site B   : chemical Modbus :5021 OPEN to the LAN (attacker 2nd laptop)" -ForegroundColor Yellow }
Write-Host ""
python -m logicward.dashboard.app
