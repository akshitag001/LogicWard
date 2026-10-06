#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# LogicWard — launch the three Pi-side services (PLC + program endpoints + agent).
#
#   bash deploy/run_pi.sh              # normal
#   SUDO_AGENT=1 bash deploy/run_pi.sh # run the agent as root so arp_watch can
#                                       # do a live ARP sweep (rogue-device sensor)
#
# Services:
#   modbus_server  Modbus TCP PLC (port 5020)          <- attacker + laptop read this
#                  + write-attribution HTTP (port 5024) <- laptop reads "who wrote what"
#   logic_store    GET/POST /program  (port 8081)      <- program-download channel
#                  + GET /program/downloader           <- "who" downloaded the program
#   agent          physical/resource/FIM sensors -> POSTs events + telemetry to laptop
#
# Ctrl+C stops all three. Logs stream to ./logs/.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

# shellcheck disable=SC1091
. .venv/bin/activate
# shellcheck disable=SC1091
[ -f deploy/pi.env ] && . deploy/pi.env
: "${LOGICWARD_INGEST_URL:?run 'bash deploy/pi_bootstrap.sh <LAPTOP_IP>' first}"
IFACE="${LOGICWARD_IFACE:-wlan0}"
mkdir -p logs
pids=()
cleanup() { echo; echo "stopping…"; kill "${pids[@]}" 2>/dev/null || true; exit 0; }
trap cleanup INT TERM

echo "Vigilo Pi services  |  ingest -> ${LOGICWARD_INGEST_URL}  |  iface ${IFACE}"
python -m logicward.plant.modbus_server > logs/modbus.log  2>&1 & pids+=($!); echo "  modbus_server  pid $! (:5020)  -> logs/modbus.log"
python -m logicward.plant.logic_store   > logs/program.log 2>&1 & pids+=($!); echo "  logic_store    pid $! (:8081)  -> logs/program.log"
sleep 1
if [ "${SUDO_AGENT:-0}" = "1" ]; then
  sudo -E env "PATH=$PATH" python -m logicward.agent.agent --iface "$IFACE" > logs/agent.log 2>&1 & pids+=($!)
  echo "  agent (root)   pid $! -> logs/agent.log  [live ARP sweep enabled]"
else
  python -m logicward.agent.agent --iface "$IFACE" > logs/agent.log 2>&1 & pids+=($!)
  echo "  agent          pid $! -> logs/agent.log"
fi
echo "Running. Ctrl+C to stop.  (find this Pi's IP with:  hostname -I)"
wait
