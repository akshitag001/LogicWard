"""LogicWard edge agent (runs on the Pi).

Wires every physical/resource sensor + the live-program FIM to the Forwarder,
which batches events to the laptop's /api/ingest. Poll-based sensors
(link/gpio/resource/arp) are scanned each interval; FIM is push-based (watchdog).

The signed-baseline FIM (`BaselineFileMonitor`) runs on the laptop next to the
engine, not here — this agent watches the live program file.

Run (on the Pi):  python -m logicward.agent.agent --iface eth0
"""
from __future__ import annotations

import argparse
import os
import threading

from logicward import config
from logicward.agent.forwarder import Forwarder
from logicward.agent.sensors.arp_watch import ArpWatch
from logicward.agent.sensors.fim_watch import ProgramFileMonitor
from logicward.agent.sensors.gpio_tamper import GpioTamper
from logicward.agent.sensors.link_watch import LinkWatch
from logicward.agent.sensors.resource import ResourceMonitor
from logicward.plant.logic_store import LIVE_PATH, ensure_live


class Agent:
    def __init__(self, forwarder: Forwarder | None = None, iface: str = "eth0",
                 live_program_path=None, allowlist: list[str] | None = None,
                 arp_cidr: str = "192.168.1.0/24", poll_interval: float | None = None):
        self.forwarder = forwarder or Forwarder()
        emit = self.forwarder.enqueue
        self.link = LinkWatch(emit, iface=iface)
        self.gpio = GpioTamper(emit)
        self.resource = ResourceMonitor(emit)
        self.arp = ArpWatch(emit, allowlist=allowlist, iface=iface)
        self.fim_program = ProgramFileMonitor(live_program_path, emit) if live_program_path else None
        self.arp_cidr = arp_cidr
        self.poll_interval = poll_interval or config.POLL_INTERVAL_SEC
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll_once(self) -> None:
        for sensor in (self.link, self.gpio, self.resource):
            try:
                sensor.scan()
            except Exception:  # noqa: BLE001 - one bad sensor must not stop the rest
                pass
        try:
            self.arp.scan(self.arp_cidr)
        except Exception:  # noqa: BLE001
            pass
        self._push_telemetry()

    def _push_telemetry(self) -> None:
        """Best-effort: forward this host's live CPU/RAM/temp to the SOC dashboard
        so the thermal Live-Plant panel shows the Pi's load (spikes under a flood)."""
        try:
            import socket

            import requests
            t = self.resource.sample()
            t["host"] = socket.gethostname()
            requests.post(config.TELEMETRY_URL, json=t, timeout=2,
                          headers={"X-LogicWard-Token": config.INGEST_TOKEN})
        except Exception:  # noqa: BLE001 - telemetry is non-critical
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.poll_interval)

    def start(self) -> "Agent":
        self.forwarder.start()
        if self.fim_program:
            self.fim_program.start()
        self._thread = threading.Thread(target=self._loop, name="lw-agent", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self.fim_program:
            self.fim_program.stop()
        self.forwarder.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="LogicWard edge agent (Pi)")
    parser.add_argument("--iface", default=os.environ.get("LOGICWARD_IFACE", "eth0"))
    parser.add_argument("--cidr", default=os.environ.get("LOGICWARD_ARP_CIDR", "192.168.1.0/24"))
    args = parser.parse_args()

    allow = [m for m in os.environ.get("LOGICWARD_ARP_ALLOWLIST", "").split(",") if m.strip()]
    ensure_live(LIVE_PATH)
    agent = Agent(iface=args.iface, live_program_path=LIVE_PATH,
                  allowlist=allow, arp_cidr=args.cidr)
    print("LogicWard agent starting")
    print(f"  iface      : {args.iface}")
    print(f"  ingest     : {config.INGEST_URL}")
    print(f"  program FIM : {LIVE_PATH}")
    agent.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
