"""Verify the physical/resource sensors + FIM + agent wiring (stage 5b gate).

Sensors are exercised in simulation (no hardware); FIM is exercised against a
real file with a real watchdog observer; and the full agent -> forwarder ->
ingest -> bus path is proven over HTTP.

Run:  python -m logicward.tests.smoke_agent
"""
from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path

import requests
from werkzeug.serving import make_server

from logicward.agent.agent import Agent
from logicward.agent.forwarder import Forwarder
from logicward.agent.sensors import fim_watch
from logicward.agent.sensors.arp_watch import ArpWatch
from logicward.agent.sensors.fim_watch import BaselineFileMonitor, ProgramFileMonitor
from logicward.agent.sensors.gpio_tamper import GpioTamper
from logicward.agent.sensors.link_watch import LinkWatch
from logicward.agent.sensors.resource import ResourceMonitor
from logicward.engine import baseline as bl
from logicward.engine.events import EventBus
from logicward.engine.server import create_app
from logicward.plant.logic_store import BASELINE_PATH

TOKEN = "smoke-agent"
_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def main() -> int:
    events: list[dict] = []
    emit = events.append

    # ── poll sensors in simulation ───────────────────────────────────────────
    link = LinkWatch(emit, iface="eth0")
    link.set_sim(True); link.scan()                 # establish baseline (up)
    link.set_sim(False); link.scan()
    check(any(e["type"] == "physical.link_down" for e in events), "link_watch: cable pull -> link_down")

    gpio = GpioTamper(emit)
    gpio.trigger_sim(True); gpio.scan()
    check(any(e["type"] == "physical.enclosure_open" for e in events), "gpio_tamper: door open -> enclosure_open")

    res = ResourceMonitor(emit, cpu_threshold=85)
    res.set_sim(cpu=97); res.scan()
    res.set_sim(cpu=10); res.scan()                 # re-arm
    res.set_sim(cpu=97); res.scan()
    spikes = [e for e in events if e["type"] == "resource.cpu_spike"]
    check(len(spikes) == 2, f"resource: spike fires, re-arms, fires again ({len(spikes)})")
    res.set_sim(cpu=42, mem=55, temp=63.5)
    s = res.sample()
    check(s["cpu"] == 42 and s["mem"] == 55 and s["temp"] == 63.5,
          "resource.sample() returns live cpu/mem/temp for the Live-Plant panel")

    arp = ArpWatch(emit, allowlist=["aa:bb:cc:00:00:01"])
    arp.observe([{"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.10"},
                 {"mac": "de:ad:be:ef:13:37", "ip": "192.168.1.66", "vendor": "Unknown"}])
    arp.observe([{"mac": "de:ad:be:ef:13:37", "ip": "192.168.1.66"}])  # dup -> no re-alert
    rogues = [e for e in events if e["type"] == "physical.rogue_device"]
    check(len(rogues) == 1 and rogues[0]["details"]["mac"] == "de:ad:be:ef:13:37",
          "arp_watch: unknown MAC -> one rogue_device (allowlisted + dup suppressed)")

    # ── FIM: program file, real watchdog observer ────────────────────────────
    check(fim_watch.available(), "watchdog available (real FIM, not fallback)")
    tmp = Path(tempfile.mkdtemp(prefix="lw_fim_"))
    live = tmp / "live.L5X"
    shutil.copyfile(BASELINE_PATH, live)
    fim_events: list[dict] = []
    mon = ProgramFileMonitor(live, fim_events.append).start()
    time.sleep(0.3)
    mutated = live.read_text(encoding="utf-8").replace("LES(Drum_Level,Drum_Level_LL_SP)",
                                                       "GRT(Drum_Level,Drum_Level_LL_SP)")
    live.write_text(mutated, encoding="utf-8")
    for _ in range(40):                              # wait up to ~4s for the fs event
        if fim_events:
            break
        time.sleep(0.1)
    mon.stop()
    check(any(e["type"] == "cyber.program_file_modified" for e in fim_events),
          "FIM: out-of-band edit of live.L5X detected by watchdog")

    # ── FIM: baseline tamper via HMAC re-verify ──────────────────────────────
    manifest_path = tmp / "baseline.signed.json"
    signed = bl.capture(BASELINE_PATH.read_bytes(), {})
    bl.save(signed, manifest_path)
    bfe: list[dict] = []
    bmon = BaselineFileMonitor(manifest_path, bfe.append)
    ev = bmon.scan()
    check(ev and ev["type"] == "cyber.baseline_relocked", "FIM: valid baseline -> relocked (info)")
    manifest_path.write_text(manifest_path.read_text().replace('"structural_hash": "sha256:',
                                                               '"structural_hash": "sha256:0'))
    ev = bmon.scan()
    check(ev and ev["type"] == "cyber.baseline_tamper" and ev["severity"] == "critical",
          "FIM: edited baseline -> HMAC break -> critical baseline_tamper")

    # ── full agent -> forwarder -> ingest -> bus over HTTP ───────────────────
    bus = EventBus()
    app = create_app(bus=bus, token=TOKEN)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/api/ingest"
    try:
        agent = Agent(forwarder=Forwarder(url=url, token=TOKEN, flush_interval=0.2),
                      iface="eth0", live_program_path=None)
        agent.gpio.trigger_sim(True)
        agent.poll_once()
        agent.forwarder.flush()
        got = requests.get(f"http://127.0.0.1:{srv.server_port}/api/events?since=0", timeout=2).json()
        check(any(e["type"] == "physical.enclosure_open" for e in got["events"]),
              "agent wiring: sensor -> forwarder -> ingest -> bus (enriched)")
        e = next(e for e in got["events"] if e["type"] == "physical.enclosure_open")
        check(e["mitre"]["technique_id"] and e["severity"], "agent-delivered event carries MITRE + severity")
    finally:
        srv.shutdown()

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
