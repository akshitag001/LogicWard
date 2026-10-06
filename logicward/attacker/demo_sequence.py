"""Scripted stage demo - normal ops -> attack -> detection (Prahari-style).

Self-contained: brings up the whole LogicWard stack in one process (SOC dashboard
+ embedded thermal PLC + logic store), opens on a URL for the projector, then
drives the full attack catalogue against it with live narration so an audience
watches each detection land on the dashboard in real time.

    python -m logicward.attacker.demo_sequence          # ~90s, watchable pacing
    python -m logicward.attacker.demo_sequence --fast    # quick smoke of the flow

Open the printed URL (login soc/soc123) and switch between Alerts, Program Diff,
and Live Plant as the attacks run.
"""
from __future__ import annotations

import argparse
import threading
import time

from werkzeug.serving import make_server

from logicward import config
from logicward.agent.sensors.arp_watch import ArpWatch
from logicward.agent.sensors.fim_watch import ProgramFileMonitor
from logicward.agent.sensors.gpio_tamper import GpioTamper
from logicward.agent.sensors.link_watch import LinkWatch
from logicward.agent.sensors.resource import ResourceMonitor
from logicward.attacker.attacks import Attacker
from logicward.dashboard.app import Dashboard, create_app
from logicward.plant import logic_store
from logicward.plant.logic_store import BASELINE_PATH, LIVE_PATH

C = {"h": "\033[96m", "a": "\033[91m", "d": "\033[92m", "m": "\033[2m", "b": "\033[1m", "x": "\033[0m"}


def banner(txt: str) -> None:
    print(f"\n{C['b']}{C['h']}=== {txt} ==={C['x']}")


def act(txt: str) -> None:
    print(f"  {C['a']}>> ATTACK{C['x']}  {txt}")


def det(txt: str) -> None:
    print(f"  {C['d']}[+] EXPECT{C['x']}  {txt}")


def _serve(app, port: int):
    srv = make_server("0.0.0.0", port, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(pause: float = 3.5) -> None:
    # clean slate: fresh baseline + running program
    for p in (config.BASELINE_MANIFEST_PATH, LIVE_PATH):
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    dash = Dashboard(embed=True).start()
    app = create_app(dashboard=dash)
    dash_srv = _serve(app, config.INGEST_PORT)

    # logic store over HTTP on the SAME running-program file the dashboard reads
    ls_app = logic_store.create_app(live_path=LIVE_PATH)
    ls_srv = _serve(ls_app, config.PROGRAM_PORT)

    # program-file FIM -> dashboard bus (out-of-band tamper signal)
    ProgramFileMonitor(LIVE_PATH, dash.bus.emit).start()

    # sensors that would live on the Pi agent -> emit straight to the bus for the demo
    emit = dash.bus.emit
    arp = ArpWatch(emit, allowlist=["00:11:22:33:44:55"])
    link = LinkWatch(emit); link.set_sim(True); link.scan()
    gpio = GpioTamper(emit)
    res = ResourceMonitor(emit)

    atk = Attacker("127.0.0.1", modbus_port=dash.plant.port,
                   program_base=f"http://127.0.0.1:{config.PROGRAM_PORT}")

    print(f"\n{C['b']}Vigilo live demo{C['x']}")
    print(f"  Dashboard : {C['h']}http://localhost:{config.INGEST_PORT}/{C['x']}  (login soc/soc123)")
    print(f"  {C['m']}Open it, then watch Alerts + Program Diff as the attack unfolds.{C['x']}")
    time.sleep(max(pause, 5))

    banner("ACT 1 - normal operations")
    print(f"  {C['m']}Plant nominal | baseline HMAC-locked | program in sync | no alerts.{C['x']}")
    time.sleep(pause)

    banner("ACT 2 - reconnaissance & footholds")
    act("Rogue engineering laptop appears on the OT segment")
    arp.observe([{"mac": "de:ad:be:ef:13:37", "ip": "192.168.1.66", "vendor": "Unknown"}])
    det("physical.rogue_device (Rogue Master, T0848)")
    time.sleep(pause)

    banner("ACT 3 - silent PLC logic tampering (program download)")
    act("Setpoint drift over Modbus - drum-level trip 220 -> 40 mm")
    atk.setpoint_drift_modbus("Drum_Level_LL_SP", 40)
    det("cyber.setpoint_drift via modbus-write (Modify Parameter, T0836)")
    time.sleep(pause)

    for name, desc, tech in [
        ("logic-inversion", "Invert drum-level trip compare LES -> GRT", "Modify Program, T0889"),
        ("condition-stripping", "Strip the running-interlock from the furnace flame trip", "Modify Program, T0889"),
        ("coil-hijack", "Repoint the feedwater trip output coil", "Modify Program, T0889"),
        ("rung-injection", "Inject a backdoor rung that unlatches the turbine trip", "Program Download, T0843"),
    ]:
        act(f"Program download - {desc}")
        atk.program_mutation(name)
        det(f"cyber.{name.replace('-', '_')} + FIM program_file_modified ({tech})")
        time.sleep(pause)

    banner("ACT 4 - process manipulation & impact")
    act("Force the fuel valve coil over Modbus")
    atk.force_coil("Fuel_Valve_Open", False)
    det("cyber.register_change (Unauthorized Command Message, T0855)")
    time.sleep(pause)

    act("DDoS flood against the Modbus server")
    rate = atk.ddos(400)
    res.set_sim(cpu=98); res.scan()
    det(f"resource.cpu_spike (Denial of Service, T0814) - flood ~{rate:.0f} req/s")
    time.sleep(pause)

    banner("ACT 5 - physical tamper")
    act("Ethernet cable pulled, then enclosure door opened")
    link.set_sim(False); link.scan()
    gpio.trigger_sim(True); gpio.scan()
    det("physical.link_down + physical.enclosure_open")
    time.sleep(pause)

    # let the drift loop settle, then summarise
    time.sleep(2)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for e in dash.bus.snapshot():
        counts[e.get("severity", "info")] = counts.get(e.get("severity", "info"), 0) + 1
    banner("DETECTION SUMMARY")
    print(f"  events: {len(dash.bus.snapshot())}  |  "
          f"{C['a']}critical {counts['critical']}{C['x']}  high {counts['high']}  "
          f"medium {counts['medium']}  low {counts['low']}  info {counts['info']}")
    print(f"  {C['m']}Every event is in the evidence log - export the signed PDF from the dashboard.{C['x']}")
    print(f"\n  {C['b']}Dashboard still live at http://localhost:{config.INGEST_PORT}/  (Ctrl+C to stop){C['x']}")

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        dash_srv.shutdown()
        ls_srv.shutdown()
        dash.stop()


def main() -> None:
    p = argparse.ArgumentParser(description="Vigilo scripted stage demo")
    p.add_argument("--fast", action="store_true", help="quick pacing (flow smoke)")
    args = p.parse_args()
    run(pause=1.0 if args.fast else 3.5)


if __name__ == "__main__":
    main()
