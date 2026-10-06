"""Verify the attacker toolkit drives real detections (stage 8 gate).

Stands up an embedded plant + logic store, points the Attacker at them, and
confirms each attack surfaces the expected drift event through the live engine.

Run:  python -m logicward.tests.smoke_attacker
"""
from __future__ import annotations

import threading

from werkzeug.serving import make_server

from logicward import config
from logicward.attacker.attacks import Attacker
from logicward.dashboard.app import Dashboard
from logicward.plant import logic_store
from logicward.plant.logic_store import LIVE_PATH

_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def main() -> int:
    for p in (config.BASELINE_MANIFEST_PATH, LIVE_PATH):
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    dash = Dashboard(embed=True).start()
    ls_app = logic_store.create_app(live_path=LIVE_PATH)
    srv = make_server("127.0.0.1", 0, ls_app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    atk = Attacker("127.0.0.1", modbus_port=dash.plant.port,
                   program_base=f"http://127.0.0.1:{srv.server_port}")

    def types():
        return {e["type"] for e in dash.bus.snapshot()}

    def event(t):
        return next((e for e in dash.bus.snapshot() if e["type"] == t), None)

    try:
        # setpoint drift over Modbus (register plane)
        check(atk.setpoint_drift_modbus("Drum_Level_LL_SP", 40), "Modbus setpoint write accepted")
        dash.drift.run_once()
        sd = event("cyber.setpoint_drift")
        check(sd is not None and sd["identity"]["channel"] == "modbus-write",
              "setpoint drift detected via modbus-write")

        # program mutations over the (unauthenticated) download channel
        base_hash = dash.diff()["baseline_hash"]
        r = atk.program_mutation("logic-inversion")
        check(r.get("status") == "downloaded" and r["hash"] != base_hash,
              "logic-inversion program download accepted + changes hash")
        check("GRT(Drum_Level,Drum_Level_LL_SP)" in atk.fetch_program(),
              "downloaded program persisted on the plant")
        dash.drift.run_once()
        check("cyber.logic_inversion" in types(), "logic inversion detected by engine")

        atk.program_mutation("condition-stripping")
        atk.program_mutation("coil-hijack")
        atk.program_mutation("rung-injection")
        dash.drift.run_once()
        t = types()
        check({"cyber.condition_stripping", "cyber.coil_hijack", "cyber.rung_injection"} <= t,
              "condition-stripping, coil-hijack, rung-injection all detected")

        # forced control coil
        check(atk.force_coil("Fuel_Valve_Open", False), "Modbus coil force accepted")
        dash.drift.run_once()
        check("cyber.register_change" in types(), "forced control coil -> register_change")

        # DDoS flood
        rate = atk.ddos(60)
        check(rate > 0, f"DDoS flood ran ({rate:.0f} req/s)")

        # program is now substantially drifted
        check(dash.diff()["changed"] >= 3, f"program diff shows multiple changes ({dash.diff()['changed']})")
    finally:
        srv.shutdown()
        dash.stop()

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
