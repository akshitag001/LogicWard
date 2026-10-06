"""Verify the signed baseline + drift engine (stage 5 gate) — the cyber plane.

Locks an HMAC-signed baseline, proves tamper breaks the signature, then drives
each of the six named mutation classes through the engine and asserts the right
event type, safety scoring, MITRE technique, and channel — plus a clean no-drift
pass (no false positives).

Run:  python -m logicward.tests.smoke_drift
"""
from __future__ import annotations

from collections import Counter

from logicward.engine import baseline as bl
from logicward.engine.drift import DriftEngine
from logicward.engine.events import EventBus
from logicward.plant import rung_to_register as r2r
from logicward.plant.logic_store import BASELINE_PATH
from logicward.plant.modbus_server import ThermalDataStore

_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def reg_snapshot(ds: ThermalDataStore) -> dict:
    return {"holding": {p.tag: ds.hr(p.tag) for p in r2r.HOLDING_REGISTERS},
            "coils": {p.tag: ds.coil(p.tag) for p in r2r.COILS}}


def run_case(signed, program_xml, registers):
    """Fresh engine + bus per case so idempotency doesn't cross cases."""
    bus = EventBus()
    eng = DriftEngine(bus, signed, program_source=lambda: program_xml,
                      register_source=lambda: registers)
    return eng.run_once()


def main() -> int:
    base_text = BASELINE_PATH.read_text(encoding="utf-8")
    base_xml = base_text.encode("utf-8")
    ds = ThermalDataStore()
    base_regs = reg_snapshot(ds)
    signed = bl.capture(base_xml, base_regs)

    # ── HMAC lock ────────────────────────────────────────────────────────────
    check(bl.verify(signed), "baseline signature verifies (HMAC-SHA256)")
    tampered = {**signed, "manifest": {**signed["manifest"], "structural_hash": "sha256:deadbeef"}}
    check(not bl.verify(tampered), "tampering the locked baseline breaks the signature")

    # ── no drift (no false positives) ────────────────────────────────────────
    evs = run_case(signed, base_xml, base_regs)
    check(len(evs) == 0, f"identical program + registers -> 0 events (got {len(evs)})")

    # ── 1. setpoint drift (structural / L5X) ─────────────────────────────────
    evs = run_case(signed, base_text.replace('Value="220.0"', 'Value="40.0"').encode(), base_regs)
    types = Counter(e["type"] for e in evs)
    e = next((x for x in evs if x["type"] == "cyber.setpoint_drift"), {})
    check(types["cyber.setpoint_drift"] == 1 and len(evs) == 1, f"setpoint drift -> 1 event ({dict(types)})")
    check(e.get("severity") in ("high", "critical") and e["details"]["safety_critical"],
          f"setpoint drift on a safety rung scored {e.get('severity')}")
    check(e.get("mitre", {}).get("technique_id") == "T0836", "setpoint drift -> MITRE T0836 (Modify Parameter)")
    check(e.get("identity", {}).get("channel") == "program-download", "setpoint drift channel = program-download")

    # ── 2. logic inversion ───────────────────────────────────────────────────
    evs = run_case(signed, base_text.replace("LES(Drum_Level,Drum_Level_LL_SP)",
                                             "GRT(Drum_Level,Drum_Level_LL_SP)").encode(), base_regs)
    e = next((x for x in evs if x["type"] == "cyber.logic_inversion"), {})
    check(len(evs) == 1 and e, "logic inversion (LES->GRT) -> 1 cyber.logic_inversion")
    check(e.get("mitre", {}).get("technique_id") == "T0889", "logic inversion -> MITRE T0889 (Modify Program)")

    # ── 3. condition stripping (remove a safety input) ───────────────────────
    evs = run_case(signed, base_text.replace("XIC(Plant_Running)XIO(Flame_Detected)OTE(Fuel_Trip)",
                                             "XIO(Flame_Detected)OTE(Fuel_Trip)").encode(), base_regs)
    e = next((x for x in evs if x["type"] == "cyber.condition_stripping"), {})
    check(len(evs) == 1 and e, "condition stripping -> 1 cyber.condition_stripping")
    check(e.get("severity") == "critical" and e["details"]["safety_critical"],
          f"stripping a safety condition scored critical (got {e.get('severity')})")

    # ── 4. coil hijack ───────────────────────────────────────────────────────
    evs = run_case(signed, base_text.replace("OTE(Feedwater_Trip)", "OTE(Cooling_Pump_Stop)").encode(), base_regs)
    e = next((x for x in evs if x["type"] == "cyber.coil_hijack"), {})
    check(len(evs) == 1 and e.get("details", {}).get("current") == "Cooling_Pump_Stop",
          "coil hijack -> 1 cyber.coil_hijack (Feedwater_Trip -> Cooling_Pump_Stop)")

    # ── 5. rung injection ────────────────────────────────────────────────────
    injected = base_text.replace(
        "      </RLLContent>",
        '       <Rung Number="6" Type="N"><Text><![CDATA[XIC(Attacker_Backdoor)OTU(Turbine_Trip);]]></Text></Rung>\n      </RLLContent>')
    evs = run_case(signed, injected.encode(), base_regs)
    e = next((x for x in evs if x["type"] == "cyber.rung_injection"), {})
    check(len(evs) == 1 and e, "rung injection -> 1 cyber.rung_injection")
    check(e.get("mitre", {}).get("technique_id") == "T0843", "rung injection -> MITRE T0843 (Program Download)")

    # ── 6. register plane: setpoint over Modbus + forced control coil ────────
    ds2 = ThermalDataStore()
    ds2.holding_registers[r2r.BY_TAG["Drum_Level_LL_SP"].address] = 500
    ds2.set_coil("Fuel_Valve_Open", False)
    evs = run_case(signed, base_xml, reg_snapshot(ds2))
    types = Counter(e["type"] for e in evs)
    check(types["cyber.setpoint_drift"] == 1 and types["cyber.register_change"] == 1 and len(evs) == 2,
          f"register plane -> setpoint_drift + register_change ({dict(types)})")
    sd = next(x for x in evs if x["type"] == "cyber.setpoint_drift")
    check(sd["identity"]["channel"] == "modbus-write", "Modbus setpoint drift channel = modbus-write")
    rc = next(x for x in evs if x["type"] == "cyber.register_change")
    check(rc["mitre"]["technique_id"] == "T0855", "forced coil -> MITRE T0855 (Unauthorized Command Message)")

    # ── idempotency: same mutation twice in one engine -> reported once ──────
    bus = EventBus()
    eng = DriftEngine(bus, signed, program_source=lambda: injected.encode(),
                      register_source=lambda: base_regs)
    first = eng.run_once()
    second = eng.run_once()
    check(len(first) == 1 and len(second) == 0, "persistent mutation reported once, not every pass")

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
