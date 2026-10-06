"""Smoke suite for the attack-origin classifier (mistake / internal / external).

Verifies the per-event heuristic buckets drift by channel + magnitude + safety,
and that every enriched event on the bus carries a non-empty `category`.

Run:  python -m logicward.tests.smoke_classify
"""
from __future__ import annotations

import sys

from logicward.engine.classify import classify_drift
from logicward.engine.events import EventBus

_passed = 0
_failed = 0


def check(desc: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {desc}")


def main() -> int:
    # -- classifier buckets --
    cases = [
        ("external", "cyber.setpoint_drift", {"safety_critical": True, "baseline": 220, "current": 40}, {"channel": "modbus-write"}),
        ("external", "cyber.register_change", {"coil": "Fuel_Valve_Open", "baseline": True, "current": False}, {"channel": "modbus-write"}),
        ("external", "cyber.register_change", {"baseline": 40, "current": 100}, {"channel": "modbus-write"}),      # big force
        ("mistake",  "cyber.register_change", {"baseline": 40, "current": 43}, {"channel": "modbus-write"}),       # small nudge
        ("internal", "cyber.logic_inversion", {"safety_critical": True}, {"channel": "program-download"}),
        ("internal", "cyber.rung_injection", {}, {"channel": "program-download"}),
        ("external", "physical.rogue_device", {}, {"channel": "network"}),
        ("external", "resource.cpu_spike", {}, {"channel": "host"}),
    ]
    for expect, etype, det, ident in cases:
        cat, reason = classify_drift(etype, det, ident)
        check(f"{etype} ({det}) -> {expect}", cat == expect)
        check(f"{etype} carries a reason", bool(reason))

    # -- every enriched event carries a category --
    bus = EventBus(evidence_path=None)
    ev = bus.emit_new("cyber.register_change", "test",
                      {"tag": "Feed1_Valve_Cmd", "baseline": 40, "current": 100},
                      identity={"who": "127.0.0.1", "channel": "modbus-write"})
    check("enriched event has a category", bool(ev.get("category")))
    check("enriched event has a category_reason", bool(ev.get("category_reason")))
    check("big register force classified external", ev.get("category") == "external")

    prog = bus.emit_new("cyber.logic_inversion", "test", {"rung_id": "MainRoutine:2"},
                        identity={"who": "127.0.0.1", "channel": "program-download"})
    check("program-download classified internal", prog.get("category") == "internal")

    total = _passed + _failed
    print("=" * 52)
    print(f"RESULT: {_passed}/{total} checks passed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
