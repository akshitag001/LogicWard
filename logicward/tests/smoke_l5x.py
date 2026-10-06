"""Verify the L5X parse/canonicalize layer (stage 4 keystone).

Proves the canonicalizer: (1) parses real rungs + setpoints, (2) is invariant to
volatile noise (export/edit dates, comments) so it won't false-positive, and
(3) detects each real logic change class (operator flip, setpoint drift, coil
hijack) as a structural-hash change.

Run:  python -m logicward.tests.smoke_l5x
"""
from __future__ import annotations

import re
from pathlib import Path

from logicward.engine import l5x

BASELINE = Path(__file__).resolve().parents[1] / "plant" / "program" / "ThermalPlant_baseline.L5X"

_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def main() -> int:
    text = BASELINE.read_text(encoding="utf-8")
    prog = l5x.parse(text)
    base_hash = l5x.structural_hash(prog)

    # 1) parsing -------------------------------------------------------------
    check(prog.controller == "ThermalPlant_Safety",
          f"controller name parsed ({prog.controller})")
    check(len(prog.setpoints) == 5, f"5 setpoints parsed (got {len(prog.setpoints)})")
    check(prog.setpoints.get("Drum_Level_LL_SP") == 220.0,
          "Drum_Level_LL_SP setpoint = 220.0")
    rungs = prog.routines.get("SafetyInterlocks", [])
    check(len(rungs) == 6, f"SafetyInterlocks has 6 rungs (got {len(rungs)})")

    r0 = rungs[0]
    ops = [i.op for i in r0.instructions]
    check(ops == ["XIC", "LES", "OTE"], f"rung 0 instructions {ops}")
    check(r0.output_coil == "Feedwater_Trip", f"rung 0 output coil ({r0.output_coil})")
    check(r0.safety_critical is True, "rung 0 (a Trip) flagged safety_critical")
    check(rungs[5].output_coil == "Vibration_Alarm" and rungs[5].safety_critical is False,
          "rung 5 (an Alarm) NOT safety_critical")

    # 2) volatile invariance -------------------------------------------------
    dated = re.sub(r'ExportDate="[^"]*"', 'ExportDate="Wed Jul 22 10:00:00 2026"', text)
    dated = re.sub(r'EditedDate="[^"]*"', 'EditedDate="Wed Jul 22 10:00:00 2026"', dated)
    check(l5x.structural_hash(l5x.parse(dated)) == base_hash,
          "date-only re-export -> IDENTICAL structural hash (no false positive)")
    check(l5x.strip_volatile_xml(dated) == l5x.strip_volatile_xml(text),
          "date-only re-export -> IDENTICAL C14N (volatile attrs stripped)")

    commented = text.replace("loss of drum level protection",
                             "REVISED COMMENT during maintenance window")
    check(l5x.structural_hash(l5x.parse(commented)) == base_hash,
          "comment-only edit -> IDENTICAL structural hash (docs are not logic)")

    # 3) real logic changes detected ----------------------------------------
    inverted = text.replace("LES(Drum_Level,Drum_Level_LL_SP)",
                            "GRT(Drum_Level,Drum_Level_LL_SP)")
    check(l5x.structural_hash(l5x.parse(inverted)) != base_hash,
          "logic inversion (LES->GRT) -> hash CHANGES")

    drifted = text.replace('Value="220.0"', 'Value="40.0"')
    dprog = l5x.parse(drifted)
    check(l5x.structural_hash(dprog) != base_hash,
          "setpoint drift (220.0->40.0) -> hash CHANGES")
    check(dprog.setpoints.get("Drum_Level_LL_SP") == 40.0,
          "drifted setpoint value read back (40.0)")

    hijacked = text.replace("OTE(Feedwater_Trip)", "OTE(Cooling_Pump_Stop)")
    check(l5x.structural_hash(l5x.parse(hijacked)) != base_hash,
          "coil hijack (Feedwater_Trip->Cooling_Pump_Stop) -> hash CHANGES")

    # neutral-text lines (dashboard diff input) ------------------------------
    lines = l5x.neutral_text_lines(prog)
    check(len(lines) == 6 and "Drum_Level_LL_SP=220" in lines[0],
          "neutral_text_lines inlines referenced setpoint for the visual diff")

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
