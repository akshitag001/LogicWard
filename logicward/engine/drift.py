"""The drift engine — diff live PLC reality against the signed baseline.

Two surfaces, both against the locked baseline (DESIGN.md §4-§5):

  * Structural (the L5X program): parse + canonicalize the live program and diff
    it rung-by-rung to name each mutation — setpoint drift, logic inversion,
    condition stripping, coil hijack, rung injection.
  * Register (Modbus): diff live holding registers + control coils to catch
    setpoint writes and unauthorized commands. Input registers are intentionally
    NOT diffed against a static baseline — they carry live process noise; only
    holding registers and operator-controlled coils are integrity-checked.

The engine is transport-agnostic: it takes a `program_source()` returning live
L5X bytes and an optional `register_source()` returning a Modbus snapshot, so it
is trivially testable and works the same against the real Pi or an in-memory
plant. Emissions go through the event bus; the bus computes severity + MITRE.

Detection is a DIFF — the rungs are never executed.
"""
from __future__ import annotations

from collections import Counter
from typing import Callable

from logicward.engine import baseline as baseline_mod
from logicward.engine import l5x
from logicward.plant import rung_to_register as r2r

# Coils the plant itself drives every scan (its own setpoint protection) — a
# change here is legitimate process behaviour, not an attack, so exclude them
# from the register-integrity check.
PLANT_DRIVEN_COILS = {
    "Feedwater_Trip", "Main_Steam_Trip", "Turbine_Trip",
    "Fuel_Trip", "Condenser_Trip", "Vibration_Alarm",
}

# Instruction op inversions used to tell "logic flipped" from "condition removed".
INVERSE_OP = {
    "XIC": "XIO", "XIO": "XIC",
    "LES": "GRT", "GRT": "LES", "LEQ": "GEQ", "GEQ": "LEQ",
    "EQU": "NEQ", "NEQ": "EQU",
}
_INPUT_OPS = l5x.CONTACTS | l5x.COMPARES


def _fmt(op: str, args) -> str:
    return f"{op}({','.join(args)})"


class DriftEngine:
    def __init__(self, bus, signed_baseline: dict,
                 program_source: Callable[[], bytes],
                 register_source: Callable[[], dict] | None = None,
                 who_source: Callable[[str | None, str], str | None] | None = None,
                 source: str = "drift_engine"):
        self.bus = bus
        self.signed = signed_baseline
        self.source = source
        m = signed_baseline["manifest"]
        self.baseline_prog = l5x.parse(m["l5x"].encode("utf-8"))
        self.baseline_hash = m["structural_hash"]
        self.baseline_setpoints = dict(self.baseline_prog.setpoints)
        self.baseline_regs = m.get("registers", {})
        self.program_source = program_source
        self.register_source = register_source
        self.who_source = who_source
        self._seen: set = set()
        self.baseline_valid = baseline_mod.verify(signed_baseline)

    # -- public --
    def run_once(self) -> list[dict]:
        """One detection pass. Returns the events emitted this pass (deduped)."""
        out = self._structural()
        if self.register_source is not None:
            out += self._registers()
        return [e for e in out if e]

    def reset(self) -> None:
        """Clear dedup memory (e.g. after a re-baseline)."""
        self._seen.clear()

    # -- emit with idempotency --
    def _emit(self, etype: str, details: dict, channel: str) -> dict | None:
        anchor = details.get("rung_id") or details.get("tag") or details.get("coil") or ""
        key = (etype, anchor, str(details.get("current")))
        if key in self._seen:
            return None
        self._seen.add(key)
        if "command" not in details:
            cmd = self._command(details, channel)
            if cmd:
                details = {**details, "command": cmd}
        who = "unknown"
        if self.who_source:
            tag = details.get("tag") or details.get("coil")
            who = self.who_source(tag, channel) or "unknown"
        return self.bus.emit_new(etype, self.source, details,
                                 identity={"who": who, "channel": channel})

    def _command(self, details: dict, channel: str) -> str | None:
        """Reconstruct the literal op that produced this drift (the 'how')."""
        if channel == "program-download":
            return "POST /program/download  (unauthenticated L5X program download)"
        tag = details.get("tag")
        if tag:
            p = r2r.BY_TAG.get(tag)
            if p:
                return f"FC06 write_holding @{p.address}={details.get('current')}  ({tag})"
        coil = details.get("coil")
        if coil:
            p = r2r.BY_TAG.get(coil)
            if p:
                on = bool(details.get("current"))
                return f"FC05 write_coil @{p.address}={'FF00' if on else '0000'}  ({coil} -> {'ON' if on else 'OFF'})"
        return None

    # -- structural (L5X) --
    def _structural(self) -> list[dict | None]:
        live = l5x.parse(self.program_source())
        # fast path: identical logic and identical setpoints -> nothing structural
        if l5x.structural_hash(live) == self.baseline_hash:
            return []

        out: list[dict | None] = []

        # setpoint drift (values live in the L5X tags)
        for tag in sorted(set(self.baseline_setpoints) | set(live.setpoints)):
            b = self.baseline_setpoints.get(tag)
            c = live.setpoints.get(tag)
            if b != c:
                out.append(self._emit("cyber.setpoint_drift", {
                    "tag": tag, "baseline": b, "current": c,
                    "rung_id": self._rung_for_setpoint(tag),
                    "safety_critical": self._setpoint_safety(tag),
                    "reason": f"Setpoint {tag} changed {b} -> {c} in the program",
                }, "program-download"))

        # rung-level structural diff
        for rname in sorted(set(self.baseline_prog.routines) | set(live.routines)):
            b_rungs = {r.number: r for r in self.baseline_prog.routines.get(rname, [])}
            l_rungs = {r.number: r for r in live.routines.get(rname, [])}
            for num in sorted(set(l_rungs) - set(b_rungs)):
                r = l_rungs[num]
                out.append(self._emit("cyber.rung_injection", {
                    "rung_id": r.rung_id(rname), "text": r.text,
                    "output_coil": r.output_coil, "safety_critical": r.safety_critical,
                    "reason": f"Unauthorized rung injected: {r.text}",
                }, "program-download"))
            for num in sorted(set(b_rungs) - set(l_rungs)):
                r = b_rungs[num]
                out.append(self._emit("cyber.condition_stripping", {
                    "rung_id": r.rung_id(rname), "removed": r.text,
                    "output_coil": r.output_coil, "safety_critical": r.safety_critical,
                    "reason": f"Entire protection rung removed: {r.text}",
                }, "program-download"))
            for num in sorted(set(b_rungs) & set(l_rungs)):
                out += self._diff_rung(rname, b_rungs[num], l_rungs[num])
        return out

    def _diff_rung(self, rname: str, b: l5x.Rung, live: l5x.Rung) -> list[dict | None]:
        out: list[dict | None] = []
        rid = b.rung_id(rname)

        if b.output_coil != live.output_coil:
            out.append(self._emit("cyber.coil_hijack", {
                "rung_id": rid, "baseline": b.output_coil, "current": live.output_coil,
                "safety_critical": b.safety_critical or live.safety_critical,
                "reason": f"Output coil repointed {b.output_coil} -> {live.output_coil}",
            }, "program-download"))

        b_in = [(i.op, tuple(i.args)) for i in b.instructions if i.op in _INPUT_OPS]
        l_in = [(i.op, tuple(i.args)) for i in live.instructions if i.op in _INPUT_OPS]
        removed = list((Counter(b_in) - Counter(l_in)).elements())
        added = list((Counter(l_in) - Counter(b_in)).elements())

        # pair removals with additions that share operands but flip the op => inversion
        used: list = []
        for rop, rargs in list(removed):
            match = next(((aop, aargs) for (aop, aargs) in added
                          if aargs == rargs and INVERSE_OP.get(rop) == aop and (aop, aargs) not in used), None)
            if match:
                used.append(match)
                removed.remove((rop, rargs))
                out.append(self._emit("cyber.logic_inversion", {
                    "rung_id": rid, "baseline": _fmt(rop, rargs), "current": _fmt(*match),
                    "safety_critical": b.safety_critical,
                    "reason": f"Logic inverted {rop} -> {match[0]} on {','.join(rargs)}",
                }, "program-download"))

        for rop, rargs in removed:                          # unmatched removals = stripped
            out.append(self._emit("cyber.condition_stripping", {
                "rung_id": rid, "removed": _fmt(rop, rargs),
                "safety_critical": b.safety_critical,
                "reason": f"Safety condition removed from {rid}: {_fmt(rop, rargs)}",
            }, "program-download"))

        for aop, aargs in added:                            # unmatched additions = altered logic
            if (aop, aargs) in used:
                continue
            out.append(self._emit("cyber.logic_inversion", {
                "rung_id": rid, "baseline": None, "current": _fmt(aop, aargs),
                "safety_critical": b.safety_critical,
                "reason": f"Unauthorized condition added to {rid}: {_fmt(aop, aargs)}",
            }, "program-download"))
        return out

    # -- register (Modbus) --
    def _registers(self) -> list[dict | None]:
        snap = self.register_source() or {}
        base_hold = self.baseline_regs.get("holding", {})
        base_coils = self.baseline_regs.get("coils", {})
        out: list[dict | None] = []

        for tag, cur in snap.get("holding", {}).items():
            b = base_hold.get(tag)
            if b is None or cur == b:
                continue
            if tag.endswith("_SP"):
                out.append(self._emit("cyber.setpoint_drift", {
                    "tag": tag, "baseline": b, "current": cur, "register": True,
                    "safety_critical": self._setpoint_safety(tag),
                    "reason": f"Setpoint register {tag} changed {b} -> {cur} over Modbus",
                }, "modbus-write"))
            else:
                out.append(self._emit("cyber.register_change", {
                    "tag": tag, "baseline": b, "current": cur,
                    "reason": f"Holding register {tag} changed {b} -> {cur} over Modbus",
                }, "modbus-write"))

        for tag, cur in snap.get("coils", {}).items():
            if tag in PLANT_DRIVEN_COILS:
                continue
            b = base_coils.get(tag)
            if b is None or bool(cur) == bool(b):
                continue
            out.append(self._emit("cyber.register_change", {
                "coil": tag, "baseline": bool(b), "current": bool(cur),
                "reason": f"Control coil {tag} forced {bool(b)} -> {bool(cur)} over Modbus",
            }, "modbus-write"))
        return out

    # -- helpers --
    def _rung_for_setpoint(self, tag: str) -> str | None:
        for rname, rungs in self.baseline_prog.routines.items():
            for r in rungs:
                if any(tag in i.args for i in r.compares):
                    return r.rung_id(rname)
        return None

    def _setpoint_safety(self, tag: str) -> bool:
        for rungs in self.baseline_prog.routines.values():
            for r in rungs:
                if any(tag in i.args for i in r.compares):
                    return r.safety_critical
        return False
