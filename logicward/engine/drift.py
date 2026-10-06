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
from collections.abc import Callable
from difflib import SequenceMatcher

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


def _freeze(x):
    """Make a nested list hashable (for rung signatures)."""
    return tuple(_freeze(i) for i in x) if isinstance(x, list) else x


def r2r_sig(r: l5x.Rung) -> tuple:
    """A hashable content signature of a rung — output coil + full logic structure.
    Two rungs are 'equal' for alignment iff this matches (so a branch regroup or an
    inverted contact makes them UNequal and they land in a replace block)."""
    return (r.output_coil, r.output_op, _freeze(r.logic_tree),
            tuple((i.op, tuple(i.args)) for i in r.instructions))


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
        # State-based dedup (Prompt 1.3): the set of drift keys active *right now*.
        # We emit when a key APPEARS and a cyber.drift_cleared when it DISAPPEARS,
        # so an attack that is restored and then re-applied alerts again.
        self._active: dict = {}
        self._pass: dict = {}
        self.baseline_valid = baseline_mod.verify(signed_baseline)

    # -- public --
    def run_once(self) -> list[dict]:
        """One detection pass. Emits on drift appearance + disappearance."""
        self._pass = {}
        self._structural()
        if self.register_source is not None:
            self._registers()
        return self._finish_pass()

    def reset(self) -> None:
        """Clear drift state (e.g. after a re-baseline) — next pass re-evaluates."""
        self._active = {}
        self._pass = {}

    # -- state-based emit: record this pass's drifts, diff against the last pass --
    def _emit(self, etype: str, details: dict, channel: str) -> None:
        anchor = details.get("rung_id") or details.get("tag") or details.get("coil") or ""
        key = (etype, anchor, str(details.get("current")))
        if "command" not in details:
            cmd = self._command(details, channel)
            if cmd:
                details = {**details, "command": cmd}
        self._pass[key] = (etype, details, channel)

    def _finish_pass(self) -> list[dict]:
        emitted: list[dict] = []
        # newly-appeared drifts -> alert
        for key, (etype, details, channel) in self._pass.items():
            if key in self._active:
                continue
            who = "unknown"
            if self.who_source:
                tag = details.get("tag") or details.get("coil")
                who = self.who_source(tag, channel) or "unknown"
            ev = self.bus.emit_new(etype, self.source, details,
                                   identity={"who": who, "channel": channel})
            if ev:
                emitted.append(ev)
        # drifts that disappeared since last pass -> informational "cleared"
        for key, (etype, details, channel) in self._active.items():
            if key in self._pass:
                continue
            anchor = details.get("rung_id") or details.get("tag") or details.get("coil") or ""
            ev = self.bus.emit_new("cyber.drift_cleared", self.source, {
                "cleared_type": etype, "rung_id": details.get("rung_id"),
                "tag": details.get("tag"), "coil": details.get("coil"),
                "safety_critical": False,
                "reason": f"Drift cleared: {etype} on {anchor or 'baselined item'} returned to baseline",
            }, identity={"who": "system", "channel": channel})
            if ev:
                emitted.append(ev)
        self._active = dict(self._pass)
        return emitted

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

        # rung-level structural diff — align by CONTENT, not by Number (Prompt 1.4),
        # so inserting one rung at the top doesn't renumber (and false-alarm) the rest.
        for rname in sorted(set(self.baseline_prog.routines) | set(live.routines)):
            b_list = self.baseline_prog.routines.get(rname, [])
            l_list = live.routines.get(rname, [])
            out += self._align_and_diff(rname, b_list, l_list)

        out += self._diff_non_rung(live)   # tags, non-ladder routines, tasks (Prompt 1.2)
        return out

    def _diff_non_rung(self, live: l5x.L5XProgram) -> list:
        """Detect changes the rung diff doesn't cover: non-setpoint tag values,
        non-ladder (ST/FBD/SFC) routines, and task scheduling."""
        out: list = []
        base = self.baseline_prog

        # non-setpoint scalar tag values (timer presets, constants, flags)
        for tag in sorted(set(base.tag_values) | set(live.tag_values)):
            if tag.split("/")[-1].endswith("_SP"):
                continue                               # handled by setpoint_drift
            b, c = base.tag_values.get(tag), live.tag_values.get(tag)
            if b != c:
                self._emit("cyber.tag_value_change", {
                    "tag": tag, "baseline": b, "current": c,
                    "reason": f"Tag/constant {tag} changed {b} -> {c} in the program",
                }, "program-download")

        # non-ladder routines
        for key in sorted(set(base.non_rll_routines) | set(live.non_rll_routines)):
            b, c = base.non_rll_routines.get(key), live.non_rll_routines.get(key)
            if b is None:
                self._emit("cyber.routine_added", {
                    "rung_id": key, "routine_type": (c or {}).get("type"), "safety_critical": True,
                    "reason": f"Non-ladder routine added: {key} ({(c or {}).get('type')})",
                }, "program-download")
            elif c is None:
                self._emit("cyber.routine_removed", {
                    "rung_id": key, "routine_type": (b or {}).get("type"), "safety_critical": True,
                    "reason": f"Routine removed: {key}",
                }, "program-download")
            elif b.get("sig") != c.get("sig"):
                self._emit("cyber.routine_modified", {
                    "rung_id": key, "routine_type": c.get("type"), "safety_critical": True,
                    "reason": f"Non-ladder routine body changed: {key} ({c.get('type')})",
                }, "program-download")

        # tasks (scan scheduling) — a rate change or moving a routine out of the scan
        for name in sorted(set(base.tasks) | set(live.tasks)):
            b, c = base.tasks.get(name), live.tasks.get(name)
            if b != c:
                self._emit("cyber.task_change", {
                    "tag": name, "baseline": b, "current": c, "safety_critical": True,
                    "reason": f"Task '{name}' scheduling changed: {b} -> {c}",
                }, "program-download")
        return out

    def _align_and_diff(self, rname: str, b_list: list, l_list: list) -> list:
        """Content-align baseline vs live rungs, then diff matched pairs."""
        out: list = []
        b_sig = [r2r_sig(r) for r in b_list]
        l_sig = [r2r_sig(r) for r in l_list]
        sm = SequenceMatcher(a=b_sig, b=l_sig, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue                                   # identical rungs — nothing drifted
            if tag == "delete":
                out += [self._removed_rung(rname, r) for r in b_list[i1:i2]]
            elif tag == "insert":
                out += [self._injected_rung(rname, r) for r in l_list[j1:j2]]
            elif tag == "replace":
                out += self._diff_replace_block(rname, b_list[i1:i2], l_list[j1:j2])
        return out

    def _diff_replace_block(self, rname: str, b_block: list, l_block: list) -> list:
        """Pair rungs in a replace block by output coil first, then similarity;
        leftovers are whole-rung injects/removals."""
        out: list = []
        b_rem = list(b_block)
        for live in l_block:
            # 1) prefer a baseline rung with the SAME output coil
            match = next((b for b in b_rem if b.output_coil == live.output_coil), None)
            # 2) else the most similar remaining baseline rung (by neutral text)
            if match is None and b_rem:
                match = max(b_rem, key=lambda b: SequenceMatcher(
                    a=b.text, b=live.text, autojunk=False).ratio())
                if SequenceMatcher(a=match.text, b=live.text, autojunk=False).ratio() < 0.4:
                    match = None
            if match is not None:
                b_rem.remove(match)
                out += self._diff_rung(rname, match, live)
            else:
                out.append(self._injected_rung(rname, live))
        for b in b_rem:                                    # unmatched baseline rungs = removed
            out.append(self._removed_rung(rname, b))
        return out

    def _injected_rung(self, rname: str, r: l5x.Rung):
        return self._emit("cyber.rung_injection", {
            "rung_id": r.rung_id(rname), "text": r.text,
            "output_coil": r.output_coil, "safety_critical": r.safety_critical,
            "reason": f"Unauthorized rung injected: {r.text}",
        }, "program-download")

    def _removed_rung(self, rname: str, r: l5x.Rung):
        return self._emit("cyber.condition_stripping", {
            "rung_id": r.rung_id(rname), "removed": r.text,
            "output_coil": r.output_coil, "safety_critical": r.safety_critical,
            "reason": f"Entire protection rung removed: {r.text}",
        }, "program-download")

    def _diff_rung(self, rname: str, b: l5x.Rung, live: l5x.Rung) -> list[dict | None]:
        out: list[dict | None] = []
        rid = live.rung_id(rname)                           # alerts point at the LIVE rung number

        if b.output_coil != live.output_coil:
            out.append(self._emit("cyber.coil_hijack", {
                "rung_id": rid, "baseline": b.output_coil, "current": live.output_coil,
                "safety_critical": b.safety_critical or live.safety_critical,
                "reason": f"Output coil repointed {b.output_coil} -> {live.output_coil}",
            }, "program-download"))

        b_in = [(i.op, tuple(i.args)) for i in b.instructions if i.op in _INPUT_OPS]
        l_in = [(i.op, tuple(i.args)) for i in live.instructions if i.op in _INPUT_OPS]

        # Pure branch restructure (Prompt 1.1): same instruction set, same output,
        # but the AND/OR grouping changed — e.g. A·B -> A+B weakens a safety trip.
        if (Counter(b_in) == Counter(l_in) and b.output_coil == live.output_coil
                and b.logic_tree != live.logic_tree):
            self._emit("cyber.branch_restructure", {
                "rung_id": rid, "baseline": b.text, "current": live.text,
                "safety_critical": b.safety_critical or live.safety_critical,
                "reason": f"Rung branch structure changed (AND/OR regrouping) on {rid}: "
                          f"{b.text} -> {live.text}",
            }, "program-download")

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
