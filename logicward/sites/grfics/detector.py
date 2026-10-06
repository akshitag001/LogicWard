"""Register-drift detector for the GRFICS chemical site.

The chemical plant has no L5X program, so this is the register plane of
LogicWard's detection applied to a second process: capture a baseline of the
writable holding registers + coils, then diff the live Modbus reality against it
every pass and emit the SAME event types the thermal drift engine does
(`cyber.setpoint_drift`, `cyber.register_change`) onto the SAME bus — so they get
LogicWard severity, MITRE-for-ICS mapping, and the evidence log for free.

Input registers (live sensors) are intentionally NOT diffed — they carry process
noise; only operator-writable holding registers and control coils are baselined.
"""
from __future__ import annotations

from logicward.sites.grfics import SITE_ID
from logicward.sites.grfics import points as pts


class ChemicalDriftDetector:
    def __init__(self, bus, register_source, who_source=None, source: str = "grfics_drift"):
        self.bus = bus
        self.register_source = register_source
        self.who_source = who_source               # tag -> attacker source IP (or None)
        self.source = source
        self.baseline = register_source()          # {holding:{tag:raw}, coils:{tag:bool}}
        self._seen: set = set()

    def relock(self) -> None:
        self.baseline = self.register_source()
        self._seen.clear()

    def reset(self) -> None:
        self._seen.clear()

    def _emit(self, etype: str, details: dict, channel: str):
        anchor = details.get("tag") or details.get("coil") or ""
        key = (etype, anchor, str(details.get("current")))
        if key in self._seen:
            return None
        self._seen.add(key)
        details = {**details, "site": SITE_ID}
        who = "unknown"
        if self.who_source:
            tag = details.get("tag") or details.get("coil")
            if tag:
                who = self.who_source(tag) or "unknown"
        return self.bus.emit_new(etype, self.source, details,
                                 identity={"who": who, "channel": channel})

    def run_once(self) -> list[dict]:
        snap = self.register_source() or {}
        base_hold = self.baseline.get("holding", {})
        base_coils = self.baseline.get("coils", {})
        out = []

        for tag, cur in snap.get("holding", {}).items():
            b = base_hold.get(tag)
            if b is None or cur == b:
                continue
            p = pts.BY_TAG[tag]
            command = f"FC06 write_holding @{p.address}={cur}  ({tag} -> {pts.eng(cur, tag):g} {p.unit})"
            if tag in pts.SAFETY_SETPOINTS:
                out.append(self._emit("cyber.setpoint_drift", {
                    "tag": tag, "baseline": pts.eng(b, tag), "current": pts.eng(cur, tag),
                    "unit": p.unit, "register": True, "safety_critical": True,
                    "command": command,
                    "reason": (f"Safety setpoint {tag} changed "
                               f"{pts.eng(b, tag)} -> {pts.eng(cur, tag)} {p.unit} "
                               f"over Modbus — protection weakened"),
                }, "modbus-write"))
            else:
                out.append(self._emit("cyber.register_change", {
                    "tag": tag, "baseline": pts.eng(b, tag), "current": pts.eng(cur, tag),
                    "unit": p.unit,
                    "command": command,
                    "reason": (f"Valve command {tag} changed "
                               f"{pts.eng(b, tag)} -> {pts.eng(cur, tag)} {p.unit} "
                               f"over Modbus"),
                }, "modbus-write"))

        for tag, cur in snap.get("coils", {}).items():
            if tag in pts.PLANT_DRIVEN_COILS:
                continue
            b = base_coils.get(tag)
            if b is None or bool(cur) == bool(b):
                continue
            cp = pts.BY_TAG[tag]
            out.append(self._emit("cyber.register_change", {
                "coil": tag, "baseline": bool(b), "current": bool(cur),
                "safety_critical": tag == "Reactor_ESD",
                "command": f"FC05 write_coil @{cp.address}={'FF00' if cur else '0000'}  ({tag} -> {'ON' if cur else 'OFF'})",
                "reason": f"Control coil {tag} forced {bool(b)} -> {bool(cur)} over Modbus",
            }, "modbus-write"))

        return [e for e in out if e]
