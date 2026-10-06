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
        # State-based dedup (Prompt 1.3): emit on appearance + a drift_cleared on
        # disappearance, so a restored-then-re-applied attack alerts again.
        self._active: dict = {}
        self._pass: dict = {}

    def relock(self) -> None:
        self.baseline = self.register_source()
        self._active = {}
        self._pass = {}

    def reset(self) -> None:
        self._active = {}
        self._pass = {}

    def _emit(self, etype: str, details: dict, channel: str) -> None:
        anchor = details.get("tag") or details.get("coil") or ""
        key = (etype, anchor, str(details.get("current")))
        details = {**details, "site": SITE_ID}
        self._pass[key] = (etype, details, channel)

    def _finish_pass(self) -> list[dict]:
        emitted: list[dict] = []
        for key, (etype, details, channel) in self._pass.items():
            if key in self._active:
                continue
            who = "unknown"
            if self.who_source:
                tag = details.get("tag") or details.get("coil")
                if tag:
                    who = self.who_source(tag) or "unknown"
            ev = self.bus.emit_new(etype, self.source, details,
                                   identity={"who": who, "channel": channel})
            if ev:
                emitted.append(ev)
        for key, (etype, details, channel) in self._active.items():
            if key in self._pass:
                continue
            anchor = details.get("tag") or details.get("coil") or ""
            ev = self.bus.emit_new("cyber.drift_cleared", self.source, {
                "site": SITE_ID, "cleared_type": etype,
                "tag": details.get("tag"), "coil": details.get("coil"),
                "safety_critical": False,
                "reason": f"Drift cleared: {etype} on {anchor or 'baselined item'} returned to baseline",
            }, identity={"who": "system", "channel": channel})
            if ev:
                emitted.append(ev)
        self._active = dict(self._pass)
        return emitted

    def run_once(self) -> list[dict]:
        self._pass = {}
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

        return self._finish_pass()
