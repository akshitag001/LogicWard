"""Ethernet link sensor — detects a cable pull via /sys/class/net/<iface>/carrier.

carrier == "1" means link up. A transition to down is a `physical.link_down`
(network isolation of the PLC); recovery is `physical.link_up`. Off-Pi (no sysfs
carrier file) it degrades to a simulation toggle via `set_sim()`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from logicward.engine.events import new_event

EmitFn = Callable[[dict], None]


class LinkWatch:
    def __init__(self, emit: EmitFn, iface: str = "eth0", source: str = "link_watch"):
        self.emit = emit
        self.iface = iface
        self.source = source
        self._path = Path(f"/sys/class/net/{iface}/carrier")
        self._sim: bool | None = None
        self._last: bool | None = None

    def set_sim(self, up: bool) -> None:
        """Force a simulated carrier state (dev/demo without the sysfs file)."""
        self._sim = up

    def _carrier_up(self) -> bool | None:
        if self._sim is not None:
            return self._sim
        try:
            return self._path.read_text().strip() == "1"
        except Exception:  # noqa: BLE001
            return None

    def scan(self) -> dict | None:
        up = self._carrier_up()
        if up is None:
            return None
        if self._last is None:
            self._last = up
            return None
        if up == self._last:
            return None
        self._last = up
        if up:
            ev = new_event("physical.link_up", self.source,
                           {"iface": self.iface, "reason": f"{self.iface} link restored"})
        else:
            ev = new_event("physical.link_down", self.source,
                           {"iface": self.iface, "reason": f"{self.iface} cable pulled / link down"},
                           identity={"who": "unknown", "channel": "physical"})
        self.emit(ev)
        return ev
