"""Simulated mitigation actions (DESIGN.md §6.4).

The appliance's response posture is detect + *simulate* mitigation: each action
is non-destructive, emits a `response.*` event onto the bus (so it lands in the
evidence log too), and never commands the real PLC. Actions are triggered from
the dashboard, gated by role.
"""
from __future__ import annotations

from typing import Callable


class ResponseEngine:
    def __init__(self, bus, restore_hook: Callable[[], bool] | None = None):
        self.bus = bus
        # optional real action for restore_baseline (e.g. re-download the approved
        # program to the logic store); if absent the action is purely simulated.
        self.restore_hook = restore_hook

    def _emit(self, etype: str, details: dict, actor: str) -> dict:
        return self.bus.emit_new(etype, "response_engine", details,
                                 identity={"who": actor, "channel": "operator"})

    def quarantine_device(self, mac: str, ip: str | None = None,
                          actor: str = "soc_analyst", ref: str | None = None) -> dict:
        return self._emit("response.quarantine_device", {
            "mac": mac, "ip": ip, "ref_event": ref,
            "action": "Isolate device from the OT segment (simulated)",
            "reason": f"Rogue device {mac} quarantined by {actor}",
        }, actor)

    def operator_ack(self, ref: str, actor: str = "operator", note: str | None = None) -> dict:
        return self._emit("response.operator_ack", {
            "ref_event": ref, "note": note,
            "reason": f"Alert {ref} acknowledged by {actor}",
        }, actor)

    def recommend_safe_state(self, rung_id: str | None, actor: str = "soc_analyst",
                             ref: str | None = None, recommendation: str | None = None) -> dict:
        return self._emit("response.recommend_safe_state", {
            "rung_id": rung_id, "ref_event": ref,
            "recommendation": recommendation or "Place affected loop in a verified safe state and "
                                                "revert the program to the approved baseline.",
            "reason": f"Safe-state recommended for {rung_id or 'affected loop'} "
                      f"(advisory — the PLC is not commanded)",
        }, actor)

    def restore_baseline(self, actor: str = "engineer", ref: str | None = None) -> dict:
        performed = False
        if self.restore_hook:
            try:
                performed = bool(self.restore_hook())
            except Exception:  # noqa: BLE001
                performed = False
        suffix = "" if performed else " (simulated — no restore hook wired)"
        return self._emit("response.restore_baseline", {
            "ref_event": ref, "performed": performed,
            "reason": f"Approved baseline program restored by {actor}{suffix}",
        }, actor)
