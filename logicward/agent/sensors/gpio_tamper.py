"""Enclosure-tamper sensor — a cabinet-door switch on a GPIO pin (gpiozero).

With hardware, a `gpiozero.Button` on the tamper switch reports the door state.
Without it (any dev laptop), the sensor degrades to a software simulation via
`trigger_sim()` — the emitted `physical.enclosure_open` event is identical, so
the whole pipeline runs with no hardware.
"""
from __future__ import annotations

from typing import Callable

from logicward.engine.events import new_event

EmitFn = Callable[[dict], None]


class GpioTamper:
    def __init__(self, emit: EmitFn, pin: int = 17, source: str = "gpio_tamper"):
        self.emit = emit
        self.pin = pin
        self.source = source
        self._button = None
        self._sim_open = False
        self._last = False
        try:
            from gpiozero import Button
            self._button = Button(pin, pull_up=True)
        except Exception:  # noqa: BLE001 - no GPIO here; simulation only
            self._button = None

    @property
    def hardware(self) -> bool:
        return self._button is not None

    def trigger_sim(self, is_open: bool = True) -> None:
        self._sim_open = is_open

    def _is_open(self) -> bool:
        if self._button is not None:
            return bool(self._button.is_pressed)
        return self._sim_open

    def scan(self) -> dict | None:
        opened = self._is_open()
        if opened == self._last:
            return None
        self._last = opened
        if not opened:
            return None
        ev = new_event("physical.enclosure_open", self.source, {
            "pin": self.pin, "safety_critical": True,
            "reason": "Enclosure/cabinet door opened (tamper switch)",
        }, identity={"who": "unknown", "channel": "physical"})
        self.emit(ev)
        return ev
