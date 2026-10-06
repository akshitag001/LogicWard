"""Resource plane — CPU/RAM spike detection (psutil), the DDoS-impact signal.

Sustained CPU or memory above threshold emits `resource.cpu_spike` /
`resource.mem_spike` (re-armed once it drops back), demonstrating the
operational impact of a Modbus flood against the PLC. psutil is imported
defensively; `set_sim()` supplies values where it is unavailable.
"""
from __future__ import annotations

from typing import Callable

from logicward.engine.events import new_event

try:
    import psutil
except Exception:  # noqa: BLE001
    psutil = None

EmitFn = Callable[[dict], None]


class ResourceMonitor:
    def __init__(self, emit: EmitFn, cpu_threshold: int = 85, mem_threshold: int = 90,
                 source: str = "resource"):
        self.emit = emit
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.source = source
        self._cpu_firing = False
        self._mem_firing = False
        self._sim: dict | None = None
        if psutil:                              # prime the non-blocking cpu_percent
            try:
                psutil.cpu_percent(interval=None)
            except Exception:  # noqa: BLE001
                pass

    def set_sim(self, cpu: float | None = None, mem: float | None = None,
                temp: float | None = None) -> None:
        self._sim = {"cpu": cpu, "mem": mem, "temp": temp}

    def _sample(self) -> tuple[float | None, float | None]:
        if self._sim is not None:
            return self._sim.get("cpu"), self._sim.get("mem")
        if not psutil:
            return None, None
        try:
            return psutil.cpu_percent(interval=None), psutil.virtual_memory().percent
        except Exception:  # noqa: BLE001
            return None, None

    def _read_temp(self) -> float | None:
        """SoC / CPU temperature in °C — the DDoS also heats the Pi. Pi-first, then psutil."""
        if self._sim is not None:
            return self._sim.get("temp")
        try:  # Raspberry Pi (and most Linux SBCs)
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                return round(int(f.read().strip()) / 1000.0, 1)
        except Exception:  # noqa: BLE001
            pass
        if psutil and hasattr(psutil, "sensors_temperatures"):
            try:
                for entries in (psutil.sensors_temperatures() or {}).values():
                    if entries:
                        return round(entries[0].current, 1)
            except Exception:  # noqa: BLE001
                pass
        return None

    def sample(self) -> dict:
        """Current host telemetry for the live panel — CPU %, RAM %, temp °C (no event)."""
        cpu, mem = self._sample()
        return {"cpu": None if cpu is None else round(cpu, 1),
                "mem": None if mem is None else round(mem, 1),
                "temp": self._read_temp()}

    def scan(self) -> list[dict]:
        cpu, mem = self._sample()
        out: list[dict] = []
        if cpu is not None:
            if cpu >= self.cpu_threshold and not self._cpu_firing:
                self._cpu_firing = True
                out.append(self._fire("resource.cpu_spike", "cpu_percent", cpu,
                                      f"CPU at {cpu:.0f}% (>= {self.cpu_threshold}%) — possible DoS load"))
            elif cpu < self.cpu_threshold:
                self._cpu_firing = False
        if mem is not None:
            if mem >= self.mem_threshold and not self._mem_firing:
                self._mem_firing = True
                out.append(self._fire("resource.mem_spike", "mem_percent", mem,
                                      f"Memory at {mem:.0f}% (>= {self.mem_threshold}%)"))
            elif mem < self.mem_threshold:
                self._mem_firing = False
        return out

    def _fire(self, etype: str, field: str, value: float, reason: str) -> dict:
        ev = new_event(etype, self.source, {field: round(value, 1), "reason": reason},
                       identity={"who": "unknown", "channel": "host"})
        self.emit(ev)
        return ev
