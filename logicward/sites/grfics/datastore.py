"""Chemical reactor datastore + reactive physics.

Presents the exact array interface LogicWard's `ModbusTCPHandler` expects
(`coils`, `discrete_inputs`, `input_registers`, `holding_registers`, `lock`,
`request_count`, `log_write`), so it drops straight into the existing raw-socket
`ModbusTCPServer` with zero changes to thermal code.

Single source of truth = the register arrays:
  * valve commands + ESD live in holding registers / coils (attacker-writable),
  * the physics reads those each tick and writes sensors to input registers,
  * the Unity feed and LogicWard detector both read the same arrays.

`simulate_process()` is a no-op so the server's built-in 1 s loop is harmless;
real physics runs from `tick(dt)` on a fast loop for smooth 3D animation.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from logicward.sites.grfics import points as pts

# Normal operating baseline (engineering units).
SEED_HOLDING = {
    "Feed1_Valve_Cmd": 40.0, "Feed2_Valve_Cmd": 40.0,
    "Purge_Valve_Cmd": 30.0, "Product_Valve_Cmd": 55.0,
    "Pressure_HH_SP": 3000.0, "Level_HH_SP": 90.0,
}
SEED_COILS = {
    "Reactor_ESD": 0, "Feed_Pump_1": 1, "Feed_Pump_2": 1,
    "Agitator_Running": 1, "Pressure_Trip": 0, "Level_Trip": 0,
}
SEED_DISCRETE = {"Pressure_Sensor_OK": 1, "Level_Sensor_OK": 1}


class ChemicalDataStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.coils = [False] * len(pts.COILS)
        self.discrete_inputs = [False] * len(pts.DISCRETE_INPUTS)
        self.input_registers = [0] * len(pts.INPUT_REGISTERS)
        self.holding_registers = [0] * len(pts.HOLDING_REGISTERS)
        self.generation = 1
        for tag, v in SEED_HOLDING.items():
            self.holding_registers[pts.BY_TAG[tag].address] = pts.raw(v, tag)
        for tag, v in SEED_COILS.items():
            self.coils[pts.BY_TAG[tag].address] = bool(v)
        for tag, v in SEED_DISCRETE.items():
            self.discrete_inputs[pts.BY_TAG[tag].address] = bool(v)

        # internal physical state (floats) — seeded at the stable equilibrium
        self.level = 40.0
        self.pressure = 1800.0
        self.A, self.B, self.C = 40.0, 30.0, 30.0
        self._flows = {"Feed1_Flow": 0.0, "Feed2_Flow": 0.0,
                       "Purge_Flow": 0.0, "Product_Flow": 0.0}
        self._push_sensors()

        self.write_log: list[dict] = []
        self.last_write_by_addr: dict[tuple[str, int], tuple[str | None, str]] = {}
        self.request_count = 0
        self._running = False

    def reset(self) -> None:
        """Instantly restores the physics simulation to its baseline equilibrium."""
        with self.lock:
            self.generation += 1
            for tag, v in SEED_HOLDING.items():
                self.holding_registers[pts.BY_TAG[tag].address] = pts.raw(v, tag)
            for tag, v in SEED_COILS.items():
                self.coils[pts.BY_TAG[tag].address] = bool(v)
            for tag, v in SEED_DISCRETE.items():
                self.discrete_inputs[pts.BY_TAG[tag].address] = bool(v)
            self.level = 40.0
            self.pressure = 1800.0
            self.A, self.B, self.C = 40.0, 30.0, 30.0
            self._flows = {"Feed1_Flow": 0.0, "Feed2_Flow": 0.0,
                           "Purge_Flow": 0.0, "Product_Flow": 0.0}
            self._push_sensors()

    # -- tag accessors (raw) --
    def _hr(self, tag: str) -> int:
        return self.holding_registers[pts.BY_TAG[tag].address]

    def _set_ir(self, tag: str, raw: int) -> None:
        self.input_registers[pts.BY_TAG[tag].address] = max(0, min(65535, int(raw)))

    def _coil(self, tag: str) -> bool:
        return self.coils[pts.BY_TAG[tag].address]

    def _set_coil(self, tag: str, val: bool) -> None:
        self.coils[pts.BY_TAG[tag].address] = bool(val)

    def _cmd(self, tag: str) -> float:
        """A valve command in engineering % from its holding register."""
        return pts.eng(self._hr(tag), tag)

    # -- Modbus server hooks --
    def simulate_process(self) -> None:
        """No-op: the reused ModbusTCPServer calls this at 1 Hz; real physics
        runs from tick() on the fast loop instead (avoids double-stepping)."""

    def log_write(self, fc: int, addr: int, value, unit_id: int, client_ip: str | None = None) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.write_log.append({"time": ts, "fc": f"0x{fc:02X}", "address": addr,
                               "value": value, "unit_id": unit_id, "client_ip": client_ip})
        if len(self.write_log) > 500:
            self.write_log.pop(0)
        # attribute WHO wrote which register/coil (FC05 -> coil, FC06/10 -> holding)
        self.last_write_by_addr[("C" if fc == 0x05 else "HR", addr)] = (client_ip, ts)

    def writer_for(self, tag: str) -> str | None:
        """Source IP of the last Modbus write to `tag`'s register/coil (or None)."""
        p = pts.BY_TAG.get(tag)
        if not p:
            return None
        ip, _ts = self.last_write_by_addr.get((p.area, p.address), (None, None))
        return ip

    # -- physics --
    def tick(self, dt: float) -> None:
        with self.lock:
            esd = self._coil("Reactor_ESD")
            # A feed valve only delivers flow when its pump is running (and no ESD),
            # so a pump-trip attack visibly STARVES the reactor — the level drains —
            # a signature distinct from every valve/overfill attack.
            p1 = self._coil("Feed_Pump_1")
            p2 = self._coil("Feed_Pump_2")
            f1 = 0.0 if (esd or not p1) else self._cmd("Feed1_Valve_Cmd")
            f2 = 0.0 if (esd or not p2) else self._cmd("Feed2_Valve_Cmd")
            purge = self._cmd("Purge_Valve_Cmd")
            product = self._cmd("Product_Valve_Cmd")

            # Flow coefficients chosen so the seed valve positions are a STABLE
            # equilibrium (level ~40 %, pressure ~1800 kPa): both derivatives are
            # ~0 at rest and self-correcting, so the plant sits calm until an
            # attack moves a valve. See datastore module notes.
            f1_flow = f1 * 0.6
            f2_flow = f2 * 0.5
            inflow = f1_flow + f2_flow
            purge_flow = purge * (0.6 + self.pressure / 3200.0)
            product_flow = product * (0.4 + self.level / 100.0)

            self.level += (inflow - product_flow) * dt * 0.75
            self.level = max(0.0, min(125.0, self.level))

            dp = inflow * 1.0 - purge_flow * 1.26
            if esd:
                dp = -purge_flow * 1.5 - 120.0
            self.pressure += dp * dt * 1.5
            self.pressure = max(0.0, min(4200.0, self.pressure))

            # Composition tracks the feed ratio and moves FAST + HARD, so a
            # feed-ratio (quality-sabotage) attack visibly recolours the reactor
            # liquid — the Unity scene tints the fluid from the A/B/C_in_purge keys.
            tgtA = max(5.0, min(95.0, 15.0 + f1 * 0.8))
            self.A += (tgtA - self.A) * dt * 0.8
            self.B += ((100.0 - self.A) * 0.4 - self.B) * dt * 0.8
            self.C = max(0.0, 100.0 - self.A - self.B)

            self._flows = {"Feed1_Flow": f1_flow, "Feed2_Flow": f2_flow,
                           "Purge_Flow": purge_flow, "Product_Flow": product_flow}

            # plant's own protection: trip if a sensor exceeds its safety setpoint.
            # An attacker who first raises the setpoint defeats this — the danger
            # then shows on the 3D scene (redline) without an automatic trip.
            press_hh = self._cmd("Pressure_HH_SP")
            level_hh = self._cmd("Level_HH_SP")
            self._set_coil("Pressure_Trip", self.pressure >= press_hh)
            self._set_coil("Level_Trip", self.level >= level_hh)
            if self._coil("Pressure_Trip") or self._coil("Level_Trip"):
                self._set_coil("Reactor_ESD", True)   # auto-ESD on genuine excursion

            self._push_sensors()

    def _push_sensors(self) -> None:
        self._set_ir("Reactor_Pressure", pts.raw(self.pressure, "Reactor_Pressure"))
        self._set_ir("Liquid_Level", pts.raw(self.level, "Liquid_Level"))
        self._set_ir("A_Composition", pts.raw(self.A, "A_Composition"))
        self._set_ir("B_Composition", pts.raw(self.B, "B_Composition"))
        self._set_ir("C_Composition", pts.raw(self.C, "C_Composition"))
        for tag, val in self._flows.items():
            self._set_ir(tag, pts.raw(val, tag))

    # -- background physics loop --
    def start(self, hz: float = 10.0) -> "ChemicalDataStore":
        if self._running:
            return self
        self._running = True

        def _loop():
            last = time.time()
            while self._running:
                now = time.time()
                self.tick(now - last)
                last = now
                time.sleep(1.0 / hz)

        threading.Thread(target=_loop, name="grfics-physics", daemon=True).start()
        return self

    def stop(self) -> None:
        self._running = False

    # -- views --
    def named_snapshot(self) -> dict:
        with self.lock:
            def block(points):
                out = {}
                for p in points:
                    raw = (self.input_registers[p.address] if p.area == "IR"
                           else self.holding_registers[p.address])
                    out[p.tag] = {"raw": raw, "eng": pts.eng(raw, p.tag), "unit": p.unit}
                return out
            return {
                "input_registers": block(pts.INPUT_REGISTERS),
                "holding_registers": block(pts.HOLDING_REGISTERS),
                "coils": {p.tag: self.coils[p.address] for p in pts.COILS},
                "discrete_inputs": {p.tag: self.discrete_inputs[p.address]
                                    for p in pts.DISCRETE_INPUTS},
            }

    def register_source(self) -> dict:
        """Holding + coils snapshot (by tag) for the drift detector."""
        with self.lock:
            return {
                "holding": {p.tag: self.holding_registers[p.address]
                            for p in pts.HOLDING_REGISTERS},
                "coils": {p.tag: self.coils[p.address] for p in pts.COILS},
            }

    def feed_json(self) -> dict:
        """The exact schema the GRFICS Unity build reads from /data/index.php."""
        with self.lock:
            def e(tag):
                if pts.BY_TAG[tag].area == "IR":
                    return pts.eng(self.input_registers[pts.BY_TAG[tag].address], tag)
                return pts.eng(self.holding_registers[pts.BY_TAG[tag].address], tag)
            esd = self._coil("Reactor_ESD")
            return {
                "process": "simpleTE",
                "outputs": {
                    "f1_flow": round(e("Feed1_Flow"), 2),
                    "f2_flow": round(e("Feed2_Flow"), 2),
                    "purge_flow": round(e("Purge_Flow"), 2),
                    "product_flow": round(e("Product_Flow"), 2),
                    "pressure": round(e("Reactor_Pressure"), 2),
                    "liquid_level": min(99.9, round(e("Liquid_Level"), 2)),

                    "A_in_purge": round(e("A_Composition"), 2),
                    "B_in_purge": round(e("B_Composition"), 2),
                    "C_in_purge": round(e("C_Composition"), 2),
                    "cost": round(e("Reactor_Pressure") * 0.01 + e("Liquid_Level") * 0.05, 3),
                },
                "state": {
                    "f1_valve_pos": 0.0 if esd else round(e("Feed1_Valve_Cmd"), 2),
                    "f2_valve_pos": 0.0 if esd else round(e("Feed2_Valve_Cmd"), 2),
                    "purge_valve_pos": 100.0 if esd else round(e("Purge_Valve_Cmd"), 2),
                    "product_valve_pos": 0.0 if esd else round(e("Product_Valve_Cmd"), 2),
                    "e_stop": 1 if esd else 0,
                },
            }
