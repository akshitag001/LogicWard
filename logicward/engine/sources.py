"""Program + register sources for the drift engine and dashboard.

The engine is transport-agnostic (it just needs `program_source()` -> L5X bytes
and `register_source()` -> {holding, coils}). Two implementations:

  * EmbeddedPlant — starts an in-process thermal PLC. One-machine dev/demo: no Pi
    required, everything runs on the laptop.
  * RemotePlant — reads the real Pi over Modbus (registers/coils) + HTTP (program).

Both also expose `named_snapshot()` (engineering values) for the live plant view.
"""
from __future__ import annotations

import requests

from logicward import config
from logicward.engine.modbus_client import ModbusClient
from logicward.plant import rung_to_register as r2r
from logicward.plant.logic_store import LIVE_PATH, ensure_live
from logicward.plant.modbus_server import ModbusTCPServer, ThermalDataStore


def _named_snapshot(ir: list[int], hr: list[int], coils: list[bool], di: list[bool]) -> dict:
    def block(points, raws):
        out = {}
        for p in points:
            raw = raws[p.address] if p.address < len(raws) else 0
            out[p.tag] = {"raw": raw, "eng": r2r.eng(raw, p.tag), "unit": p.unit}
        return out
    return {
        "input_registers": block(r2r.INPUT_REGISTERS, ir),
        "holding_registers": block(r2r.HOLDING_REGISTERS, hr),
        "coils": {p.tag: (coils[p.address] if p.address < len(coils) else False) for p in r2r.COILS},
        "discrete_inputs": {p.tag: (di[p.address] if p.address < len(di) else False) for p in r2r.DISCRETE_INPUTS},
    }


class EmbeddedPlant:
    """In-process thermal PLC for a single-machine run."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.ds = ThermalDataStore()
        self.server = ModbusTCPServer(host=host, port=port, datastore=self.ds)
        self.live_path = ensure_live(LIVE_PATH)

    def start(self) -> "EmbeddedPlant":
        self.server.start(background=True)
        return self

    def stop(self) -> None:
        self.server.stop()

    @property
    def port(self) -> int:
        return self.server.port

    def program_source(self) -> bytes:
        return self.live_path.read_bytes()

    def register_source(self) -> dict:
        return {"holding": {p.tag: self.ds.hr(p.tag) for p in r2r.HOLDING_REGISTERS},
                "coils": {p.tag: self.ds.coil(p.tag) for p in r2r.COILS}}

    def writer_for(self, tag: str) -> str | None:
        """Source IP of the last Modbus write to `tag` (attacker attribution)."""
        return self.ds.writer_for(tag)

    def program_writer(self) -> str | None:
        return None  # embedded program writes go direct to live.L5X (no network identity)

    def named_snapshot(self) -> dict:
        return self.ds.named_snapshot()


class RemotePlant:
    """Read the real Pi: Modbus for registers/coils, HTTP for the program."""

    def __init__(self, host: str, modbus_port: int, program_url: str,
                 writes_url: str | None = None):
        self.client = ModbusClient(host, modbus_port)
        self.program_url = program_url
        # the Pi's write-attribution endpoint (who wrote which register/coil)
        self.writes_url = writes_url or f"http://{host}:{config.WRITES_PORT}/writes"

    def program_source(self) -> bytes:
        return requests.get(self.program_url, timeout=3).json()["l5x"].encode("utf-8")

    def register_source(self) -> dict:
        hold = self.client.read_holding_registers(0, len(r2r.HOLDING_REGISTERS))
        coils = self.client.read_coils(0, len(r2r.COILS))
        return {"holding": {p.tag: hold[p.address] for p in r2r.HOLDING_REGISTERS} if hold else {},
                "coils": {p.tag: coils[p.address] for p in r2r.COILS} if coils else {}}

    def writer_for(self, tag: str) -> str | None:
        """Query the Pi's write-attribution map for who last wrote `tag`."""
        p = r2r.BY_TAG.get(tag)
        if not p:
            return None
        try:
            writes = requests.get(self.writes_url, timeout=1).json().get("writes", {})
        except Exception:  # noqa: BLE001
            return None
        entry = writes.get(f"{p.area}:{p.address}")
        return entry.get("ip") if entry else None

    def program_writer(self) -> str | None:
        try:
            return requests.get(self.program_url + "/downloader", timeout=1).json().get("ip")
        except Exception:  # noqa: BLE001
            return None

    def named_snapshot(self) -> dict:
        return _named_snapshot(
            self.client.read_input_registers(0, len(r2r.INPUT_REGISTERS)),
            self.client.read_holding_registers(0, len(r2r.HOLDING_REGISTERS)),
            self.client.read_coils(0, len(r2r.COILS)),
            self.client.read_discrete_inputs(0, len(r2r.DISCRETE_INPUTS)),
        )
