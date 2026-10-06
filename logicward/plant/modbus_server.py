"""Thermal power plant PLC — Modbus TCP server.

Re-themed from OT_SECURITY's raw-socket Modbus server: same unauthenticated
MBAP/PDU handling (FC 01-06, 0F, 10, 11) — realistic OT insecurity — over a
boiler / turbine / generator process model. Setpoints live in holding registers,
so an attacker lowering a trip setpoint over Modbus both (a) shows up as register
drift to the engine and (b) actually weakens the plant's protection in the live
view.

The process model simulates physics + the plant's *own* setpoint-driven trips.
It does NOT interpret the L5X rungs — that program is data the detection engine
diffs, never something executed here.

Run:  python -m logicward.plant.modbus_server   [port]
"""
from __future__ import annotations

import logging
import random
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone

from logicward import config
from logicward.plant import rung_to_register as r2r

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [PLANT] %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("plant")


# ── Datastore + process model ─────────────────────────────────────────────────

SEED_INPUT = {                        # engineering values -> seeded raw below
    "Generator_MW": 250, "Steam_Pressure": 165.0, "Main_Steam_Temp": 538,
    "Drum_Level": 350, "Turbine_Speed": 3000, "Condenser_Vacuum": 92,
    "Bearing_Vibration": 4.5,
}
SEED_HOLDING = {
    "Steam_Press_HH_SP": 175.0, "Drum_Level_LL_SP": 220, "Turbine_Overspeed_SP": 3300,
    "Condenser_Vac_LO_SP": 85, "Bearing_Vib_HI_SP": 11.2, "Load_Setpoint_MW": 250,
}
SEED_COILS = {
    "Plant_Running": 1, "Feedwater_Pump_1": 1, "Feedwater_Pump_2": 0,
    "Fuel_Valve_Open": 1, "Main_Steam_Valve_Open": 1, "Generator_Breaker_Closed": 1,
    "Vibration_Alarm": 0, "Feedwater_Trip": 0, "Main_Steam_Trip": 0,
    "Turbine_Trip": 0, "Fuel_Trip": 0, "Condenser_Trip": 0,
}
SEED_DISCRETE = {"Flame_Detected": 1, "Drum_Level_Sensor_OK": 1, "Vacuum_Sensor_OK": 1}


class ThermalDataStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.coils = [False] * len(r2r.COILS)
        self.discrete_inputs = [False] * len(r2r.DISCRETE_INPUTS)
        self.input_registers = [0] * len(r2r.INPUT_REGISTERS)
        self.holding_registers = [0] * len(r2r.HOLDING_REGISTERS)
        for tag, v in SEED_INPUT.items():
            self.input_registers[r2r.BY_TAG[tag].address] = r2r.raw(v, tag)
        for tag, v in SEED_HOLDING.items():
            self.holding_registers[r2r.BY_TAG[tag].address] = r2r.raw(v, tag)
        for tag, v in SEED_COILS.items():
            self.coils[r2r.BY_TAG[tag].address] = bool(v)
        for tag, v in SEED_DISCRETE.items():
            self.discrete_inputs[r2r.BY_TAG[tag].address] = bool(v)
        self.write_log: list[dict] = []
        self.last_write_by_addr: dict[tuple[str, int], tuple[str | None, str]] = {}
        self.request_count = 0

    # -- tag accessors --
    def ir(self, tag: str) -> int:
        return self.input_registers[r2r.BY_TAG[tag].address]

    def set_ir(self, tag: str, raw: int) -> None:
        self.input_registers[r2r.BY_TAG[tag].address] = max(0, min(65535, int(raw)))

    def hr(self, tag: str) -> int:
        return self.holding_registers[r2r.BY_TAG[tag].address]

    def coil(self, tag: str) -> bool:
        return self.coils[r2r.BY_TAG[tag].address]

    def set_coil(self, tag: str, val: bool) -> None:
        self.coils[r2r.BY_TAG[tag].address] = bool(val)

    def di(self, tag: str) -> bool:
        return self.discrete_inputs[r2r.BY_TAG[tag].address]

    # -- physics + protection --
    def simulate_process(self) -> None:
        with self.lock:
            running = self.coils[r2r.BY_TAG["Plant_Running"].address]

            if running:
                # generation tracks the load setpoint; process values wander with noise
                target_mw = self.hr("Load_Setpoint_MW")
                mw = self.ir("Generator_MW")
                self.set_ir("Generator_MW", mw + int((target_mw - mw) * 0.2) + random.randint(-2, 2))
                self.set_ir("Steam_Pressure", 1650 + random.randint(-25, 25))      # ~165.0 bar
                self.set_ir("Main_Steam_Temp", 538 + random.randint(-3, 3))
                self.set_ir("Drum_Level", 350 + random.randint(-8, 8))
                self.set_ir("Turbine_Speed", 3000 + random.randint(-8, 8))
                self.set_ir("Condenser_Vacuum", 92 + random.randint(-2, 2))
                self.set_ir("Bearing_Vibration", 45 + random.randint(-4, 4))       # ~4.5 mm/s
            else:
                for tag, decay in (("Generator_MW", 12), ("Steam_Pressure", 30),
                                   ("Turbine_Speed", 40), ("Drum_Level", 3)):
                    self.set_ir(tag, max(0, self.ir(tag) - random.randint(0, decay)))

            # plant's own setpoint-driven protection (same scale IR vs HR -> compare raw)
            self.set_coil("Feedwater_Trip", running and self.ir("Drum_Level") < self.hr("Drum_Level_LL_SP"))
            self.set_coil("Main_Steam_Trip", running and self.ir("Steam_Pressure") > self.hr("Steam_Press_HH_SP"))
            self.set_coil("Turbine_Trip", self.ir("Turbine_Speed") > self.hr("Turbine_Overspeed_SP"))
            self.set_coil("Fuel_Trip", running and not self.di("Flame_Detected"))
            self.set_coil("Condenser_Trip", running and self.ir("Condenser_Vacuum") < self.hr("Condenser_Vac_LO_SP"))
            self.set_coil("Vibration_Alarm", self.ir("Bearing_Vibration") > self.hr("Bearing_Vib_HI_SP"))

    def log_write(self, fc: int, addr: int, value, unit_id: int, client_ip: str | None = None) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.write_log.append({"time": ts, "fc": f"0x{fc:02X}", "address": addr,
                               "value": value, "unit_id": unit_id, "client_ip": client_ip})
        if len(self.write_log) > 500:
            self.write_log.pop(0)
        # attribute WHO wrote which register/coil (FC05 -> coil, FC06/10 -> holding)
        self.last_write_by_addr[("C" if fc == 0x05 else "HR", addr)] = (client_ip, ts)
        log.warning(f"[WRITE] FC={fc:02X} addr={addr} val={value} unit={unit_id} from={client_ip}")

    def writer_for(self, tag: str) -> str | None:
        """Source IP of the last Modbus write to `tag`'s register/coil (or None)."""
        p = r2r.BY_TAG.get(tag)
        if not p:
            return None
        ip, _ts = self.last_write_by_addr.get((p.area, p.address), (None, None))
        return ip

    def named_snapshot(self) -> dict:
        """Human/engine-friendly view of live state (used by the dashboard/tests)."""
        with self.lock:
            def block(points):
                return {p.tag: {"raw": self._raw_of(p), "eng": r2r.eng(self._raw_of(p), p.tag),
                                "unit": p.unit} for p in points}
            return {
                "input_registers": block(r2r.INPUT_REGISTERS),
                "holding_registers": block(r2r.HOLDING_REGISTERS),
                "coils": {p.tag: self.coils[p.address] for p in r2r.COILS},
                "discrete_inputs": {p.tag: self.discrete_inputs[p.address] for p in r2r.DISCRETE_INPUTS},
            }

    def _raw_of(self, p: r2r.Point) -> int:
        if p.area == "IR":
            return self.input_registers[p.address]
        if p.area == "HR":
            return self.holding_registers[p.address]
        return 0


# ── Modbus TCP protocol handler (adapted from OT_SECURITY) ────────────────────

class ModbusTCPHandler:
    EX_ILLEGAL_FUNCTION = 0x01
    EX_ILLEGAL_DATA_ADDRESS = 0x02
    EX_ILLEGAL_DATA_VALUE = 0x03

    def __init__(self, ds: ThermalDataStore):
        self.ds = ds

    def _exc(self, tid, unit, fc, code):
        pdu = struct.pack("BB", fc | 0x80, code)
        return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu

    def _resp(self, tid, unit, pdu):
        return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu

    def handle(self, data: bytes, client_ip: str | None = None) -> bytes | None:
        if len(data) < 8:
            return None
        tid, proto, _length, unit = struct.unpack(">HHHB", data[:7])
        if proto != 0:
            return None
        fc = data[7]
        payload = data[8:]
        self.ds.request_count += 1

        if fc in (0x01, 0x02):                      # read coils / discrete inputs
            if len(payload) < 4:
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count = struct.unpack(">HH", payload[:4])
            with self.ds.lock:
                bits = self.ds.coils if fc == 0x01 else self.ds.discrete_inputs
            if start + count > len(bits):
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            nbytes = (count + 7) // 8
            buf = bytearray(nbytes)
            for i in range(count):
                if bits[start + i]:
                    buf[i // 8] |= 1 << (i % 8)
            return self._resp(tid, unit, struct.pack("BB", fc, nbytes) + bytes(buf))

        if fc in (0x03, 0x04):                      # read holding / input registers
            if len(payload) < 4:
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count = struct.unpack(">HH", payload[:4])
            with self.ds.lock:
                regs = self.ds.holding_registers if fc == 0x03 else self.ds.input_registers
            if start + count > len(regs):
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            pdu = struct.pack("BB", fc, count * 2)
            for i in range(count):
                pdu += struct.pack(">H", regs[start + i] & 0xFFFF)
            return self._resp(tid, unit, pdu)

        if fc == 0x05:                              # write single coil (unauthenticated)
            addr, value = struct.unpack(">HH", payload[:4])
            if addr >= len(self.ds.coils):
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            with self.ds.lock:
                self.ds.coils[addr] = (value == 0xFF00)
            self.ds.log_write(fc, addr, value == 0xFF00, unit, client_ip)
            return self._resp(tid, unit, struct.pack("B", fc) + payload[:4])

        if fc == 0x06:                              # write single holding register
            addr, value = struct.unpack(">HH", payload[:4])
            if addr >= len(self.ds.holding_registers):
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            with self.ds.lock:
                self.ds.holding_registers[addr] = value
            self.ds.log_write(fc, addr, value, unit, client_ip)
            return self._resp(tid, unit, struct.pack("B", fc) + payload[:4])

        if fc == 0x10:                              # write multiple holding registers
            start, count, bytecount = struct.unpack(">HHB", payload[:5])
            body = payload[5:5 + bytecount]
            if start + count > len(self.ds.holding_registers):
                return self._exc(tid, unit, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            with self.ds.lock:
                for i in range(count):
                    self.ds.holding_registers[start + i] = struct.unpack(">H", body[i * 2:i * 2 + 2])[0]
            for i in range(count):                   # attribute every register in the block
                self.ds.log_write(0x06, start + i, "multi", unit, client_ip)
            return self._resp(tid, unit, struct.pack(">BHH", fc, start, count))

        if fc == 0x11:                              # report server id (info leak)
            ident = b"LogicWard-ThermalPLC\x00FW:2.1.0\x00Vendor:ACME-Power\x00"
            return self._resp(tid, unit, struct.pack("BB", fc, len(ident) + 1) + b"\xFF" + ident)

        return self._exc(tid, unit, fc, self.EX_ILLEGAL_FUNCTION)


# ── TCP server ────────────────────────────────────────────────────────────────

class ModbusTCPServer:
    def __init__(self, host="0.0.0.0", port=502, datastore: ThermalDataStore | None = None):
        self.host = host
        self.port = port
        self.ds = datastore or ThermalDataStore()
        self.handler = ModbusTCPHandler(self.ds)
        self.running = False
        self._srv: socket.socket | None = None

    def _client(self, conn, addr):
        try:
            conn.settimeout(30)
            while self.running:
                header = conn.recv(6)
                if len(header) < 6:
                    break
                length = struct.unpack(">H", header[4:6])[0]
                body = b""
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        break
                    body += chunk
                resp = self.handler.handle(header + body, addr[0] if addr else None)
                if resp:
                    conn.sendall(resp)
        except (socket.timeout, OSError):
            pass
        finally:
            conn.close()

    def _sim_loop(self):
        while self.running:
            self.ds.simulate_process()
            time.sleep(1)

    def start(self, background: bool = False):
        self.running = True
        threading.Thread(target=self._sim_loop, daemon=True).start()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._srv.bind((self.host, self.port))
        except PermissionError:
            log.warning(f"port {self.port} needs root; falling back to 5020")
            self.port = 5020
            self._srv.bind((self.host, self.port))
        self.port = self._srv.getsockname()[1]      # resolve ephemeral (port=0) binds
        self._srv.listen(10)
        log.info(f"Thermal PLC (Modbus TCP) online at {self.host}:{self.port}  [VULN: unauthenticated]")

        def _accept():
            while self.running:
                try:
                    conn, addr = self._srv.accept()
                except OSError:
                    break
                threading.Thread(target=self._client, args=(conn, addr), daemon=True).start()

        if background:
            threading.Thread(target=_accept, daemon=True).start()
        else:
            try:
                _accept()
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        self.running = False
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass


def serve_writes(ds, port: int | None = None) -> None:
    """Tiny HTTP endpoint exposing the write-attribution map (who wrote what),
    so a remote laptop's drift engine can attribute Modbus writes to a source IP.
    Runs in a daemon thread beside the raw-socket Modbus server (Pi side)."""
    from flask import Flask, jsonify
    app = Flask(__name__)

    @app.get("/writes")
    def writes():
        return jsonify({"writes": {f"{area}:{addr}": {"ip": ip, "ts": ts}
                                   for (area, addr), (ip, ts) in ds.last_write_by_addr.items()}})

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "writes": len(ds.last_write_by_addr)})

    app.run(host="0.0.0.0", port=port or config.WRITES_PORT, threaded=True)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else config.MODBUS_PORT
    server = ModbusTCPServer(port=port)
    threading.Thread(target=serve_writes, args=(server.ds,), daemon=True).start()
    log.info(f"write-attribution HTTP on :{config.WRITES_PORT}  (GET /writes -> who wrote what)")
    server.start()


if __name__ == "__main__":
    main()
