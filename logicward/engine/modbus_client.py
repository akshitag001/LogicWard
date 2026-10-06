"""Minimal raw Modbus TCP client — the laptop reads the Pi PLC.

Just the reads the drift engine + dashboard need (FC 01-04). One transaction per
call (connect/send/recv/close) — simple and robust for a 1 Hz poll. Modelled on
OT_SECURITY's raw client.
"""
from __future__ import annotations

import socket
import struct


class ModbusClient:
    def __init__(self, host: str, port: int, unit: int = 1, timeout: float = 2.0):
        self.host = host
        self.port = port
        self.unit = unit
        self.timeout = timeout
        self._tid = 0

    def _txn(self, pdu: bytes) -> bytes | None:
        self._tid = (self._tid + 1) % 0xFFFF
        mbap = struct.pack(">HHHB", self._tid, 0, len(pdu) + 1, self.unit)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            s.sendall(mbap + pdu)
            resp = s.recv(1024)
            s.close()
            return resp
        except OSError:
            return None

    def _read_regs(self, fc: int, start: int, count: int) -> list[int]:
        resp = self._txn(struct.pack(">BHH", fc, start, count))
        if not resp or len(resp) < 9 or resp[7] & 0x80:
            return []
        bc = resp[8]
        data = resp[9:9 + bc]
        return [struct.unpack(">H", data[i * 2:i * 2 + 2])[0] for i in range(bc // 2)]

    def _read_bits(self, fc: int, start: int, count: int) -> list[bool]:
        resp = self._txn(struct.pack(">BHH", fc, start, count))
        if not resp or len(resp) < 9 or resp[7] & 0x80:
            return []
        bc = resp[8]
        data = resp[9:9 + bc]
        return [bool((data[i // 8] >> (i % 8)) & 1) for i in range(count)]

    def read_holding_registers(self, start: int, count: int) -> list[int]:
        return self._read_regs(0x03, start, count)

    def read_input_registers(self, start: int, count: int) -> list[int]:
        return self._read_regs(0x04, start, count)

    def read_coils(self, start: int, count: int) -> list[bool]:
        return self._read_bits(0x01, start, count)

    def read_discrete_inputs(self, start: int, count: int) -> list[bool]:
        return self._read_bits(0x02, start, count)
