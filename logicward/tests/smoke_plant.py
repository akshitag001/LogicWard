"""Verify the thermal PLC (Modbus server) + logic store (stage 4b gate).

Modbus: reads live thermal registers/coils over real TCP, confirms sane startup
values with no trips, then lowers a trip setpoint over Modbus and watches the
plant's protection actually assert the trip. Logic store: serves the program +
hash and accepts a program download that changes the structural hash.

Run:  python -m logicward.tests.smoke_plant
"""
from __future__ import annotations

import socket
import struct
import time

from logicward.engine import l5x
from logicward.plant import logic_store
from logicward.plant.modbus_server import ModbusTCPServer, ThermalDataStore

_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


# -- minimal raw Modbus client --
def _txn(port: int, pdu: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
    resp = s.recv(512)
    s.close()
    return resp


def read_regs(port, fc, start, count):
    r = _txn(port, struct.pack(">BHH", fc, start, count))
    bc = r[8]
    data = r[9:9 + bc]
    return [struct.unpack(">H", data[i * 2:i * 2 + 2])[0] for i in range(count)]


def read_bits(port, fc, start, count):
    r = _txn(port, struct.pack(">BHH", fc, start, count))
    bc = r[8]
    data = r[9:9 + bc]
    return [bool((data[i // 8] >> (i % 8)) & 1) for i in range(count)]


def write_reg(port, addr, value):
    return _txn(port, struct.pack(">BHH", 0x06, addr, value))


def main() -> int:
    # ── Modbus server ────────────────────────────────────────────────────────
    ds = ThermalDataStore()
    srv = ModbusTCPServer(host="127.0.0.1", port=0, datastore=ds)
    srv.start(background=True)
    time.sleep(0.3)
    port = srv.port
    try:
        ir = read_regs(port, 0x04, 0, 7)                 # input registers
        check(240 <= ir[0] <= 260, f"Generator_MW ~250 (got {ir[0]})")
        check(200 <= ir[3] <= 500, f"Drum_Level in mm range (got {ir[3]})")
        check(2980 <= ir[4] <= 3020, f"Turbine_Speed ~3000 rpm (got {ir[4]})")

        hr = read_regs(port, 0x03, 0, 6)                 # holding registers (setpoints)
        check(hr[1] == 220, f"Drum_Level_LL_SP == 220 (got {hr[1]})")
        check(hr[0] == 1750, f"Steam_Press_HH_SP raw == 1750 (=175.0 bar) (got {hr[0]})")

        coils = read_bits(port, 0x01, 0, 12)
        check(coils[0] is True, "Plant_Running coil set")
        check(not any(coils[7:12]), f"no trips asserted at startup (trips={coils[7:12]})")

        # attacker lowers... actually RAISES the low-level trip setpoint above the
        # current drum level -> protection should fire the feedwater trip
        write_reg(port, 1, 500)                           # Drum_Level_LL_SP := 500
        time.sleep(1.4)                                   # let a sim tick run
        coils2 = read_bits(port, 0x01, 0, 12)
        check(coils2[7] is True,
              f"Feedwater_Trip asserts after setpoint pushed above drum level (got {coils2[7]})")
    finally:
        srv.stop()

    # ── Logic store ──────────────────────────────────────────────────────────
    import tempfile
    from pathlib import Path
    tmp_live = Path(tempfile.mkdtemp(prefix="lw_ls_")) / "live.L5X"
    app = logic_store.create_app(live_path=tmp_live)
    client = app.test_client()

    prog = client.get("/program").get_json()
    check(prog["rung_count"] == 6, f"/program reports 6 rungs (got {prog['rung_count']})")
    check(prog["hash"].startswith("sha256:"), "/program returns a structural hash")
    baseline_hash = prog["hash"]

    baseline_text = logic_store.BASELINE_PATH.read_text(encoding="utf-8")
    mutated = baseline_text.replace("LES(Drum_Level,Drum_Level_LL_SP)",
                                    "GRT(Drum_Level,Drum_Level_LL_SP)")
    dl = client.post("/program/download", json={"l5x": mutated}).get_json()
    check(dl["status"] == "downloaded" and dl["hash"] != baseline_hash,
          "program download accepted and changes the hash")

    now = client.get("/program").get_json()
    check(now["hash"] == dl["hash"], "downloaded program persisted (live reflects it)")
    check(tmp_live.exists() and l5x.structural_hash(l5x.load(tmp_live)) == dl["hash"],
          "live.L5X written to disk (FIM-observable)")

    bad = client.post("/program/download", data="<not-valid-l5x",
                      content_type="application/xml")
    check(bad.status_code == 400, f"malformed program rejected 400 (got {bad.status_code})")

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
