"""Rogue-device sensor — ARP allowlist diff (reuses the PiSentinel approach).

Any MAC on the OT segment that is not on the approved allowlist is a
`physical.rogue_device`. Discovery uses scapy ARP when available; for dev/tests
and to keep the pipeline hardware-free, `observe()` accepts an explicit device
list so a rogue can be injected deterministically.
"""
from __future__ import annotations

from typing import Callable

from logicward.engine.events import new_event

try:
    from scapy.all import ARP, Ether, srp
    _HAVE_SCAPY = True
except Exception:  # noqa: BLE001
    _HAVE_SCAPY = False

EmitFn = Callable[[dict], None]


def _norm(mac: str) -> str:
    return mac.lower().replace("-", ":")


class ArpWatch:
    def __init__(self, emit: EmitFn, allowlist: list[str] | None = None,
                 iface: str | None = None, source: str = "arp_watch"):
        self.emit = emit
        self.iface = iface
        self.source = source
        self.allowlist = {_norm(m) for m in (allowlist or [])}
        self._reported: set[str] = set()

    def observe(self, devices: list[dict]) -> list[dict]:
        """Evaluate a list of {mac, ip, vendor} — emit for each new rogue MAC."""
        out: list[dict] = []
        for dev in devices:
            mac = _norm(dev.get("mac", ""))
            if not mac or mac in self.allowlist or mac in self._reported:
                continue
            self._reported.add(mac)
            ev = new_event("physical.rogue_device", self.source, {
                "mac": mac, "ip": dev.get("ip"), "vendor": dev.get("vendor", "Unknown"),
                "reason": f"Unapproved device {mac} ({dev.get('ip', '?')}) on the OT segment",
            }, identity={"who": dev.get("ip"), "mac": mac, "channel": "network"})
            self.emit(ev)
            out.append(ev)
        return out

    def scan(self, cidr: str = "192.168.1.0/24", timeout: float = 2.0) -> list[dict]:
        """Live ARP sweep (Pi). No-op where scapy is unavailable."""
        if not _HAVE_SCAPY:
            return []
        try:
            answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                              timeout=timeout, iface=self.iface, verbose=False)
        except Exception:  # noqa: BLE001
            return []
        devices = [{"mac": r.hwsrc, "ip": r.psrc} for _, r in answered]
        return self.observe(devices)
