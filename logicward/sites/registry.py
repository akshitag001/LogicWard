"""Registry of monitored sites for the multi-site SOC platform.

Lightweight metadata that drives the SOC dashboard's site selector and the
attacker console's target selector. Adding a future site (water, substation)
means adding a ``SiteProfile`` here plus its collector/point-map — no dashboard
code changes. Every event on the shared bus is attributed to a site via
``details.site`` (thermal events omit it and default to ``thermal-pi``).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

DEFAULT_SITE = "thermal-pi"


@dataclass(frozen=True)
class SiteProfile:
    site_id: str
    name: str
    vendor: str
    protocol: str
    program_type: str   # "L5X" | "ST" | "—"
    viz_type: str       # "mimic" | "unity"
    icon: str


SITE_PROFILES: list[SiteProfile] = [
    SiteProfile("thermal-pi", "Thermal Power Plant", "Rockwell", "Modbus TCP",
                "L5X", "mimic", "⚡"),
    SiteProfile("grfics-chem", "GRFICS Chemical Reactor", "OpenPLC", "Modbus TCP",
                "ST", "unity", "⚗️"),
]

BY_ID: dict[str, SiteProfile] = {p.site_id: p for p in SITE_PROFILES}


def site_of(event: dict) -> str:
    """The site an event belongs to (thermal events omit it → default)."""
    return (event.get("details") or {}).get("site", DEFAULT_SITE)


def site_list(available: set[str] | None = None) -> list[dict]:
    """Profiles as JSON dicts, each flagged ``available`` (live this run)."""
    out = []
    for p in SITE_PROFILES:
        d = asdict(p)
        d["available"] = available is None or p.site_id in available
        out.append(d)
    return out
