"""Smoke suite for Site B — GRFICS chemical reactor (3D demo).

Exercises the real pipeline: physics stability at rest, the 5 DISTINCT
demo-ordered attacks over real Modbus, register-drift detection onto the shared
bus (types + severity + MITRE + site tag), the Unity feed schema, and reset.
Each attack is asserted against its OWN signature so no two collapse to the same
behaviour (quality=composition, pump=level-down, overfill=level-up+trip,
estop=instant-halt, redline=blast).

Run:  python -m logicward.tests.smoke_grfics
"""
from __future__ import annotations

import sys
import time

from logicward.sites.grfics import SITE_ID
from logicward.sites.grfics.app import SiteB

_passed = 0
_failed = 0


def check(desc: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {desc}")


def main() -> int:
    site = SiteB(modbus_port=5041)
    time.sleep(0.5)

    def feed():
        return site.ds.feed_json()

    # -- 1. feed schema matches what the Unity build reads --
    f = feed()
    for k in ("f1_flow", "purge_flow", "pressure", "liquid_level", "A_in_purge"):
        check(f"feed.outputs has {k}", k in f["outputs"])
    for k in ("f1_valve_pos", "purge_valve_pos", "e_stop"):
        check(f"feed.state has {k}", k in f["state"])

    # -- 2. stable at rest: no drift, no trip --
    time.sleep(1.5)
    o = feed()["outputs"]
    check("pressure stable at rest", 1500 < o["pressure"] < 2100)
    check("level stable at rest", 30 < o["liquid_level"] < 50)
    check("no false trip at rest", feed()["state"]["e_stop"] == 0)
    site.detector.run_once()
    check("no drift events at rest", len(site.bus.get_since(0)[0]) == 0)

    def fire(name, secs):
        """reset, capture baseline, fire attack, observe peaks over `secs`."""
        site.reset()
        time.sleep(0.8)
        _, cur = site.bus.get_since(0)
        base = feed()["outputs"]
        getattr(site.attacker, name)()
        pmax = amax = lmax = 0.0
        pmin = lmin = 1e9
        tripped = False
        deadline = time.time() + secs
        while time.time() < deadline:
            ff = feed()
            oo = ff["outputs"]
            pmax = max(pmax, oo["pressure"]); pmin = min(pmin, oo["pressure"])
            lmax = max(lmax, oo["liquid_level"]); lmin = min(lmin, oo["liquid_level"])
            amax = max(amax, oo["A_in_purge"])
            if ff["state"]["e_stop"]:
                tripped = True
            time.sleep(0.05)
        site.detector.run_once()
        evs = site.bus.get_since(cur)[0]
        obs = dict(pmax=pmax, pmin=pmin, lmax=lmax, lmin=lmin, amax=amax,
                   tripped=tripped, state=feed()["state"])
        return base, obs, evs

    def has(evs, t):
        return any(e["type"] == t for e in evs)

    def tagged(evs):
        return bool(evs) and all(e["details"].get("site") == SITE_ID for e in evs)

    # -- 3. quality-sabotage: composition swings, stealthy (no trip / level / pressure move) --
    base, o, evs = fire("quality_sabotage", 4)
    check("quality detected (register_change)", has(evs, "cyber.register_change"))
    check("attack attributed to source IP (not 'unknown')",
          bool(evs) and all(e["identity"]["who"] not in (None, "unknown") for e in evs))
    check("alert surfaces the literal Modbus command (details.command)",
          bool(evs) and all(e["details"].get("command", "").startswith("FC06") for e in evs))
    check("quality events tagged + MITRE", tagged(evs) and all(e["mitre"].get("technique_id") for e in evs))
    check("quality swings COMPOSITION (colour)", o["amax"] > base["A_in_purge"] + 12)
    check("quality is STEALTHY (level flat)", o["lmin"] > 30 and o["lmax"] < 55)
    check("quality does NOT trip", not o["tripped"])
    check("quality diverges the feed valves", o["state"]["f1_valve_pos"] > 60 and o["state"]["f2_valve_pos"] < 20)

    # -- 4. pump-starve: level DRAINS, no trip (opposite of overfill) --
    base, o, evs = fire("pump_starve", 6)
    check("pump-starve detected (pump coil)", any(e["details"].get("coil") == "Feed_Pump_1" for e in evs))
    check("pump-starve DRAINS the level", o["lmin"] < 20)
    check("pump-starve does NOT trip", not o["tripped"])
    check("pump-starve shuts feed-1 valve", o["state"]["f1_valve_pos"] < 5)

    # -- 5. overfill: level RISES to overflow + trip --
    base, o, evs = fire("overfill", 6)
    check("overfill detected (register_change)", has(evs, "cyber.register_change"))
    check("overfill RAISES level toward overflow", o["lmax"] > 85)
    check("overfill trips the reactor", o["tripped"])

    # -- 6. estop-injection: instant halt, no prior excursion (distinct from overfill) --
    base, o, evs = fire("estop_injection", 3)
    check("estop detected (ESD coil)", any(e["details"].get("coil") == "Reactor_ESD" for e in evs))
    check("estop halts the reactor", o["tripped"])
    check("estop has no level excursion", o["lmax"] < 55)

    # -- 7. pressure-redline (BLAST): both safety setpoints defeated, pressure -> blast --
    base, o, evs = fire("pressure_redline", 16)
    sp = [e for e in evs if e["type"] == "cyber.setpoint_drift"]
    check("redline defeats TWO safety setpoints", len(sp) == 2)
    check("redline setpoint_drifts are high severity", bool(sp) and all(e["severity"] == "high" for e in sp))
    check("redline emits register_change (valves/purge)", has(evs, "cyber.register_change"))
    check("redline drives pressure to BLAST (>= 3900 kPa)", o["pmax"] >= 3900)

    # -- 7b. attacker.fire() returns the exact Modbus commands (drives console log) --
    site.reset(); time.sleep(0.6)
    r = site.attacker.fire("estop-injection")
    check("attacker.fire returns the exact commands sent",
          bool(r.get("commands")) and r["commands"][0].startswith("FC05 write_coil"))

    # -- 8. reset restores baseline + detection still works --
    site.reset()
    time.sleep(1.0)
    o = feed()["outputs"]
    check("reset restores pressure", 1500 < o["pressure"] < 2100)
    check("reset restores level", 30 < o["liquid_level"] < 50)
    check("reset clears ESD", feed()["state"]["e_stop"] == 0)
    site.detector.run_once()
    _, cur = site.bus.get_since(0)
    site.attacker.overfill()
    time.sleep(0.3)
    site.detector.run_once()
    check("detection works after reset", len(site.bus.get_since(cur)[0]) >= 1)

    total = _passed + _failed
    print("=" * 52)
    print(f"RESULT: {_passed}/{total} checks passed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
