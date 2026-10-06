"""Smoke suite for the unified multi-site SOC dashboard + attacker console.

Verifies that the GRFICS chemical reactor is merged into the SOC dashboard as a
second site sharing ONE event bus: the site registry, the mounted 3D/feed/API
blueprint, site-tagged events in the unified feed, per-site evidence + PDF, and
the attacker console launching attacks against BOTH sites.

Run:  python -m logicward.tests.smoke_multisite
"""
from __future__ import annotations

import sys
import time

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
    from logicward.dashboard.app import create_app as soc_app

    app = soc_app(embed=True)
    dash = app.config["DASH"]
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"] = "soc"

    # -- 1. chemical site embedded on the shared bus --
    check("chemical Site B embedded", dash.chem is not None)
    check("chem shares the SOC bus", dash.chem is not None and dash.chem.bus is dash.bus)

    # -- 2. registry / site selector API --
    sites = c.get("/api/sites").get_json()["sites"]
    ids = {s["site_id"]: s["available"] for s in sites}
    check("registry lists thermal-pi", ids.get("thermal-pi") is True)
    check("registry lists grfics-chem available", ids.get("grfics-chem") is True)

    # -- 3. unified dashboard template has the multi-site UI --
    html = c.get("/dashboard").data
    check("dashboard has site selector", b"siteTabs" in html)
    check("dashboard has chemical 3D panel", b"plant-chem" in html)
    check("dashboard has chemical diff note", b"diff-chem-note" in html)

    # -- 4. 3D scene + feed mounted on the SOC app --
    check("3D scene served (/viz/)", c.get("/viz/").status_code == 200)
    feed = c.get("/data/index.php").get_json()
    check("GRFICS feed schema (pressure)", "pressure" in feed.get("outputs", {}))
    check("Site-B state API", c.get("/api/site-b/state").status_code == 200)

    # -- 5. chemical attack -> unified feed, site-tagged, MITRE-mapped --
    r = c.post("/api/site-b/attack/pressure-redline").get_json()
    check("chem attack ok", r.get("ok") is True)
    time.sleep(1.2)
    ev = c.get("/api/events?since=0").get_json()["events"]
    chem = [e for e in ev if (e.get("details") or {}).get("site") == "grfics-chem"]
    check("chem event on unified feed", len(chem) >= 1)
    check("chem event is high setpoint_drift", any(
        e["type"] == "cyber.setpoint_drift" and e["severity"] == "high" for e in chem))
    check("chem event MITRE-mapped", all(e.get("mitre", {}).get("technique_id") for e in chem))
    # thermal events (if any) default to thermal-pi (never mis-tagged as chem)
    check("thermal events default to thermal-pi", all(
        (e.get("details") or {}).get("site", "thermal-pi") == "thermal-pi"
        for e in ev if e not in chem))

    # -- 6. per-site evidence + PDF --
    evd = c.get("/api/evidence?site=grfics-chem").get_json()["events"]
    check("evidence filtered to chem", len(evd) >= 1 and all(
        (e.get("details") or {}).get("site") == "grfics-chem" for e in evd))
    pdf = c.get("/api/evidence/report.pdf?site=grfics-chem")
    check("per-site PDF renders", pdf.status_code == 200 and pdf.data[:4] == b"%PDF")

    # -- 7. attacker console targets BOTH sites --
    from logicward.attacker.dashboard.app import create_app as atk_app
    aapp = atk_app(host="127.0.0.1", chem_host="127.0.0.1", chem_port=dash.chem.modbus_port)
    ac = aapp.test_client()
    ahtml = ac.get("/").data
    check("attacker console has thermal section", b"Thermal Power Plant" in ahtml)
    check("attacker console has chemical section", b"GRFICS Chemical Reactor" in ahtml)
    resp = ac.post("/api/attack", json={"id": "pressure-redline"}).get_json()
    check("attacker console fires chemical attack", resp.get("status") == "success")

    total = _passed + _failed
    print("=" * 52)
    print(f"RESULT: {_passed}/{total} checks passed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
