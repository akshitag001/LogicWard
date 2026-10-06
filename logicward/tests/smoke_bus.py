"""Round-trip smoke test for the event bus (DESIGN.md stage 2 gate).

Starts a real ingest/poll server in a thread, uses the real agent Forwarder to
POST events over HTTP, then polls them back and asserts the bus enriched each one
(severity + MITRE + identity + seq). Also checks token auth, schema rejection,
idempotency, cursor semantics, and the evidence log.

Run:  python -m logicward.tests.smoke_bus
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

import requests
from werkzeug.serving import make_server

from logicward.agent.forwarder import Forwarder
from logicward.engine.events import EventBus, new_event
from logicward.engine.server import create_app

TOKEN = "smoke-token"
_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="lw_smoke_"))
    evidence = tmp / "evidence.jsonl"
    bus = EventBus(evidence_path=evidence, history_max=1000)
    app = create_app(bus=bus, token=TOKEN)

    # start the server on an ephemeral port
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    port = srv.server_port
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    ingest_url = f"{base}/api/ingest"

    try:
        # wait for liveness
        for _ in range(50):
            try:
                if requests.get(f"{base}/health", timeout=1).status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.05)

        # 1) round-trip via the real Forwarder ------------------------------------
        fwd = Forwarder(url=ingest_url, token=TOKEN, flush_interval=0.2)
        fwd.emit("physical.rogue_device", "arp_watch",
                 {"mac": "de:ad:be:ef:00:01", "ip": "192.168.1.66", "vendor": "Unknown"})
        fwd.emit("resource.cpu_spike", "resource", {"cpu_percent": 97})
        crit = fwd.emit("cyber.condition_stripping", "drift_engine",
                        {"rung_id": "R07_DRUM_LOW_TRIP", "removed_input": "DRUM_LEVEL",
                         "safety_critical": True})
        ok = fwd.flush()
        check(ok, "forwarder.flush() succeeded")
        check(fwd.pending == 0, "forwarder buffer drained after flush")

        poll = requests.get(f"{base}/api/events?since=0", timeout=2).json()
        evs = poll["events"]
        check(len(evs) == 3, f"poll returned all 3 events (got {len(evs)})")
        by_type = {e["type"]: e for e in evs}

        e = by_type.get("cyber.condition_stripping", {})
        check(e.get("severity") == "critical",
              f"safety-critical condition_stripping scored critical (got {e.get('severity')})")
        check(e.get("mitre", {}).get("technique_id") == "T0889",
              "MITRE enrichment present (Modify Program / T0889)")
        check(e.get("mitre", {}).get("verified") is True, "MITRE mapping marked verified (T0889 confirmed)")
        check("seq" in e and "received_at" in e, "bus assigned seq + received_at")
        check(e.get("identity", {}).get("channel") == "program-download",
              "identity channel inferred (program-download)")

        rogue = by_type.get("physical.rogue_device", {})
        check(rogue.get("identity", {}).get("channel") == "network",
              "rogue_device identity channel = network")
        check(rogue.get("severity") == "medium",
              f"rogue_device scored medium (got {rogue.get('severity')})")

        cursor = poll["cursor"]

        # 2) cursor semantics ------------------------------------------------------
        again = requests.get(f"{base}/api/events?since={cursor}", timeout=2).json()
        check(len(again["events"]) == 0, "polling at latest cursor returns nothing new")

        # 3) idempotency: same event_id twice = one accepted -----------------------
        dup = new_event("physical.link_down", "link_watch", {"iface": "eth0"},
                        event_id="fixed-id-123")
        r1 = requests.post(ingest_url, json={"events": [dup]},
                           headers={"X-LogicWard-Token": TOKEN}, timeout=2).json()
        r2 = requests.post(ingest_url, json={"events": [dup]},
                           headers={"X-LogicWard-Token": TOKEN}, timeout=2).json()
        check(r1["accepted"] == 1 and r2["accepted"] == 0,
              f"idempotent ingest by event_id (first {r1['accepted']}, retry {r2['accepted']})")

        # 4) auth: wrong token = 401 ----------------------------------------------
        bad = requests.post(ingest_url, json={"events": [new_event('resource.mem_spike', 'x')]},
                            headers={"X-LogicWard-Token": "nope"}, timeout=2)
        check(bad.status_code == 401, f"wrong token rejected 401 (got {bad.status_code})")

        # 5) schema: missing type = 422 -------------------------------------------
        badschema = requests.post(ingest_url, json={"events": [{"source": "x"}]},
                                  headers={"X-LogicWard-Token": TOKEN}, timeout=2)
        check(badschema.status_code == 422, f"bad schema rejected 422 (got {badschema.status_code})")

        # 6) evidence log persisted -----------------------------------------------
        lines = [ln for ln in evidence.read_text(encoding="utf-8").splitlines() if ln.strip()]
        check(len(lines) == 4, f"evidence log has 4 events (3 + 1 dedup'd link_down) (got {len(lines)})")

    finally:
        srv.shutdown()

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
