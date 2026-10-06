"""Verify the SOC dashboard end-to-end (stage 7 gate).

Exercises login/RBAC, the live overview, drift surfacing after a program change,
the GitHub-style diff API, the evidence feed, the signed PDF export, and the
role-gated response/baseline actions — all via the Flask test client against an
embedded plant.

Run:  python -m logicward.tests.smoke_dashboard
"""
from __future__ import annotations

import time

from logicward import config
from logicward.dashboard.app import Dashboard, create_app
from logicward.plant.logic_store import BASELINE_PATH, LIVE_PATH

_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def login(app, user, pw):
    c = app.test_client()
    c.post("/login", data={"username": user, "password": pw})
    return c


def main() -> int:
    # start from a clean baseline + live program
    for p in (config.BASELINE_MANIFEST_PATH, LIVE_PATH):
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    dash = Dashboard(embed=True).start()
    app = create_app(dashboard=dash)
    try:
        anon = app.test_client()
        check(anon.get("/").status_code == 302, "unauthenticated / redirects to login")
        check(anon.get("/api/overview").status_code == 401, "unauthenticated API -> 401")

        soc = login(app, "soc", "soc123")
        check(soc.get("/dashboard").status_code == 200, "login works, dashboard renders")

        ov = soc.get("/api/overview").get_json()
        check(ov["baseline_integrity"] == "VALID", "baseline integrity VALID at start")
        check(ov["program_in_sync"] is True, "program in sync with baseline at start")

        plant = soc.get("/api/plant").get_json()
        check("Generator_MW" in plant["input_registers"], "live plant snapshot served")

        # -- host telemetry (CPU/RAM/temp) — the Live Plant DDoS-impact panel --
        from logicward import config as _cfg
        tlm = soc.get("/api/telemetry").get_json()
        check({"cpu", "mem", "temp"}.issubset(tlm.keys()), "telemetry serves cpu/mem/temp")
        check(tlm.get("source") == "local", "telemetry falls back to local host sample")
        pushed = app.test_client().post(
            "/api/telemetry", json={"cpu": 96.5, "mem": 61.0, "temp": 74.3, "host": "pi-01"},
            headers={"X-LogicWard-Token": _cfg.INGEST_TOKEN})
        check(pushed.status_code == 200, "agent can push Pi telemetry (token-authed)")
        tlm2 = soc.get("/api/telemetry").get_json()
        check(tlm2.get("source") == "pi" and tlm2.get("cpu") == 96.5, "pushed Pi telemetry wins over local")
        check(app.test_client().post("/api/telemetry", json={"cpu": 1}).status_code == 401,
              "telemetry push without token -> 401")

        # induce a logic-inversion drift on the running program, then run one pass
        mutated = BASELINE_PATH.read_text(encoding="utf-8").replace(
            "LES(Drum_Level,Drum_Level_LL_SP)", "GRT(Drum_Level,Drum_Level_LL_SP)")
        dash.plant.live_path.write_text(mutated, encoding="utf-8")
        dash.drift.run_once()
        time.sleep(0.1)

        ov = soc.get("/api/overview").get_json()
        check(ov["program_in_sync"] is False, "overview shows program DRIFTED after change")

        evs = soc.get("/api/events?since=0").get_json()["events"]
        check(any(e["type"] == "cyber.logic_inversion" for e in evs), "logic inversion appears in event feed")

        diff = soc.get("/api/diff").get_json()
        check(diff["changed"] >= 1, f"diff API reports changes ({diff['changed']})")
        changed_rows = [r for r in diff["rows"] if r["type"] == "changed"]
        check(changed_rows and any(s.get("hl") for s in changed_rows[0]["right_seg"]),
              "diff has inline red/green highlight segments")

        pdf = soc.get("/api/evidence/report.pdf")
        check(pdf.status_code == 200 and pdf.data[:4] == b"%PDF", "SOC can export signed PDF forensic report")

        ack = soc.post("/api/response/ack", json={"ref": evs[0]["event_id"]})
        check(ack.status_code == 200, "response: acknowledge action works")

        # -- Prompt 2.1: "Acknowledge all" must NOT destroy the evidence log --
        ev_before = [ln for ln in config.EVIDENCE_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        api_before = len(soc.get("/api/evidence").get_json()["events"])
        ackall = soc.post("/api/alerts/ack_all")
        check(ackall.status_code == 200 and "acknowledged" in ackall.get_json(),
              "POST /api/alerts/ack_all acknowledges (no delete)")
        ev_after = [ln for ln in config.EVIDENCE_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        check(len(ev_after) == len(ev_before) + 1,
              f"ack_all keeps evidence log + appends 1 ack event ({len(ev_before)}->{len(ev_after)})")
        api_after = len(soc.get("/api/evidence").get_json()["events"])
        check(api_after >= api_before, f"/api/evidence still returns every event ({api_after} >= {api_before})")
        gone = soc.post("/api/alerts/clear")
        check(gone.status_code == 410, f"legacy /api/alerts/clear returns 410 Gone (got {gone.status_code})")
        acked_state = soc.get("/api/alerts/acked").get_json()
        check(evs[0]["event_id"] in acked_state["acked"], "single-acked event id is tracked server-side")

        # RBAC negatives
        op = login(app, "operator", "operator123")
        check(op.get("/api/evidence/report.pdf").status_code == 403, "operator CANNOT export PDF (403)")
        check(op.post("/api/baseline/lock").status_code == 403, "operator CANNOT re-lock baseline (403)")

        eng = login(app, "engineer", "engineer123")
        check(eng.post("/api/baseline/lock").status_code == 200, "engineer CAN re-lock baseline")
    finally:
        dash.stop()

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
