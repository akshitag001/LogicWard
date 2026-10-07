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
    try:
        c._csrf = c.get("/api/csrf").get_json().get("csrf", "")
    except Exception:  # noqa: BLE001
        c._csrf = ""
    return c


def cpost(c, url, **kw):
    """POST with this client's CSRF token (browser state-changing request)."""
    headers = kw.pop("headers", {}) or {}
    headers.setdefault("X-CSRF-Token", getattr(c, "_csrf", ""))
    return c.post(url, headers=headers, **kw)


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

        # -- Prompt 3.2: the PDF is really Ed25519-signed (bundle = canonical artifact) --
        import io
        import json as _json
        import zipfile

        from logicward.dashboard.report_sign import verify_report
        zp = soc.get("/api/evidence/report.zip")
        check(zp.status_code == 200 and zp.data[:2] == b"PK", "3.2: report.zip bundles pdf + sig + pubkey")
        zf = zipfile.ZipFile(io.BytesIO(zp.data))
        zpdf = zf.read("report.pdf"); zsig = _json.loads(zf.read("report.sig"))
        zpub = zf.read("report_pubkey.pem")
        check(zsig.get("algo") == "ed25519" and verify_report(zpdf, zsig, zpub),
              "3.2: signature verifies against the generated PDF (Ed25519)")
        check(not verify_report(zpdf[:-1] + bytes([zpdf[-1] ^ 1]), zsig, zpub),
              "3.2: flipping one PDF byte fails verification")
        check(soc.get("/api/evidence/report.sig").get_json().get("fingerprint", "").startswith("sha256:"),
              "3.2: report.sig exposes the signing-key fingerprint")

        ack = cpost(soc, "/api/response/ack", json={"ref": evs[0]["event_id"]})
        check(ack.status_code == 200, "response: acknowledge action works")

        # -- Prompt 2.1: "Acknowledge all" must NOT destroy the evidence log --
        ev_before = [ln for ln in config.EVIDENCE_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        api_before = len(soc.get("/api/evidence").get_json()["events"])
        ackall = cpost(soc, "/api/alerts/ack_all")
        check(ackall.status_code == 200 and "acknowledged" in ackall.get_json(),
              "POST /api/alerts/ack_all acknowledges (no delete)")
        ev_after = [ln for ln in config.EVIDENCE_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        check(len(ev_after) == len(ev_before) + 1,
              f"ack_all keeps evidence log + appends 1 ack event ({len(ev_before)}->{len(ev_after)})")
        api_after = len(soc.get("/api/evidence").get_json()["events"])
        check(api_after >= api_before, f"/api/evidence still returns every event ({api_after} >= {api_before})")
        gone = cpost(soc, "/api/alerts/clear")
        check(gone.status_code == 410, f"legacy /api/alerts/clear returns 410 Gone (got {gone.status_code})")
        acked_state = soc.get("/api/alerts/acked").get_json()
        check(evs[0]["event_id"] in acked_state["acked"], "single-acked event id is tracked server-side")

        # RBAC negatives
        op = login(app, "operator", "operator123")
        check(op.get("/api/evidence/report.pdf").status_code == 403, "operator CANNOT export PDF (403)")
        check(cpost(op, "/api/baseline/lock").status_code == 403, "operator CANNOT re-lock baseline (403)")

        eng = login(app, "engineer", "engineer123")
        check(cpost(eng, "/api/baseline/lock").status_code == 200, "engineer CAN re-lock baseline")

        # -- Prompt 2.4: auth + CSRF + login rate limiting --
        check(anon.get("/api/events").status_code == 401, "/api/events without login -> 401")
        check(app.test_client().get("/health").get_json() == {"status": "ok"},
              "/health is public but leaks no cursor")
        check(soc.post("/api/response/ack", json={"ref": "x"}).status_code == 400,
              "state-changing POST without CSRF token -> 400")
        check(cpost(soc, "/api/response/ack", json={"ref": "x"}).status_code == 200,
              "same POST WITH CSRF token -> 200")
        check(app.test_client().post("/api/telemetry", json={"cpu": 1},
              query_string={"token": config.INGEST_TOKEN}).status_code == 401,
              "telemetry token via ?query= is rejected (header only)")
        rl = app.test_client()
        codes = [rl.post("/login", data={"username": "soc", "password": "wrong"}).status_code
                 for _ in range(6)]
        check(codes[-1] == 429, f"6 bad logins from one IP -> 429 rate limited ({codes})")
        check(soc.get("/api/insider/attacks").status_code == 404,
              "2.5: SOC app no longer exposes /api/insider/* (moved to red-team console)")
    finally:
        dash.stop()

    tamper_test()
    secrets_test()

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


def tamper_test() -> None:
    """Prompt 2.2 — a tampered baseline must fail CLOSED at startup."""
    import json

    bpath = config.BASELINE_MANIFEST_PATH
    for p in list(bpath.parent.glob(bpath.name + ".tampered-*")):
        p.unlink()
    # corrupt the signed baseline left on disk (break the signature by editing the manifest)
    signed = json.loads(bpath.read_text(encoding="utf-8"))
    signed["manifest"]["structural_hash"] = "sha256:deadbeefdeadbeef"
    corrupt_bytes = json.dumps(signed, indent=2).encode("utf-8")
    bpath.write_bytes(corrupt_bytes)

    dash2 = Dashboard(embed=True)   # construct only (no loop) — fail-closed happens in __init__
    try:
        evs = dash2.bus.snapshot()
        check(any(e["type"] == "cyber.baseline_tamper" and e["severity"] == "critical" for e in evs),
              "tampered baseline at startup -> critical cyber.baseline_tamper emitted")
        check(dash2.baseline_state == "INVALID", "dashboard comes up in INVALID (fail-closed) state")
        ov = dash2.overview()
        check(ov["baseline_integrity"] == "TAMPERED", "overview reports baseline_integrity=TAMPERED")
        check(ov["detection_paused"] is True, "detection is paused while baseline is invalid")
        # the tampered file must NOT be overwritten with a fresh capture — it is quarantined
        quarantined = list(bpath.parent.glob(bpath.name + ".tampered-*"))
        check(len(quarantined) == 1 and quarantined[0].read_bytes() == corrupt_bytes,
              "tampered file quarantined intact, NOT overwritten")
        check(not bpath.exists(), "no fresh baseline silently written in place of the tampered one")
        # re-lock on an invalid baseline needs a typed confirmation
        app2 = create_app(dashboard=dash2)
        eng = login(app2, "engineer", "engineer123")
        check(cpost(eng, "/api/baseline/lock").status_code == 428,
              "re-lock on invalid baseline without confirm -> 428")
        ok = cpost(eng, "/api/baseline/lock", json={"confirm": "RELOCK"})
        check(ok.status_code == 200 and dash2.baseline_state == "VALID",
              "engineer re-locks with confirm='RELOCK' -> baseline VALID again")
    finally:
        dash2.stop()
        for p in list(bpath.parent.glob(bpath.name + ".tampered-*")):
            p.unlink()


def secrets_test() -> None:
    """Prompt 2.3 — production mode must fail fast without real secrets."""
    import os
    saved = {k: os.environ.get(k) for k in
             ("LOGICWARD_DEMO_MODE", "LOGICWARD_SECRET", "LOGICWARD_TOKEN", "LOGICWARD_HMAC_KEY")}
    try:
        os.environ["LOGICWARD_DEMO_MODE"] = "0"
        for k in ("LOGICWARD_SECRET", "LOGICWARD_TOKEN", "LOGICWARD_HMAC_KEY"):
            os.environ.pop(k, None)
        raised = ""
        try:
            create_app(embed=True)
        except RuntimeError as exc:
            raised = str(exc)
        check("LOGICWARD_SECRET" in raised and "DEMO_MODE=0" in raised,
              "DEMO_MODE=0 with no secrets -> create_app() raises a clear error")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


if __name__ == "__main__":
    raise SystemExit(main())
