"""Reproducible UI screenshots + a short demo GIF (Prompt 5.1).

Runs the dashboard in-process (fresh temp DATA_DIR so the feed is clean), drives
attacks through the attacker MUTATORS (never by clicking), waits until the
expected event appears on /api/events, then screenshots. Images land in
docs/screenshots/ at 1600x900, device scale 2, light theme.

Usage:
    playwright install chromium        # one-time
    python scripts/capture_screenshots.py
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
from pathlib import Path

# fresh, isolated runtime state BEFORE importing the app/config
_TMP = Path(tempfile.mkdtemp(prefix="lw_shots_"))
os.environ["LOGICWARD_DATA_DIR"] = str(_TMP)
os.environ["LOGICWARD_EVIDENCE_PATH"] = str(_TMP / "evidence.jsonl")
os.environ["LOGICWARD_BASELINE_MANIFEST"] = str(_TMP / "baseline.signed.json")
os.environ.setdefault("LOGICWARD_MULTISITE", "1")

import requests  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from logicward.attacker import attacks  # noqa: E402
from logicward.dashboard.app import Dashboard, create_app  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)
PORT = 8080


def wait_health(base: str, tries: int = 100) -> None:
    for _ in range(tries):
        try:
            if requests.get(base + "/health", timeout=1).status_code == 200:
                return
        except requests.RequestException:
            time.sleep(0.1)


def wait_event(base: str, cookie: dict, etype: str, tries: int = 60) -> bool:
    for _ in range(tries):
        try:
            evs = requests.get(base + "/api/events?since=0", cookies=cookie, timeout=2).json()["events"]
            if any(e["type"] == etype for e in evs):
                return True
        except requests.RequestException:
            pass
        time.sleep(0.2)
    return False


def main() -> int:
    from playwright.sync_api import sync_playwright

    from logicward.plant.logic_store import BASELINE_PATH

    dash = Dashboard(embed=True).start()
    # Clean, deterministic start: live program == shipped approved baseline, and
    # treat the trust-on-first-use baseline as reviewed (VALID) so shots are clean.
    live = dash.plant.live_path
    base_text = BASELINE_PATH.read_text(encoding="utf-8")
    live.write_text(base_text, encoding="utf-8")
    dash.baseline_state = "VALID"
    dash.drift.reset()

    app = create_app(dashboard=dash)
    srv = make_server("127.0.0.1", PORT, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{PORT}"
    wait_health(base)

    # red-team console on 9090 (for shot 08)
    from logicward.attacker.dashboard.app import create_app as console_app
    csrv = make_server("127.0.0.1", 9090, console_app(host="127.0.0.1"), threaded=True)
    threading.Thread(target=csrv.serve_forever, daemon=True).start()

    with sync_playwright() as p:
        browser = p.chromium.launch()

        def session(user: str, pw: str):
            ctx = browser.new_context(viewport={"width": 1600, "height": 900},
                                      device_scale_factor=2, color_scheme="light")
            pg = ctx.new_page()
            pg.goto(f"{base}/login")
            pg.fill("input[name=username]", user)
            pg.fill("input[name=password]", pw)
            pg.click("button[type=submit], input[type=submit], .btn")
            pg.wait_for_load_state("networkidle")
            return ctx, pg

        def shot(pg, name: str):
            pg.wait_for_timeout(700)
            pg.screenshot(path=str(OUT / name), full_page=False)
            print("saved", name)

        # 01 login
        ctx = browser.new_context(viewport={"width": 1600, "height": 900},
                                  device_scale_factor=2, color_scheme="light")
        pg = ctx.new_page(); pg.goto(f"{base}/login"); shot(pg, "01-login.png"); ctx.close()

        # 02 overview clean (soc)
        ctx, pg = session("soc", "soc123")
        shot(pg, "02-overview-clean.png")

        # drive a logic-inversion attack via the MUTATOR, wait for the event
        live.write_text(attacks.mut_logic_inversion(base_text), encoding="utf-8")
        dash.drift.run_once()
        cookie = {c["name"]: c["value"] for c in ctx.cookies()}
        wait_event(base, cookie, "cyber.logic_inversion")

        # 03 attack mimic (plant tab)
        pg.goto(f"{base}/dashboard"); pg.wait_for_timeout(500)
        node = pg.query_selector('.nav-item[data-tab="plant"]')
        if node:
            node.click()
        shot(pg, "03-attack-mimic.png")

        # 05 alert feed
        node = pg.query_selector('.nav-item[data-tab="alerts"]')
        if node:
            node.click()
        shot(pg, "05-alert-feed.png")

        # 06 evidence (chain VERIFIED)
        node = pg.query_selector('.nav-item[data-tab="evidence"]')
        if node:
            node.click()
        shot(pg, "06-evidence.png")
        ctx.close()

        # 04 program diff (engineer)
        ctx, pg = session("engineer", "engineer123")
        node = pg.query_selector('.nav-item[data-tab="diff"]')
        if node:
            node.click()
        shot(pg, "04-program-diff.png")
        ctx.close()

        # 09 chemical site (soc) — select the chemical reactor, open its view
        ctx, pg = session("soc", "soc123")
        try:
            pg.click("text=Chemical reactor", timeout=3000)
            pg.wait_for_timeout(600)
            node = pg.query_selector('.nav-item[data-tab="plant"]')
            if node:
                node.click()
            shot(pg, "09-chemical-site.png")
        except Exception as exc:  # noqa: BLE001
            print("skip 09-chemical-site.png:", exc)
        ctx.close()

        # 10 roles & access (ciso)
        ctx, pg = session("ciso", "ciso123")
        node = pg.query_selector('.nav-item[data-tab="roles"]')
        if node:
            node.click()
        shot(pg, "10-rbac-roles.png")
        ctx.close()

        # 08 red-team console
        ctx = browser.new_context(viewport={"width": 1600, "height": 900},
                                  device_scale_factor=2, color_scheme="light")
        pg = ctx.new_page()
        pg.goto("http://127.0.0.1:9090/")
        shot(pg, "08-redteam-console.png")
        ctx.close()

        # demo.gif — clean overview -> attack lands -> mimic red -> diff
        live.write_text(base_text, encoding="utf-8")   # reset to clean for the recording
        dash.drift.reset()
        gif_dir = OUT / "_video"
        vctx = browser.new_context(viewport={"width": 1200, "height": 750},
                                   device_scale_factor=1, color_scheme="light",
                                   record_video_dir=str(gif_dir),
                                   record_video_size={"width": 1200, "height": 750})
        vpg = vctx.new_page()
        vpg.goto(f"{base}/login")
        vpg.fill("input[name=username]", "engineer"); vpg.fill("input[name=password]", "engineer123")
        vpg.click("button[type=submit]"); vpg.wait_for_load_state("networkidle")
        vpg.wait_for_timeout(1500)                       # clean overview
        live.write_text(attacks.mut_logic_inversion(base_text), encoding="utf-8")
        dash.drift.run_once()
        vpg.wait_for_timeout(1800)
        n = vpg.query_selector('.nav-item[data-tab="plant"]')
        if n:
            n.click()
        vpg.wait_for_timeout(2500)                       # mimic goes red
        n = vpg.query_selector('.nav-item[data-tab="diff"]')
        if n:
            n.click()
        vpg.wait_for_timeout(3000)                       # diff view
        vctx.close()
        browser.close()

    # convert the recorded webm -> palette-optimized gif (<8 MB, 1200px)
    try:
        import shutil
        import subprocess
        webms = sorted((OUT / "_video").glob("*.webm"))
        if webms and shutil.which("ffmpeg"):
            src = str(webms[-1])
            pal = str(OUT / "_palette.png")
            subprocess.run(["ffmpeg", "-y", "-i", src, "-vf", "fps=10,scale=1000:-1:flags=lanczos,palettegen=max_colors=128",
                            pal], capture_output=True, check=True)
            subprocess.run(["ffmpeg", "-y", "-i", src, "-i", pal, "-lavfi",
                            "fps=10,scale=1000:-1:flags=lanczos[x];[x][1:v]paletteuse",
                            str(OUT / "demo.gif")], capture_output=True, check=True)
            print("saved demo.gif")
            for w in webms:
                w.unlink()
            Path(pal).unlink(missing_ok=True)
            try:
                (OUT / "_video").rmdir()
            except OSError:
                pass
    except Exception as exc:  # noqa: BLE001
        print("skip demo.gif:", exc)

    # 07 report PDF first page
    try:
        import pypdfium2 as pdfium
        s = requests.Session()
        s.post(f"{base}/login", data={"username": "soc", "password": "soc123"})
        pdf = s.get(f"{base}/api/evidence/report.pdf").content
        doc = pdfium.PdfDocument(pdf)
        bmp = doc[0].render(scale=2.0)
        bmp.to_pil().save(OUT / "07-report-pdf.png")
        print("saved 07-report-pdf.png")
    except Exception as exc:  # noqa: BLE001
        print("skip 07-report-pdf.png:", exc)

    srv.shutdown()
    dash.stop()

    # verify non-blank (variance) + report
    import numpy as np  # noqa: PLC0415
    from PIL import Image
    missing = []
    for f in sorted(OUT.glob("*.png")):
        arr = np.asarray(Image.open(f).convert("L"))
        if arr.std() < 3:
            missing.append(f.name + " (blank)")
    print("\nscreenshots:", sorted(x.name for x in OUT.glob("*.png")))
    if missing:
        print("WARNING blank images:", missing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
