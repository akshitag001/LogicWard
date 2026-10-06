"""Logic store — the PLC's program endpoints (runs on the Pi).

Serves the running L5X program and accepts program "downloads", mirroring how an
engineering workstation reads from / writes to a real PLC:

    GET  /program        -> { l5x, hash, controller, rung_count }   (engine pulls this)
    GET  /program/raw    -> the raw .L5X (application/xml)
    GET  /program/hash   -> { hash }
    POST /program/download  -> replace the running program            (attacker's channel)
    GET  /health

The running program is persisted to ``program/live.L5X`` so the passive FIM
sensor can watch the file for out-of-band tampering (DESIGN: FIM watches BOTH the
Pi live program and the laptop baseline). A malformed download is rejected — the
program never lands in a broken state.

Run:  python -m logicward.plant.logic_store
"""
from __future__ import annotations

import shutil
from pathlib import Path

from flask import Blueprint, Flask, Response, current_app, jsonify, request

from logicward import config
from logicward.engine import l5x

PROGRAM_DIR = Path(__file__).resolve().parent / "program"
BASELINE_PATH = PROGRAM_DIR / "ThermalPlant_baseline.L5X"
LIVE_PATH = PROGRAM_DIR / "live.L5X"

program_api = Blueprint("logic_store", __name__)


def _live_path() -> Path:
    return current_app.config["LOGICWARD_LIVE_PATH"]


def _summary(xml: bytes) -> dict:
    prog = l5x.parse(xml)
    rung_count = sum(len(v) for v in prog.routines.values())
    return {"l5x": xml.decode("utf-8"), "hash": l5x.structural_hash(prog),
            "controller": prog.controller, "rung_count": rung_count}


@program_api.get("/program")
def get_program():
    return jsonify(_summary(_live_path().read_bytes()))


@program_api.get("/program/raw")
def get_program_raw():
    return Response(_live_path().read_bytes(), mimetype="application/xml")


@program_api.get("/program/hash")
def get_program_hash():
    return jsonify({"hash": l5x.structural_hash(l5x.parse(_live_path().read_bytes()))})


@program_api.post("/program/download")
def download_program():
    """Replace the running program (simulated engineering-workstation download)."""
    if request.content_type and "application/json" in request.content_type:
        body = request.get_json(silent=True) or {}
        xml = (body.get("l5x") or "").encode("utf-8")
    else:
        xml = request.get_data()
    if not xml:
        return jsonify({"error": "empty program"}), 400
    try:
        summary = _summary(xml)                     # validates it parses
    except Exception as exc:                        # noqa: BLE001 - reject malformed
        return jsonify({"error": f"invalid L5X: {exc}"}), 400
    _live_path().write_bytes(xml)                   # FIM will observe this write
    current_app.config["LAST_DOWNLOAD"] = {"ip": request.remote_addr}   # attribute WHO downloaded
    return jsonify({"status": "downloaded", "hash": summary["hash"],
                    "controller": summary["controller"], "rung_count": summary["rung_count"]})


@program_api.get("/program/downloader")
def program_downloader():
    """Source IP of the last program download (attacker attribution for program drift)."""
    return jsonify(current_app.config.get("LAST_DOWNLOAD") or {"ip": None})


@program_api.get("/health")
def health():
    return jsonify({"status": "ok", "live": str(_live_path())})


def ensure_live(live_path: Path = LIVE_PATH) -> Path:
    """Make sure a running program exists — seed it from the approved baseline."""
    live_path.parent.mkdir(parents=True, exist_ok=True)
    if not live_path.exists():
        shutil.copyfile(BASELINE_PATH, live_path)
    return live_path


def create_app(live_path: Path | None = None) -> Flask:
    app = Flask(__name__)
    app.config["LOGICWARD_LIVE_PATH"] = ensure_live(live_path or LIVE_PATH)
    app.register_blueprint(program_api)
    return app


def main() -> None:
    app = create_app()
    print("LogicWard logic store (PLC program endpoints)")
    print(f"  program : GET  http://0.0.0.0:{config.PROGRAM_PORT}/program")
    print(f"  download: POST http://0.0.0.0:{config.PROGRAM_PORT}/program/download")
    print(f"  live    : {app.config['LOGICWARD_LIVE_PATH']}")
    app.run(host="0.0.0.0", port=config.PROGRAM_PORT, threaded=True)


if __name__ == "__main__":
    main()
