"""Ingest + poll HTTP surface around the event bus.

Exposes the two endpoints the agent and dashboard use (DESIGN.md §3.5, §3.7):

    POST /api/ingest          agent -> bus  (token-auth, batched Events)
    GET  /api/events?since=N  dashboard <- bus  (cursor poll)
    GET  /health              liveness + current cursor

Built as a Flask blueprint so the dashboard can mount the same routes; also
runnable standalone (`python -m logicward.engine.server`) for the bus smoke test.
"""
from __future__ import annotations

from flask import Blueprint, Flask, current_app, jsonify, request

from logicward import config
from logicward.engine.events import EventBus, validate_event

api = Blueprint("logicward_api", __name__)


def _bus() -> EventBus:
    return current_app.config["LOGICWARD_BUS"]


@api.post("/api/ingest")
def ingest():
    if request.headers.get("X-LogicWard-Token") != current_app.config["LOGICWARD_TOKEN"]:
        return jsonify({"error": "invalid or missing token"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "body must be JSON object {events:[...]}"}), 422

    events = data.get("events")
    if events is None and data.get("type"):     # tolerate a single bare event
        events = [data]
    if not isinstance(events, list):
        return jsonify({"error": "body must contain an 'events' array"}), 422

    accepted = 0
    errors: list[dict] = []
    bus = _bus()
    for ev in events:
        problems = validate_event(ev)
        if problems:
            errors.append({"event_id": ev.get("event_id") if isinstance(ev, dict) else None,
                           "errors": problems})
            continue
        if bus.emit(ev) is not None:
            accepted += 1  # None == idempotent duplicate, silently ok

    if accepted == 0 and errors:
        return jsonify({"accepted": 0, "errors": errors}), 422
    return jsonify({"accepted": accepted, "errors": errors})


@api.get("/api/events")
def events():
    since = request.args.get("since", default=0, type=int)
    evs, cursor = _bus().get_since(since)
    return jsonify({"events": evs, "cursor": cursor})


@api.get("/health")
def health():
    return jsonify({"status": "ok", "cursor": _bus().latest_seq})


def create_app(bus: EventBus | None = None, token: str | None = None) -> Flask:
    """Build a Flask app wrapping a bus. The dashboard reuses this blueprint."""
    app = Flask(__name__)
    app.config["LOGICWARD_BUS"] = bus or EventBus(
        evidence_path=config.EVIDENCE_PATH, history_max=config.EVENT_HISTORY_MAX)
    app.config["LOGICWARD_TOKEN"] = token or config.INGEST_TOKEN
    app.register_blueprint(api)
    return app


def main() -> None:
    app = create_app()
    print("LogicWard ingest/poll server")
    print(f"  ingest : POST http://{config.INGEST_HOST}:{config.INGEST_PORT}/api/ingest")
    print(f"  events : GET  http://{config.INGEST_HOST}:{config.INGEST_PORT}/api/events?since=N")
    print(f"  evidence log: {config.EVIDENCE_PATH}")
    app.run(host=config.INGEST_HOST, port=config.INGEST_PORT, threaded=True)


if __name__ == "__main__":
    main()
