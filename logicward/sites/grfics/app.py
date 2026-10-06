"""LogicWard Site B - GRFICS Chemical Reactor demo dashboard.

One Flask app that runs the whole Site-B demo:

  * ChemicalDataStore + reactive physics (drives the real GRFICS Unity 3D scene),
  * LogicWard raw-socket Modbus TCP server over that datastore (attack surface),
  * ChemicalDriftDetector on a 1 s loop feeding a real LogicWard EventBus
    (severity + MITRE-for-ICS + evidence log),
  * the 3D scene embedded in an iframe next to a live alert feed, process gauges,
    and one-click attacks - so an attack visibly hits the plant AND lands in the
    detection feed on the same screen.

Run:  python -m logicward.sites.grfics.app
Open: http://127.0.0.1:8095/
"""
from __future__ import annotations

import threading

from flask import Flask, render_template

from logicward import config
from logicward.engine.events import EventBus
from logicward.plant.modbus_server import ModbusTCPServer
from logicward.sites.grfics import SITE_ID, SITE_NAME
from logicward.sites.grfics.attacks import ChemAttacker
from logicward.sites.grfics.blueprint import make_grfics_blueprint
from logicward.sites.grfics.datastore import ChemicalDataStore
from logicward.sites.grfics.detector import ChemicalDriftDetector


class SiteB:
    """Owns the live objects for the chemical site.

    ``bus`` can be injected so the unified SOC dashboard shares ONE event bus
    across sites; left None (standalone mode) it creates its own.
    """

    def __init__(self, bus: EventBus | None = None, modbus_port: int | None = None):
        self.bus = bus or EventBus(evidence_path=config.DATA_DIR / "grfics_evidence.jsonl",
                                   history_max=config.EVENT_HISTORY_MAX)
        self.ds = ChemicalDataStore().start(hz=10.0)
        self.server = ModbusTCPServer(host=config.GRFICS_MODBUS_HOST,
                                      port=modbus_port or config.GRFICS_MODBUS_PORT,
                                      datastore=self.ds)
        self.server.start(background=True)
        self.modbus_port = self.server.port
        self.detector = ChemicalDriftDetector(self.bus, self.ds.register_source,
                                              who_source=self.ds.writer_for)
        self.attacker = ChemAttacker(host="127.0.0.1", port=self.modbus_port)
        self._stop = threading.Event()
        threading.Thread(target=self._loop, name="grfics-detect", daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.detector.run_once()
            except Exception:  # noqa: BLE001
                pass
            self._stop.wait(config.POLL_INTERVAL_SEC)

    def reset(self):
        """Restore the plant to its baseline and clear detector memory."""
        self.ds.stop()
        self.ds = ChemicalDataStore().start(hz=10.0)
        self.server.ds = self.ds
        self.server.handler.ds = self.ds
        self.detector.register_source = self.ds.register_source
        self.detector.who_source = self.ds.writer_for
        self.attacker = ChemAttacker(host="127.0.0.1", port=self.modbus_port)
        self.detector.relock()


def create_app(site: SiteB | None = None) -> Flask:
    app = Flask(__name__)
    site = site or SiteB()
    app.config["SITE"] = site

    # the standalone Site-B dashboard page (the SOC dashboard uses its own UI)
    @app.route("/")
    def index():
        return render_template("grfics.html", site_name=SITE_NAME, site_id=SITE_ID,
                               modbus_port=site.modbus_port)

    # the 3D scene, process feed, and Site-B APIs all live in the shared blueprint
    app.register_blueprint(make_grfics_blueprint(site))
    return app


def main() -> None:
    app = create_app()
    site = app.config["SITE"]
    print("=" * 60)
    print("LogicWard Site B - GRFICS Chemical Reactor")
    print(f"  dashboard : http://127.0.0.1:{config.GRFICS_DASH_PORT}/")
    print(f"  3D scene  : http://127.0.0.1:{config.GRFICS_DASH_PORT}/viz/")
    print(f"  Modbus    : 127.0.0.1:{site.modbus_port}  (unauthenticated)")
    print("=" * 60)
    app.run(host="127.0.0.1", port=config.GRFICS_DASH_PORT, threaded=True)


if __name__ == "__main__":
    main()
