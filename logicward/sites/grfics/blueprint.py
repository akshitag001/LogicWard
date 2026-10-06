"""Flask blueprint exposing the GRFICS Site-B surface.

Extracted so BOTH the standalone Site-B app AND the unified SOC dashboard mount
the exact same routes over one shared ``SiteB`` object. Paths are namespaced
(``/viz``, ``/data``, ``/api/site-b/*``) so they never collide with the SOC
dashboard's own ``/api/*`` routes or templates. ``viz.html`` renders from this
package's ``templates/`` folder (declared on the blueprint), and the Unity scene
loads its build assets by absolute ``/viz/Build/...`` URLs — no ``url_for`` /
static coupling — so the same blueprint works mounted at any app root.
"""
from __future__ import annotations

import os

from flask import (Blueprint, jsonify, render_template, request,
                   send_from_directory)

from logicward import config
from logicward.sites.grfics import points as pts
from logicward.sites.grfics.attacks import ATTACKS as CHEM_ATTACKS

_TEMPLATES = os.path.join(os.path.dirname(__file__), "templates")


def make_grfics_blueprint(site, name: str = "grfics") -> Blueprint:
    """Build a blueprint serving the 3D scene, process feed, and Site-B APIs for
    the given live ``SiteB`` object."""
    bp = Blueprint(name, __name__, template_folder=_TEMPLATES)
    build_dir = config.GRFICS_BUILD_DIR

    # -- the real GRFICS Unity 3D scene (minimal host page + build assets) --
    @bp.route("/viz/")
    def viz():
        return render_template("viz.html")

    @bp.route("/viz/Build/<path:fname>")
    def viz_build(fname):
        return send_from_directory(build_dir / "Build", fname)

    @bp.route("/viz/TemplateData/<path:fname>")
    def viz_template(fname):
        return send_from_directory(build_dir / "TemplateData", fname)

    # -- the process feed the Unity scene reads (exact GRFICS schema) --
    @bp.route("/data/index.php", methods=["GET", "POST"])
    def data_feed():
        return jsonify(site.ds.feed_json())

    @bp.route("/versions.php")
    @bp.route("/version.php")
    def versions():
        return jsonify({"version": "logicward-site-b", "created": "local"})

    # -- Site-B APIs (namespaced) --
    @bp.get("/api/site-b/state")
    def state():
        return jsonify({"feed": site.ds.feed_json(),
                        "snapshot": site.ds.named_snapshot(),
                        "generation": site.ds.generation})

    @bp.get("/api/site-b/events")
    def events():
        since = request.args.get("since", default=0, type=int)
        evs, cursor = site.bus.get_since(since)
        return jsonify({"events": evs, "cursor": cursor})

    @bp.get("/api/site-b/points")
    def points():
        return jsonify({
            "holding": [{"tag": p.tag, "unit": p.unit} for p in pts.HOLDING_REGISTERS],
            "coils": [{"tag": p.tag} for p in pts.COILS if p.tag not in pts.PLANT_DRIVEN_COILS],
        })

    @bp.get("/api/site-b/diff")
    def site_diff():
        """Register-plane diff: signed chemical baseline vs live holding registers + coils."""
        base = site.detector.baseline or {}
        live = site.ds.register_source() or {}
        rows = []
        for tag, cur in (live.get("holding") or {}).items():
            b = (base.get("holding") or {}).get(tag)
            p = pts.BY_TAG.get(tag)
            rows.append({
                "tag": tag, "addr": f"HR[{p.address}]" if p else "HR", "unit": p.unit if p else "",
                "baseline": pts.eng(b, tag) if b is not None else None,
                "current": pts.eng(cur, tag),
                "drift": (b is not None and cur != b),
                "safety": tag in pts.SAFETY_SETPOINTS,
            })
        for tag, cur in (live.get("coils") or {}).items():
            if tag in pts.PLANT_DRIVEN_COILS:
                continue
            b = (base.get("coils") or {}).get(tag)
            p = pts.BY_TAG.get(tag)
            rows.append({
                "tag": tag, "addr": f"C[{p.address}]" if p else "C", "unit": "",
                "baseline": bool(b) if b is not None else None,
                "current": bool(cur),
                "drift": (b is not None and bool(cur) != bool(b)),
                "safety": tag == "Reactor_ESD",
            })
        return jsonify({"rows": rows, "changed": sum(1 for r in rows if r["drift"])})

    @bp.post("/api/site-b/attack/<attack>")
    def attack(attack):
        if attack not in CHEM_ATTACKS:
            return jsonify({"error": f"unknown attack {attack}"}), 404
        return jsonify(site.attacker.fire(attack))

    @bp.post("/api/site-b/reset")
    def reset():
        site.reset()
        return jsonify({"status": "ok", "message": "Chemical plant reset to equilibrium"})

    return bp
