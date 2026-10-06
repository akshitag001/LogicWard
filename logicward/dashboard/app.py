"""LogicWard SOC dashboard — Flask app (runs on the laptop).
Modified by Komal & Antigravity (Adani Project RBAC Upgrades)

Composes the whole laptop side: mounts the engine ingest/poll blueprint (so the
Pi agent can POST and the UI can poll), runs the drift engine on a background
loop, watches the signed baseline with FIM, wires the response engine, and serves
the role-gated SOC UI (live plant view, GitHub-style program diff, alert feed,
evidence + PDF).

Runs single-machine by default (an embedded plant), or against a real Pi when
LOGICWARD_EMBED_PLANT=0.

Run:  python -m logicward.dashboard.app
Logins:  operator/operator123 · engineer/engineer123 · soc/soc123
"""
from __future__ import annotations

import functools
import os
import threading
import time

from flask import (Flask, Response, jsonify, redirect, render_template, request,
                   session, url_for)

from logicward import config
from logicward.agent.sensors.fim_watch import BaselineFileMonitor
from logicward.agent.sensors.resource import ResourceMonitor
from logicward.dashboard import evidence as evidence_mod
from logicward.engine import baseline as bl
from logicward.engine import l5x, l5x_diff
from logicward.engine.drift import DriftEngine
from logicward.engine.events import EventBus
from logicward.engine.response import ResponseEngine
from logicward.engine.server import api as engine_api
from logicward.engine.sources import EmbeddedPlant, RemotePlant
from logicward.sites import registry

# ── RBAC — 6 OT/ICS roles, capability-based ──────────────────────────────────
# These are the six functional roles shown on the "Roles & Access" tab. Access is
# gated by CAPABILITY (what a role may DO), not a linear rank, because the roles
# have different scopes (a Network Engineer can quarantine a device but not touch
# the PLC program; a Control Engineer is the reverse).
USERS = {
    "operator": {"password": "operator123", "role": "operator",         "name": "Operator (Control Room)"},
    "engineer": {"password": "engineer123", "role": "control_engineer", "name": "C&I / Control Engineer"},
    "netsec":   {"password": "netsec123",   "role": "network_engineer", "name": "OT Network / Security Engineer"},
    "soc":      {"password": "soc123",      "role": "soc_analyst",      "name": "SOC Analyst"},
    "vendor":   {"password": "vendor123",   "role": "vendor",           "name": "Vendor / OEM Contractor"},
    "ciso":     {"password": "ciso123",     "role": "ciso",             "name": "CISO / Plant Cyber Head"},
}

# Capabilities gate every action/control (UI + API):
#   ack               acknowledge a single alert
#   ack_all           acknowledge / clear the whole alert feed
#   baseline          re-lock / restore the approved baseline (engineering)
#   network_response  quarantine a rogue device (network/security)
#   safe_state        recommend a safe-state on a safety-critical alert
#   evidence          export the signed forensic PDF / view the evidence log
#   compliance        CISO oversight (cross-role incident command)
ALL_CAPS = ("ack", "ack_all", "baseline", "network_response", "safe_state", "evidence", "compliance")
ROLE_CAPS: dict[str, set[str]] = {
    "operator":         {"ack", "ack_all"},
    "control_engineer": {"ack", "ack_all", "baseline", "safe_state"},
    "network_engineer": {"ack", "ack_all", "network_response"},
    "soc_analyst":      {"ack", "ack_all", "network_response", "safe_state", "evidence"},
    "vendor":           set(),                 # scoped, read-only (heavily monitored)
    "ciso":             set(ALL_CAPS),         # full cross-role authority
}
# retained for display ordering only (NOT used for gating)
ROLE_RANK = {"operator": 1, "vendor": 1, "control_engineer": 2, "network_engineer": 2,
             "soc_analyst": 3, "ciso": 4}


def caps_for(role: str) -> set[str]:
    return ROLE_CAPS.get(role, set())


# ── production-grade analytics helpers (additive) ─────────────────────────────
_SEV_WEIGHT = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
_RISK_BANDS = [(85, "CRITICAL"), (65, "HIGH"), (40, "ELEVATED"), (20, "MODERATE"), (0, "LOW")]


def _risk(counts: dict, integrity: str, in_sync: bool) -> tuple[int, str]:
    """Explainable 0-100 platform risk score from active alerts + posture."""
    score = sum(_SEV_WEIGHT.get(sev, 0) * n for sev, n in counts.items())
    if integrity != "VALID":
        score += 40                     # a tampered baseline is a major posture hit
    if not in_sync:
        score += 15                     # running program has drifted from baseline
    score = max(0, min(100, int(score)))
    band = next(name for thr, name in _RISK_BANDS if score >= thr)
    return score, band


def _site_health(events: list[dict], chem_up: bool) -> list[dict]:
    """Per-site alert rollup for the multi-site health panel."""
    out = []
    for p in registry.SITE_PROFILES:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for e in events:
            if registry.site_of(e) == p.site_id:
                s = e.get("severity", "info")
                sev[s] = sev.get(s, 0) + 1
        online = True if p.site_id == "thermal-pi" else chem_up
        out.append({
            "site_id": p.site_id, "name": p.name, "icon": p.icon,
            "online": online, "events": sum(sev.values()),
            "critical": sev["critical"], "high": sev["high"],
            "status": ("CRITICAL" if sev["critical"] else
                       "WARNING" if (sev["high"] or sev["medium"]) else "NOMINAL"),
        })
    return out


class Dashboard:
    """Holds the live objects the routes act on."""

    def __init__(self, embed: bool = True):
        self.bus = EventBus(evidence_path=config.EVIDENCE_PATH,
                            history_max=config.EVENT_HISTORY_MAX)
        if embed:
            self.plant = EmbeddedPlant().start()
        else:
            self.plant = RemotePlant(config.PI_HOST, config.MODBUS_PORT, config.PROGRAM_URL)

        # lock (or load) the baseline from the current approved program + registers
        self.baseline_path = config.BASELINE_MANIFEST_PATH
        self.signed = self._load_or_capture_baseline()
        self.baseline_prog = l5x.parse(self.signed["manifest"]["l5x"].encode())

        self.drift = DriftEngine(self.bus, self.signed,
                                 program_source=self.plant.program_source,
                                 register_source=self.plant.register_source,
                                 who_source=self._who)
        self.response = ResponseEngine(self.bus, restore_hook=self._restore_baseline_program)
        self.baseline_fim = BaselineFileMonitor(self.baseline_path, self.bus.emit)

        # -- host telemetry (CPU / RAM / temp) — makes the DDoS impact visible --
        # In embedded/single-machine runs we sample THIS host's psutil; on a real
        # Pi the edge agent pushes the Pi's readings to POST /api/telemetry, which
        # then win over the local sample. The monitor also edge-fires cpu_spike.
        self._resmon = ResourceMonitor(self.bus.emit)
        self._pushed_telemetry: dict | None = None

        # -- Site B: GRFICS chemical reactor (optional, shares THIS bus) --
        # A second monitored site: its own Modbus PLC + physics + register-drift
        # detector, all feeding the same event bus so both plants share one feed,
        # timeline, and evidence log. Guarded so a missing GRFICS build never
        # breaks the thermal dashboard. Disable with LOGICWARD_MULTISITE=0.
        self.chem = None
        if os.environ.get("LOGICWARD_MULTISITE", "1") != "0":
            try:
                from logicward.sites.grfics.app import SiteB
                self.chem = SiteB(bus=self.bus, modbus_port=config.GRFICS_MODBUS_PORT)
            except Exception:  # noqa: BLE001
                self.chem = None

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- baseline lifecycle --
    def _load_or_capture_baseline(self) -> dict:
        try:
            signed = bl.load(self.baseline_path)
            if bl.verify(signed):
                return signed
        except Exception:  # noqa: BLE001
            pass
        return self._capture_baseline()

    def _capture_baseline(self) -> dict:
        signed = bl.capture(self.plant.program_source(), self.plant.register_source())
        bl.save(signed, self.baseline_path)
        return signed

    def relock_baseline(self) -> dict:
        self.signed = self._capture_baseline()
        self.baseline_prog = l5x.parse(self.signed["manifest"]["l5x"].encode())
        self.drift = DriftEngine(self.bus, self.signed,
                                 program_source=self.plant.program_source,
                                 register_source=self.plant.register_source,
                                 who_source=self._who)
        return self.signed

    def _who(self, tag: str | None, channel: str) -> str | None:
        """Attribute a detected change to the attacker's source IP (or None)."""
        if tag and hasattr(self.plant, "writer_for"):
            ip = self.plant.writer_for(tag)
            if ip:
                return ip
        if channel == "program-download" and hasattr(self.plant, "program_writer"):
            return self.plant.program_writer()
        return None

    def _restore_baseline_program(self) -> bool:
        """Restore hook: re-download the approved program to the plant."""
        l5x_str = self.signed["manifest"]["l5x"]
        live = getattr(self.plant, "live_path", None)
        if live is not None:
            live.write_text(l5x_str, encoding="utf-8")
            return True
        
        prog_url = getattr(self.plant, "program_url", None)
        if prog_url:
            import requests
            try:
                requests.post(f"{prog_url}/download", json={"l5x": l5x_str}, timeout=5)
                return True
            except Exception:
                pass
        return False

    # -- background drift loop --
    def start(self) -> "Dashboard":
        self.baseline_fim.start()
        self._thread = threading.Thread(target=self._loop, name="lw-drift", daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.drift.run_once()
            except Exception:  # noqa: BLE001
                pass
            try:
                self._resmon.scan()          # edge-fire cpu/mem spike on sustained load
            except Exception:  # noqa: BLE001
                pass
            self._stop.wait(config.POLL_INTERVAL_SEC)

    def telemetry(self) -> dict:
        """Live host telemetry for the thermal Live-Plant panel. Agent-pushed Pi
        readings (fresh) win; otherwise sample this host locally (embedded/laptop)."""
        t = self._pushed_telemetry
        if t and (time.time() - t.get("_rx", 0) < 6):
            return {"cpu": t.get("cpu"), "mem": t.get("mem"), "temp": t.get("temp"),
                    "host": t.get("host", config.PI_HOST), "source": "pi"}
        s = self._resmon.sample()
        s["host"] = "localhost"
        s["source"] = "local"
        return s

    def stop(self) -> None:
        self._stop.set()
        self.baseline_fim.stop()
        if hasattr(self.plant, "stop"):
            self.plant.stop()

    # -- views' data --
    def overview(self) -> dict:
        events = self.bus.snapshot()
        counts = evidence_mod.summary(events)
        live = l5x.parse(self.plant.program_source())
        diff = l5x_diff.diff_programs(self.baseline_prog, live)
        integrity = "VALID" if bl.verify(self.signed) else "TAMPERED"
        risk_score, risk_band = _risk(counts, integrity, diff["changed"] == 0)
        return {
            "controller": self.signed["manifest"]["controller"],
            "baseline_hash": self.signed["manifest"]["structural_hash"],
            "baseline_integrity": integrity,
            "live_hash": diff["live_hash"],
            "program_in_sync": diff["changed"] == 0,
            "program_changed": diff["changed"],
            "severity_counts": counts,
            "event_total": len(events),
            "critical_open": counts.get("critical", 0),
            # -- production-grade additions (all additive) --
            "risk_score": risk_score,
            "risk_band": risk_band,
            "sites": _site_health(events, self.chem is not None),
            "rollback": {
                "baseline_integrity": integrity,
                "program_in_sync": diff["changed"] == 0,
                "drifted_rungs": diff["changed"],
                "restorable": diff["changed"] > 0 or integrity != "VALID",
            },
        }

    def diff(self) -> dict:
        live = l5x.parse(self.plant.program_source())
        return l5x_diff.diff_programs(self.baseline_prog, live)


# ── auth helpers ──────────────────────────────────────────────────────────────

def _current_role() -> str | None:
    u = session.get("user")
    return USERS[u]["role"] if u in USERS else None


def login_required(fn):
    @functools.wraps(fn)
    def wrap(*a, **k):
        if session.get("user") not in USERS:
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login"))
        return fn(*a, **k)
    return wrap


def require_cap(cap: str):
    """Gate a route on a capability (see ROLE_CAPS)."""
    def deco(fn):
        @functools.wraps(fn)
        def wrap(*a, **k):
            role = _current_role()
            if not role:
                return jsonify({"error": "authentication required"}), 401
            if cap not in caps_for(role):
                return jsonify({"error": f"role '{role}' lacks capability '{cap}'"}), 403
            return fn(*a, **k)
        return wrap
    return deco


def create_app(dashboard: Dashboard | None = None, embed: bool | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("LOGICWARD_SECRET", "logicward-dev-secret")
    if embed is None:
        embed = os.environ.get("LOGICWARD_EMBED_PLANT", "1") != "0"
    dash = dashboard or Dashboard(embed=embed).start()

    # engine ingest/poll blueprint shares our bus + token
    app.config["LOGICWARD_BUS"] = dash.bus
    app.config["LOGICWARD_TOKEN"] = config.INGEST_TOKEN
    app.register_blueprint(engine_api)
    app.config["DASH"] = dash

    # Site B (chemical reactor): mount its 3D scene + feed + APIs on this app so
    # both plants live under one dashboard, one bus, one login.
    if dash.chem is not None:
        from logicward.sites.grfics.blueprint import make_grfics_blueprint
        app.register_blueprint(make_grfics_blueprint(dash.chem))

    # -- auth --
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if u in USERS and USERS[u]["password"] == p:
                session["user"] = u
                return redirect(url_for("dashboard_page"))
            return render_template("login.html", error="Invalid credentials"), 401
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    def index():
        return redirect(url_for("dashboard_page") if session.get("user") in USERS else url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard_page():
        u = session["user"]
        role = USERS[u]["role"]
        return render_template("dashboard.html", user=USERS[u]["name"], username=u,
                               role=role, caps=",".join(sorted(caps_for(role))))

    # -- data APIs --
    @app.get("/api/sites")
    @login_required
    def api_sites():
        available = {"thermal-pi"}
        if dash.chem is not None:
            available.add("grfics-chem")
        return jsonify({"sites": registry.site_list(available), "default": registry.DEFAULT_SITE})

    @app.get("/api/overview")
    @login_required
    def api_overview():
        return jsonify(dash.overview())

    @app.get("/api/plant")
    @login_required
    def api_plant():
        return jsonify(dash.plant.named_snapshot())

    @app.get("/api/telemetry")
    @login_required
    def api_telemetry():
        return jsonify(dash.telemetry())

    @app.post("/api/telemetry")
    def api_telemetry_ingest():
        # The Pi edge agent pushes its CPU/RAM/temp here (token-authed, same token
        # as event ingest). Kept off the event bus — this is a live gauge, not
        # evidence; sustained spikes still surface as resource.cpu_spike alerts.
        tok = request.headers.get("X-LogicWard-Token") or request.args.get("token")
        if tok != config.INGEST_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        dash._pushed_telemetry = {
            "cpu": body.get("cpu"), "mem": body.get("mem"), "temp": body.get("temp"),
            "host": body.get("host", config.PI_HOST), "_rx": time.time(),
        }
        return jsonify({"status": "ok"})

    @app.get("/api/diff")
    @login_required
    def api_diff():
        return jsonify(dash.diff())

    @app.get("/api/evidence")
    @login_required
    def api_evidence():
        sev = request.args.get("severity")
        site = request.args.get("site")
        return jsonify({"events": evidence_mod.query(dash.bus.snapshot(), severity=sev,
                                                     site=site, limit=300)})

    @app.post("/api/alerts/clear")
    @require_cap("ack_all")
    def api_alerts_clear():
        dash.bus.clear()
        dash.drift.reset()
        return jsonify({"status": "cleared", "message": "All alerts have been cleared from memory and disk."})

    @app.get("/api/evidence/report.pdf")
    @require_cap("evidence")
    def api_report():
        site = request.args.get("site")
        events = dash.bus.snapshot()
        if site:
            events = evidence_mod.query(events, site=site, limit=100000)
        prof = registry.BY_ID.get(site)
        meta = {"controller": (prof.name if prof else dash.signed["manifest"]["controller"]),
                "baseline_hash": dash.signed["manifest"]["structural_hash"],
                "baseline_integrity": "VALID" if bl.verify(dash.signed) else "TAMPERED",
                "site": (prof.name if prof else "All sites")}
        pdf = evidence_mod.build_pdf(events, meta)
        fname = f"logicward_{site or 'all-sites'}_report.pdf"
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    # -- actions (role-gated) --
    @app.post("/api/baseline/lock")
    @require_cap("baseline")
    def api_lock():
        # if the running program has drifted, accepting it as the baseline without
        # review is a change-management error -> a "mistake"-category governance event.
        drifted = 0
        try:
            drifted = dash.diff().get("changed", 0)
        except Exception:  # noqa: BLE001
            drifted = 0
        dash.relock_baseline()
        dash.bus.emit_new("response.restore_baseline", "dashboard",
                          {"reason": f"Baseline re-locked by {session['user']}", "performed": True},
                          identity={"who": session["user"], "channel": "operator"})
        if drifted:
            dash.bus.emit_new(
                "cyber.baseline_relocked", "dashboard",
                {"reason": (f"{session['user']} accepted a DRIFTED program ({drifted} rung(s) changed) as the "
                            "new signed baseline without review — a change-management error"),
                 "changed": drifted},
                identity={"who": session["user"], "channel": "operator"},
                category="mistake")
        return jsonify({"status": "locked", "hash": dash.signed["manifest"]["structural_hash"],
                        "accepted_drift": drifted})

    # ── Insider attacker surface (C&I / Control Engineer on the engineering workstation) ──
    # These push program logic through the download channel -> classified INTERNAL.
    INSIDER_ATTACKS = {
        "logic-inversion": "Invert the drum-level trip comparator (LES → GRT)",
        "condition-stripping": "Strip the Plant_Running interlock from the flame trip",
        "coil-hijack": "Redirect the Feedwater_Trip output coil",
        "rung-injection": "Inject a hidden backdoor rung",
        "program-setpoint": "Lower the drum-level trip setpoint 220 → 40 in the program",
    }

    @app.get("/api/insider/attacks")
    @require_cap("baseline")
    def api_insider_list():
        return jsonify({"attacks": [{"id": k, "desc": v} for k, v in INSIDER_ATTACKS.items()],
                        "target": config.PI_HOST})

    @app.post("/api/insider/attack/<atk>")
    @require_cap("baseline")
    def api_insider_attack(atk):
        from logicward.attacker.terminal import run_scoped
        if atk not in INSIDER_ATTACKS:
            return jsonify({"ok": False, "output": f"unknown insider attack: {atk}"}), 404
        cmd = f"python -m logicward.attacker.attacks --host {config.PI_HOST} --modbus-port {config.MODBUS_PORT} {atk}"
        ok, out = run_scoped(cmd)
        return jsonify({"ok": ok, "output": out, "cmd": cmd})

    @app.post("/api/insider/exec")
    @require_cap("baseline")
    def api_insider_exec():
        from logicward.attacker.terminal import run_scoped
        data = request.get_json(silent=True) or {}
        ok, out = run_scoped(data.get("cmd", ""))
        return jsonify({"ok": ok, "output": out})

    @app.post("/api/response/ack")
    @require_cap("ack")
    def api_ack():
        d = request.get_json(silent=True) or {}
        ev = dash.response.operator_ack(d.get("ref", ""), actor=session["user"], note=d.get("note"))
        return jsonify(ev)

    @app.post("/api/response/quarantine")
    @require_cap("network_response")
    def api_quarantine():
        d = request.get_json(silent=True) or {}
        ev = dash.response.quarantine_device(d.get("mac", "?"), d.get("ip"), actor=session["user"],
                                             ref=d.get("ref"))
        return jsonify(ev)

    @app.post("/api/response/safe_state")
    @require_cap("safe_state")
    def api_safe_state():
        d = request.get_json(silent=True) or {}
        ev = dash.response.recommend_safe_state(d.get("rung_id"), actor=session["user"], ref=d.get("ref"))
        return jsonify(ev)

    @app.post("/api/response/restore")
    @require_cap("baseline")
    def api_restore():
        d = request.get_json(silent=True) or {}
        ev = dash.response.restore_baseline(actor=session["user"], ref=d.get("ref"))
        return jsonify(ev)

    return app


def main() -> None:
    app = create_app()
    print("Vigilo SOC dashboard")
    print(f"  http://0.0.0.0:{config.INGEST_PORT}/   (login: soc/soc123)")
    app.run(host=config.INGEST_HOST, port=config.INGEST_PORT, threaded=True)


if __name__ == "__main__":
    main()
