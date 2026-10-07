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
import secrets
import threading
import time
from datetime import timedelta

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for

# ── RBAC — 6 OT/ICS roles, capability-based ──────────────────────────────────
# These are the six functional roles shown on the "Roles & Access" tab. Access is
# gated by CAPABILITY (what a role may DO), not a linear rank, because the roles
# have different scopes (a Network Engineer can quarantine a device but not touch
# the PLC program; a Control Engineer is the reverse).
from werkzeug.security import check_password_hash, generate_password_hash

from logicward import config
from logicward.agent.sensors.fim_watch import BaselineFileMonitor
from logicward.agent.sensors.resource import ResourceMonitor
from logicward.dashboard import evidence as evidence_mod
from logicward.engine import baseline as bl
from logicward.engine import events as events_mod
from logicward.engine import l5x, l5x_diff
from logicward.engine.drift import DriftEngine
from logicward.engine.events import EventBus
from logicward.engine.response import ResponseEngine
from logicward.engine.server import api as engine_api
from logicward.engine.sources import EmbeddedPlant, RemotePlant
from logicward.sites import registry

# Demo credentials (unchanged usernames/passwords) — but stored as salted PBKDF2
# hashes, never plaintext (Prompt 2.4). The hashes are derived once at import.
_DEMO_PASSWORDS = {
    "operator": "operator123", "engineer": "engineer123", "netsec": "netsec123",
    "soc": "soc123", "vendor": "vendor123", "ciso": "ciso123",
}
_ROLE_NAMES = {
    "operator": ("operator",         "Operator (Control Room)"),
    "engineer": ("control_engineer", "C&I / Control Engineer"),
    "netsec":   ("network_engineer", "OT Network / Security Engineer"),
    "soc":      ("soc_analyst",      "SOC Analyst"),
    "vendor":   ("vendor",           "Vendor / OEM Contractor"),
    "ciso":     ("ciso",             "CISO / Plant Cyber Head"),
}
USERS = {
    u: {"pw_hash": generate_password_hash(pw), "role": _ROLE_NAMES[u][0], "name": _ROLE_NAMES[u][1]}
    for u, pw in _DEMO_PASSWORDS.items()
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
        # Baseline integrity state (Prompt 2.2 — fail closed):
        #   VALID   — signature verified, detection running
        #   INITIAL — trust-on-first-use capture (no prior file); review it
        #   INVALID — saved baseline failed HMAC verify; detection PAUSED
        self.baseline_state = "VALID"
        self.signed = self._load_or_capture_baseline()
        self.baseline_prog = l5x.parse(self.signed["manifest"]["l5x"].encode())

        self.drift = DriftEngine(self.bus, self.signed,
                                 program_source=self.plant.program_source,
                                 register_source=self.plant.register_source,
                                 who_source=self._who,
                                 journal_source=getattr(self.plant, "write_journal", None))
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

        # Acknowledged alerts — event_ids an operator has acked. Acking HIDES an
        # alert from the active feed; it never deletes evidence (append-only).
        self.acked_ids: set[str] = set()

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def ack_event(self, event_id: str) -> None:
        if event_id:
            self.acked_ids.add(event_id)

    def ack_all(self) -> int:
        """Mark every currently-open (non-response) alert acknowledged. Returns
        the number newly acked. Destroys nothing — the evidence log is untouched."""
        newly = 0
        for e in self.bus.snapshot():
            eid = e.get("event_id")
            if not eid or eid in self.acked_ids:
                continue
            if str(e.get("type", "")).startswith("response."):
                continue
            self.acked_ids.add(eid)
            newly += 1
        return newly

    # -- baseline lifecycle --
    def _load_or_capture_baseline(self) -> dict:
        """Load the signed baseline, FAILING CLOSED on tamper (Prompt 2.2).

        * File missing  -> trust-on-first-use capture, state INITIAL.
        * File present + signature verifies -> state VALID.
        * File present + signature FAILS -> we do NOT silently re-capture the
          (possibly attacker-approved) live program. We quarantine the file,
          raise a critical cyber.baseline_tamper, and come up in INVALID state
          with detection paused until an engineer/CISO deliberately re-locks.
        """
        if not self.baseline_path.exists():
            signed = self._capture_baseline(source="initial")
            self.baseline_state = "INITIAL"
            self.bus.emit_new("baseline.initial_capture", "dashboard", {
                "reason": "Trust-on-first-use baseline captured (no prior signed baseline on disk) — review it",
                "controller": signed["manifest"]["controller"],
                "structural_hash": signed["manifest"]["structural_hash"],
            }, identity={"who": "dashboard", "channel": "operator"})
            return signed

        try:
            signed = bl.load(self.baseline_path)
        except Exception:  # noqa: BLE001 - unreadable/corrupt file is also tamper
            signed = None

        if signed is not None and bl.verify(signed):
            self.baseline_state = "VALID"
            return signed

        # --- fail closed: quarantine the tampered file, do NOT overwrite it ---
        quarantined = None
        try:
            ts = time.strftime("%Y%m%d-%H%M%S")
            quarantined = self.baseline_path.with_suffix(
                self.baseline_path.suffix + f".tampered-{ts}")
            self.baseline_path.rename(quarantined)
        except Exception:  # noqa: BLE001
            quarantined = None

        self.baseline_state = "INVALID"
        self.bus.emit_new("cyber.baseline_tamper", "dashboard", {
            "reason": ("Signed baseline failed HMAC verification at startup — the file was "
                       "modified off-platform. Detection is PAUSED and the live program was "
                       "NOT accepted. An engineer/CISO must review and re-lock."),
            "safety_critical": True,
            "quarantined_to": str(quarantined) if quarantined else None,
            "baseline_path": str(self.baseline_path),
        }, severity="critical", identity={"who": "unknown", "channel": "host"})

        # Keep the (unverified) manifest in memory only so the object can build;
        # the drift loop is gated on baseline_state and will not run detection.
        if signed is None:
            signed = self._capture_baseline(source="file", save=False)
        return signed

    def _capture_baseline(self, source: str | None = None, save: bool = True) -> dict:
        """Capture + sign a baseline. Source of the approved program:
        LOGICWARD_BASELINE_SOURCE=file (default) uses the shipped, reviewed
        ThermalPlant_baseline.L5X; =live captures whatever the PLC is running now."""
        src = source or os.environ.get("LOGICWARD_BASELINE_SOURCE", "file")
        from logicward.plant.logic_store import BASELINE_PATH as SHIPPED_BASELINE
        if src in ("file", "initial") and SHIPPED_BASELINE.exists():
            program_xml = SHIPPED_BASELINE.read_bytes()
        else:
            program_xml = self.plant.program_source()
        signed = bl.capture(program_xml, self.plant.register_source())
        if save:
            bl.save(signed, self.baseline_path)
        return signed

    def relock_baseline(self) -> dict:
        # Re-locking deliberately accepts the CURRENTLY running program as the new
        # approved baseline (the engineer has reviewed it), so capture from live.
        self.signed = self._capture_baseline(source="live")
        self.baseline_prog = l5x.parse(self.signed["manifest"]["l5x"].encode())
        self.baseline_state = "VALID"
        self.drift = DriftEngine(self.bus, self.signed,
                                 program_source=self.plant.program_source,
                                 register_source=self.plant.register_source,
                                 who_source=self._who,
                                 journal_source=getattr(self.plant, "write_journal", None))
        self.drift.reset()
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
        self.drift.reset()   # Prompt 1.3: clear drift state so a re-applied attack alerts again
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
    def start(self) -> Dashboard:
        self.baseline_fim.start()
        self._thread = threading.Thread(target=self._loop, name="lw-drift", daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.baseline_state != "INVALID":   # fail closed: no detection on a tampered baseline
                    self.drift.run_once()
            except Exception as exc:  # noqa: BLE001
                self._report_loop_error("drift", exc)
            try:
                self._resmon.scan()          # edge-fire cpu/mem spike on sustained load
            except Exception as exc:  # noqa: BLE001
                self._report_loop_error("resource", exc)
            self._stop.wait(config.POLL_INTERVAL_SEC)

    def _report_loop_error(self, component: str, exc: Exception) -> None:
        """A crashed detector must be VISIBLE, not silently swallowed (Prompt 3.4)."""
        key = f"loop:{component}:{type(exc).__name__}"
        if events_mod.throttled_warn(key, f"{component} loop error: {type(exc).__name__}: {exc}"):
            try:
                self.bus.emit_new("system.detector_error", "dashboard", {
                    "component": component, "error": f"{type(exc).__name__}: {exc}",
                    "reason": f"{component} detector raised {type(exc).__name__} — see logs",
                }, identity={"who": "system", "channel": "host"})
            except Exception:  # noqa: BLE001
                pass

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
        if self.bus.evidence is not None:
            try:
                self.bus.evidence.checkpoint()
            except Exception:  # noqa: BLE001
                pass
        self.baseline_fim.stop()
        if hasattr(self.plant, "stop"):
            self.plant.stop()
        if self.chem is not None and hasattr(self.chem, "stop"):
            self.chem.stop()         # free the Site-B Modbus port (no leak across runs)

    # -- views' data --
    def overview(self) -> dict:
        events = self.bus.snapshot()
        counts = evidence_mod.summary(events)
        live = l5x.parse(self.plant.program_source())
        diff = l5x_diff.diff_programs(self.baseline_prog, live)
        chain_ok, chain_bad = (self.bus.evidence.verify() if self.bus.evidence else (True, None))
        integrity = "VALID" if bl.verify(self.signed) else "TAMPERED"
        if self.baseline_state == "INVALID":
            integrity = "TAMPERED"
        risk_score, risk_band = _risk(counts, integrity, diff["changed"] == 0)
        return {
            "controller": self.signed["manifest"]["controller"],
            "baseline_hash": self.signed["manifest"]["structural_hash"],
            "baseline_integrity": integrity,
            "evidence_chain": "VERIFIED" if chain_ok else f"BROKEN at line {chain_bad}",
            "evidence_chain_ok": chain_ok,
            "baseline_state": self.baseline_state,
            "baseline_invalid": self.baseline_state == "INVALID",
            "detection_paused": self.baseline_state == "INVALID",
            "baseline_initial": self.baseline_state == "INITIAL",
            "baseline_notice": (
                "BASELINE INVALID — signed baseline failed verification; detection is paused. "
                "An engineer or CISO must review and re-lock." if self.baseline_state == "INVALID"
                else "Trust-on-first-use baseline — review it." if self.baseline_state == "INITIAL"
                else None),
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
    # Session-cookie signing key (Prompt 2.3): never ship a static default.
    if config.demo_mode():
        app.secret_key = os.environ.get("LOGICWARD_SECRET") or secrets.token_hex(32)
        print("[LogicWard] DEMO MODE active — ephemeral session key + demo credentials. "
              "Set LOGICWARD_DEMO_MODE=0 (with LOGICWARD_SECRET/TOKEN/HMAC_KEY) for production.")
    else:
        missing = config.validate_secrets()
        if missing:
            raise RuntimeError(
                "Refusing to start with LOGICWARD_DEMO_MODE=0: set strong, non-default "
                "values for: " + ", ".join(missing) + ". See .env.example.")
        app.secret_key = os.environ["LOGICWARD_SECRET"]
    if embed is None:
        embed = os.environ.get("LOGICWARD_EMBED_PLANT", "1") != "0"
    dash = dashboard or Dashboard(embed=embed).start()

    # engine ingest/poll blueprint shares our bus + token
    app.config["LOGICWARD_BUS"] = dash.bus
    app.config["LOGICWARD_TOKEN"] = config.INGEST_TOKEN
    app.config["LOGICWARD_REQUIRE_SESSION"] = True   # /api/events needs a login here
    app.register_blueprint(engine_api)
    app.config["DASH"] = dash

    # -- session hardening (Prompt 2.4) --
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )

    # Site B (chemical reactor): mount its 3D scene + feed + APIs on this app so
    # both plants live under one dashboard, one bus, one login.
    if dash.chem is not None:
        from logicward.sites.grfics.blueprint import make_grfics_blueprint
        app.register_blueprint(make_grfics_blueprint(dash.chem))

    # -- CSRF: per-session token required on browser state-changing POSTs --
    # Machine endpoints (token-authed) are exempt; /login is form-posted pre-session.
    CSRF_EXEMPT = {"/api/ingest", "/api/telemetry", "/login"}

    @app.before_request
    def _csrf_guard():
        if session.get("user") in USERS and not session.get("csrf"):
            session["csrf"] = secrets.token_hex(16)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.path in CSRF_EXEMPT or not request.path.startswith("/api/"):
                return None
            tok = request.headers.get("X-CSRF-Token", "")
            if not tok or tok != session.get("csrf"):
                return jsonify({"error": "CSRF token missing or invalid"}), 400
        return None

    @app.get("/api/csrf")
    @login_required
    def api_csrf():
        return jsonify({"csrf": session.get("csrf", "")})

    # in-memory login rate limiter: 5 failures / minute / IP
    _login_fails: dict[str, list[float]] = {}

    def _rate_limited(ip: str) -> bool:
        now = time.time()
        hits = [t for t in _login_fails.get(ip, []) if now - t < 60]
        _login_fails[ip] = hits
        return len(hits) >= 5

    # -- auth --
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "?"
            if _rate_limited(ip):
                dash.bus.emit_new("response.login_failed", "dashboard",
                                  {"reason": f"Login rate limit hit from {ip}", "ip": ip, "rate_limited": True},
                                  identity={"who": ip, "channel": "operator"})
                return render_template("login.html", error="Too many attempts — wait a minute."), 429
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if u in USERS and check_password_hash(USERS[u]["pw_hash"], p):
                session.permanent = True
                session["user"] = u
                session["csrf"] = secrets.token_hex(16)
                _login_fails.pop(ip, None)
                dash.bus.emit_new("response.login", "dashboard",
                                  {"reason": f"Login success: {u}", "user": u, "ip": ip},
                                  identity={"who": u, "channel": "operator"})
                return redirect(url_for("dashboard_page"))
            _login_fails.setdefault(ip, []).append(time.time())
            dash.bus.emit_new("response.login_failed", "dashboard",
                              {"reason": f"Login failed for '{u}' from {ip}", "user": u, "ip": ip},
                              identity={"who": ip, "channel": "operator"})
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
                               role=role, caps=",".join(sorted(caps_for(role))),
                               csrf_token=session.get("csrf", ""))

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
        tok = request.headers.get("X-LogicWard-Token")   # header only (Prompt 2.4) — no ?token=
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
        chain_ok, chain_bad = (dash.bus.evidence.verify() if dash.bus.evidence else (True, None))
        return jsonify({"events": evidence_mod.query(dash.bus.snapshot(), severity=sev,
                                                     site=site, limit=300),
                        "chain": {"ok": chain_ok, "bad_line": chain_bad,
                                  "status": "VERIFIED" if chain_ok else f"BROKEN at line {chain_bad}"}})

    @app.post("/api/alerts/ack_all")
    @require_cap("ack_all")
    def api_alerts_ack_all():
        # Acknowledge (hide from the active feed) every open alert. This NEVER
        # deletes evidence — the forensic log on disk is append-only. Each
        # bulk-ack is itself recorded as a response.operator_ack event.
        n = dash.ack_all()
        dash.bus.emit_new("response.operator_ack", "dashboard",
                          {"reason": f"{session['user']} acknowledged all open alerts ({n})",
                           "bulk": True, "count": n},
                          identity={"who": session["user"], "channel": "operator"})
        return jsonify({"status": "acknowledged", "acknowledged": n,
                        "message": f"{n} alert(s) acknowledged. Evidence log is unchanged."})

    @app.post("/api/alerts/clear")
    @require_cap("ack_all")
    def api_alerts_clear_gone():
        # Removed: this used to wipe the evidence log (MITRE ICS T0872 Indicator
        # Removal on Host). Use POST /api/alerts/ack_all, which hides alerts
        # without destroying the forensic record.
        return jsonify({"error": "gone",
                        "message": "Endpoint removed. Use POST /api/alerts/ack_all; "
                                   "the evidence log is append-only and cannot be cleared."}), 410

    @app.get("/api/alerts/acked")
    @login_required
    def api_alerts_acked():
        return jsonify({"acked": sorted(dash.acked_ids)})

    def _build_report(site):
        # Build from the FULL evidence log on disk (not the capped in-memory buffer).
        if dash.bus.evidence is not None:
            events = [e for e in dash.bus.evidence.read_all() if not e.get("checkpoint")]
        else:
            events = dash.bus.snapshot()
        if site:
            events = evidence_mod.query(events, site=site, limit=10 ** 7)
        prof = registry.BY_ID.get(site)
        chain_ok, chain_bad = (dash.bus.evidence.verify() if dash.bus.evidence else (True, None))
        head = dash.bus.evidence._head if dash.bus.evidence else ""
        from logicward.dashboard import report_sign
        fp = report_sign.load_or_create_key()
        meta = {"controller": (prof.name if prof else dash.signed["manifest"]["controller"]),
                "baseline_hash": dash.signed["manifest"]["structural_hash"],
                "baseline_integrity": "VALID" if bl.verify(dash.signed) else "TAMPERED",
                "site": (prof.name if prof else "All sites")}
        chain = {"status": "VERIFIED" if chain_ok else f"BROKEN at line {chain_bad}",
                 "head": head, "fingerprint": report_sign._fingerprint(report_sign.public_pem(fp))}
        pdf = evidence_mod.build_pdf(events, meta, chain=chain)
        return pdf

    @app.get("/api/evidence/report.pdf")
    @require_cap("evidence")
    def api_report():
        site = request.args.get("site")
        pdf = _build_report(site)
        fname = f"logicward_{site or 'all-sites'}_report.pdf"
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    @app.get("/api/evidence/report.sig")
    @require_cap("evidence")
    def api_report_sig():
        from logicward.dashboard import report_sign
        pdf = _build_report(request.args.get("site"))
        return jsonify(report_sign.sign_pdf(pdf))

    @app.get("/api/evidence/report.zip")
    @require_cap("evidence")
    def api_report_zip():
        import io
        import zipfile

        from logicward.dashboard import report_sign
        site = request.args.get("site")
        pdf = _build_report(site)
        manifest = report_sign.sign_pdf(pdf)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("report.pdf", pdf)
            z.writestr("report.sig", report_sign.sig_json(manifest))
            z.writestr("report_pubkey.pem", manifest["public_key_pem"])
        fname = f"logicward_{site or 'all-sites'}_report.zip"
        return Response(buf.getvalue(), mimetype="application/zip",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    # -- actions (role-gated) --
    @app.post("/api/baseline/lock")
    @require_cap("baseline")
    def api_lock():
        # When the baseline is INVALID (startup tamper), re-locking requires an
        # engineer/CISO and a typed confirmation — it clears a fail-closed state.
        if dash.baseline_state == "INVALID":
            role = _current_role()
            if role not in ("control_engineer", "ciso"):
                return jsonify({"error": "baseline invalid — only an engineer or CISO may re-lock"}), 403
            confirm = (request.get_json(silent=True) or {}).get("confirm", "")
            if str(confirm).strip().upper() != "RELOCK":
                return jsonify({"error": "confirmation required",
                                "message": "Re-locking a tampered baseline requires confirm='RELOCK'."}), 428
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

    # NOTE (Prompt 2.5): the insider attack console lives in the red-team console
    # (logicward/attacker/dashboard), not in this defender app.

    @app.post("/api/response/ack")
    @require_cap("ack")
    def api_ack():
        d = request.get_json(silent=True) or {}
        ref = d.get("ref", "")
        dash.ack_event(ref)
        ev = dash.response.operator_ack(ref, actor=session["user"], note=d.get("note"))
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
    print(f"  http://{config.INGEST_HOST}:{config.INGEST_PORT}/   (login: soc/soc123)")
    app.run(host=config.INGEST_HOST, port=config.INGEST_PORT, threaded=True)


if __name__ == "__main__":
    main()
