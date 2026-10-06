"""LogicWard deployment configuration.

Defaults are safe for a single-machine dev run (everything on localhost).
For the split Pi/laptop topology, override per host with LOGICWARD_* environment
variables — e.g. on the Pi set ``LOGICWARD_INGEST_URL`` to the laptop's LAN IP.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f"LOGICWARD_{name}", default)


# ── Laptop: ingest endpoint + dashboard ───────────────────────────────────────
INGEST_HOST = _env("INGEST_HOST", "0.0.0.0")
INGEST_PORT = int(_env("INGEST_PORT", "8080"))
# Shared secret the agent presents in the X-LogicWard-Token header. Demo-grade —
# a single static token, documented as such. Change it for any shared network.
INGEST_TOKEN = _env("TOKEN", "logicward-dev-token-change-me")

# URL the Pi agent POSTs events to. On the Pi: LOGICWARD_INGEST_URL=http://<laptop-ip>:8080/api/ingest
INGEST_URL = _env("INGEST_URL", f"http://127.0.0.1:{INGEST_PORT}/api/ingest")

# URL the Pi agent POSTs live CPU/RAM/temp telemetry to (same host/token as ingest).
TELEMETRY_URL = _env("TELEMETRY_URL", INGEST_URL.replace("/api/ingest", "/api/telemetry"))

# ── Pi: PLC (Modbus) + program endpoints ──────────────────────────────────────
PI_HOST = _env("PI_HOST", "127.0.0.1")
MODBUS_PORT = int(_env("MODBUS_PORT", "5020"))          # 502 needs root; 5020 for dev
PROGRAM_PORT = int(_env("PROGRAM_PORT", "8081"))
PROGRAM_URL = _env("PROGRAM_URL", f"http://{PI_HOST}:{PROGRAM_PORT}/program")
# Pi-side write-attribution HTTP endpoint (who wrote which Modbus register/coil)
WRITES_PORT = int(_env("WRITES_PORT", "5024"))

# ── Engine + agent timing (seconds) ───────────────────────────────────────────
POLL_INTERVAL_SEC = float(_env("POLL_INTERVAL", "1.0"))
AGENT_FLUSH_INTERVAL_SEC = float(_env("AGENT_FLUSH_INTERVAL", "1.0"))

# ── Baseline integrity ────────────────────────────────────────────────────────
# HMAC-SHA256 key that signs the locked baseline. Demo-grade (a static key) —
# it detects tamper-without-the-key, not a full KMS. Change it per deployment.
HMAC_KEY = _env("HMAC_KEY", "logicward-baseline-signing-key-change-me")

# ── Site B: GRFICS chemical reactor (3D demo) ─────────────────────────────────
# The compiled Unity WebGL build ships with the GRFICS repo (sibling of this one
# by default). Override with LOGICWARD_GRFICS_BUILD_DIR if you move it.
GRFICS_BUILD_DIR = Path(_env(
    "GRFICS_BUILD_DIR",
    str(Path(__file__).resolve().parents[2]
        / "Open Source OT Security Lab" / "GRFICSv3"
        / "simulation" / "web_visualization")))
GRFICS_MODBUS_PORT = int(_env("GRFICS_MODBUS_PORT", "5021"))
GRFICS_DASH_PORT = int(_env("GRFICS_DASH_PORT", "8095"))
# Bind address for the chemical (Site B) Modbus server. Localhost by default;
# set LOGICWARD_GRFICS_MODBUS_HOST=0.0.0.0 to accept attacks from a second laptop
# (the two-laptop demo — the attacker's real IP then shows up as "by whom").
GRFICS_MODBUS_HOST = _env("GRFICS_MODBUS_HOST", "127.0.0.1")

# ── Storage ───────────────────────────────────────────────────────────────────
DATA_DIR = Path(_env("DATA_DIR", str(Path(__file__).resolve().parent / "data")))
EVIDENCE_PATH = Path(_env("EVIDENCE_PATH", str(DATA_DIR / "evidence.jsonl")))
BASELINE_MANIFEST_PATH = Path(_env("BASELINE_MANIFEST", str(DATA_DIR / "baseline.signed.json")))
EVENT_HISTORY_MAX = int(_env("EVENT_HISTORY_MAX", "5000"))
