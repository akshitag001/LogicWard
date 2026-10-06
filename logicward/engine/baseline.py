"""Baseline capture + HMAC-SHA256 signed lock.

Locking the approved configuration captures the L5X program, its structural
hash, the setpoints, and a register/coil snapshot into a manifest, then signs
the manifest with HMAC-SHA256. If anyone edits the locked baseline on disk, the
signature no longer verifies — tamper is detectable (DESIGN: the laptop FIM
watches this file and re-verifies on change).

Honest framing: HMAC detects tamper-without-the-key; it is integrity, not access
control. Appropriate and defensible for the appliance's evidence integrity story.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from logicward import config
from logicward.engine import l5x
from logicward.engine.events import now_iso

ALGO = "hmac-sha256"


def _key() -> bytes:
    return config.HMAC_KEY.encode("utf-8")


def _canonical_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(payload: bytes) -> str:
    return f"{ALGO}:" + hmac.new(_key(), payload, hashlib.sha256).hexdigest()


def capture(program_xml: bytes | str, registers: dict | None = None) -> dict:
    """Build a signed baseline manifest from an approved L5X + register snapshot.

    `registers` is the optional live snapshot: {"holding": {tag: raw}, "coils":
    {tag: bool}} — captured over Modbus at lock time.
    """
    if isinstance(program_xml, str):
        program_xml = program_xml.encode("utf-8")
    prog = l5x.parse(program_xml)
    manifest = {
        "version": 1,
        "created_at": now_iso(),
        "controller": prog.controller,
        "structural_hash": l5x.structural_hash(prog),
        "l5x": program_xml.decode("utf-8"),
        "setpoints": {k: prog.setpoints[k] for k in sorted(prog.setpoints)},
        "registers": registers or {},
    }
    return {"manifest": manifest, "algo": ALGO, "signature": sign(_canonical_bytes(manifest))}


def verify(signed: dict) -> bool:
    """True iff the signature still matches the manifest (constant-time compare)."""
    try:
        expected = sign(_canonical_bytes(signed["manifest"]))
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(expected, signed.get("signature", ""))


def save(signed: dict, path: str | Path | None = None) -> Path:
    p = Path(path or config.BASELINE_MANIFEST_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(signed, indent=2), encoding="utf-8")
    return p


def load(path: str | Path | None = None) -> dict:
    p = Path(path or config.BASELINE_MANIFEST_PATH)
    return json.loads(p.read_text(encoding="utf-8"))
