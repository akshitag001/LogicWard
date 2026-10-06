"""Attack-origin classifier — mistake / internal / external.

The problem statement asks us to separate PLC drift by *who/why*: an accidental
unapproved change, a malicious insider on a legitimate engineering path, or an
external intruder. This is a pure, per-event heuristic on **observable IOCs**
(channel + magnitude + safety context), so it works even when the attacker and
the SOC share one host/IP (a single-laptop demo) — it never relies on the source
IP to tell the classes apart.

  external — untrusted origin / attack infrastructure:
    rogue device (unknown MAC), a network flood (resource.*), a physical tamper,
    or an unauthenticated Modbus register/coil force that defeats a safety
    function or drives a value outside the operating envelope.
  internal — legitimate engineering path, unauthorized change:
    a program-download logic change (logic inversion / condition stripping /
    coil hijack / rung injection) — the insider / compromised engineering
    workstation.
  mistake — an authorized-looking, small in-band setpoint change with no attack
    signature: the accidental / unapproved operator nudge.

Returned as (category, reason); the reason is the plain-English "why" shown in
the expanded log detail.
"""
from __future__ import annotations

# UI label + accent tone per category (kept here so the server and docs agree).
CATEGORY_META = {
    "external": {"label": "External", "tone": "external"},
    "internal": {"label": "Internal", "tone": "internal"},
    "mistake":  {"label": "Mistake",  "tone": "mistake"},
}

# a register change is "large" (outside a plausible operator nudge) past this
# fraction of the baseline value — used to split an external force from a slip.
_LARGE_FRACTION = 0.25


def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _is_large(details: dict) -> bool:
    """True if baseline->current is a big move (or a coil flip / drive to a rail)."""
    b, c = _num(details.get("baseline")), _num(details.get("current"))
    if b is None or c is None:
        # coil forces (True/False) and rail moves have no numeric baseline -> treat as large
        return details.get("coil") is not None
    denom = max(abs(b), 1.0)
    return abs(c - b) / denom > _LARGE_FRACTION


def classify_drift(etype: str, details: dict | None, identity: dict | None) -> tuple[str, str]:
    details = details or {}
    identity = identity or {}
    channel = identity.get("channel")
    safety = bool(details.get("safety_critical"))

    # ── external — untrusted origin / attack infrastructure ──
    if etype == "physical.rogue_device":
        return "external", "unrecognized device on the OT segment (unknown MAC)"
    if etype.startswith("resource."):
        return "external", "resource exhaustion consistent with a network flood (DoS)"
    if etype.startswith("physical."):
        return "external", "physical-layer tamper / link event on the OT segment"

    # ── internal — legitimate engineering path, unauthorized change ──
    if channel == "program-download":
        return "internal", "control logic modified through the engineering program-download channel"

    # ── register plane (unauthenticated Modbus write) ──
    if channel == "modbus-write":
        if safety:
            return "external", "unauthenticated Modbus write defeating a safety function"
        if _is_large(details):
            return "external", "unauthenticated Modbus force outside the operating envelope"
        return "mistake", "setpoint nudged within the plausible operating band — likely an unapproved operator change"

    # ── response / baseline-integrity / other control-plane drift ──
    if etype.startswith("response."):
        return "internal", "operator response action on the control plane"
    return "internal", "configuration drift on the control plane"
