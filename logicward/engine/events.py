"""The LogicWard event bus — the spine every detector feeds.

One `Event` contract, three planes (cyber / physical / resource) + response
actions, two emit paths (local in-process and remote via HTTP ingest). On every
`emit()` the bus validates, enriches (severity + MITRE + identity + seq), then
fans out to three sinks: the append-only evidence log, the dashboard poll buffer,
and any live subscribers.

See DESIGN.md §3–§4 for the full specification.
"""
from __future__ import annotations

import json
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from logicward.engine import mitre_map
from logicward.engine.classify import classify_drift

# ── The Event contract ────────────────────────────────────────────────────────

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")

#: Base severity weight per event type. All tuning lives here (DESIGN.md §4.3).
BASE_WEIGHTS: dict[str, int] = {
    "cyber.condition_stripping": 80,   # safety interlock removed — most dangerous
    "cyber.logic_inversion":     75,   # a trip that now fires backwards
    "cyber.coil_hijack":         70,   # control redirected to the wrong actuator
    "cyber.rung_injection":      70,   # foreign logic added to the program
    "cyber.setpoint_drift":      55,   # threshold moved (escalates on a safety rung)
    "cyber.register_change":     35,   # raw value moved — corroborated by other signals
    "physical.enclosure_open":   60,   # physical access to the cabinet
    "physical.rogue_device":     50,   # unknown MAC on the OT segment
    "physical.link_down":        45,   # cable pull / network isolation
    "physical.link_up":          10,   # informational recovery
    "resource.cpu_spike":        40,   # consistent with DDoS impact
    "resource.mem_spike":        40,
    "response.quarantine_device":   10,
    "response.recommend_safe_state":10,
    "response.restore_baseline":    10,
    "response.operator_ack":         5,
}
DEFAULT_WEIGHT = 30
SAFETY_MULTIPLIER = 1.25


def now_iso() -> str:
    """UTC timestamp, millisecond precision, e.g. 2026-07-27T18:22:04.517Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def compute_severity(event_type: str, details: dict) -> str:
    """Map an event to a severity band from its base weight + safety context."""
    base = BASE_WEIGHTS.get(event_type, DEFAULT_WEIGHT)
    score = base * (SAFETY_MULTIPLIER if details.get("safety_critical") else 1.0)
    score = min(score, 100.0)
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def channel_for_type(event_type: str) -> str:
    """The attack channel implied by an event type (for the identity record)."""
    if event_type in ("cyber.setpoint_drift", "cyber.register_change"):
        return "modbus-write"
    if event_type.startswith("cyber."):
        return "program-download"
    if event_type == "physical.rogue_device":
        return "network"
    if event_type.startswith("physical."):
        return "physical"
    if event_type.startswith("resource."):
        return "host"
    if event_type.startswith("response."):
        return "operator"
    return "unknown"


def new_event(event_type: str, source: str, details: dict | None = None, *,
              severity: str | None = None, timestamp: str | None = None,
              event_id: str | None = None, identity: dict | None = None,
              category: str | None = None) -> dict:
    """Build a well-formed (pre-enrichment) Event.

    `severity` left None means "let the bus compute it". `event_id` is always
    populated so remote ingest is idempotent across retries. `category` left None
    means "let the bus classify it"; pass it to override (e.g. a governance mistake).
    """
    ev = {
        "event_id": event_id or str(uuid.uuid4()),
        "type": event_type,
        "timestamp": timestamp or now_iso(),
        "source": source,
        "severity": severity,
        "details": dict(details or {}),
    }
    if identity:
        ev["identity"] = identity
    if category:
        ev["category"] = category
    return ev


def validate_event(ev: object) -> list[str]:
    """Return a list of schema problems ([] means valid)."""
    if not isinstance(ev, dict):
        return ["event is not a JSON object"]
    errors: list[str] = []
    for field in ("type", "source"):
        val = ev.get(field)
        if not isinstance(val, str) or not val:
            errors.append(f"missing/invalid required field: {field}")
    if "details" in ev and not isinstance(ev["details"], dict):
        errors.append("details must be an object")
    sev = ev.get("severity")
    if sev is not None and sev not in SEVERITY_LEVELS:
        errors.append(f"invalid severity: {sev!r}")
    return errors


# ── Evidence log (append-only sink) ───────────────────────────────────────────

class EvidenceLog:
    """Thread-safe append-only JSONL store — the forensic record (who/when/what)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock:
            text = self.path.read_text(encoding="utf-8")
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]

    def clear(self) -> None:
        with self._lock:
            if self.path.exists():
                self.path.write_text("", encoding="utf-8")


# ── The bus ───────────────────────────────────────────────────────────────────

class EventBus:
    """In-process publish/subscribe bus with evidence + poll-buffer sinks."""

    def __init__(self, evidence_path: str | Path | None = None,
                 history_max: int = 5000,
                 mitre_mapper: Callable[[str, dict], dict] | None = None):
        self._lock = threading.RLock()
        self._history: deque[dict] = deque(maxlen=history_max)
        self._subscribers: list[Callable[[dict], None]] = []
        self._seq = 0
        self._seen_ids: set[str] = set()
        self.evidence = EvidenceLog(evidence_path) if evidence_path else None
        self._mitre = mitre_mapper or mitre_map.map_event

    # -- publish --
    def emit(self, event: dict) -> dict | None:
        """Validate, enrich, and fan out one event.

        Returns the enriched event, or None if it was a duplicate (a retried
        remote emit with an event_id we've already accepted) — making ingest
        idempotent.
        """
        errors = validate_event(event)
        if errors:
            raise ValueError("invalid event: " + "; ".join(errors))

        with self._lock:
            eid = event.get("event_id")
            if eid and eid in self._seen_ids:
                return None  # idempotent drop
            self._seq += 1
            enriched = self._enrich(event, self._seq)
            if eid:
                self._seen_ids.add(eid)
            self._history.append(enriched)
            if self.evidence:
                self.evidence.append(enriched)
            subscribers = list(self._subscribers)

        for callback in subscribers:
            try:
                callback(enriched)
            except Exception:  # a bad subscriber must not break the bus
                pass
        return enriched

    def clear(self) -> None:
        """Clear all in-memory event history and the evidence log."""
        with self._lock:
            self._history.clear()
            self._seen_ids.clear()
            self._seq = 0
            if self.evidence:
                self.evidence.clear()

    def _enrich(self, event: dict, seq: int) -> dict:
        etype = event["type"]
        details = dict(event.get("details") or {})
        severity = event.get("severity") or compute_severity(etype, details)
        identity = dict(event.get("identity") or {})
        identity.setdefault("who", event["source"])
        identity.setdefault("mac", None)
        identity.setdefault("channel", channel_for_type(etype))
        category = event.get("category")
        if category:
            category_reason = event.get("category_reason") or "declared by the reporting surface"
        else:
            category, category_reason = classify_drift(etype, details, identity)
        return {
            "event_id": event.get("event_id") or str(uuid.uuid4()),
            "type": etype,
            "timestamp": event.get("timestamp") or now_iso(),
            "source": event["source"],
            "severity": severity,
            "details": details,
            "identity": identity,
            "category": category,
            "category_reason": category_reason,
            "mitre": self._mitre(etype, details),
            "received_at": now_iso(),
            "seq": seq,
        }

    # -- convenience local emit --
    def emit_new(self, event_type: str, source: str, details: dict | None = None,
                 **kwargs) -> dict | None:
        return self.emit(new_event(event_type, source, details, **kwargs))

    # -- subscribe --
    def subscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)

    # -- poll (dashboard) --
    def get_since(self, cursor: int) -> tuple[list[dict], int]:
        """Events with seq > cursor, plus the latest cursor value."""
        with self._lock:
            events = [e for e in self._history if e["seq"] > cursor]
            return events, self._seq

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._history)

    @property
    def latest_seq(self) -> int:
        with self._lock:
            return self._seq
