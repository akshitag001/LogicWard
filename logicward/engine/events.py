"""The LogicWard event bus — the spine every detector feeds.

One `Event` contract, three planes (cyber / physical / resource) + response
actions, two emit paths (local in-process and remote via HTTP ingest). On every
`emit()` the bus validates, enriches (severity + MITRE + identity + seq), then
fans out to three sinks: the append-only evidence log, the dashboard poll buffer,
and any live subscribers.

See DESIGN.md §3–§4 for the full specification.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from logicward import config
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
    "cyber.branch_restructure":  75,   # AND/OR regrouping — e.g. a trip now fires on OR not AND
    "cyber.setpoint_drift":      55,   # threshold moved (escalates on a safety rung)
    "cyber.tag_value_change":    50,   # non-setpoint tag/constant/preset changed in the program
    "cyber.routine_added":       75,   # a non-ladder routine (ST/FBD/SFC) was added
    "cyber.routine_removed":     75,   # a routine was removed from the program
    "cyber.routine_modified":    75,   # a non-ladder routine body changed
    "cyber.task_change":         60,   # task scheduling changed (rate/scheduled programs)
    "cyber.register_change":     35,   # raw value moved — corroborated by other signals
    "cyber.baseline_tamper":     95,   # the signed baseline itself was altered off-platform
    "baseline.initial_capture":   0,   # trust-on-first-use capture (informational)
    "cyber.drift_cleared":        0,   # a previously-detected drift returned to baseline (info)
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
    "response.login":                0,
    "response.login_failed":        20,
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

GENESIS = "GENESIS"
CHECKPOINT_EVERY = 50


def _entry_hash(prev_hash: str, payload: dict) -> str:
    """sha256(prev_hash + canonical JSON of the line WITHOUT its entry_hash)."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def _chain_hmac(entry_hash: str) -> str:
    return "hmac-sha256:" + hmac.new(config.HMAC_KEY.encode("utf-8"),
                                     entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_chain(path: str | Path) -> tuple[bool, int | None]:
    """Verify the hash chain. Returns (ok, first_bad_line) — 1-indexed line number
    of the first tampered/broken entry, or None when the whole chain is intact."""
    p = Path(path)
    if not p.exists():
        return True, None
    prev = GENESIS
    for i, ln in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        if not ln.strip():
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            return False, i
        stored = rec.get("entry_hash")
        if rec.get("prev_hash") != prev or not stored:
            return False, i
        payload = {k: v for k, v in rec.items() if k not in ("entry_hash", "hmac")}
        if _entry_hash(prev, payload) != stored:
            return False, i
        if rec.get("checkpoint") and rec.get("hmac") != _chain_hmac(stored):
            return False, i
        prev = stored
    return True, None


class EvidenceLog:
    """Thread-safe, append-only, HASH-CHAINED JSONL store (Prompt 3.1).

    Each line carries prev_hash + entry_hash; every CHECKPOINT_EVERY entries (and on
    close) an HMAC-signed checkpoint pins the chain head, so a tampered line is
    detectable and the head cannot be silently recomputed without the key."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._head = GENESIS
        self._since_checkpoint = 0
        self._resume_head()

    def _resume_head(self) -> None:
        if not self.path.exists():
            return
        last = None
        for ln in self.path.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                last = ln
        if last:
            try:
                self._head = json.loads(last).get("entry_hash") or GENESIS
            except ValueError:
                self._head = GENESIS

    def _write_record(self, record: dict) -> dict:
        record["prev_hash"] = self._head
        record["entry_hash"] = _entry_hash(self._head, record)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._head = record["entry_hash"]
        return record

    def append(self, event: dict) -> None:
        with self._lock:
            self._write_record(dict(event))
            self._since_checkpoint += 1
            if self._since_checkpoint >= CHECKPOINT_EVERY:
                self._checkpoint_locked()

    def _checkpoint_locked(self) -> None:
        rec = self._write_record({"checkpoint": True, "type": "evidence.checkpoint",
                                  "timestamp": now_iso()})
        rec["hmac"] = _chain_hmac(rec["entry_hash"])     # sign the chain head
        self._rewrite_last(rec)
        self._since_checkpoint = 0

    def _rewrite_last(self, rec: dict) -> None:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[-1] = json.dumps(rec, ensure_ascii=False)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def checkpoint(self) -> None:
        """Write a signed checkpoint now (e.g. on shutdown)."""
        with self._lock:
            if self._since_checkpoint:
                self._checkpoint_locked()

    def verify(self) -> tuple[bool, int | None]:
        with self._lock:
            return verify_chain(self.path)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock:
            text = self.path.read_text(encoding="utf-8")
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]

    def _truncate_for_tests(self) -> None:
        """Test-only: wipe the log. Never reachable from HTTP — the evidence log
        is append-only in normal operation (deleting it is MITRE ICS T0872)."""
        with self._lock:
            if self.path.exists():
                self.path.write_text("", encoding="utf-8")
            self._head = GENESIS
            self._since_checkpoint = 0


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
        """Test-only: clear the in-memory poll buffer. Does NOT touch the
        evidence log on disk — that record is append-only."""
        with self._lock:
            self._history.clear()
            self._seen_ids.clear()
            self._seq = 0

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
