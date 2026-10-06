"""Passive File Integrity Monitoring (FIM) via watchdog.

Real-time, OS-level file watching — no polling of the PLC. Two roles (DESIGN:
FIM watches BOTH files):

  * Pi side — watch the running program ``live.L5X``. Any modify/create/move is
    an out-of-band program tamper: a second attack channel distinct from the
    ``POST /program/download`` API. Emits ``cyber.program_file_modified`` with
    the new structural hash.
  * Laptop side — watch the signed baseline manifest. If it changes, re-verify
    the HMAC; a break emits a ``critical`` ``cyber.baseline_tamper``, a valid
    re-sign emits an informational ``cyber.baseline_relocked``.

`emit` is any callable taking an Event dict (the agent Forwarder's `enqueue`, or
a bus's `emit`) so the same sensor works on either host. watchdog is imported
defensively; without it the sensor degrades to an explicit `.scan()` call so the
pipeline still runs.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

from logicward.engine import baseline as bl
from logicward.engine import l5x
from logicward.engine.events import new_event

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    _HAVE_WATCHDOG = True
except Exception:  # noqa: BLE001 - optional dependency; fall back to manual scan
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore
    _HAVE_WATCHDOG = False

EmitFn = Callable[[dict], None]


def _sha_of(path: Path) -> str | None:
    try:
        return l5x.structural_hash(l5x.load(path))
    except Exception:  # noqa: BLE001
        return None


class ProgramFileMonitor:
    """Watch the live program file for out-of-band tampering."""

    def __init__(self, path: str | Path, emit: EmitFn, source: str = "fim_watch",
                 debounce: float = 0.4):
        self.path = Path(path)
        self.emit = emit
        self.source = source
        self.debounce = debounce
        self._last_hash = _sha_of(self.path)
        self._last_event = 0.0
        self._observer = None

    def scan(self) -> dict | None:
        """Check the file once; emit if its structural hash changed. Returns the
        event (or None). Usable directly when watchdog is unavailable."""
        current = _sha_of(self.path)
        if current is None or current == self._last_hash:
            self._last_hash = current if current else self._last_hash
            return None
        prev, self._last_hash = self._last_hash, current
        ev = new_event("cyber.program_file_modified", self.source, {
            "path": str(self.path),
            "baseline_hash": prev,
            "current_hash": current,
            "reason": f"Program file {self.path.name} modified out-of-band (FIM)",
        }, identity={"who": "unknown", "channel": "file-tamper"})
        self.emit(ev)
        return ev

    def start(self) -> "ProgramFileMonitor":
        if not _HAVE_WATCHDOG:
            return self
        handler = _Handler(self)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.path.parent), recursive=False)
        self._observer.start()
        return self

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)

    def _on_change(self, changed: Path) -> None:
        if changed.name != self.path.name:
            return
        now = time.time()
        if now - self._last_event < self.debounce:  # collapse editor multi-writes
            return
        self._last_event = now
        self.scan()


class BaselineFileMonitor:
    """Watch the signed baseline manifest; re-verify HMAC on any change."""

    def __init__(self, path: str | Path, emit: EmitFn, source: str = "fim_watch",
                 debounce: float = 0.4):
        self.path = Path(path)
        self.emit = emit
        self.source = source
        self.debounce = debounce
        self._last_event = 0.0
        self._observer = None

    def scan(self) -> dict | None:
        try:
            signed = bl.load(self.path)
        except Exception:  # noqa: BLE001
            return None
        if bl.verify(signed):
            ev = new_event("cyber.baseline_relocked", self.source, {
                "path": str(self.path),
                "reason": "Baseline manifest changed and re-verified (new approved lock)",
            }, severity="info", identity={"who": "engineer", "channel": "file-tamper"})
        else:
            ev = new_event("cyber.baseline_tamper", self.source, {
                "path": str(self.path), "safety_critical": True,
                "reason": "Locked baseline altered on disk — HMAC signature no longer valid",
            }, severity="critical", identity={"who": "unknown", "channel": "file-tamper"})
        self.emit(ev)
        return ev

    def start(self) -> "BaselineFileMonitor":
        if not _HAVE_WATCHDOG:
            return self
        handler = _Handler(self)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.path.parent), recursive=False)
        self._observer.start()
        return self

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)

    def _on_change(self, changed: Path) -> None:
        if changed.name != self.path.name:
            return
        now = time.time()
        if now - self._last_event < self.debounce:
            return
        self._last_event = now
        self.scan()


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor):
        self._monitor = monitor

    def on_modified(self, event):
        if not event.is_directory:
            self._monitor._on_change(Path(event.src_path))

    def on_created(self, event):
        if not event.is_directory:
            self._monitor._on_change(Path(event.src_path))

    def on_moved(self, event):
        dest = getattr(event, "dest_path", None)
        if dest:
            self._monitor._on_change(Path(dest))


def available() -> bool:
    return _HAVE_WATCHDOG
