"""Agent-side event forwarder (DESIGN.md §3.5).

Physical/resource sensors run on the Pi, but the bus lives on the laptop. The
forwarder buffers Events locally and POSTs them to `/api/ingest` in batches,
retrying with exponential backoff and *keeping the buffer* if the laptop is
briefly unreachable — so physical events are never silently lost. Because every
Event carries a stable `event_id`, the ingest endpoint is idempotent and a
retried batch is de-duplicated server-side.
"""
from __future__ import annotations

import threading
from collections import deque

import requests

from logicward import config
from logicward.engine.events import new_event


class Forwarder:
    def __init__(self, url: str | None = None, token: str | None = None,
                 flush_interval: float | None = None, max_buffer: int = 5000,
                 timeout: float = 5.0):
        self.url = url or config.INGEST_URL
        self.token = token or config.INGEST_TOKEN
        self.flush_interval = flush_interval or config.AGENT_FLUSH_INTERVAL_SEC
        self.timeout = timeout
        self._buf: deque[dict] = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._backoff = 1.0
        self._backoff_max = 30.0
        # observability counters (handy in the smoke test + a future agent status page)
        self.sent = 0
        self.failed_flushes = 0
        self.dropped_poison = 0

    # -- producer API (sensors call these) --
    def emit(self, event_type: str, source: str, details: dict | None = None,
             **kwargs) -> dict:
        """Build a standard Event and queue it for delivery."""
        ev = new_event(event_type, source, details, **kwargs)
        self.enqueue(ev)
        return ev

    def enqueue(self, event: dict) -> None:
        with self._lock:
            self._buf.append(event)

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._buf)

    # -- lifecycle --
    def start(self) -> "Forwarder":
        if self._thread and self._thread.is_alive():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="lw-forwarder", daemon=True)
        self._thread.start()
        return self

    def stop(self, drain: bool = True) -> None:
        if drain:
            self.flush()
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            ok = self.flush()
            self._stop.wait(self.flush_interval if ok else self._backoff)

    # -- delivery --
    def flush(self) -> bool:
        """Try to deliver everything currently buffered. Returns True on success
        (or when there's nothing to send)."""
        with self._lock:
            if not self._buf:
                return True
            batch = list(self._buf)

        try:
            resp = requests.post(
                self.url,
                json={"events": batch},
                headers={"X-LogicWard-Token": self.token,
                         "Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except requests.RequestException:
            self.failed_flushes += 1
            self._backoff = min(self._backoff * 2, self._backoff_max)
            return False

        if resp.status_code == 200:
            self._drop_from_front(len(batch))
            try:
                self.sent += resp.json().get("accepted", len(batch))
            except Exception:
                self.sent += len(batch)
            self._backoff = 1.0
            return True

        if resp.status_code == 422:
            # Poison batch (schema rejected) — drop it rather than loop forever.
            self._drop_from_front(len(batch))
            self.dropped_poison += len(batch)

        # 401 (bad token) and other errors: keep the buffer, back off, retry.
        self.failed_flushes += 1
        self._backoff = min(self._backoff * 2, self._backoff_max)
        return False

    def _drop_from_front(self, count: int) -> None:
        with self._lock:
            for _ in range(count):
                if self._buf:
                    self._buf.popleft()
