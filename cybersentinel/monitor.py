"""Monitor — the orchestrator thread.

Sweeps every enabled collector on a fixed interval, persists their events,
runs the detection engine over each sweep, persists any alerts, and
periodically enforces retention. Runs in a background thread so it can sit
alongside the HTTP API in one process.
"""

from __future__ import annotations

import threading
import time

from .collectors import build_collectors
from .detection import DetectionEngine
from .notify import build_notifier
from .scheduler import ReportScheduler
from .storage import Storage


class Monitor:
    def __init__(self, config, storage: Storage):
        self.config = config
        self.storage = storage
        self.host = config.get("host_label", "localhost")
        self.interval = max(1, int(config.get("collect_interval", 5)))
        self.collectors = build_collectors(config, host=self.host)
        self.engine = DetectionEngine(config, host=self.host)
        self.notifier = build_notifier(config)
        self.scheduler = ReportScheduler(config, storage)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_sweep = 0.0
        self.sweep_count = 0
        self.last_error = None
        self.started_at = 0.0

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._run, name="cs-monitor",
                                        daemon=True)
        self._thread.start()
        self.scheduler.start()

    def stop(self) -> None:
        self._stop.set()
        self.scheduler.stop()
        if self._thread:
            self._thread.join(timeout=self.interval + 2)

    # --- loop -------------------------------------------------------------
    def _run(self) -> None:
        retention_days = self.config.tier.get("retention_days", 7)
        last_retention = 0.0
        while not self._stop.is_set():
            start = time.time()
            try:
                self.sweep_once()
                if start - last_retention > 3600:
                    self.storage.enforce_retention(retention_days)
                    last_retention = start
            except Exception as exc:  # pragma: no cover
                self.last_error = str(exc)
            # sleep the remainder of the interval, but stay responsive to stop
            elapsed = time.time() - start
            self._stop.wait(max(0.0, self.interval - elapsed))

    def sweep_once(self) -> tuple[int, int]:
        """Run one full sweep. Returns (events, alerts) counts."""
        batch = []
        for collector in self.collectors:
            events = collector.safe_collect()
            for ev in events:
                self.storage.add_event(ev)
            batch.extend(events)
        alerts = self.engine.evaluate(batch)
        # drop anything the user marked "safe" (before storing or notifying)
        allowed = self.storage.allowed_keys()
        if allowed:
            alerts = [a for a in alerts if not self.storage.is_allowed(a, allowed)]
        for al in alerts:
            self.storage.add_alert(al)
        if alerts:
            self.notifier.dispatch(alerts)
        self.last_sweep = time.time()
        self.sweep_count += 1
        return len(batch), len(alerts)

    # --- introspection for the API ---------------------------------------
    def status(self) -> dict:
        return {
            "host": self.host,
            "tier": self.config.tier_name,
            "interval_sec": self.interval,
            "running": bool(self._thread and self._thread.is_alive()),
            "sweeps": self.sweep_count,
            "last_sweep": self.last_sweep,
            "started_at": self.started_at,
            "last_error": self.last_error,
            "collectors": [
                {"name": c.name, "primed": c._primed} for c in self.collectors
            ],
            "notifiers": self.notifier.active,
            "report_channels": [c.name for c in self.scheduler.channels],
            "can_block": bool(self.config.get("response.allow_block", True)),
            "notify_min_severity": self.notifier.min_severity.label,
        }
