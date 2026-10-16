"""Scheduled report delivery (daily / weekly) through the report channels.

Each schedule has a *slot* (e.g. every day 20:00). For every slot Kaguya makes
at most two attempts:

  1. at the slot time (or as soon as it is running after that), and
  2. if any channel failed or nothing was sent, one retry at `retry_hour`
     (default 08:00 the next morning), only to the channels that still
     haven't received it.

State lives in the database, so restarts never skip or duplicate a report.
Runs in its own daemon thread.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta

from . import reports
from .notify import build_report_channels

RETRY_GAP_SEC = 1800          # never hammer a failing channel


class ReportScheduler:
    def __init__(self, config, storage, channels=None):
        self.config = config
        self.storage = storage
        self.channels = build_report_channels(config) if channels is None else channels
        self._stop = threading.Event()
        self._thread = None

    # which schedules are on: name -> report period
    def _schedules(self):
        return {name: period for name, period in (("daily", "day"), ("weekly", "week"))
                if self.config.get(f"reports.{name}.enabled", False)}

    def due_time(self, name, now=None):
        """Most recent moment this schedule's slot opened (epoch seconds)."""
        now = now or datetime.now()
        hour = int(self.config.get(f"reports.{name}.hour", 20)) % 24
        t = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if name == "weekly":
            wd = int(self.config.get("reports.weekly.weekday", 0)) % 7
            t -= timedelta(days=(t.weekday() - wd) % 7)
        if t > now:
            t -= timedelta(days=7 if name == "weekly" else 1)
        return t.timestamp()

    def retry_time(self, name, due_ts):
        """First `retry_hour` o'clock strictly after the slot opened."""
        hour = int(self.config.get(f"reports.{name}.retry_hour", 8)) % 24
        d = datetime.fromtimestamp(due_ts)
        r = d.replace(hour=hour, minute=0, second=0, microsecond=0)
        if r <= d:
            r += timedelta(days=1)
        return r.timestamp()

    # --- state -------------------------------------------------------------
    def _load(self, name, slot):
        try:
            st = json.loads(self.storage.get_meta(f"report.state.{name}") or "{}")
        except ValueError:
            st = {}
        if st.get("slot") != slot:                       # a new slot: start fresh
            st = {"slot": slot, "tries": 0, "last": 0.0, "done": False, "pending": None}
        return st

    def _save(self, name, st):
        self.storage.set_meta(f"report.state.{name}", json.dumps(st))

    # --- delivery ----------------------------------------------------------
    def _deliver(self, period, subject, fmt="pdf", only=None):
        """Send to channels (optionally only those named). Returns {channel: error}."""
        rep = reports.build_report(self.storage, period)
        text = reports.summary_text(rep)
        mime, ext = reports.FORMATS[fmt]
        attachment = (reports.filename(rep, ext), reports.render(rep, fmt), mime)
        failures = {}
        for ch in self.channels:
            if only is not None and ch.name not in only:
                continue
            try:
                ch(subject, text, attachment)
            except Exception as e:
                failures[ch.name] = str(e)
        return failures

    def deliver(self, period, subject, fmt="pdf"):
        """One-off send to every channel (used by `kaguya report --send`)."""
        return [f"{n}: {e}" for n, e in self._deliver(period, subject, fmt).items()]

    def tick(self, now=None):
        """Attempt anything due. Returns the schedule names attempted this tick."""
        t = time.time() if now is None else now
        attempted = []
        for name, period in self._schedules().items():
            slot = self.due_time(name, datetime.fromtimestamp(t))
            st = self._load(name, slot)
            if st["done"] or st["tries"] >= 2:
                continue
            if st["tries"] == 0:
                ready = t >= slot
            else:                                         # the 8am retry
                ready = t >= self.retry_time(name, slot) and t - st["last"] >= RETRY_GAP_SEC
            if not ready:
                continue
            only = st["pending"]
            failures = self._deliver(period, f"Kaguya {name} security report", only=only)
            failures.pop("console", None)
            st["tries"] += 1
            st["last"] = t
            st["pending"] = sorted(failures) if failures else None
            st["done"] = not failures
            self._save(name, st)
            attempted.append(name)
        return attempted

    # --- thread ------------------------------------------------------------
    def start(self):
        if not self._schedules():
            return
        self._thread = threading.Thread(target=self._run, name="cs-reports", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                pass
            self._stop.wait(60)
