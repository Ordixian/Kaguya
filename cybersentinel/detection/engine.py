"""Detection engine: runs rules over each sweep's events and de-duplicates.

The engine keeps a short rolling history of events in memory so that
windowed rules (brute-force, fan-out) have context without hammering the
database. It also suppresses duplicate alerts: an identical (rule, key)
within a cooldown window is dropped so the dashboard is not flooded.
"""

from __future__ import annotations

import time

from .rules import ALL_RULES, RuleContext
from ..events import Event, Alert


class DetectionEngine:
    def __init__(self, config, host: str = "localhost",
                 history_sec: int = 900, cooldown_sec: int = 120,
                 rules=None):
        self.config = config
        self.host = host
        self.history_sec = history_sec
        self.cooldown_sec = cooldown_sec
        self.rules = rules if rules is not None else ALL_RULES
        self._history: list[Event] = []
        self._recent_alert_keys: dict[str, float] = {}

    def _prune_history(self):
        cutoff = time.time() - self.history_sec
        self._history = [e for e in self._history if e.ts >= cutoff]

    @staticmethod
    def _alert_key(alert: Alert) -> str:
        d = alert.data or {}
        sig = (d.get("ip") or d.get("path") or d.get("port")
               or d.get("process") or d.get("raddr") or alert.title)
        return f"{alert.rule}:{sig}"

    def evaluate(self, batch: list[Event]) -> list[Alert]:
        """Feed a sweep's events through all rules, return fresh alerts."""
        self._history.extend(batch)
        self._prune_history()
        ctx = RuleContext(self.config, self._history, self.host)

        produced: list[Alert] = []
        for rule in self.rules:
            try:
                produced.extend(rule(batch, ctx) or [])
            except Exception:  # pragma: no cover - a rule must not kill the loop
                continue

        now = time.time()
        fresh: list[Alert] = []
        for alert in produced:
            key = self._alert_key(alert)
            last = self._recent_alert_keys.get(key, 0)
            if now - last >= self.cooldown_sec:
                self._recent_alert_keys[key] = now
                fresh.append(alert)
        return fresh
