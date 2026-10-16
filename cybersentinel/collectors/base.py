"""Collector base class.

A collector observes one aspect of the host and, each time it is swept,
returns a list of Events describing what changed since the last sweep.
Collectors hold their own in-memory baseline so they can emit *diffs*
(new process, new listening port) rather than re-reporting steady state.
"""

from __future__ import annotations

from ..events import Event


class Collector:
    name = "base"

    def __init__(self, config, host: str = "localhost"):
        self.config = config or {}
        self.host = host
        self._primed = False   # first sweep establishes a baseline silently

    def collect(self) -> list[Event]:
        """Return new events since the previous sweep. Override me."""
        raise NotImplementedError

    def safe_collect(self) -> list[Event]:
        """Wrap collect() so one failing collector never kills the loop."""
        try:
            return self.collect() or []
        except Exception as exc:  # pragma: no cover - defensive
            return [Event(
                source=self.name,
                category="collector.error",
                title=f"{self.name} collector error",
                description=str(exc),
            )]

    def event(self, category: str, title: str, **kw) -> Event:
        kw.setdefault("host", self.host)
        return Event(source=self.name, category=category, title=title, **kw)
