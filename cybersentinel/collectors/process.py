"""Process collector — real running processes.

Emits a `process.new` event the first time a PID/exe is seen after the
baseline sweep, carrying exe path, cmdline, user and parent. Detection
rules decide whether a given new process is suspicious (e.g. executing
from /tmp or running as root).
"""

from __future__ import annotations

from .base import Collector
from ..events import Event, Severity

try:
    import psutil  # type: ignore
    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False


class ProcessCollector(Collector):
    name = "process"

    def __init__(self, config, host="localhost"):
        super().__init__(config, host)
        self._seen: set[int] = set()

    def collect(self) -> list[Event]:
        if not _HAVE_PSUTIL:
            return []
        events: list[Event] = []
        current: set[int] = set()
        for proc in psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username", "ppid", "create_time"]):
            try:
                info = proc.info
            except Exception:
                continue
            pid = info["pid"]
            current.add(pid)
            if self._primed and pid not in self._seen:
                cmd = " ".join(info.get("cmdline") or []) or info.get("name") or "?"
                events.append(self.event(
                    "process.new",
                    f"New process: {info.get('name') or '?'}",
                    severity=Severity.INFO,
                    description=cmd[:400],
                    data={
                        "pid": pid,
                        "name": info.get("name"),
                        "exe": info.get("exe"),
                        "cmdline": cmd[:1000],
                        "user": info.get("username"),
                        "ppid": info.get("ppid"),
                    },
                ))
        self._seen = current
        self._primed = True
        return events
