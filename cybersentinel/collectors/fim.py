"""File Integrity Monitoring collector.

Hashes each configured path (SHA-256) and emits an event when a watched
file is created, modified or deleted relative to the previous sweep.
Directories are walked one level deep. Missing files are tolerated — they
simply emit `file.new` if they later appear.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .base import Collector
from ..events import Event, Severity


class FIMCollector(Collector):
    name = "fim"

    def __init__(self, config, host="localhost"):
        super().__init__(config, host)
        self._baseline: dict[str, tuple] = {}   # path -> (sha256, size, mtime)
        self._paths = [Path(p).expanduser() for p in config.get("paths", [])]

    def _targets(self) -> list[Path]:
        files = []
        for p in self._paths:
            if p.is_dir():
                try:
                    files.extend(c for c in p.iterdir() if c.is_file())
                except OSError:
                    continue
            else:
                files.append(p)
        return files

    @staticmethod
    def _digest(path: Path):
        try:
            st = path.stat()
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return (h.hexdigest(), st.st_size, st.st_mtime)
        except OSError:
            return None

    def collect(self) -> list[Event]:
        events: list[Event] = []
        snapshot: dict[str, tuple] = {}
        for path in self._targets():
            d = self._digest(path)
            if d is not None:
                snapshot[str(path)] = d

        if self._primed:
            for path, meta in snapshot.items():
                old = self._baseline.get(path)
                if old is None:
                    events.append(self.event(
                        "file.new", f"New watched file: {path}",
                        severity=Severity.MEDIUM,
                        data={"path": path, "sha256": meta[0], "size": meta[1]}))
                elif old[0] != meta[0]:
                    events.append(self.event(
                        "file.modified", f"Watched file modified: {path}",
                        severity=Severity.MEDIUM,
                        description=f"size {old[1]} -> {meta[1]}",
                        data={"path": path, "old_sha256": old[0],
                              "new_sha256": meta[0], "size": meta[1]}))
            for path in set(self._baseline) - set(snapshot):
                events.append(self.event(
                    "file.deleted", f"Watched file deleted: {path}",
                    severity=Severity.HIGH,
                    data={"path": path}))

        self._baseline = snapshot
        self._primed = True
        return events
