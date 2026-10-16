"""Core data types: severities, Events (raw observations) and Alerts."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity levels. Higher is worse."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, value) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


def _now() -> float:
    return time.time()


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass
class Event:
    """A single raw observation emitted by a collector.

    Events are facts about the host ("a new process appeared", "a socket
    started listening"). They are deliberately low-level; turning them into
    something worth a human's attention is the detection engine's job.
    """

    source: str                       # collector name, e.g. "network"
    category: str                     # dotted type, e.g. "listen.new"
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    host: str = "localhost"
    data: dict = field(default_factory=dict)
    ts: float = field(default_factory=_now)
    id: str = field(default_factory=_new_id)

    def to_row(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["data"] = json.dumps(self.data, default=str)
        return d

    @staticmethod
    def from_row(row: dict) -> "Event":
        return Event(
            id=row["id"],
            ts=row["ts"],
            source=row["source"],
            category=row["category"],
            title=row["title"],
            severity=Severity(row["severity"]),
            description=row.get("description", ""),
            host=row.get("host", "localhost"),
            data=json.loads(row["data"]) if row.get("data") else {},
        )


@dataclass
class Alert:
    """A detection-engine verdict: something a human should look at."""

    rule: str                         # rule id, e.g. "ssh_bruteforce"
    title: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    host: str = "localhost"
    event_ids: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    status: str = "open"              # open | acknowledged | resolved
    ts: float = field(default_factory=_now)
    id: str = field(default_factory=_new_id)

    def to_row(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["event_ids"] = json.dumps(self.event_ids)
        d["data"] = json.dumps(self.data, default=str)
        return d

    @staticmethod
    def from_row(row: dict) -> "Alert":
        return Alert(
            id=row["id"],
            ts=row["ts"],
            rule=row["rule"],
            title=row["title"],
            severity=Severity(row["severity"]),
            description=row.get("description", ""),
            host=row.get("host", "localhost"),
            event_ids=json.loads(row["event_ids"]) if row.get("event_ids") else [],
            data=json.loads(row["data"]) if row.get("data") else {},
            status=row.get("status", "open"),
        )
