"""SQLite-backed storage for events and alerts. Thread-safe via a lock."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import uuid

from .events import Event, Alert, Severity
from .keys import alert_key


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    source      TEXT NOT NULL,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    description TEXT,
    host        TEXT,
    data        TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    rule        TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    description TEXT,
    host        TEXT,
    event_ids   TEXT,
    data        TEXT,
    status      TEXT DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS allowlist (
    id      TEXT PRIMARY KEY,
    rule    TEXT NOT NULL,
    value   TEXT NOT NULL,
    label   TEXT,
    created REAL NOT NULL,
    UNIQUE(rule, value)
);

CREATE TABLE IF NOT EXISTS blocks (
    ip      TEXT PRIMARY KEY,
    ts      REAL NOT NULL,
    method  TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""


class Storage:
    def __init__(self, path: str = "data/cybersentinel.db", max_events: int = 0):
        self.path = path
        self.max_events = max_events
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # --- writes -----------------------------------------------------------
    def add_event(self, event: Event) -> None:
        row = event.to_row()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO events "
                "(id, ts, source, category, title, severity, description, host, data) "
                "VALUES (:id,:ts,:source,:category,:title,:severity,:description,:host,:data)",
                row,
            )
            self._conn.commit()

    def add_alert(self, alert: Alert) -> None:
        row = alert.to_row()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO alerts "
                "(id, ts, rule, title, severity, description, host, event_ids, data, status) "
                "VALUES (:id,:ts,:rule,:title,:severity,:description,:host,:event_ids,:data,:status)",
                row,
            )
            self._conn.commit()

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET status=? WHERE id=?", (status, alert_id)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def bulk_set_status(self, ids: list, status: str) -> int:
        with self._lock:
            cur = self._conn.executemany(
                "UPDATE alerts SET status=? WHERE id=?", [(status, i) for i in ids])
            self._conn.commit()
            return cur.rowcount

    # --- safe-list ("mark as safe") ---------------------------------------
    def add_allow(self, rule: str, value: str, label: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM allowlist WHERE rule=? AND value=?", (rule, value)).fetchone()
            if row:
                return row["id"]
            aid = uuid.uuid4().hex[:12]
            self._conn.execute(
                "INSERT INTO allowlist (id, rule, value, label, created) VALUES (?,?,?,?,?)",
                (aid, rule, value, label, time.time()))
            self._conn.commit()
            return aid

    def list_allow(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM allowlist ORDER BY created DESC").fetchall()
        return [dict(r) for r in rows]

    def remove_allow(self, allow_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM allowlist WHERE id=?", (allow_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def allowed_keys(self) -> set:
        with self._lock:
            rows = self._conn.execute("SELECT rule, value FROM allowlist").fetchall()
        return {(r["rule"], r["value"]) for r in rows}

    def is_allowed(self, alert: Alert, allowed: set | None = None) -> bool:
        allowed = self.allowed_keys() if allowed is None else allowed
        return (alert.rule, alert_key(alert.rule, alert.title, alert.data)[0]) in allowed

    def resolve_matching(self, rule: str, value: str) -> int:
        """Resolve every open alert whose key matches (used after marking safe)."""
        ids = [a.id for a in self.recent_alerts(limit=100_000, status="open")
               if a.rule == rule and alert_key(a.rule, a.title, a.data)[0] == value]
        return self.bulk_set_status(ids, "resolved") if ids else 0

    # --- blocked IPs ------------------------------------------------------
    def add_block(self, ip: str, method: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO blocks (ip, ts, method) VALUES (?,?,?)",
                (ip, time.time(), method))
            self._conn.commit()

    def remove_block(self, ip: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM blocks WHERE ip=?", (ip,))
            self._conn.commit()
            return cur.rowcount > 0

    def list_blocks(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM blocks ORDER BY ts DESC").fetchall()
        return [dict(r) for r in rows]

    # --- tiny key/value store (e.g. last scheduled-report time) -----------
    def get_meta(self, k: str, default=None):
        with self._lock:
            row = self._conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row["v"] if row else default

    def set_meta(self, k: str, v: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?,?)", (k, v))
            self._conn.commit()

    def get_alert(self, alert_id: str):
        with self._lock:
            row = self._conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return Alert.from_row(dict(row)) if row else None

    # --- reads ------------------------------------------------------------
    def recent_events(self, limit: int = 200, since: float | None = None,
                      category: str | None = None) -> list[Event]:
        q = "SELECT * FROM events"
        conds, args = [], []
        if since is not None:
            conds.append("ts >= ?"); args.append(since)
        if category:
            conds.append("category = ?"); args.append(category)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY ts DESC LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [Event.from_row(dict(r)) for r in rows]

    def events_since(self, since: float, category: str | None = None) -> list[Event]:
        return self.recent_events(limit=100_000, since=since, category=category)

    def recent_alerts(self, limit: int = 200, status: str | None = None) -> list[Alert]:
        q = "SELECT * FROM alerts"
        args = []
        if status:
            q += " WHERE status = ?"; args.append(status)
        q += " ORDER BY ts DESC LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [Alert.from_row(dict(r)) for r in rows]

    def alerts_between(self, since: float, until: float, limit: int = 2000) -> list[Alert]:
        """Alerts with since <= ts <= until, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT ?",
                (since, until, limit)).fetchall()
        return [Alert.from_row(dict(r)) for r in rows]

    def distinct_open_alerts(self) -> list:
        """One open alert per issue (the worst, then newest), highest severity first."""
        best = {}
        for a in self.recent_alerts(limit=5000, status="open"):   # newest first
            k = (a.rule, alert_key(a.rule, a.title, a.data)[0])
            if k not in best or a.severity > best[k].severity:
                best[k] = a
        return sorted(best.values(), key=lambda a: (-int(a.severity), -a.ts))

    def distinct_open_by_severity(self) -> dict:
        """Open alerts counted once per issue (repeats of one thing = one problem)."""
        out = {}
        for a in self.distinct_open_alerts():
            out[a.severity.label] = out.get(a.severity.label, 0) + 1
        return out

    def stats(self) -> dict:
        with self._lock:
            ev_total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            al_total = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            al_open = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            by_sev = {}
            for r in self._conn.execute(
                "SELECT severity, COUNT(*) c FROM alerts WHERE status='open' GROUP BY severity"):
                by_sev[Severity(r["severity"]).label] = r["c"]
            by_cat = {}
            for r in self._conn.execute(
                "SELECT category, COUNT(*) c FROM events GROUP BY category "
                "ORDER BY c DESC LIMIT 12"):
                by_cat[r["category"]] = r["c"]
        return {
            "events_total": ev_total,
            "alerts_total": al_total,
            "alerts_open": al_open,
            "open_alerts_by_severity": by_sev,
            "events_by_category": by_cat,
        }

    # --- retention --------------------------------------------------------
    def enforce_retention(self, retention_days: int) -> int:
        """Delete events/alerts beyond retention; honour max_events ceiling."""
        removed = 0
        with self._lock:
            if retention_days and retention_days > 0:
                cutoff = time.time() - retention_days * 86400
                cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                removed += cur.rowcount
                self._conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
            if self.max_events and self.max_events > 0:
                cur = self._conn.execute(
                    "DELETE FROM events WHERE id IN ("
                    "SELECT id FROM events ORDER BY ts DESC LIMIT -1 OFFSET ?)",
                    (self.max_events,),
                )
                removed += cur.rowcount
            self._conn.commit()
        return removed

    def close(self) -> None:
        with self._lock:
            self._conn.close()
