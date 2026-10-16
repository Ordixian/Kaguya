"""Detection rules.

Each rule is a callable that receives the batch of new Events from the
current sweep plus a `ctx` object (giving access to config and a short
rolling history) and returns a list of Alerts. Rules are pure functions of
their inputs where possible, which makes them trivially unit-testable.
"""

from __future__ import annotations

import time
from collections import defaultdict

from ..events import Event, Alert, Severity


class RuleContext:
    """Rolling window of recent events shared across rules in a sweep."""

    def __init__(self, config, history: list[Event], host: str):
        self.config = config
        self.history = history       # recent events (incl. this batch)
        self.host = host

    def cfg(self, rule: str, key: str, default=None):
        return self.config.get(f"detection.{rule}.{key}", default)

    def within(self, category: str, window_sec: float) -> list[Event]:
        cutoff = time.time() - window_sec
        return [e for e in self.history
                if e.category == category and e.ts >= cutoff]


# --- individual rules -----------------------------------------------------

def rule_ssh_bruteforce(batch, ctx):
    if not ctx.cfg("ssh_bruteforce", "enabled", True):
        return []
    if not any(e.category in ("ssh.failed", "ssh.invalid_user") for e in batch):
        return []
    threshold = ctx.cfg("ssh_bruteforce", "threshold", 5)
    window = ctx.cfg("ssh_bruteforce", "window_sec", 300)
    recent = ctx.within("ssh.failed", window) + ctx.within("ssh.invalid_user", window)
    by_ip = defaultdict(list)
    for e in recent:
        by_ip[e.data.get("ip", "?")].append(e)
    alerts = []
    for ip, evs in by_ip.items():
        if len(evs) >= threshold:
            users = sorted({e.data.get("user", "?") for e in evs})
            alerts.append(Alert(
                rule="ssh_bruteforce",
                title=f"SSH brute-force from {ip} ({len(evs)} attempts)",
                severity=Severity.HIGH,
                host=ctx.host,
                description=(f"{len(evs)} failed SSH logins from {ip} in "
                             f"{window}s targeting users: {', '.join(users[:8])}"),
                event_ids=[e.id for e in evs],
                data={"ip": ip, "attempts": len(evs), "users": users}))
    return alerts


def rule_new_listen_port(batch, ctx):
    if not ctx.cfg("new_listen_port", "enabled", True):
        return []
    alerts = []
    for e in batch:
        if e.category != "listen.new":
            continue
        loopback = e.data.get("loopback")
        alerts.append(Alert(
            rule="new_listen_port",
            title=f"New listening port {e.data.get('proto')}/{e.data.get('port')}",
            severity=Severity.LOW if loopback else Severity.MEDIUM,
            host=ctx.host,
            description=(f"{e.data.get('process') or 'A process'} opened "
                         f"{e.data.get('ip')}:{e.data.get('port')}"),
            event_ids=[e.id],
            data=e.data))
    return alerts


def rule_suspicious_exec_path(batch, ctx):
    if not ctx.cfg("suspicious_exec_path", "enabled", True):
        return []
    sus = ctx.cfg("suspicious_exec_path", "paths",
                  ["/tmp", "/dev/shm", "/run/user", "/var/tmp"])
    alerts = []
    for e in batch:
        if e.category != "process.new":
            continue
        exe = e.data.get("exe") or ""
        cmd = e.data.get("cmdline") or ""
        # check the exe and every cmdline token, so "/bin/sh /tmp/x.sh" is caught
        tokens = [exe] + cmd.split()
        hit = next((p for p in sus
                    if any(t.startswith(p) for t in tokens)), None)
        if hit:
            alerts.append(Alert(
                rule="suspicious_exec_path",
                title=f"Process executing from {hit}: {e.data.get('name')}",
                severity=Severity.HIGH,
                host=ctx.host,
                description=f"PID {e.data.get('pid')} ({e.data.get('user')}): {cmd[:300]}",
                event_ids=[e.id],
                data=e.data))
    return alerts


def rule_connection_fanout(batch, ctx):
    if not ctx.cfg("connection_fanout", "enabled", True):
        return []
    if not any(e.category == "conn.new" for e in batch):
        return []
    threshold = ctx.cfg("connection_fanout", "threshold", 15)
    window = ctx.cfg("connection_fanout", "window_sec", 60)
    recent = ctx.within("conn.new", window)
    by_proc = defaultdict(set)
    sample = defaultdict(list)
    for e in recent:
        key = e.data.get("process") or f"pid:{e.data.get('pid')}"
        ip = (e.data.get("raddr") or "").rsplit(":", 1)[0]
        by_proc[key].add(ip)
        sample[key].append(e)
    alerts = []
    for proc, ips in by_proc.items():
        if len(ips) >= threshold:
            alerts.append(Alert(
                rule="connection_fanout",
                title=f"Connection fan-out: {proc} -> {len(ips)} hosts",
                severity=Severity.MEDIUM,
                host=ctx.host,
                description=(f"{proc} opened connections to {len(ips)} distinct "
                             f"remote hosts in {window}s (possible scan/beaconing)"),
                event_ids=[e.id for e in sample[proc]],
                data={"process": proc, "distinct_hosts": len(ips),
                      "hosts": sorted(ips)[:30]}))
    return alerts


def rule_known_bad_port(batch, ctx):
    if not ctx.cfg("known_bad_port", "enabled", True):
        return []
    bad = set(ctx.cfg("known_bad_port", "ports", [23, 1337, 4444, 5555, 6667, 31337]))
    alerts = []
    for e in batch:
        if e.category == "conn.new":
            raddr = e.data.get("raddr") or ""
            port = raddr.rsplit(":", 1)[-1]
            if port.isdigit() and int(port) in bad:
                alerts.append(Alert(
                    rule="known_bad_port",
                    title=f"Connection to suspicious port {port}",
                    severity=Severity.MEDIUM,
                    host=ctx.host,
                    description=f"{e.data.get('process') or 'process'} -> {raddr}",
                    event_ids=[e.id],
                    data=e.data))
        elif e.category == "listen.new":
            # a service *listening* on a known-bad port is a classic backdoor
            port = e.data.get("port")
            if port in bad:
                alerts.append(Alert(
                    rule="known_bad_port",
                    title=f"Backdoor-style listener on port {port}",
                    severity=Severity.HIGH,
                    host=ctx.host,
                    description=(f"{e.data.get('process') or 'A process'} is "
                                 f"listening on known-bad port {port}"),
                    event_ids=[e.id],
                    data=e.data))
    return alerts


def rule_file_integrity(batch, ctx):
    if not ctx.cfg("file_integrity", "enabled", True):
        return []
    alerts = []
    for e in batch:
        if e.category not in ("file.modified", "file.deleted", "file.new"):
            continue
        sev = Severity.HIGH if e.category == "file.deleted" else Severity.MEDIUM
        alerts.append(Alert(
            rule="file_integrity",
            title=e.title,
            severity=sev,
            host=ctx.host,
            description=e.description or e.data.get("path", ""),
            event_ids=[e.id],
            data=e.data))
    return alerts


def rule_privilege_event(batch, ctx):
    if not ctx.cfg("privilege_event", "enabled", True):
        return []
    alerts = []
    for e in batch:
        if e.category == "auth.sudo":
            alerts.append(Alert(
                rule="privilege_event",
                title=f"Privilege use: sudo by {e.data.get('user')}",
                severity=Severity.INFO,
                host=ctx.host,
                description=f"COMMAND={e.data.get('cmd', '')}"[:300],
                event_ids=[e.id],
                data=e.data))
        elif e.category == "process.new" and e.data.get("user") == "root":
            # Ignore kernel threads (kworker, ksoftirqd, [udev-worker], …):
            # they have no real executable and are not user-space activity.
            name = (e.data.get("name") or "")
            exe = e.data.get("exe")
            is_kernel_thread = (not exe) or name.startswith(("kworker", "ksoftirqd",
                                "migration", "rcu_", "kthreadd")) or (
                name.startswith("(") and name.endswith(")"))
            if is_kernel_thread:
                continue
            alerts.append(Alert(
                rule="privilege_event",
                title=f"New root process: {name}",
                severity=Severity.LOW,
                host=ctx.host,
                description=(e.data.get("cmdline") or "")[:300],
                event_ids=[e.id],
                data=e.data))
    return alerts


ALL_RULES = [
    rule_ssh_bruteforce,
    rule_new_listen_port,
    rule_suspicious_exec_path,
    rule_connection_fanout,
    rule_known_bad_port,
    rule_file_integrity,
    rule_privilege_event,
]
