"""Network collector — real listening sockets and outbound connections.

Uses psutil where available (richest data, incl. owning PID/process), and
falls back to parsing `ss -tunap` output so it still works in restricted
environments. Emits diffs: a port that *starts* listening, a remote
endpoint a process *newly* connects to.
"""

from __future__ import annotations

import socket
import subprocess

from .base import Collector
from ..events import Event, Severity

try:
    import psutil  # type: ignore
    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False

# Only true loopback addresses. 0.0.0.0 / :: mean "all interfaces" — the
# *most* exposed bind, so they must NOT be treated as loopback.
_LOOPBACK = {"127.0.0.1", "::1"}


class NetworkCollector(Collector):
    name = "network"

    def __init__(self, config, host="localhost"):
        super().__init__(config, host)
        self._listen: set[tuple] = set()      # (ip, port, proto)
        self._conns: set[tuple] = set()        # (raddr_ip, raddr_port, pid)

    # --- data sources -----------------------------------------------------
    def _psutil_snapshot(self):
        listen, conns = set(), {}
        for c in psutil.net_connections(kind="inet"):
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            if c.status == psutil.CONN_LISTEN or (proto == "udp" and not c.raddr):
                if c.laddr:
                    listen.add((c.laddr.ip, c.laddr.port, proto))
            elif c.status == psutil.CONN_ESTABLISHED and c.raddr:
                key = (c.raddr.ip, c.raddr.port, c.pid)
                conns[key] = {
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "pid": c.pid,
                    "proto": proto,
                    "process": _proc_name(c.pid),
                }
        return listen, conns

    def _ss_snapshot(self):
        listen, conns = set(), {}
        out = subprocess.run(
            ["ss", "-tunap"], capture_output=True, text=True, timeout=10
        ).stdout
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto, state = parts[0], parts[1]
            local, peer = parts[4], parts[5] if len(parts) > 5 else ""
            if state in ("LISTEN", "UNCONN"):
                ip, _, port = local.rpartition(":")
                if port.isdigit():
                    listen.add((ip.strip("[]"), int(port), proto))
            elif state == "ESTAB" and peer:
                ip, _, port = peer.rpartition(":")
                if port.isdigit():
                    conns[(ip.strip("[]"), int(port), None)] = {
                        "laddr": local, "raddr": peer, "pid": None,
                        "proto": proto, "process": _ss_proc(line),
                    }
        return listen, conns

    def collect(self) -> list[Event]:
        if _HAVE_PSUTIL:
            listen, conns = self._psutil_snapshot()
        else:
            listen, conns = self._ss_snapshot()
        conn_keys = set(conns.keys())

        events: list[Event] = []
        if self._primed:
            for key in listen - self._listen:
                ip, port, proto = key
                local = ip in _LOOPBACK or ip.startswith("127.")
                # 0.0.0.0 / :: bind to every interface — explicitly exposed
                if ip in ("0.0.0.0", "::"):
                    local = False
                events.append(self.event(
                    "listen.new",
                    f"New listening socket {proto}/{port}",
                    severity=Severity.LOW if local else Severity.MEDIUM,
                    description=f"{proto} {ip}:{port} started listening",
                    data={"ip": ip, "port": port, "proto": proto,
                          "loopback": local, "process": _port_proc(ip, port)},
                ))
            for key in self._listen - listen:
                ip, port, proto = key
                events.append(self.event(
                    "listen.closed", f"Listening socket {proto}/{port} closed",
                    severity=Severity.INFO,
                    data={"ip": ip, "port": port, "proto": proto}))
            for key in conn_keys - self._conns:
                info = conns[key]
                events.append(self.event(
                    "conn.new", f"Outbound connection to {info['raddr']}",
                    severity=Severity.INFO,
                    description=f"{info['process'] or 'process'} -> {info['raddr']}",
                    data=info))

        self._listen, self._conns = listen, conn_keys
        self._primed = True
        return events


def _proc_name(pid):
    if not pid or not _HAVE_PSUTIL:
        return None
    try:
        return psutil.Process(pid).name()
    except Exception:
        return None


def _port_proc(ip, port):
    if not _HAVE_PSUTIL:
        return None
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and c.laddr.port == port and c.pid:
                return _proc_name(c.pid)
    except Exception:
        return None
    return None


def _ss_proc(line):
    # extract users:(("name",pid=...,fd=...))
    if "users:" in line:
        try:
            return line.split('users:(("', 1)[1].split('"', 1)[0]
        except Exception:
            return None
    return None
