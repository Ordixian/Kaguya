"""Auth-log collector — real SSH / sudo / PAM authentication events.

Source selection (first that yields data wins):
  1. A readable log file from config `paths` (/var/log/auth.log, secure).
  2. `journalctl` for sshd/sudo units (systemd hosts with no flat file).

The file reader tails incrementally from a byte offset, so repeated sweeps
only parse new lines. Lines are matched against the familiar OpenSSH / sudo
message formats and turned into structured events.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from .base import Collector
from ..events import Event, Severity

RE_FAILED = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-f]+)")
RE_ACCEPTED = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-f]+)")
RE_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-f]+)")
RE_SUDO = re.compile(r"sudo:\s+(?P<user>\S+).*COMMAND=(?P<cmd>.+)$")


class AuthLogCollector(Collector):
    name = "authlog"

    def __init__(self, config, host="localhost"):
        super().__init__(config, host)
        self._file = None
        self._offset = 0
        self._journal_cursor = None
        self._source = self._pick_source()

    def _pick_source(self):
        for p in self.config.get("paths", []):
            path = Path(p).expanduser()
            if path.exists() and os.access(path, os.R_OK):
                self._file = str(path)
                try:
                    self._offset = path.stat().st_size  # start at tail
                except OSError:
                    self._offset = 0
                return "file"
        if self.config.get("use_journal", True) and _have_journal():
            return "journal"
        return "none"

    def collect(self) -> list[Event]:
        if self._source == "file":
            lines = self._read_file_tail()
        elif self._source == "journal":
            lines = self._read_journal()
        else:
            return []
        events = [e for ln in lines if (e := self._parse(ln))]
        self._primed = True
        return events

    def _read_file_tail(self) -> list[str]:
        try:
            size = os.path.getsize(self._file)
            if size < self._offset:          # rotated
                self._offset = 0
            with open(self._file, "r", errors="replace") as fh:
                fh.seek(self._offset)
                data = fh.read()
                self._offset = fh.tell()
            return data.splitlines()
        except OSError:
            return []

    def _read_journal(self) -> list[str]:
        cmd = ["journalctl", "-q", "--no-pager", "-o", "short-iso",
               "_COMM=sshd", "+", "_COMM=sudo"]
        if self._journal_cursor:
            cmd += ["--after-cursor", self._journal_cursor]
        else:
            cmd += ["--since", "5 minutes ago"]
        cmd += ["--show-cursor"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=10).stdout.splitlines()
        except Exception:
            return []
        lines = []
        for ln in out:
            if ln.startswith("-- cursor:"):
                self._journal_cursor = ln.split("-- cursor:", 1)[1].strip()
            else:
                lines.append(ln)
        return lines

    def _parse(self, line: str) -> Event | None:
        m = RE_FAILED.search(line)
        if m:
            return self.event(
                "ssh.failed", f"Failed SSH login for {m.group('user')}",
                severity=Severity.LOW,
                description=line.strip()[:300],
                data={"user": m.group("user"), "ip": m.group("ip"),
                      "invalid": bool(m.group(1))})
        m = RE_INVALID.search(line)
        if m:
            return self.event(
                "ssh.invalid_user", f"SSH login for invalid user {m.group('user')}",
                severity=Severity.LOW,
                description=line.strip()[:300],
                data={"user": m.group("user"), "ip": m.group("ip")})
        m = RE_ACCEPTED.search(line)
        if m:
            return self.event(
                "ssh.accepted", f"Accepted SSH login for {m.group('user')}",
                severity=Severity.INFO,
                description=line.strip()[:300],
                data={"user": m.group("user"), "ip": m.group("ip")})
        m = RE_SUDO.search(line)
        if m:
            return self.event(
                "auth.sudo", f"sudo by {m.group('user')}",
                severity=Severity.INFO,
                description=line.strip()[:300],
                data={"user": m.group("user"), "cmd": m.group("cmd").strip()})
        return None


def _have_journal() -> bool:
    try:
        subprocess.run(["journalctl", "--version"], capture_output=True,
                       timeout=5)
        return True
    except Exception:
        return False
