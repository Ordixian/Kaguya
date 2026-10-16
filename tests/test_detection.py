"""Unit tests for the detection engine and rules.

These construct Events directly (no host access needed) so they run anywhere
and prove each rule fires on the right input and stays quiet otherwise.

Run with:  python -m pytest -q   (or)  python tests/test_detection.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybersentinel import config as config_mod
from cybersentinel.events import Event, Severity
from cybersentinel.detection import DetectionEngine
from cybersentinel.detection.rules import RuleContext, rule_ssh_bruteforce


def _engine():
    cfg = config_mod.load(None)
    # no cooldown so each test sees its alert
    return DetectionEngine(cfg, host="test", cooldown_sec=0)


def _ssh_fail(ip, user="root"):
    return Event(source="authlog", category="ssh.failed",
                 title="fail", severity=Severity.LOW,
                 data={"ip": ip, "user": user})


def test_ssh_bruteforce_fires_above_threshold():
    eng = _engine()
    batch = [_ssh_fail("10.0.0.9", f"u{i}") for i in range(6)]
    alerts = eng.evaluate(batch)
    rules = {a.rule for a in alerts}
    assert "ssh_bruteforce" in rules
    bf = next(a for a in alerts if a.rule == "ssh_bruteforce")
    assert bf.severity == Severity.HIGH
    assert bf.data["attempts"] >= 5


def test_ssh_bruteforce_quiet_below_threshold():
    eng = _engine()
    alerts = eng.evaluate([_ssh_fail("10.0.0.9") for _ in range(3)])
    assert not any(a.rule == "ssh_bruteforce" for a in alerts)


def test_suspicious_exec_path_fires():
    eng = _engine()
    ev = Event(source="process", category="process.new", title="p",
               data={"pid": 42, "name": "x", "exe": "/tmp/x",
                     "cmdline": "/tmp/x --evil", "user": "nobody"})
    alerts = eng.evaluate([ev])
    assert any(a.rule == "suspicious_exec_path" and a.severity == Severity.HIGH
               for a in alerts)


def test_new_listen_port_non_loopback_is_medium():
    eng = _engine()
    ev = Event(source="network", category="listen.new", title="l",
               data={"ip": "0.0.0.0", "port": 4444, "proto": "tcp",
                     "loopback": False})
    alerts = eng.evaluate([ev])
    a = next(a for a in alerts if a.rule == "new_listen_port")
    assert a.severity == Severity.MEDIUM


def test_connection_fanout_fires():
    eng = _engine()
    batch = [Event(source="network", category="conn.new", title="c",
                   data={"process": "scanner", "raddr": f"10.0.0.{i}:80",
                         "pid": 7}) for i in range(20)]
    alerts = eng.evaluate(batch)
    assert any(a.rule == "connection_fanout" for a in alerts)


def test_known_bad_port_fires():
    eng = _engine()
    ev = Event(source="network", category="conn.new", title="c",
               data={"process": "nc", "raddr": "1.2.3.4:4444"})
    alerts = eng.evaluate([ev])
    assert any(a.rule == "known_bad_port" for a in alerts)


def test_file_integrity_delete_is_high():
    eng = _engine()
    ev = Event(source="fim", category="file.deleted",
               title="Watched file deleted: /etc/passwd",
               data={"path": "/etc/passwd"})
    alerts = eng.evaluate([ev])
    a = next(a for a in alerts if a.rule == "file_integrity")
    assert a.severity == Severity.HIGH


def test_cooldown_suppresses_duplicates():
    cfg = config_mod.load(None)
    eng = DetectionEngine(cfg, host="test", cooldown_sec=120)
    batch = [_ssh_fail("10.0.0.9", f"u{i}") for i in range(6)]
    first = eng.evaluate(batch)
    second = eng.evaluate(batch)       # same signature within cooldown
    assert any(a.rule == "ssh_bruteforce" for a in first)
    assert not any(a.rule == "ssh_bruteforce" for a in second)


def test_rule_context_window():
    cfg = config_mod.load(None)
    old = _ssh_fail("1.1.1.1"); old.ts = time.time() - 10_000
    new = _ssh_fail("1.1.1.1")
    ctx = RuleContext(cfg, [old, new], "test")
    assert len(ctx.within("ssh.failed", 300)) == 1


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
