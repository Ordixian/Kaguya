"""Tests for the notification manager — severity gating and sink dispatch.

No real network/desktop calls: a fake sink records what it received.
Run with:  python -m pytest -q   (or)  python tests/test_notify.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybersentinel import config as config_mod
from cybersentinel.events import Alert, Severity
from cybersentinel.notify import NotificationManager, Sink, build_notifier


class RecordingSink(Sink):
    name = "recording"

    def __init__(self):
        self.got = []

    def send(self, alert):
        self.got.append(alert)


def _alert(sev):
    return Alert(rule="r", title="t", severity=sev)


def _wait_for(pred, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_min_severity_gates_low_alerts():
    sink = RecordingSink()
    mgr = NotificationManager([sink], min_severity=Severity.HIGH)
    mgr.dispatch([_alert(Severity.LOW), _alert(Severity.MEDIUM)])
    # nothing qualifies; give the (non-)thread a beat
    assert not _wait_for(lambda: sink.got, timeout=0.3)


def test_high_alert_reaches_sink():
    sink = RecordingSink()
    mgr = NotificationManager([sink], min_severity=Severity.HIGH)
    mgr.dispatch([_alert(Severity.HIGH), _alert(Severity.CRITICAL),
                  _alert(Severity.LOW)])
    assert _wait_for(lambda: len(sink.got) == 2)
    assert {a.severity for a in sink.got} == {Severity.HIGH, Severity.CRITICAL}


def test_failing_sink_does_not_block_others():
    class Boom(Sink):
        name = "boom"
        def send(self, alert):
            raise RuntimeError("down")
    good = RecordingSink()
    mgr = NotificationManager([Boom(), good], min_severity=Severity.INFO)
    mgr.dispatch([_alert(Severity.HIGH)])
    assert _wait_for(lambda: len(good.got) == 1)


def test_build_notifier_defaults_to_console_only():
    cfg = config_mod.load(None)
    mgr = build_notifier(cfg)
    assert "console" in mgr.active
    assert mgr.min_severity == Severity.HIGH


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
