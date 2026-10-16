"""Tests for plain-English explanations and report export.

Run with:  python -m pytest -q   (or)  python tests/test_reports.py
"""

import io
import os
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybersentinel import reports
from cybersentinel.events import Alert, Severity
from cybersentinel.explain import explain_alert, ALL_RULES_COVERED
from cybersentinel.storage import Storage


def _storage(tmp):
    st = Storage(os.path.join(tmp, "t.db"))
    now = time.time()
    st.add_alert(Alert(rule="suspicious_exec_path", title="=evil",
                       severity=Severity.HIGH, ts=now - 60,
                       data={"pid": 1, "name": "x", "exe": "/tmp/a; rm -rf ~", "user": "u"}))
    st.add_alert(Alert(rule="ssh_bruteforce", title="old", severity=Severity.HIGH,
                       ts=now - 3 * 86400, data={"ip": "1.2.3.4", "attempts": 6}))
    return st


def test_every_rule_has_a_guide():
    for rule in ALL_RULES_COVERED:
        ex = explain_alert({"rule": rule, "title": "t", "data": {}})
        assert ex["what"] and ex["cause"] and ex["fix"]


def test_commands_are_shell_quoted():
    ex = explain_alert({"rule": "suspicious_exec_path", "title": "t",
                        "data": {"pid": 1, "name": "x", "exe": "/tmp/a; rm -rf ~", "user": "u"}})
    cmds = " ".join(f.get("cmd", "") for f in ex["fix"])
    assert "'/tmp/a; rm -rf ~'" in cmds


def test_period_windows_filter_alerts():
    with tempfile.TemporaryDirectory() as tmp:
        st = _storage(tmp)
        assert reports.build_report(st, "hour")["total"] == 1
        assert reports.build_report(st, "week")["total"] == 2


def test_all_formats_render():
    with tempfile.TemporaryDirectory() as tmp:
        rep = reports.build_report(_storage(tmp), "all")
        assert reports.render(rep, "pdf").startswith(b"%PDF-")
        z = zipfile.ZipFile(io.BytesIO(reports.render(rep, "docx")))
        assert "word/document.xml" in z.namelist()
        assert b"'=evil" in reports.render(rep, "csv")      # formula-injection guard


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f()
            print("ok", n)
