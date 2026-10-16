"""Tests for grouping keys, safe-list, block-IP guards, API request guards,
health score, event explanations and scheduled reports.

No firewall/network calls are made: subprocess and channels are faked.
Run with:  python -m pytest -q   (or)  python tests/test_actions.py
"""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybersentinel import config as config_mod, response
from cybersentinel.api.server import serve
from cybersentinel.events import Alert, Severity
from cybersentinel.explain import explain_event, health_score
from cybersentinel.keys import alert_key
from cybersentinel.monitor import Monitor
from cybersentinel.scheduler import ReportScheduler
from cybersentinel.storage import Storage


def _st(tmp):
    return Storage(os.path.join(tmp, "t.db"))


def _ssh(ip="8.8.8.8", n=6, **kw):
    return Alert(rule="ssh_bruteforce", title=f"SSH brute-force from {ip} ({n} attempts)",
                 severity=Severity.HIGH, data={"ip": ip, "attempts": n}, **kw)


def test_alert_key_ignores_changing_counts():
    a, b = _ssh(n=6), _ssh(n=40)
    assert alert_key(a.rule, a.title, a.data) == alert_key(b.rule, b.title, b.data)
    assert alert_key(a.rule, a.title, a.data) != alert_key(*(lambda x: (x.rule, x.title, x.data))(_ssh("1.1.1.1")))


def test_safe_list_resolves_existing_and_suppresses_future():
    with tempfile.TemporaryDirectory() as tmp:
        st = _st(tmp)
        old = _ssh()
        st.add_alert(old)
        value, label = alert_key(old.rule, old.title, old.data)
        st.add_allow(old.rule, value, label)
        assert st.resolve_matching(old.rule, value) == 1
        assert st.get_alert(old.id).status == "resolved"
        assert st.is_allowed(_ssh(n=99))
        assert not st.is_allowed(_ssh("9.9.9.9"))
        # monitor drops allowed alerts before storing
        cfg = config_mod.load(None)
        cfg._d["collectors"] = {k: {"enabled": False} for k in ("network", "process", "authlog", "fim")}
        mon = Monitor(cfg, st)
        mon.engine.evaluate = lambda batch: [_ssh(n=7), _ssh("9.9.9.9")]
        mon.sweep_once()
        titles = [a.title for a in st.recent_alerts(status="open")]
        assert any("9.9.9.9" in t for t in titles) and not any("8.8.8.8" in t for t in titles)


def test_block_ip_refuses_dangerous_targets():
    for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "nope", "1.2.3.4; rm -rf /"):
        try:
            response.validate_ip(bad)
            assert False, bad
        except response.BlockError:
            pass
    try:
        response.validate_ip("192.168.1.1")
        assert False
    except response.BlockError:
        pass
    assert str(response.validate_ip("192.168.1.1", allow_private=True)) == "192.168.1.1"


def test_block_ip_runs_argv_without_shell_and_reports_permission_failure():
    calls = []

    class R:
        returncode, stdout, stderr = 1, "", "sudo: a password is required"

    orig = response.subprocess.run
    response.subprocess.run = lambda argv, **kw: (calls.append((argv, kw)), R())[1]
    try:
        res = response.block_ip("8.8.8.8")
    finally:
        response.subprocess.run = orig
    assert isinstance(calls[0][0], list) and not calls[0][1].get("shell")
    assert not res["ok"] and "8.8.8.8" in res["manual"]


def _serve(st):
    cfg = config_mod.load(None)

    class M:
        config = cfg
        def status(self): return {"host": "box"}

    httpd = serve(st, M(), port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _post(port, path, body=None, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="POST",
                                 data=json.dumps(body or {}).encode(), headers=headers or {})
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_api_rejects_cross_site_and_rebinding_posts():
    with tempfile.TemporaryDirectory() as tmp:
        st = _st(tmp)
        a = _ssh(); st.add_alert(a)
        httpd, port = _serve(st)
        try:
            ok = {"X-Kaguya-Request": "1"}
            assert _post(port, f"/api/alerts/{a.id}/ack")[0] == 403                       # no header
            assert _post(port, f"/api/alerts/{a.id}/ack", headers={**ok, "Origin": "http://evil.example"})[0] == 403
            assert _post(port, f"/api/alerts/{a.id}/ack", headers={**ok, "Host": "evil.example:8787"})[0] == 403
            assert st.get_alert(a.id).status == "open"
            assert _post(port, f"/api/alerts/{a.id}/ack", headers=ok)[0] == 200
            assert st.get_alert(a.id).status == "acknowledged"
            r = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/alerts")
            assert r.headers.get("Access-Control-Allow-Origin") is None                   # no wildcard CORS
            # bulk + safe endpoints
            assert _post(port, "/api/alerts/bulk/resolve", {"ids": [a.id]}, ok)[1]["updated"] == 1
            code, res = _post(port, f"/api/alerts/{a.id}/safe", headers=ok)
            assert code == 200 and st.list_allow()
        finally:
            httpd.shutdown()


def test_block_endpoint_only_accepts_ssh_alerts():
    with tempfile.TemporaryDirectory() as tmp:
        st = _st(tmp)
        other = Alert(rule="new_listen_port", title="x", data={"ip": "8.8.8.8"})
        st.add_alert(other)
        httpd, port = _serve(st)
        try:
            assert _post(port, f"/api/alerts/{other.id}/block", headers={"X-Kaguya-Request": "1"})[0] == 400
        finally:
            httpd.shutdown()


def test_health_score_levels():
    assert health_score({})["level"] == "clear"
    assert health_score({"low": 3})["level"] == "good"
    assert health_score({"medium": 1})["level"] == "fine"
    assert health_score({"high": 1})["level"] == "attention"
    assert health_score({"critical": 1})["level"] == "act"
    assert 0 <= health_score({"critical": 9})["score"] <= 100


def test_event_explanations():
    for cat in ("process.new", "listen.new", "conn.new", "ssh.failed", "file.modified", "weird.unknown"):
        x = explain_event({"category": cat, "title": "t", "data": {"port": 22, "raddr": "1.1.1.1:443", "name": "sshd"}})
        assert x["what"] and x["normal"]


class _Chan:
    """Fake channel; `fail` toggles errors, `got` records sends."""
    def __init__(self, name, fail=False):
        self.name, self.fail, self.got = name, fail, []

    def __call__(self, subject, text, attachment=None):
        if self.fail:
            raise RuntimeError("down")
        self.got.append((subject, text, attachment))


def _sched(tmp, channels, **reports_cfg):
    st = _st(tmp)
    st.add_alert(_ssh())
    cfg = config_mod.load(None)
    cfg._d["reports"] = {"daily": {"enabled": True, "hour": 20, "retry_hour": 8},
                         "weekly": {"enabled": False}, **reports_cfg}
    return ReportScheduler(cfg, st, channels=channels)


def _ts(d, h, m=0):
    return datetime(2026, 10, d, h, m).timestamp()      # Oct 14 2026 = Wednesday


def test_daily_sends_at_8pm_once_and_includes_gen_z_summary():
    with tempfile.TemporaryDirectory() as tmp:
        ch = _Chan("email")
        s = _sched(tmp, [ch])
        assert s.tick(_ts(13, 20, 1)) == ["daily"]                 # first night
        assert s.tick(_ts(14, 19, 59)) == []                       # not yet 8pm on the 14th
        assert s.tick(_ts(14, 20, 1)) == ["daily"]
        assert s.tick(_ts(14, 20, 30)) == []                       # done: no repeat
        assert s.tick(_ts(15, 8, 5)) == []                         # no 8am send if it worked
        subject, text, att = ch.got[0]
        assert "Vibe check" in text and "Recommended action" in text
        assert att[0].endswith(".pdf") and att[1].startswith(b"%PDF")
        assert s.tick(_ts(15, 20, 2)) == ["daily"]                 # next night
        assert len(ch.got) == 3


def test_failed_8pm_send_retries_at_8am_only_failed_channels():
    with tempfile.TemporaryDirectory() as tmp:
        good, bad = _Chan("slack"), _Chan("email", fail=True)
        s = _sched(tmp, [good, bad])
        assert s.tick(_ts(14, 20, 5)) == ["daily"]
        assert len(good.got) == 1 and not bad.got
        assert s.tick(_ts(14, 23, 0)) == []                        # not before 8am
        bad.fail = False
        assert s.tick(_ts(15, 8, 1)) == ["daily"]                  # the 8am retry
        assert len(bad.got) == 1 and len(good.got) == 1            # slack not duplicated
        assert s.tick(_ts(15, 9, 0)) == []                         # done


def test_retry_happens_once_then_gives_up_until_next_slot():
    with tempfile.TemporaryDirectory() as tmp:
        bad = _Chan("email", fail=True)
        s = _sched(tmp, [bad])
        assert s.tick(_ts(14, 20, 5)) == ["daily"]
        assert s.tick(_ts(15, 8, 1)) == ["daily"]
        assert s.tick(_ts(15, 12, 0)) == []                        # max 2 tries per slot
        bad.fail = False
        assert s.tick(_ts(15, 20, 3)) == ["daily"]                 # next slot works again


def test_not_running_at_8pm_catches_up():
    with tempfile.TemporaryDirectory() as tmp:
        ch = _Chan("email")
        s = _sched(tmp, [ch])
        assert s.tick(_ts(15, 7, 0)) == ["daily"]                  # started next morning
        assert len(ch.got) == 1


def test_weekly_is_monday_8pm():
    with tempfile.TemporaryDirectory() as tmp:
        ch = _Chan("email")
        s = _sched(tmp, [ch], daily={"enabled": False},
                   weekly={"enabled": True, "hour": 20, "weekday": 0, "retry_hour": 8})
        assert s.tick(_ts(12, 20, 30)) == ["weekly"]               # Mon Oct 12
        assert s.tick(_ts(18, 12, 0)) == []                        # Sunday: nothing
        assert s.tick(_ts(19, 19, 59)) == []                       # Monday, before 8pm
        assert s.tick(_ts(19, 20, 1)) == ["weekly"]                # Monday 8pm
        assert s.tick(_ts(20, 9, 0)) == []                         # sent fine -> no 8am retry
        assert len(ch.got) == 2


def test_quick_summary_groups_and_stays_plain():
    from cybersentinel.explain import quick_summary
    issues = [{"rule": "new_listen_port", "severity": "low", "data": {"port": p}} for p in range(8000, 8006)]
    q = quick_summary(issues, health_score({"low": 6}))
    assert len(q["actions"]) == 1 and "6 programs" in q["actions"][0]
    assert quick_summary([], health_score({}))["vibe"].startswith("Vibe check: immaculate")
    assert all(ord(c) < 0x2000 or c in "'" for a in q["actions"] for c in a)   # no emoji that PDFs can't draw


def test_scheduler_survives_failing_channel():
    with tempfile.TemporaryDirectory() as tmp:
        s = _sched(tmp, [_Chan("boom", fail=True)])
        assert s.deliver("day", "s") == ["boom: down"]


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
