"""HTTP API + static dashboard, built on the standard library only.

Endpoints (all JSON unless noted):
    GET  /                         -> dashboard (index.html)
    GET  /api/status               -> monitor + tier status
    GET  /api/stats                -> aggregate counts
    GET  /api/events?limit&since&category
    GET  /api/alerts?limit&status
    GET  /api/report?period&format&from&to -> downloadable alert history
                                      (period: hour|6h|day|week|month|quarter|year|all;
                                       format: pdf|docx|csv; from/to: epoch seconds)
    POST /api/alerts/<id>/safe     -> "mark as safe": silence this kind of alert
    POST /api/alerts/<id>/block    -> block the attacker IP of an SSH brute-force alert
    POST /api/alerts/bulk/<action> -> body {"ids": [...]}; ack | resolve | reopen
    GET  /api/allowlist            -> safe-list;  POST /api/allowlist/<id>/remove
    GET  /api/blocks               -> IPs blocked from here; POST /api/blocks/<ip>/unblock
    POST /api/alerts/<id>/ack      -> acknowledge an alert
    POST /api/alerts/<id>/resolve  -> resolve an alert
    GET  /api/healthz              -> liveness

All POSTs must carry the header "X-Kaguya-Request: 1" and a local Host (and,
when present, a same-host Origin). That blocks drive-by requests from other
web pages (CSRF) and DNS-rebinding, since these endpoints can change firewall
rules. There is deliberately no wildcard CORS.

Zero third-party dependencies so it runs anywhere Python does.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .. import reports, response
from ..explain import explain_alert, explain_event, health_score
from ..keys import alert_key

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
_CONTENT = {".html": "text/html", ".js": "application/javascript",
            ".css": "text/css", ".svg": "image/svg+xml",
            ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".webp": "image/webp", ".mp4": "video/mp4", ".webm": "video/webm", ".gif": "image/gif", ".ico": "image/x-icon"}

# optional dashboard mascot images (mascot) served from web/ if present
_MASCOT_FILES = {"mascot-calm.png", "mascot-alert.png",
                 "mascot-calm.jpg", "mascot-alert.jpg",
                 "mascot-calm.webp", "mascot-alert.webp",
                 # animated version shown when the mascot is clicked
                 "mascot.gif", "mascot.webp",
                 # optional full-page wallpaper (toggled from the top bar)
                 "wallpaper.jpg", "wallpaper.jpeg", "wallpaper.png", "wallpaper.webp",
                 "wallpaper.mp4", "wallpaper.webm"}


def make_handler(storage, monitor):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Kaguya/2.13"

        # keep the console quiet; the monitor is the interesting log
        def log_message(self, fmt, *args):
            pass

        # --- helpers ------------------------------------------------------
        def _json(self, obj, code=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _static(self, name):
            path = (WEB_DIR / name).resolve()
            if not str(path).startswith(str(WEB_DIR)) or not path.is_file():
                return self._json({"error": "not found"}, 404)
            body = path.read_bytes()
            ctype = _CONTENT.get(path.suffix, "application/octet-stream")
            rng = self.headers.get("Range", "")
            if path.suffix in (".mp4", ".webm") and rng.startswith("bytes="):
                # video needs byte-range replies so browsers can stream/loop it
                total = len(body)
                try:
                    a, _, b = rng[6:].split(",")[0].partition("-")
                    start = int(a) if a else max(0, total - int(b))
                    end = int(b) if (a and b) else total - 1
                except ValueError:
                    start, end = 0, total - 1
                end = min(end, total - 1)
                if start > end:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{total}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                chunk = body[start:end + 1]
                self.send_response(206)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(len(chunk)))
                self.end_headers()
                self.wfile.write(chunk)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            if path.suffix in (".mp4", ".webm"):
                self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self, value):
            """Accept IP literals, localhost and this machine's own name only.

            A DNS-rebinding page is reached through its own domain name, so
            requiring an IP / local name defeats it.
            """
            if not value:
                return False
            host = value.rsplit("@", 1)[-1]
            if host.startswith("["):
                host = host[1:].split("]", 1)[0]
            elif host.count(":") == 1:
                host = host.split(":", 1)[0]
            host = host.lower()
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                pass
            return (host == "localhost" or host.endswith(".localhost")
                    or host == socket.gethostname().lower()
                    or host == str(monitor.status().get("host", "")).lower())

        def _guard(self, write):
            if not self._host_ok(self.headers.get("Host", "")):
                self._json({"error": "bad host"}, 403)
                return False
            if write:
                origin = self.headers.get("Origin")
                if origin and urlparse(origin).netloc != self.headers.get("Host"):
                    self._json({"error": "cross-origin request refused"}, 403)
                    return False
                if self.headers.get("X-Kaguya-Request") != "1":
                    self._json({"error": "missing X-Kaguya-Request header"}, 403)
                    return False
            return True

        def _body(self):
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 65536)
                return json.loads(self.rfile.read(n) or b"{}") if n else {}
            except (ValueError, TypeError):
                return {}

        # --- routing ------------------------------------------------------
        def do_GET(self):
            if not self._guard(False):
                return
            u = urlparse(self.path)
            q = parse_qs(u.query)
            p = u.path

            if p in ("/", "/index.html"):
                return self._static("index.html")
            if p in ("/app.js", "/styles.css"):
                return self._static(p.lstrip("/"))
            if p.lstrip("/") in _MASCOT_FILES:
                return self._static(p.lstrip("/"))
            if p == "/api/healthz":
                return self._json({"ok": True, "ts": time.time()})
            if p == "/api/status":
                return self._json(monitor.status())
            if p == "/api/stats":
                st = storage.stats()
                st["health"] = health_score(storage.distinct_open_by_severity())
                return self._json(st)
            if p == "/api/allowlist":
                return self._json(storage.list_allow())
            if p == "/api/blocks":
                return self._json(storage.list_blocks())
            if p == "/api/events":
                limit = int(q.get("limit", ["200"])[0])
                since = float(q["since"][0]) if "since" in q else None
                category = q.get("category", [None])[0]
                evs = storage.recent_events(limit=limit, since=since,
                                            category=category)
                return self._json([_event_dict(e) for e in evs])
            if p == "/api/alerts":
                limit = int(q.get("limit", ["200"])[0])
                status = q.get("status", [None])[0]
                als = storage.recent_alerts(limit=limit, status=status)
                return self._json([_alert_dict(a) for a in als])
            if p == "/api/report":
                return self._report(q)
            return self._json({"error": "not found"}, 404)

        def _report(self, q):
            fmt = q.get("format", ["pdf"])[0]
            period = q.get("period", ["day"])[0]
            try:
                if fmt not in reports.FORMATS:
                    raise ValueError(f"unknown format '{fmt}'")
                start = float(q["from"][0]) if "from" in q else None
                end = float(q["to"][0]) if "to" in q else None
                rep = reports.build_report(storage, period, start, end,
                                           host=monitor.status().get("host"))
                body = reports.render(rep, fmt)
            except (ValueError, OverflowError, OSError) as e:
                return self._json({"error": str(e)}, 400)
            mime, ext = reports.FORMATS[fmt]
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition",
                             f'attachment; filename="{reports.filename(rep, ext)}"')
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if not self._guard(True):
                return
            parts = urlparse(self.path).path.strip("/").split("/")
            body = self._body()
            if len(parts) == 4 and parts[:2] == ["api", "alerts"]:
                a, b = parts[2], parts[3]
                if a == "bulk":
                    return self._bulk(b, body)
                if b in ("ack", "resolve", "reopen"):
                    status = {"ack": "acknowledged", "resolve": "resolved",
                              "reopen": "open"}[b]
                    if storage.set_alert_status(a, status):
                        return self._json({"ok": True, "id": a, "status": status})
                    return self._json({"error": "unknown alert"}, 404)
                if b == "safe":
                    return self._safe(a)
                if b == "block":
                    return self._block(a, body)
            if len(parts) == 4 and parts[:2] == ["api", "allowlist"] and parts[3] == "remove":
                ok = storage.remove_allow(parts[2])
                return self._json({"ok": ok}, 200 if ok else 404)
            if len(parts) == 4 and parts[:2] == ["api", "blocks"] and parts[3] == "unblock":
                return self._unblock(parts[2])
            return self._json({"error": "not found"}, 404)

        def _bulk(self, action, body):
            status = {"ack": "acknowledged", "resolve": "resolved",
                      "reopen": "open"}.get(action)
            ids = body.get("ids")
            if not status or not isinstance(ids, list) or len(ids) > 5000 \
                    or not all(isinstance(i, str) for i in ids):
                return self._json({"error": "bad request"}, 400)
            return self._json({"ok": True, "updated": storage.bulk_set_status(ids, status)})

        def _safe(self, alert_id):
            a = storage.get_alert(alert_id)
            if not a:
                return self._json({"error": "unknown alert"}, 404)
            value, label = alert_key(a.rule, a.title, a.data)
            storage.add_allow(a.rule, value, label)
            n = storage.resolve_matching(a.rule, value)
            return self._json({"ok": True, "label": label, "resolved": n})

        def _block(self, alert_id, body):
            if not monitor.config.get("response.allow_block", True):
                return self._json({"error": "blocking is disabled in the config"}, 403)
            a = storage.get_alert(alert_id)
            if not a or a.rule != "ssh_bruteforce":
                return self._json({"error": "only SSH brute-force alerts can block an IP"}, 400)
            try:
                res = response.block_ip((a.data or {}).get("ip"),
                                        allow_private=bool(body.get("confirm_private")))
            except response.BlockError as e:
                return self._json({"ok": False, "message": str(e),
                                   "needs_private_confirm": "private" in str(e)}, 400)
            if res["ok"]:
                storage.add_block(res["ip"], res.get("method", ""))
            return self._json(res)

        def _unblock(self, ip):
            try:
                res = response.unblock_ip(ip)
            except response.BlockError as e:
                return self._json({"ok": False, "message": str(e)}, 400)
            if res["ok"]:
                storage.remove_block(res["ip"])
            return self._json(res)

    return Handler


def _event_dict(e):
    d = _event_base(e)
    d["explain"] = explain_event(d)
    return d


def _event_base(e):
    return {"id": e.id, "ts": e.ts, "source": e.source, "category": e.category,
            "title": e.title, "severity": e.severity.label,
            "description": e.description, "host": e.host, "data": e.data}


def _alert_dict(a):
    d = _alert_base(a)
    d["explain"] = explain_alert(d)
    d["group"], d["group_label"] = (lambda k: (f"{a.rule}:{k[0]}", k[1]))(
        alert_key(a.rule, a.title, a.data))
    return d


def _alert_base(a):
    return {"id": a.id, "ts": a.ts, "rule": a.rule, "title": a.title,
            "severity": a.severity.label, "description": a.description,
            "host": a.host, "status": a.status, "event_ids": a.event_ids,
            "data": a.data}


def serve(storage, monitor, host="127.0.0.1", port=8787):
    handler = make_handler(storage, monitor)
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd
