# API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET | `/api/status` | Monitor + tier status |
| GET | `/api/stats` | Aggregate counts & severity rollup |
| GET | `/api/events?limit&since&category` | Raw events |
| GET | `/api/alerts?limit&status` | Alerts (filter by status) |
| POST | `/api/alerts/<id>/ack` | Acknowledge an alert |
| POST | `/api/alerts/<id>/resolve` | Resolve an alert |
| POST | `/api/alerts/bulk/<ack\|resolve\|reopen>` | Body `{"ids": [...]}` |
| POST | `/api/alerts/<id>/safe` | Mark this kind of alert safe (adds to the safe-list) |
| POST | `/api/alerts/<id>/block` | Block the IP of an SSH brute-force alert |
| GET | `/api/allowlist`, `/api/blocks` | Safe-list and blocked IPs |
| GET | `/api/report?period&format&from&to` | Download history (`pdf` \| `docx` \| `csv`) |
| GET | `/api/healthz` | Liveness probe |

```bash
curl -s http://127.0.0.1:8787/api/alerts | jq .
```

**Write endpoints are protected.** Every POST must send `X-Kaguya-Request: 1` and a
local `Host`/`Origin`, and there is no wildcard CORS — so a web page you visit
can't silently ack alerts, edit the safe-list or change your firewall:

```bash
curl -s -X POST -H 'X-Kaguya-Request: 1' http://127.0.0.1:8787/api/alerts/<id>/resolve
```
