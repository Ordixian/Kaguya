# 🌙 Kaguya

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

**Moonlit Host Security Monitor · Threat Detection · Monitoring**

Kaguya is a personal host security monitoring tool. It collects **real
telemetry** from the machine it runs on — network sockets, running processes,
authentication logs, and file integrity — feeds it through a detection engine,
and surfaces alerts on a live anime-themed dashboard and JSON API.

The core (HTTP API, dashboard, storage, and detection engine) runs on the
**Python standard library alone** — no framework, no database server, no agent
fleet to deploy.

> **Open-source edition, made by Ordixian / Frost.** Built on the open-source
> *CyberSentinel* detection engine, with a redesigned enterprise-style console.
> Questions or ideas? Tap **Frost** in the dashboard footer, or message on
> WhatsApp: <https://wa.me/2349055012367> (+234 905 501 2367) · GitHub: <https://github.com/Ordixian>.

```
  _  __      _      ____   _   _  __   __   _
 | |/ /     / \    / ___| | | | | \ \ / /  / \
 | ' /     / _ \  | |  _  | | | |  \ V /  / _ \
 | . \    / ___ \ | |_| | | |_| |   | |  / ___ \
 |_|\_\  /_/   \_\ \____|  \___/    |_| /_/   \_\
          moonlit host security monitor
```

---

## Quick start guide (5 minutes)

**You need:** a Linux, macOS or Windows machine, **Python 3.9+**, and a web
browser. Nothing else — no database server, no cloud account.

1. **Get the code** and open a terminal in the folder:
   ```bash
   cd Kaguya-OpenSource          # or wherever you unpacked/cloned it
   ```
2. **Install** (pick one — details further down):
   ```bash
   pipx install -e ".[recommended]"      # Linux/macOS, recommended
   # or: python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[recommended]"
   # or, with no install at all:  pip install -r requirements.txt
   ```
3. **Run it** from this folder (so it finds `config/config.yaml`):
   ```bash
   kaguya run                    # or: python3 -m cybersentinel run
   ```
4. **Open the dashboard:** <http://127.0.0.1:8787>
5. **Check it works** with the safe self-test in [Try it](#try-it-safe-self-test).
   Real alerts appear as Kaguya sees real activity on your machine.

**Optional extras**

| Want to… | Do this |
|----------|---------|
| Run in the background / at login | See [Run Kaguya in the background](#run-kaguya-in-the-background) (a ready-made `deploy/kaguya.service`). |
| Get emailed daily/weekly PDF reports | In `config/config.yaml` set `notify.email` (`enabled: true`, `smtp_host`, `username`, `from`, `to`), then `export CS_SMTP_PASSWORD='your-smtp-key'`. **Never** put the password in the file. |
| Slack / webhook alerts | Fill `notify.slack.webhook_url` or set env `CS_SLACK_WEBHOOK` (`CS_WEBHOOK_URL` for generic webhooks). |
| Use Docker | `docker compose up -d` (see [Docker](#docker)). |
| Wallpaper image/video | Save `wallpaper.jpg/.png/.webp` or `wallpaper.mp4/.webm` in `cybersentinel/web/`, then flip the **Wallpaper** switch (or press **W**). **Hold** an empty part of the page to peek at it. |
| Mascot | Save `mascot-calm.png` (and optionally `mascot-alert.png`, `mascot.gif`) in `cybersentinel/web/`. |
| Block attacker IPs | Needs root or passwordless sudo for `ufw`/`iptables`; otherwise the exact command is shown for you to run. |

**Troubleshooting**

- *Port 8787 already in use* → stop the other copy, or change `server.port` in `config/config.yaml`.
- *`externally-managed-environment` error* → use `pipx` or a virtualenv (above).
- *Page looks old* → hard-refresh with **Ctrl+Shift+R**.
- *Not seeing auth/SSH alerts* → reading system logs may need your user in the `adm`/`systemd-journal` group, or run with sudo.
- *Dashboard is local-only on purpose.* It binds to `127.0.0.1`; don't expose it to the internet.

---

## Features

- **Live host telemetry** — sockets, processes, auth logs and file integrity; no mock data.
- **Detection engine** — SSH brute force, new listening ports, known-bad ports, connection fan-out, privilege events, suspicious exec paths, file-integrity changes.
- **MITRE ATT&CK tags** on alerts (e.g. `T1110` Brute Force).
- **Enterprise console UI** — obsidian dark theme, host-health matrix, severity strip, dense alert and telemetry streams, monospace for machine data.
- **Light / dark theme** (button or **T**), **alert chime + toasts** with a **mute** (button or **M**).
- **Wallpaper switch** — image or looping video behind the dashboard, on/off toggle (**W**), and **hold-to-peek**.
- **Mood mascot** — calm/alert states, click to enlarge, bring your own art.
- **Plain-English explanations** for every alert and event, with copy-ready fix commands.
- **Alert grouping**, ack / resolve / reopen (single or all).
- **Safe list** — silence a specific kind of alert and undo it later.
- **Block IP** for SSH brute-force alerts (`ufw`/`iptables`, never a shell).
- **Reports** — download history as PDF / Word / CSV; scheduled daily & weekly reports to email, Slack or webhook.
- **Notification sinks** — console, desktop, Slack, webhook, email.
- **Hardened API** — every write needs a custom header, a local Host and a same-origin check; no wildcard CORS.
- **Zero-dependency core** (Python standard library), with optional `psutil` + `PyYAML`.
- **Packaging** — `kaguya` command, Docker, systemd user service, CI workflow, test suite.

---

## Why

Most host-monitoring stacks (ELK + Beats + Wazuh managers, etc.) are powerful
but heavy to stand up. Kaguya targets the other end: a single file-tree you can
run in one command, that still does the useful 20% — real detections on real
data — with a path to scale up.

---

## Install the `kaguya` command

Needs **Python 3.9+**. Installing the package puts a `kaguya` command on your
PATH so you can skip `python -m cybersentinel`. An **editable** install (`-e`)
is recommended — your edits to the code, config, and mascot images take effect
with no reinstall.

### 🐧 Linux

On Debian/Parrot/Ubuntu the system Python is "externally managed", so use
**pipx** (isolated, reversible with `pipx uninstall kaguya`):

```bash
pipx install -e ".[recommended]"      # run from the repo directory
```

<details>
<summary>Alternatives (venv, or no install)</summary>

```bash
# A virtualenv:
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[recommended]"

# …or no install at all — run the module directly:
pip install -r requirements.txt       # optional extras
python3 -m cybersentinel run
```
</details>

### 🪟 Windows

Use **PowerShell** with Python from [python.org](https://www.python.org/) or the
Microsoft Store:

```powershell
python -m pip install --user pipx ; python -m pipx ensurepath
pipx install -e ".[recommended]"      # run from the repo folder
```

<details>
<summary>Alternative (venv)</summary>

```powershell
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -e ".[recommended]"
```
</details>

## Launch

Once installed, the `kaguya` command works from anywhere — but **run it from the
repo directory** so it picks up `config/config.yaml` (otherwise built-in
defaults are used; or pass `-c /path/to/config.yaml`).

```bash
kaguya sweep      # one-shot: baseline the host, wait, then print findings
kaguya run        # run the monitor + dashboard (the main mode)
kaguya status     # show config / tier / database status
```

The dashboard is at <http://127.0.0.1:8787>. `Ctrl-C` stops the monitor.
(No install? The same commands work as `python -m cybersentinel <cmd>`.)

> **Tip (Linux, full visibility):** auth-log/journald access and other users'
> process details need elevated rights. Add your user to the `adm` /
> `systemd-journal` group, or run with `sudo`. Without that, Kaguya still sees
> sockets, your own processes, and readable files.
>
> **Windows:** launch an elevated terminal ("Run as administrator") for complete
> process/socket ownership data. The `authlog` collector is Linux-only and stays
> idle there; network, process, and file-integrity collectors all work.

### Try it (safe self-test)

In another terminal, generate activity the engine will catch:

```bash
# a "backdoor-style" listener on a known-bad port
python3 -c "import socket,time; s=socket.socket(); \
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); \
  s.bind(('0.0.0.0',4444)); s.listen(1); time.sleep(120)"

# a process executing from /tmp  (Linux)
echo -e '#!/bin/sh\nsleep 120' > /tmp/demo.sh && chmod +x /tmp/demo.sh && /bin/sh /tmp/demo.sh
```

Within one sweep interval the dashboard shows **HIGH** alerts for the backdoor
listener and the `/tmp` execution — you'll hear the alert chime, a toast slides
in, and the mascot switches to its alert mood.

---

## The dashboard

The live dashboard at <http://127.0.0.1:8787> is anime-themed and includes:

| Feature | How |
|---------|-----|
| **Light / Dark theme** | 🌗 button (top-right) or press **T**. Follows your OS theme until you pick; your choice is remembered. |
| **Alert chime + toast** | A soft bell and a slide-in card on every new HIGH/critical alert. |
| **Mute** | 🔊 button or press **M** (remembered across reloads). |
| **Greeting + Refresh** | A greeting bar with host + uptime, and a manual **Refresh** button. |
| **Mood mascot** | Calm when quiet, **alert** (red glow + shake) when a HIGH alert fires. **Click** it to enlarge and play `mascot.gif`; **double-click** (or Esc) to put it back. |
| **Plain-English explanations** | Every alert and event has a 💡 button: what it means, likely cause, how worried to be, and fix steps with copy-ready commands. |
| **Alert grouping** | Repeats of the same thing collapse into one card (`×40`) with ack/resolve-all and a member list. |
| **System health tile** | "All clear / Looking good / Mostly fine / Needs attention / Act now" with a 0-100 score (repeats count once). |
| **✓ Mark as safe** | Silences one specific kind of alert (a port, program path, IP, file…). Review or undo in **🛡 Safe list**. |
| **🚫 Block this IP** | On SSH brute-force alerts. Adds a firewall rule via `ufw`/`iptables` (needs root or passwordless sudo; otherwise shows the exact command to run). Refuses loopback; private/LAN addresses need extra confirmation. |
| **⬇ Download history** | Hourly → yearly (or custom dates) as PDF, Word (.docx) or CSV. CLI: `kaguya report --period week --format pdf`. |

### Adding your own mascot art

The mascot shows a styled placeholder until you drop in your own images. Save:

- `cybersentinel/web/mascot-calm.png` — the calm pose
- `cybersentinel/web/mascot-alert.png` — the alert pose *(optional; without it the calm image gets a red glow when alerts fire)*
- `cybersentinel/web/mascot.gif` — an animation, shown when you click it *(optional)*

Transparent PNGs look best. They load automatically — no restart needed, just
refresh the page.

---

## Architecture

```
          ┌──────────────┐   events   ┌──────────────────┐  alerts  ┌─────────┐
 host ──▶ │  Collectors  │ ─────────▶ │ Detection Engine │ ───────▶ │ SQLite  │
          │  (live data) │            │  (windowed rules)│          │ storage │
          └──────────────┘            └──────────────────┘          └────┬────┘
             network                      ssh brute-force                │
             process                      new listening port             │
             authlog                      suspicious exec path        ┌───▼────────────┐
             fim                          connection fan-out          │ HTTP API +     │
                                          known-bad port              │ live dashboard │
                                          file integrity              │ (stdlib only)  │
                                          privilege events            └────────────────┘
```

| Layer | What it does | Module |
|-------|--------------|--------|
| **Collectors** | Observe one aspect of the host each sweep and emit *diffs* (a port that *started* listening, a *new* process). | `cybersentinel/collectors/` |
| **Detection engine** | Runs rules over a rolling event window, de-duplicates with a cooldown. | `cybersentinel/detection/` |
| **Storage** | SQLite; indexes, retention, severity rollups. | `cybersentinel/storage.py` |
| **API + dashboard** | `http.server`-based JSON API and a zero-dependency web UI that polls it. | `cybersentinel/api/`, `cybersentinel/web/` |
| **Monitor** | Background orchestrator thread tying it together. | `cybersentinel/monitor.py` |

### Collectors (all live, no mock data)

- **network** — listening sockets and outbound connections via `psutil`
  (falls back to parsing `ss -tunap`). Emits `listen.new`, `listen.closed`,
  `conn.new`.
- **process** — new processes with exe path, cmdline, user, parent
  (`process.new`).
- **authlog** — SSH / sudo / PAM events from `/var/log/auth.log` or
  `/var/log/secure`; on systemd-only hosts it falls back to `journalctl`
  (`ssh.failed`, `ssh.accepted`, `ssh.invalid_user`, `auth.sudo`). *(Linux)*
- **fim** — SHA-256 file integrity monitoring of configured paths
  (`file.new`, `file.modified`, `file.deleted`).

### Detection rules

| Rule | Fires when | Severity |
|------|-----------|----------|
| `ssh_bruteforce` | ≥ N failed SSH logins from one IP within a window | HIGH |
| `new_listen_port` | a socket starts listening (MEDIUM if externally bound, LOW on loopback) | LOW/MED |
| `suspicious_exec_path` | a process runs from `/tmp`, `/dev/shm`, `/run/user`, `/var/tmp` | HIGH |
| `connection_fanout` | one process connects to many distinct hosts quickly (scan/beacon) | MEDIUM |
| `known_bad_port` | connection to — or a listener on — a known-bad port (4444, 1337, …) | MED/HIGH |
| `file_integrity` | a watched file is created / modified / deleted | MED/HIGH |
| `privilege_event` | `sudo` usage or a new root process | INFO/LOW |

All thresholds, ports, and watched paths are configurable in
`config/config.yaml`.

---

## API

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

---

## Notifications

Kaguya can push an alert to one or more sinks the moment the engine raises it
(gated by `notifications.min_severity`, default `high`). Sinks are
dependency-free and each is isolated — a dead destination never blocks the
monitor or the other sinks.

| Sink | Config | Notes |
|------|--------|-------|
| **console** | on by default | one-line banner to stdout |
| **desktop** | `notifications.desktop.enabled` | Linux toast via `notify-send` |
| **webhook** | `notifications.webhook.enabled` + `url` / `CS_WEBHOOK_URL` | generic JSON POST |
| **slack** | `notifications.slack.enabled` + `webhook_url` / `CS_SLACK_WEBHOOK` | Slack/Mattermost incoming webhook |

> Keep secrets out of the repo: set `CS_SLACK_WEBHOOK` / `CS_WEBHOOK_URL` in
> the environment and they override the (blank) config values.

```bash
# e.g. Slack alerts for HIGH+ events
export CS_SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"
# enable the slack sink in config/config.yaml, then:
python3 -m cybersentinel run
```

### Scheduled reports (daily / weekly)

Turn on `reports.daily` / `reports.weekly` in `config/config.yaml` (defaults: every day 8pm, every Monday 8pm; if a send fails or Kaguya wasn't running, it retries once at `retry_hour`, 8am, only to the channels that missed it). Summaries go to
every enabled channel: console, Slack (text summary), generic webhook, and **email
with the PDF attached** (`notifications.email`, password in env `CS_SMTP_PASSWORD`).
Test any time with `kaguya report --period week --send`. The last-sent time is kept
in the database, so restarts never skip or duplicate a report.

---

## Tiers

| | **Community** (free) | **Pro** | **Enterprise** |
|--|--|--|--|
| Hosts | 1 | 25 | unlimited |
| Retention | 7 days | 90 days | 365 days |
| Max events | 100k | 5M | unlimited |
| Collectors | all | all | all |
| Detection engine | full | full | full |

Set the tier in `config/config.yaml` (`tier: community`) or via `CS_TIER`.

---

## Configuration

Everything has a built-in default; `config/config.yaml` just exposes the
common knobs. Environment overrides (handy in containers):
`CS_API_HOST`, `CS_API_PORT`, `CS_TIER`, `CS_DATABASE`.

---

## Docker

```bash
docker compose up --build
```

`docker-compose.yml` uses `network_mode: host` and `pid: host` so collectors
see the real host (drop these for a sandboxed, container-only view), and
mounts `/var/log` read-only for auth-log collection.

---

## Run Kaguya in the background

Scheduled reports (8pm daily, Monday 8pm weekly, 8am retry) only go out while Kaguya is
running. This keeps it running all the time, starts it at boot, and restarts it if it crashes.
It runs as **your user** (no root), using the unit file in `deploy/kaguya.service`.

**Set up (once):**

```bash
# 0. stop any Kaguya you started by hand in a terminal (Ctrl-C) so port 8787 is free

# 1. install the unit file
mkdir -p ~/.config/systemd/user
cp ~/CyberSentiel/deploy/kaguya.service ~/.config/systemd/user/

# 2. make sure the email key file exists (chmod 600), one line:
#    export CS_SMTP_PASSWORD='your-smtp-key'
ls -l ~/.config/kaguya/smtp.env

# 3. start it now and on every login
systemctl --user daemon-reload
systemctl --user enable --now kaguya

# 4. keep it running at boot even when you're not logged in
sudo loginctl enable-linger "$USER"
```

**Everyday commands:**

| What | Command |
|------|---------|
| Is it running? | `systemctl --user status kaguya` |
| Live logs | `journalctl --user -u kaguya -f` |
| Restart (after editing `config/config.yaml`) | `systemctl --user restart kaguya` |
| Stop / start | `systemctl --user stop kaguya` / `systemctl --user start kaguya` |
| Turn off for good | `systemctl --user disable --now kaguya` |
| Test an email right now | `kaguya report --period day --send` |

The dashboard stays at <http://127.0.0.1:8787>.

**If something's off:**
- *Won't start / "address already in use":* an old Kaguya is still holding port 8787. Find it with `ss -ltnp | grep 8787` and stop it.
- *"No such file" for the unit paths:* the unit assumes the repo is at `~/CyberSentiel` and the command at `~/.local/bin/kaguya` (where `pipx` puts it). Edit `WorkingDirectory=` / `ExecStart=` if yours differ.
- *Emails don't send from the service:* the service can't see your terminal's variables, only the key file. Check `~/.config/kaguya/smtp.env` exists and has the `export CS_SMTP_PASSWORD=...` line.
- *Missing SSH-login alerts:* as a normal user the service can't read `/var/log/auth.log`. Add yourself to the `adm` group (`sudo usermod -aG adm $USER`, then log out/in); Kaguya falls back to the journal otherwise.

**Run as a system-wide root service instead (optional):** adapt the unit into
`/etc/systemd/system/kaguya.service` with `WantedBy=multi-user.target`, a `User=` line, and
`Environment=`/`EnvironmentFile=` for the key (system units need `KEY=value` lines, no `export`).
Root can see every process and the whole auth log, and can also apply **Block this IP** by itself.

> **Privileges:** Kaguya runs unprivileged and degrades gracefully. Without
> elevated rights it still sees sockets, your own processes, and readable
> files, but auth-log/journald access and other users' process details require
> membership in `adm`/`systemd-journal` or root.

---

## Tests

```bash
python3 tests/test_detection.py      # no deps
# or
python3 -m pytest -q
```

---

## Built on open source

Python standard library (`http.server`, `sqlite3`, `hashlib`), `psutil`,
`PyYAML`, and standard tooling (`ss`, `journalctl`). Everything in this repo
is **MIT licensed** — see [`LICENSE`](LICENSE).

---

## Credits & contact

**Open-source edition made by Ordixian / Frost.**
Built on the open-source *CyberSentinel* project (MIT).

Tap **Frost** in the dashboard footer, or reach out on WhatsApp:
<https://wa.me/2349055012367> · +234 905 501 2367
GitHub: <https://github.com/Ordixian>
