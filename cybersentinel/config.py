"""Configuration loading with sane defaults and tier enforcement.

The config is plain YAML (falls back to the bundled defaults if PyYAML is
missing or the file is absent) so the tool runs out of the box.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_YAML = False


# Free "community" tier limits. The paid tiers simply raise these ceilings;
# nothing is crippled — the community tier is a real, usable product.
TIERS = {
    "community": {
        "max_hosts": 1,
        "retention_days": 7,
        "max_events": 100_000,
        "collectors": ["network", "process", "authlog", "fim"],
    },
    "pro": {
        "max_hosts": 25,
        "retention_days": 90,
        "max_events": 5_000_000,
        "collectors": ["network", "process", "authlog", "fim"],
    },
    "enterprise": {
        "max_hosts": 0,            # 0 == unlimited
        "retention_days": 365,
        "max_events": 0,
        "collectors": ["network", "process", "authlog", "fim"],
    },
}


DEFAULTS = {
    "tier": "community",
    "host_label": os.uname().nodename if hasattr(os, "uname") else "localhost",
    "database": "data/cybersentinel.db",
    "api": {"host": "127.0.0.1", "port": 8787},
    "collect_interval": 5,            # seconds between collector sweeps
    "collectors": {
        "network": {"enabled": True},
        "process": {"enabled": True},
        "authlog": {
            "enabled": True,
            # Tried in order; first readable source wins. journalctl is the
            # fallback on systemd hosts with no /var/log/auth.log.
            "paths": ["/var/log/auth.log", "/var/log/secure"],
            "use_journal": True,
        },
        "fim": {
            "enabled": True,
            "paths": [
                "/etc/passwd",
                "/etc/hosts",
                "/etc/crontab",
                "~/.bashrc",
                "~/.profile",
                "~/.ssh/authorized_keys",
            ],
        },
    },
    "notifications": {
        "min_severity": "high",       # info|low|medium|high|critical
        "console": {"enabled": True},
        "desktop": {"enabled": False},  # needs `notify-send`
        "webhook": {"enabled": False, "url": ""},   # or env CS_WEBHOOK_URL
        "slack": {"enabled": False, "webhook_url": ""},  # or env CS_SLACK_WEBHOOK
        # report-only channel (attaches the PDF); password via env CS_SMTP_PASSWORD
        "email": {"enabled": False, "smtp_host": "", "smtp_port": 587,
                  "starttls": True, "username": "", "from": "", "to": []},
    },
    "reports": {
        # local time. A failed/missed send is retried once at retry_hour.
        "daily": {"enabled": False, "hour": 20, "retry_hour": 8},
        "weekly": {"enabled": False, "hour": 20, "weekday": 0, "retry_hour": 8},  # 0 = Monday
    },
    "response": {"allow_block": True},   # dashboard "Block this IP" button
    "detection": {
        "ssh_bruteforce": {"enabled": True, "threshold": 5, "window_sec": 300},
        "new_listen_port": {"enabled": True},
        "suspicious_exec_path": {
            "enabled": True,
            "paths": ["/tmp", "/dev/shm", "/run/user", "/var/tmp"],
        },
        "connection_fanout": {"enabled": True, "threshold": 15, "window_sec": 60},
        "known_bad_port": {
            "enabled": True,
            "ports": [23, 1337, 4444, 5555, 6667, 31337],
        },
        "file_integrity": {"enabled": True},
        "privilege_event": {"enabled": True},
    },
}


class Config:
    def __init__(self, data: dict):
        self._d = data

    # --- dotted lookups ---------------------------------------------------
    def get(self, path: str, default=None):
        node = self._d
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def __getitem__(self, key):
        return self._d[key]

    @property
    def tier(self) -> dict:
        name = self._d.get("tier", "community")
        return TIERS.get(name, TIERS["community"])

    @property
    def tier_name(self) -> str:
        return self._d.get("tier", "community")

    def collector_enabled(self, name: str) -> bool:
        if name not in self.tier["collectors"]:
            return False
        return bool(self.get(f"collectors.{name}.enabled", False))

    @property
    def raw(self) -> dict:
        return self._d


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_env(data: dict) -> dict:
    """Env overrides win over the file (handy in containers)."""
    if os.environ.get("CS_API_HOST"):
        data.setdefault("api", {})["host"] = os.environ["CS_API_HOST"]
    if os.environ.get("CS_API_PORT"):
        data.setdefault("api", {})["port"] = int(os.environ["CS_API_PORT"])
    if os.environ.get("CS_TIER"):
        data["tier"] = os.environ["CS_TIER"]
    if os.environ.get("CS_DATABASE"):
        data["database"] = os.environ["CS_DATABASE"]
    if data.get("host_label") in (None, "null"):
        data["host_label"] = (os.uname().nodename
                              if hasattr(os, "uname") else "localhost")
    return data


def load(path: str | None = None) -> Config:
    """Load config from YAML, deep-merged over DEFAULTS, then env overrides."""
    data = dict(DEFAULTS)
    if path:
        p = Path(path).expanduser()
        if p.exists() and _HAVE_YAML:
            with open(p) as fh:
                user = yaml.safe_load(fh) or {}
            data = _deep_merge(DEFAULTS, user)
    return Config(_apply_env(data))
