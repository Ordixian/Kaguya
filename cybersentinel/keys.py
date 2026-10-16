"""Stable identity for alerts: what makes two alerts "the same thing".

Used for grouping repeats on the dashboard and for the safe-list (so
"mark as safe" silences exactly the thing the user looked at, no more).
"""

from __future__ import annotations


def alert_key(rule: str, title: str, data: dict) -> tuple[str, str]:
    """Return (value, human_label) identifying the subject of an alert."""
    d = data or {}
    t = (title or "").lower()
    if rule == "ssh_bruteforce":
        ip = str(d.get("ip") or "?")
        return ip, f"failed SSH logins from {ip}"
    if rule == "new_listen_port":
        v = f"{d.get('proto', 'tcp')}/{d.get('port')}"
        return v, f"programs listening on port {v}"
    if rule == "known_bad_port":
        if "listener" in t or "backdoor" in t:
            v = f"listen:{d.get('proto', 'tcp')}/{d.get('port')}"
            return v, f"a listener on port {d.get('port')}"
        v = f"conn:{d.get('raddr')}"
        return v, f"connections to {d.get('raddr')}"
    if rule == "suspicious_exec_path":
        v = str(d.get("exe") or d.get("name") or "?")
        return v, f"the program {v} running from a temporary folder"
    if rule == "connection_fanout":
        v = str(d.get("process") or "?")
        return v, f"many-host connections from {v}"
    if rule == "file_integrity":
        kind = "deleted" if "delet" in t else "new" if "new" in t else "modified"
        v = f"{kind}:{d.get('path')}"
        return v, f"{kind} file {d.get('path')}"
    if rule == "privilege_event":
        if "sudo" in t:
            v = f"sudo:{d.get('user')}:{d.get('cmd')}"
            return v, f"sudo use by {d.get('user')}"
        v = f"root:{d.get('name')}"
        return v, f"new root programs named {d.get('name')}"
    return title or "?", title or "this alert"
