"""Active response: block an attacker's IP at the host firewall.

Deliberately narrow: IPs are validated with the `ipaddress` module, commands
are run as argument lists (never through a shell), and loopback / unspecified /
multicast / link-local addresses are always refused. Private LAN addresses
need an explicit extra confirmation. If the process lacks permission the
caller gets the exact command to run by hand instead.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess


class BlockError(Exception):
    pass


def validate_ip(raw, allow_private=False):
    try:
        ip = ipaddress.ip_address(str(raw).strip())
    except ValueError:
        raise BlockError(f"'{raw}' is not a valid IP address")
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise BlockError(f"{ip} is a special address that must never be blocked")
    if ip.is_private and not allow_private:
        raise BlockError(f"{ip} is a private/local-network address (could be your own router or device). "
                         "Confirm explicitly if you really want to block it")
    return ip


def _plan(ip, undo):
    """Return (argv, manual_command) for the available firewall tool."""
    s = str(ip)
    if shutil.which("ufw"):
        argv = ["ufw", "delete", "deny", "from", s] if undo else ["ufw", "insert", "1", "deny", "from", s]
    else:
        tool = "ip6tables" if ip.version == 6 else "iptables"
        if not shutil.which(tool):
            raise BlockError("no firewall tool found (ufw or iptables)")
        argv = [tool, "-D" if undo else "-I", "INPUT", "-s", s, "-j", "DROP"]
    return argv, "sudo " + " ".join(argv)


def _run(ip, undo, allow_private):
    ip = validate_ip(ip, allow_private)
    argv, manual = _plan(ip, undo)
    full = argv if os.geteuid() == 0 else ["sudo", "-n"] + argv
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "ip": str(ip), "message": f"Could not run the firewall tool: {e}",
                "manual": manual}
    if r.returncode == 0:
        return {"ok": True, "ip": str(ip), "method": argv[0],
                "message": f"{'Unblocked' if undo else 'Blocked'} {ip} using {argv[0]}."}
    err = (r.stderr or r.stdout or "").strip().splitlines()
    return {"ok": False, "ip": str(ip), "manual": manual,
            "message": "Kaguya doesn't have permission to change the firewall"
                       + (f" ({err[-1][:120]})" if err else "")
                       + ". Run the command below in a terminal instead."}


def block_ip(ip, allow_private=False):
    return _run(ip, False, allow_private)


def unblock_ip(ip):
    return _run(ip, True, True)
