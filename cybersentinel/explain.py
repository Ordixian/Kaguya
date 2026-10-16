"""Plain-English explanations for alerts.

Turns a detection alert into something a non-technical person can act on:
what it is, what probably caused it, how worried to be, and how to fix it.
Pure functions over the alert dict, so the dashboard and the exported
reports share the exact same wording.
"""

from __future__ import annotations

from shlex import quote as q

# --- what common programs are, in everyday words ---------------------------
PROCESS_GLOSSARY = {
    "sshd": "The remote-login service. It lets other computers log in to this one over the network.",
    "ssh": "A tool for logging in to another computer over the network.",
    "systemd": "The 'manager' of the computer: it starts and stops background services.",
    "cron": "The scheduler. It runs tasks automatically at set times (like a calendar for programs).",
    "bash": "A text command window (a shell). Anything typed into a terminal runs through it.",
    "sh": "A text command window (a shell). Scripts are often run through it.",
    "zsh": "A text command window (a shell).",
    "python": "The Python language runtime. It runs scripts written in Python.",
    "python3": "The Python language runtime. It runs scripts written in Python.",
    "node": "Runs JavaScript programs outside a web browser.",
    "sudo": "Lets a user run one command with administrator powers.",
    "su": "Switches to another user account, often the administrator.",
    "curl": "Downloads or sends data over the internet from the command line.",
    "wget": "Downloads files from the internet from the command line.",
    "nc": "'Netcat' - a tool that opens raw network connections. Useful to admins, also popular with attackers.",
    "ncat": "'Netcat' - a tool that opens raw network connections. Useful to admins, also popular with attackers.",
    "nmap": "A network scanner that checks which doors (ports) are open on computers.",
    "firefox": "The Firefox web browser.",
    "chrome": "The Chrome web browser.",
    "chromium": "The Chromium web browser.",
    "code": "The VS Code editor.",
    "apt": "The software installer/updater for Debian-style Linux.",
    "apt-get": "The software installer/updater for Debian-style Linux.",
    "dpkg": "The low-level package installer used by apt.",
    "pip": "Installs Python add-on packages.",
    "pipx": "Installs Python command-line apps in their own sandbox.",
    "docker": "Runs apps inside isolated 'containers'.",
    "dockerd": "The background service that runs Docker containers.",
    "nginx": "A web server - it serves websites to visitors.",
    "apache2": "A web server - it serves websites to visitors.",
    "mysqld": "A database server (MySQL/MariaDB).",
    "postgres": "A database server (PostgreSQL).",
    "networkmanager": "Manages Wi-Fi and network connections.",
    "xorg": "Draws the graphical desktop on screen.",
    "cupsd": "The printing service.",
    "avahi-daemon": "Helps devices find each other on your home/office network (printers, TVs, etc.).",
    "kaguya": "This monitor itself.",
}


def _glossary(name):
    n = (name or "").strip().lower()
    if not n:
        return ""
    if n in PROCESS_GLOSSARY:
        return PROCESS_GLOSSARY[n]
    base = n.rstrip("0123456789.").rstrip("-")
    return PROCESS_GLOSSARY.get(base, "")


# well-known ports in plain words
PORT_GLOSSARY = {
    21: "FTP (old-style file transfer)", 22: "SSH (remote login)", 23: "Telnet (old, unencrypted remote login)",
    25: "email sending (SMTP)", 53: "DNS (looks up website names)", 80: "a normal website (HTTP)",
    110: "email (POP3)", 143: "email (IMAP)", 443: "a secure website (HTTPS)", 445: "Windows file sharing (SMB)",
    631: "printing (CUPS)", 1337: "a port often used by hacking tools", 3306: "a MySQL database",
    3389: "Windows Remote Desktop", 4444: "the default port of many hacking tools (Metasploit)",
    5432: "a PostgreSQL database", 5555: "a port often used by backdoors and Android debugging",
    5900: "VNC remote screen sharing", 6667: "IRC chat (often used to control infected machines)",
    8080: "an alternative website port", 8787: "the Kaguya dashboard", 31337: "'Elite' - a classic hacker backdoor port",
}


def _port_word(port):
    try:
        return PORT_GLOSSARY.get(int(port), "")
    except (TypeError, ValueError):
        return ""


def _s(v, default="unknown"):
    return str(v) if v not in (None, "") else default


# --- per-rule guides -------------------------------------------------------
# Each builder returns: what, cause (list), risk, safe_if, fix (list of
# {text, cmd?}).  `d` is the alert's data dict.

def _ssh_bruteforce(a, d):
    ip, n = _s(d.get("ip")), d.get("attempts", "several")
    users = ", ".join((d.get("users") or [])[:6]) or "various names"
    return dict(
        what=(f"Someone at the internet address {ip} tried to log in to this computer {n} times "
              f"in a few minutes and got the password wrong every time. Think of it as a person "
              f"rattling your door handle over and over, trying different keys."),
        cause=[f"A bot or attacker is guessing passwords (it tried the names: {users}). "
               "This is extremely common for any computer reachable from the internet.",
               "Less likely: you or a colleague mistyped a password several times, or an old "
               "saved password in a script/phone is out of date."],
        risk=("Medium-high. Failed guesses alone do no harm, but if one guess ever succeeds the "
              "attacker is inside your machine."),
        safe_if=f"{ip} is your own device or a teammate and you recognise the login attempts.",
        fix=[
            dict(text="Check whether any of the guesses actually worked (look for 'Accepted' lines from that address).",
                 cmd=f"sudo grep 'Accepted' /var/log/auth.log | grep -F -- {q(ip)}"),
            dict(text="Block that address from reaching this computer.",
                 cmd=f"sudo ufw deny from {q(ip)}"),
            dict(text="Stop passwords from working for remote login at all - use SSH keys instead. "
                      "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, then restart SSH.",
                 cmd="sudo systemctl restart ssh"),
            dict(text="Install an automatic bouncer that bans repeat offenders.",
                 cmd="sudo apt install fail2ban"),
            dict(text="If a guess DID work, change that account's password immediately and treat the machine as compromised."),
        ])


def _new_listen_port(a, d):
    port, proto, ip = d.get("port"), _s(d.get("proto"), "tcp"), _s(d.get("ip"))
    proc = d.get("process")
    pw = _port_word(port)
    exposed = not d.get("loopback", False)
    what = (f"A program ({_s(proc, 'name not detected')}) just opened a 'door' (port {port}"
            f"{', ' + pw if pw else ''}) on this computer and started waiting for connections. ")
    what += ("This door is open to other computers on your network." if exposed
             else "This door only accepts connections from this same computer, so it is not reachable from outside.")
    g = _glossary(proc)
    if g:
        what += f" About that program: {g}"
    return dict(
        what=what,
        cause=["You or an installer just started a service (a web server, database, dev tool, file sharing, etc.).",
               "A normal app opened a helper port for itself.",
               "Less likely: malware opened a backdoor so an attacker can connect later."],
        risk=("Low if it only listens on this computer; medium if it is open to the network, "
              "because anyone who can reach it can try to use it."),
        safe_if="you just started or installed the program that owns this port.",
        fix=[
            dict(text="Find out exactly which program owns the door.",
                 cmd=f"sudo ss -ltnp | grep {q(':' + str(port) + ' ')}"),
            dict(text="If you don't recognise it, stop the program (use the PID shown above).",
                 cmd="sudo kill <PID>"),
            dict(text="If you need the program but not outside access, set it to listen on 127.0.0.1 only, or block the port.",
                 cmd=f"sudo ufw deny {q(str(port) + '/' + proto)}"),
            dict(text="If you started it on purpose, mark this alert Resolved."),
        ])


def _suspicious_exec_path(a, d):
    name, pid, user = _s(d.get("name")), _s(d.get("pid")), _s(d.get("user"))
    exe = _s(d.get("exe"), "(path hidden)")
    what = (f"A program called '{name}' (process number {pid}, run by the account '{user}') is "
            f"running from a temporary folder ({exe}). Temporary folders are scratch space - "
            "legitimate software almost never runs from there, but malware loves it because anyone can write there.")
    g = _glossary(d.get("name"))
    if g:
        what += f" The name itself belongs to: {g}"
    return dict(
        what=what,
        cause=["Malware or an attacker's script that was downloaded and launched.",
               "A web exploit that dropped a file into /tmp and ran it.",
               "Harmless: an installer, build tool, AppImage or a script you ran yourself from /tmp."],
        risk="High. This is one of the most common signs of a compromised machine.",
        safe_if="you started it yourself (e.g. an installer or a script you downloaded and ran just now).",
        fix=[
            dict(text="Look at what is really running and where it came from.",
                 cmd=f"ls -l /proc/{q(pid)}/exe; cat /proc/{q(pid)}/cmdline | tr '\\0' ' '"),
            dict(text="If you don't recognise it, stop it.",
                 cmd=f"sudo kill -9 {q(pid)}"),
            dict(text="Keep a copy for inspection, then delete the file so it can't start again.",
                 cmd=f"sudo cp {q(exe)} ~/suspect.bin && sudo rm {q(exe)}" if exe.startswith("/") else None),
            dict(text="Check it didn't set itself up to restart (scheduled tasks and login scripts).",
                 cmd="crontab -l; sudo ls /etc/cron.d; systemctl list-timers"),
            dict(text="Change your passwords if you can't explain how it got there."),
        ])


def _connection_fanout(a, d):
    proc, n = _s(d.get("process")), d.get("distinct_hosts", "many")
    what = (f"The program '{proc}' reached out to {n} different computers within one minute. "
            "Normal apps usually talk to a handful of servers; contacting dozens quickly looks like "
            "scanning the network for victims, or an infected machine 'phoning home'.")
    g = _glossary(proc)
    if g:
        what += f" About that program: {g}"
    return dict(
        what=what,
        cause=["A scanner or worm probing other machines.",
               "Malware checking in with its controller, or sending out spam/attacks.",
               "Harmless: a web browser loading a busy page, a torrent/P2P app, a package manager, a network scan you ran."],
        risk="Medium. Usually benign for browsers; worrying for unfamiliar programs.",
        safe_if="the program is a browser, download manager or something you ran on purpose.",
        fix=[
            dict(text="See where it is connecting.",
                 cmd="sudo ss -tnp | grep -i -F -- " + (q(proc) if proc != "unknown" and "pid:" not in proc else "<name>")),
            dict(text="If it's not something you started, stop it and look for how it started.",
                 cmd="sudo pkill -f <name>"),
            dict(text="Check what the program is and where it lives on disk.",
                 cmd="ps aux | grep -i <name>"),
        ])


def _known_bad_port(a, d):
    listening = "listen" in (a.get("title") or "").lower() or "backdoor" in (a.get("title") or "").lower()
    port = d.get("port")
    if not listening:
        raddr = _s(d.get("raddr"))
        port = raddr.rsplit(":", 1)[-1]
    pw = _port_word(port)
    if listening:
        what = (f"A program is waiting for connections on port {port}"
                f"{' (' + pw + ')' if pw else ''}, a number that hacking tools and backdoors favour. "
                "A backdoor is a hidden way in that lets an attacker control the computer later.")
        risk = "High."
    else:
        what = (f"This computer connected out to {_s(d.get('raddr'))} on port {port}"
                f"{' (' + pw + ')' if pw else ''}. That port number is strongly linked to hacking tools and malware control channels.")
        risk = "Medium. It could be a coincidence, but it deserves a look."
    return dict(
        what=what,
        cause=["Malware calling its controller, or an attacker's backdoor listening.",
               "A penetration-testing or CTF tool you are running yourself (Metasploit, netcat, etc.).",
               "An unrelated app that happens to use the same port number."],
        risk=risk,
        safe_if="you are running a security tool, lab or game that uses this port.",
        fix=[
            dict(text="Identify which program is responsible.",
                 cmd=f"sudo ss -tnp | grep -F -- {q(':' + str(port))}"),
            dict(text="If unknown, stop the program and block the port.",
                 cmd=f"sudo kill <PID>; sudo ufw deny out {q(str(port))}"),
            dict(text="Scan for other signs: strange accounts, scheduled tasks, startup items.",
                 cmd="sudo lastlog | head; crontab -l"),
        ])


def _file_integrity(a, d):
    path = _s(d.get("path"))
    t = (a.get("title") or "").lower()
    if "delete" in t:
        verb, tail = "was deleted", "Attackers sometimes delete files to cover their tracks or break a security setting."
        sev = "High"
    elif "new" in t:
        verb, tail = "has appeared that wasn't there before", "Attackers sometimes plant new files in sensitive folders."
        sev = "Medium"
    else:
        verb, tail = "was changed", "Attackers sometimes change system files to create a hidden way back in or to hide themselves."
        sev = "Medium"
    return dict(
        what=(f"An important system file ({path}) {verb}. Kaguya keeps a fingerprint of a few "
              f"sensitive files so it can tell when they change. {tail}"),
        cause=["A normal software update, or you editing a setting on purpose.",
               "Adding or removing a user account, or changing a password (this changes the 'passwd'/'shadow' files).",
               "Less likely: an attacker modifying the system."],
        risk=f"{sev}. Safe if you just updated or configured something; suspicious if not.",
        safe_if="you or the package manager recently changed it (check the time on this alert).",
        fix=[
            dict(text="See what changed recently on that file.",
                 cmd=f"ls -l --time-style=full-iso -- {q(path)}" if path != "unknown" else None),
            dict(text="Check whether a package update touched it around that time.",
                 cmd="grep -E 'upgrade|install' /var/log/dpkg.log | tail -20"),
            dict(text="Check who logged in at that time.",
                 cmd="last -n 20"),
            dict(text="If you can't explain the change, restore it from a backup and review your accounts."),
        ])


def _privilege_event(a, d):
    if a.get("rule") == "privilege_event" and "sudo" in (a.get("title") or "").lower():
        user, cmd = _s(d.get("user")), _s(d.get("cmd"))
        return dict(
            what=(f"The account '{user}' used 'sudo' - a way to borrow administrator powers for one task - "
                  f"to run: {cmd}. This is a routine record, not a warning on its own."),
            cause=["You or an admin ran an administrator command (installing software, changing settings)."],
            risk="Info. Only matters if you did not do this.",
            safe_if="you recognise the command and the time.",
            fix=[
                dict(text="If you don't recognise it, see who was logged in then.", cmd="last -n 20"),
                dict(text="Otherwise nothing to do - mark it Resolved."),
            ])
    name = _s(d.get("name"))
    g = _glossary(d.get("name"))
    what = (f"A new program called '{name}' has started with full administrator ('root') powers. "
            "Root can do anything on the computer, so Kaguya notes every new one.")
    if g:
        what += f" About that program: {g}"
    return dict(
        what=what,
        cause=["Normal system services and scheduled tasks start this way.",
               "You ran a command with sudo.",
               "Less likely: something unwanted gained administrator rights."],
        risk="Low. Pay attention only if the program name is unfamiliar.",
        safe_if="the name is a known system tool, or you ran it with sudo just now.",
        fix=[
            dict(text="Check what it is and who started it.",
                 cmd=f"ps -fp {q(_s(d.get('pid'), '<PID>'))}"),
            dict(text="If it's unfamiliar, look at its location before deciding.",
                 cmd=f"ls -l /proc/{q(_s(d.get('pid'), '<PID>'))}/exe"),
        ])


_BUILDERS = {
    "ssh_bruteforce": _ssh_bruteforce,
    "new_listen_port": _new_listen_port,
    "suspicious_exec_path": _suspicious_exec_path,
    "connection_fanout": _connection_fanout,
    "known_bad_port": _known_bad_port,
    "file_integrity": _file_integrity,
    "privilege_event": _privilege_event,
}


def explain_alert(alert: dict) -> dict:
    """Return a plain-English explanation for an alert dict (as served by the API)."""
    data = alert.get("data") or {}
    builder = _BUILDERS.get(alert.get("rule"))
    if builder:
        g = builder(alert, data)
    else:
        g = dict(
            what=alert.get("description") or alert.get("title") or "Kaguya noticed unusual activity.",
            cause=["The detection rule that raised this alert doesn't have a plain-English guide yet."],
            risk=f"Severity is {alert.get('severity', 'unknown')}.",
            safe_if="you recognise the activity.",
            fix=[dict(text="Review the details below, then acknowledge or resolve the alert.")])
    # drop steps whose command couldn't be built
    g["fix"] = [{k: v for k, v in s.items() if v} for s in g["fix"]]
    g["rule"] = alert.get("rule")
    return g


ALL_RULES_COVERED = tuple(_BUILDERS)


# --- overall health, in one glance ----------------------------------------

def health_score(open_by_severity: dict) -> dict:
    """Summarise open alerts as a 0-100 score plus a plain-English verdict."""
    c = open_by_severity or {}
    crit, high = c.get("critical", 0), c.get("high", 0)
    med, low = c.get("medium", 0), c.get("low", 0)
    score = max(0, round(100 - 40 * crit - 20 * high - 6 * med - min(10, 1.5 * low)))
    if crit:
        lvl, title = "act", "Act now"
        msg = f"{crit} critical alert(s) need immediate attention. Open them below and follow the fix steps."
    elif high:
        lvl, title = "attention", "Needs attention"
        msg = f"{high} serious alert(s) are waiting. Review them below - each one explains what to do."
    elif med:
        lvl, title = "fine", "Mostly fine"
        msg = f"{med} moderate alert(s) to look at when you have a moment."
    elif low:
        lvl, title = "good", "Looking good"
        msg = "Only minor, low-risk notices. Nothing urgent."
    else:
        lvl, title = "clear", "All clear"
        msg = "No open alerts. Kaguya is watching and everything looks normal."
    return {"score": score, "level": lvl, "title": title, "message": msg}


# --- plain-English notes for the raw event stream --------------------------

_EVENT_GUIDE = {
    "process.new": ("A program just started on this computer.",
                    "Completely normal - programs start all the time. Only worry if the name is unfamiliar AND it runs from a temporary folder."),
    "listen.new": ("A program opened a 'door' (port) and is waiting for other programs to connect.",
                   "Normal when you start a server or app. Worth a look if you didn't start anything."),
    "listen.closed": ("A program closed one of its 'doors' (ports).",
                      "Normal - it usually means an app was shut down."),
    "conn.new": ("A program on this computer connected out to another computer on the network or internet.",
                 "Normal for browsers, updates and chat apps. Odd only if the program is unfamiliar or the destination is strange."),
    "ssh.failed": ("Someone tried to log in remotely and the password was wrong.",
                   "One or two is usually a typo. Many in a row from one address means someone is guessing passwords."),
    "ssh.invalid_user": ("Someone tried to log in remotely with a username that doesn't exist here.",
                         "Common internet background noise from bots guessing common names like 'admin'."),
    "ssh.accepted": ("Someone successfully logged in remotely.",
                     "Fine if it was you or a teammate. Suspicious if you don't recognise the user or address."),
    "auth.sudo": ("Someone used 'sudo' to run a command with administrator powers.",
                  "Routine when you or an admin install or change things."),
    "file.new": ("A new file appeared in a folder Kaguya guards.",
                 "Expected after installing software or editing settings; suspicious otherwise."),
    "file.modified": ("A guarded system file changed.",
                      "Expected after updates or when you change settings; suspicious otherwise."),
    "file.deleted": ("A guarded system file was deleted.",
                     "Rare. Check you didn't remove it on purpose."),
    "collector.error": ("One of Kaguya's sensors had a problem reading its data.",
                        "Usually a permissions issue (e.g. can't read the login log). Monitoring continues with the other sensors."),
}


def explain_event(event: dict) -> dict:
    cat = event.get("category") or ""
    what, normal = _EVENT_GUIDE.get(cat, (
        event.get("description") or event.get("title") or "Kaguya noticed some activity.",
        "Events are just observations; only alerts mean something may be wrong."))
    d = event.get("data") or {}
    extra = ""
    if cat == "process.new":
        g = _glossary(d.get("name"))
        extra = f"About '{d.get('name')}': {g}" if g else ""
    elif cat in ("listen.new", "listen.closed"):
        pw = _port_word(d.get("port"))
        extra = f"Port {d.get('port')} is normally {pw}." if pw else ""
    elif cat == "conn.new":
        port = str(d.get("raddr") or "").rsplit(":", 1)[-1]
        pw = _port_word(port)
        g = _glossary(d.get("process"))
        extra = " ".join(x for x in (f"It connected to port {port}, normally {pw}." if pw else "",
                                     f"About '{d.get('process')}': {g}" if g else "") if x)
    return {"what": what, "normal": normal, "extra": extra}


# --- "what do I do rn" quick summary (casual tone on purpose) ---------------

_VIBE = {
    "clear": "Vibe check: immaculate. Zero open alerts, nothing needs you. Go touch grass.",
    "good": "Vibe check: mostly chill. Only tiny low-risk stuff, nothing urgent.",
    "fine": "Vibe check: kinda mid. A few things to peep when you get a sec.",
    "attention": "Vibe check: not it. Some stuff needs you today, don't sleep on it.",
    "act": "Vibe check: we got a problem fr. Handle the critical stuff first, everything else can wait.",
}


def _action_line(a: dict) -> str:
    rule, d = a.get("rule"), a.get("data") or {}
    if rule == "ssh_bruteforce":
        return (f"Someone at {_s(d.get('ip'))} keeps spamming your SSH login. Block that IP "
                "(the Block IP button on the dashboard) and switch to SSH keys, passwords are mid.")
    if rule == "suspicious_exec_path":
        return (f"'{_s(d.get('name'))}' is running out of a temp folder which is sus af. "
                "Check what it is, and if you didn't start it, kill it and delete the file.")
    if rule == "new_listen_port":
        return (f"Something opened port {_s(d.get('port'))}. If you started it, hit Mark as safe. "
                "If you didn't, shut it down, no cap.")
    if rule == "connection_fanout":
        return (f"'{_s(d.get('process'))}' is hitting tons of hosts at once. A browser? Fine. "
                "Random program? Yeet it and see where it came from.")
    if rule == "known_bad_port":
        return ("Something is using a port hackers love. If it's not your pentest tool, "
                "find the program and shut it down.")
    if rule == "file_integrity":
        return (f"{_s(d.get('path'))} changed. If you didn't update or edit it, "
                "restore it from backup and check who logged in (`last`).")
    if rule == "privilege_event":
        return "New admin-level activity. If that was you, ignore it. If not, run `last` and check who was on."
    return f"{_s(a.get('title'))}: open the alert for the full breakdown."


def _group_line(rule: str, members: list) -> str:
    if len(members) == 1:
        return _action_line(members[0])
    n = len(members)
    if rule == "new_listen_port":
        ports = ", ".join(str((m.get("data") or {}).get("port")) for m in members[:4])
        return (f"{n} programs opened new ports (like {ports}). If you just launched your apps/dev servers, "
                "hit Mark as safe. If not, find out what's listening with `sudo ss -ltnp`.")
    if rule == "ssh_bruteforce":
        return f"{n} different addresses are spamming your SSH login. Block them and switch to SSH keys, passwords are mid."
    return f"{n} separate issues of this type. " + _action_line(members[0])


def quick_summary(issues: list, health: dict, limit: int = 5) -> dict:
    """Casual 'what to do' summary from distinct open alerts (dicts, worst first)."""
    actions = []
    if not issues:
        actions.append("Nothing to do rn. Kaguya's still watching, you just vibe.")
    else:
        groups = {}                       # keep first-seen (= worst-first) order
        for a in issues:
            groups.setdefault(a.get("rule"), []).append(a)
        items = list(groups.items())
        for rule, members in items[:limit]:
            actions.append(f"[{str(members[0].get('severity', '')).upper()}] {_group_line(rule, members)}")
        if len(items) > limit:
            rest = sum(len(m) for _, m in items[limit:])
            actions.append(f"+{rest} more smaller issues. Open the dashboard and clear them out when you can.")
    return {"vibe": _VIBE.get(health.get("level"), _VIBE["clear"]), "actions": actions}
