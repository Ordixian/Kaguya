# Run Kaguya in the background

Scheduled reports (8pm daily, Monday 8pm weekly, 8am retry) only go out while Kaguya is
running. This keeps it running all the time, starts it at boot, and restarts it if it crashes.
It runs as **your user** (no root), using the unit file in `deploy/kaguya.service`.

**Set up (once):**

```bash
# 0. stop any Kaguya you started by hand in a terminal (Ctrl-C) so port 8787 is free

# 1. install the unit file
mkdir -p ~/.config/systemd/user
cp deploy/kaguya.service   # run from your clone folder; then set WorkingDirectory= inside it ~/.config/systemd/user/

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
- *"No such file" for the unit paths:* the unit assumes your clone folder is `~/Kaguya` and the command is at `~/.local/bin/kaguya` (where `pipx` puts it). Edit `WorkingDirectory=` / `ExecStart=` in the unit file to match your clone folder.
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
