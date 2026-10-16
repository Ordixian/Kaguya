"""Notification sinks — fire when the engine raises a qualifying alert.

Sinks are intentionally dependency-free (stdlib ``urllib`` for HTTP, a
``notify-send`` subprocess for desktop). Each sink is guarded so a failing
or slow destination never blocks or crashes the monitor loop; dispatch runs
on a background thread.

Secrets (Slack/webhook URLs) should come from the environment
(``CS_SLACK_WEBHOOK``, ``CS_WEBHOOK_URL``) rather than the committed config
file — ``build_notifier`` prefers env values when present.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

from ..events import Severity, Alert


class Sink:
    name = "sink"

    def enabled(self) -> bool:
        return True

    def send(self, alert: Alert) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class ConsoleSink(Sink):
    """Always-available: prints a one-line banner to stdout."""
    name = "console"

    def send(self, alert: Alert) -> None:
        print(f"[ALERT] {alert.severity.label.upper():8} "
              f"{alert.rule:20} {alert.title}", flush=True)


class DesktopSink(Sink):
    """Linux desktop toast via `notify-send` (no-op if unavailable)."""
    name = "desktop"

    def __init__(self):
        self._bin = shutil.which("notify-send")

    def enabled(self) -> bool:
        return self._bin is not None

    def send(self, alert: Alert) -> None:
        urgency = "critical" if alert.severity >= Severity.HIGH else "normal"
        subprocess.run(
            [self._bin, "-u", urgency, "-a", "Kaguya",
             f"🌙 {alert.severity.label.upper()}: {alert.title}",
             alert.description or ""],
            timeout=5, check=False)


class WebhookSink(Sink):
    """Generic JSON POST of the alert to a configured URL."""
    name = "webhook"

    def __init__(self, url: str):
        self.url = url

    def enabled(self) -> bool:
        return bool(self.url)

    def send(self, alert: Alert) -> None:
        payload = {
            "id": alert.id, "ts": alert.ts, "rule": alert.rule,
            "severity": alert.severity.label, "title": alert.title,
            "description": alert.description, "host": alert.host,
            "data": alert.data,
        }
        _post_json(self.url, payload)


class SlackSink(Sink):
    """Slack / Mattermost incoming-webhook message."""
    name = "slack"
    _EMOJI = {"critical": "🚨", "high": "🔴", "medium": "🟠",
              "low": "🔵", "info": "⚪"}

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def send(self, alert: Alert) -> None:
        emoji = self._EMOJI.get(alert.severity.label, "•")
        text = (f"{emoji} *Kaguya · {alert.severity.label.upper()}*\n"
                f"*{alert.title}*\n{alert.description}\n"
                f"_host:_ `{alert.host}`  _rule:_ `{alert.rule}`")
        _post_json(self.webhook_url, {"text": text})


def _post_json(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST")
    urllib.request.urlopen(req, timeout=8).read()


class NotificationManager:
    def __init__(self, sinks: list[Sink], min_severity: Severity):
        self.sinks = [s for s in sinks if s.enabled()]
        self.min_severity = min_severity

    @property
    def active(self) -> list[str]:
        return [s.name for s in self.sinks]

    def dispatch(self, alerts: list[Alert]) -> None:
        """Send qualifying alerts to every active sink, off the hot path."""
        if not self.sinks:
            return
        qualifying = [a for a in alerts if a.severity >= self.min_severity]
        if not qualifying:
            return
        threading.Thread(target=self._dispatch, args=(qualifying,),
                         daemon=True).start()

    def _dispatch(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            for sink in self.sinks:
                try:
                    sink.send(alert)
                except Exception:  # a dead sink must never break the others
                    continue


def build_notifier(config) -> NotificationManager:
    min_sev = Severity.parse(config.get("notifications.min_severity", "high"))
    sinks: list[Sink] = []
    if config.get("notifications.console.enabled", True):
        sinks.append(ConsoleSink())
    if config.get("notifications.desktop.enabled", False):
        sinks.append(DesktopSink())

    webhook_url = (os.environ.get("CS_WEBHOOK_URL")
                   or config.get("notifications.webhook.url", ""))
    if config.get("notifications.webhook.enabled", False) and webhook_url:
        sinks.append(WebhookSink(webhook_url))

    slack_url = (os.environ.get("CS_SLACK_WEBHOOK")
                 or config.get("notifications.slack.webhook_url", ""))
    if config.get("notifications.slack.enabled", False) and slack_url:
        sinks.append(SlackSink(slack_url))

    return NotificationManager(sinks, min_sev)


# --- report channels: where scheduled summaries go -------------------------
# Separate from alert sinks so a daily report never spams per-alert channels.
# Each channel is callable as channel(subject, text, attachment) where
# attachment is (filename, bytes, mime) or None.

class ReportChannel:
    name = "channel"

    def __call__(self, subject, text, attachment=None):  # pragma: no cover
        raise NotImplementedError


class ConsoleReport(ReportChannel):
    name = "console"

    def __call__(self, subject, text, attachment=None):
        print(f"\n=== {subject} ===\n{text}\n", flush=True)


class SlackReport(ReportChannel):
    name = "slack"

    def __init__(self, url):
        self.url = url

    def __call__(self, subject, text, attachment=None):
        # incoming webhooks cannot carry files, so Slack gets the summary text
        _post_json(self.url, {"text": f"*{subject}*\n{text}"})


class WebhookReport(ReportChannel):
    name = "webhook"

    def __init__(self, url):
        self.url = url

    def __call__(self, subject, text, attachment=None):
        _post_json(self.url, {"type": "report", "subject": subject, "text": text})


class EmailReport(ReportChannel):
    """SMTP email with the PDF attached. Password comes from CS_SMTP_PASSWORD."""
    name = "email"

    def __init__(self, host, port, username, password, sender, to, starttls=True):
        self.host, self.port, self.username = host, int(port), username
        self.password, self.sender, self.to, self.starttls = password, sender, to, starttls

    def __call__(self, subject, text, attachment=None):
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, self.sender, ", ".join(self.to)
        msg.set_content(text)
        if attachment:
            fname, data, mime = attachment
            maintype, _, subtype = mime.partition("/")
            msg.add_attachment(data, maintype=maintype, subtype=subtype.split(";")[0], filename=fname)
        with smtplib.SMTP(self.host, self.port, timeout=15) as smtp:
            if self.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(msg)


def build_report_channels(config) -> list:
    chans: list = []
    if config.get("notifications.console.enabled", True):
        chans.append(ConsoleReport())
    webhook_url = (os.environ.get("CS_WEBHOOK_URL")
                   or config.get("notifications.webhook.url", ""))
    if config.get("notifications.webhook.enabled", False) and webhook_url:
        chans.append(WebhookReport(webhook_url))
    slack_url = (os.environ.get("CS_SLACK_WEBHOOK")
                 or config.get("notifications.slack.webhook_url", ""))
    if config.get("notifications.slack.enabled", False) and slack_url:
        chans.append(SlackReport(slack_url))
    to = config.get("notifications.email.to", []) or []
    if isinstance(to, str):
        to = [to]
    host = config.get("notifications.email.smtp_host", "")
    if config.get("notifications.email.enabled", False) and host and to:
        user = config.get("notifications.email.username", "")
        chans.append(EmailReport(
            host, config.get("notifications.email.smtp_port", 587), user,
            os.environ.get("CS_SMTP_PASSWORD", ""),
            config.get("notifications.email.from", user or "kaguya@localhost"), to,
            bool(config.get("notifications.email.starttls", True))))
    return chans


__all__ = ["build_report_channels", "ReportChannel", "NotificationManager", "build_notifier", "Sink",
           "ConsoleSink", "DesktopSink", "WebhookSink", "SlackSink"]
