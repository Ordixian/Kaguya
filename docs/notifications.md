# Notifications and scheduled reports

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

## Scheduled reports (daily / weekly)

Turn on `reports.daily` / `reports.weekly` in `config/config.yaml` (defaults: every day 8pm, every Monday 8pm; if a send fails or Kaguya wasn't running, it retries once at `retry_hour`, 8am, only to the channels that missed it). Summaries go to
every enabled channel: console, Slack (text summary), generic webhook, and **email
with the PDF attached** (`notifications.email`, password in env `CS_SMTP_PASSWORD`).
Test any time with `kaguya report --period week --send`. The last-sent time is kept
in the database, so restarts never skip or duplicate a report.
