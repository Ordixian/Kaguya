# Changelog

All notable changes to Kaguya (formerly CyberSentinel). Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [2.13.0] - 2026-10-16

First public open-source release. Git history was squashed for this edition.

### Added
- Live host telemetry from four collectors: network sockets, processes, auth logs (files or `journalctl`), and SHA-256 file integrity.
- Detection engine with windowed rules and cooldown de-duplication: SSH brute force, new listening ports, known-bad ports, connection fan-out, suspicious exec paths, file integrity changes, privilege events. Alerts carry MITRE ATT&CK tags.
- Web dashboard and JSON API built on the Python standard library only (dark/light theme, alert chime and toasts, alert grouping, ack/resolve/reopen, safe list, wallpaper and mascot support).
- Plain-English explanations and copy-ready fix commands for every alert.
- **Block this IP** response action for SSH brute-force alerts (`ufw`/`iptables`, never a shell).
- Reports as PDF, Word or CSV, plus scheduled daily and weekly reports with a retry window.
- Notification sinks: console, desktop, Slack, generic webhook, email (PDF attached).
- Hardened API: custom header, local Host and same-origin checks on all writes; no wildcard CORS.
- `kaguya` command (`run`, `sweep`, `status`, `report`), Dockerfile, systemd user unit, CI workflow, test suite.
- `docs/` folder, `SECURITY.md`, `CONTRIBUTING.md`, issue and PR templates.

### Changed
- Project renamed from CyberSentinel to Kaguya. The Python package is still named `cybersentinel` internally.
- Version bumped from the `0.1.0` placeholder to `2.13.0`; `kaguya status` now prints the version.
- Removed personal contact details from the README and dashboard footer.
- Tier table is now documented as planned; only the community tier is implemented.

## Earlier versions (CyberSentinel, pre-release)

Internal, unpublished. Their history is not part of this repository.

- **2.x**: dashboard console redesign, reports, notification sinks, block-IP, safe list.
- **1.x**: detection engine, SQLite storage, JSON API.
- **0.x**: collectors and first prototype.

[2.13.0]: https://github.com/Ordixian/Kaguya/releases/tag/v2.13.0
