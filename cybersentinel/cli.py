"""Command-line entrypoint.

    kaguya run       # monitor + dashboard (default)   [= python -m cybersentinel run]
    kaguya sweep     # one sweep, print findings, exit
    kaguya status    # show tier/config and exit
    kaguya report    # write an alert-history report (or --send it to Slack/email)
"""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__, config as config_mod
from .storage import Storage
from .monitor import Monitor
from .api import serve


BANNER = r"""
  _  __      _      ____   _   _  __   __   _
 | |/ /     / \    / ___| | | | | \ \ / /  / \
 | ' /     / _ \  | |  _  | | | |  \ V /  / _ \
 | . \    / ___ \ | |_| | | |_| |   | |  / ___ \
 |_|\_\  /_/   \_\ \____|  \___/    |_| /_/   \_\
          moonlit host security monitor  v%s
""" % __version__


def _load(args):
    cfg = config_mod.load(args.config)
    storage = Storage(cfg.get("database", "data/cybersentinel.db"),
                      max_events=cfg.tier.get("max_events", 0))
    return cfg, storage


def cmd_run(args):
    cfg, storage = _load(args)
    monitor = Monitor(cfg, storage)
    host = cfg.get("api.host", "127.0.0.1")
    port = int(cfg.get("api.port", 8787))

    print(BANNER)
    print(f"  tier        : {cfg.tier_name}")
    print(f"  host label  : {cfg.get('host_label')}")
    print(f"  collectors  : {', '.join(c.name for c in monitor.collectors) or 'none'}")
    print(f"  interval    : {monitor.interval}s")
    print(f"  database    : {storage.path}")
    print(f"  dashboard   : http://{host}:{port}")
    print("  (Ctrl-C to stop)\n")

    monitor.start()
    httpd = serve(storage, monitor, host=host, port=port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down…")
    finally:
        monitor.stop()
        httpd.shutdown()
        storage.close()
    return 0


def cmd_sweep(args):
    cfg, storage = _load(args)
    monitor = Monitor(cfg, storage)
    print(f"Priming {len(monitor.collectors)} collector(s)…")
    monitor.sweep_once()                 # first sweep = baseline (silent)
    time.sleep(args.wait)
    n_events, n_alerts = monitor.sweep_once()
    print(f"\nSweep complete: {n_events} new event(s), {n_alerts} alert(s)\n")
    for a in storage.recent_alerts(limit=50):
        print(f"  [{a.severity.label.upper():8}] {a.rule:22} {a.title}")
    if not n_alerts:
        print("  (no alerts — baseline looks clean)")
    storage.close()
    return 0


def cmd_status(args):
    cfg, storage = _load(args)
    s = storage.stats()
    print(BANNER)
    print(f"  tier            : {cfg.tier_name}")
    print(f"  retention (days): {cfg.tier.get('retention_days')}")
    print(f"  max events      : {cfg.tier.get('max_events') or 'unlimited'}")
    print(f"  database        : {storage.path}")
    print(f"  events stored   : {s['events_total']}")
    print(f"  alerts stored   : {s['alerts_total']} ({s['alerts_open']} open)")
    print(f"  open by severity: {s['open_alerts_by_severity'] or '—'}")
    storage.close()
    return 0


def cmd_report(args):
    from . import reports
    from .scheduler import ReportScheduler
    cfg, storage = _load(args)
    if args.send:
        sched = ReportScheduler(cfg, storage)
        print("sending via:", ", ".join(c.name for c in sched.channels) or "nothing configured")
        failures = sched.deliver(args.period, f"Kaguya {args.period} report (manual)", args.format)
        for f in failures:
            print("  failed ->", f)
        storage.close()
        return 1 if failures else 0
    rep = reports.build_report(storage, args.period, host=cfg.get("host_label"))
    out = args.output or reports.filename(rep, reports.FORMATS[args.format][1])
    with open(out, "wb") as fh:
        fh.write(reports.render(rep, args.format))
    print(f"wrote {out} ({rep['total']} alert(s), {rep['label']})")
    storage.close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="kaguya", description="Moonlit host security monitor.")
    parser.add_argument("-c", "--config", default="config/config.yaml",
                        help="path to config YAML (default: config/config.yaml)")
    sub = parser.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="run monitor + dashboard (default)")
    p_run.set_defaults(func=cmd_run)

    p_sweep = sub.add_parser("sweep", help="one baseline+live sweep, then exit")
    p_sweep.add_argument("--wait", type=float, default=3.0,
                         help="seconds between baseline and live sweep")
    p_sweep.set_defaults(func=cmd_sweep)

    p_status = sub.add_parser("status", help="show config/tier/db status")
    p_status.set_defaults(func=cmd_status)

    p_rep = sub.add_parser("report", help="export alert history (pdf/docx/csv)")
    p_rep.add_argument("--period", default="day", choices=list(__import__(
        "cybersentinel.reports", fromlist=["PERIODS"]).PERIODS))
    p_rep.add_argument("--format", default="pdf", choices=["pdf", "docx", "csv"])
    p_rep.add_argument("-o", "--output", help="output file (default: auto-named)")
    p_rep.add_argument("--send", action="store_true",
                       help="deliver through the configured report channels instead")
    p_rep.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    if not args.cmd:
        args.func = cmd_run
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
