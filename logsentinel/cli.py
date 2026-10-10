"""Command line interface."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from typing import List, Optional

from .config import Config
from .engine import analyze, summarize
from .models import SEVERITIES, severity_rank
from .parsers import parse_access_line, parse_auth_line, parse_file
from .report import render_html, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="Detect SSH and web attacks in log files and map them to MITRE ATT&CK.")
    p.add_argument("--auth", action="append", default=[], metavar="FILE",
                   help="SSH auth log (e.g. /var/log/auth.log). Can be repeated.")
    p.add_argument("--web", action="append", default=[], metavar="FILE",
                   help="Apache/Nginx combined access log. Can be repeated.")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="Year for auth.log timestamps (syslog has none). Default: current year.")
    p.add_argument("--config", metavar="JSON", help="JSON file that overrides detection thresholds.")
    p.add_argument("--allowlist", default="", metavar="IPS",
                   help="Comma-separated IPs/CIDRs to ignore, e.g. 10.0.0.0/8,192.0.2.10")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low",
                   help="Hide alerts below this level.")
    p.add_argument("--json", metavar="FILE", help="Write alerts as JSON.")
    p.add_argument("--html", metavar="FILE", help="Write a self-contained HTML report.")
    p.add_argument("--fail-on", choices=SEVERITIES,
                   help="Exit with code 2 if any alert has at least this severity (useful in scripts/CI).")
    p.add_argument("--no-color", action="store_true", help="Disable colored terminal output.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.auth and not args.web:
        print("Nothing to do: give at least one --auth or --web file.", file=sys.stderr)
        return 1

    cfg = Config.from_file(args.config) if args.config else Config()
    cfg.allowlist += [x.strip() for x in args.allowlist.split(",") if x.strip()]

    events, ignored = [], 0
    try:
        for path in args.auth:
            ev, ig = parse_file(path, lambda line: parse_auth_line(line, args.year))
            events += ev
            ignored += ig
        for path in args.web:
            ev, ig = parse_file(path, parse_access_line)
            events += ev
            ignored += ig
    except OSError as exc:
        print(f"Cannot read file: {exc}", file=sys.stderr)
        return 1

    alerts = [a for a in analyze(events, cfg)
              if severity_rank(a.severity) >= severity_rank(args.min_severity)]
    summary = summarize(events, alerts)

    color = sys.stdout.isatty() and not args.no_color
    print(render_text(alerts, summary, color=color))
    print(f"({ignored} unrelated log lines ignored)")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(render_json(alerts, summary))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(alerts, summary))

    if args.fail_on and any(severity_rank(a.severity) >= severity_rank(args.fail_on) for a in alerts):
        return 2
    return 0
