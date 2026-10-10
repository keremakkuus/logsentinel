"""Output formats: terminal text, JSON, and a self-contained HTML report."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Dict, List

from .models import Alert

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[36m"}
_RESET = "\033[0m"


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def render_text(alerts: List[Alert], summary: Dict, color: bool = False) -> str:
    sev = summary["by_severity"]
    out = [
        "LogSentinel report",
        f"Events analysed: {summary['events_total']} "
        f"(auth: {summary['events_auth']}, web: {summary['events_web']})",
        f"Alerts: {summary['alerts_total']}  |  critical {sev['critical']}  high {sev['high']}  "
        f"medium {sev['medium']}  low {sev['low']}",
        "",
    ]
    for a in alerts:
        tag = f"[{a.severity.upper()}]"
        if color:
            tag = f"{_COLORS[a.severity]}{tag}{_RESET}"
        out.append(f"{tag} {a.rule_id}  {a.ip}  ({a.mitre_id} {a.mitre_name})")
        out.append(f"    {a.title}")
        out.append(f"    {_fmt(a.first_seen)} -> {_fmt(a.last_seen)} UTC | {a.count} events")
        out.append(f"    {a.description}")
        if a.sources:
            out.append(f"    Sources: {', '.join(a.sources[:8])}" + (" ..." if len(a.sources) > 8 else ""))
        out.append(f"    Action: {a.recommendation}")
        out.append("")
    if not alerts:
        out.append("No alerts. Nothing matched the detection rules.")
    return "\n".join(out)


def render_json(alerts: List[Alert], summary: Dict) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "alerts": [a.to_dict() for a in alerts],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _mitre_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5d6670;--line:#e1e4e8;
--critical:#b00020;--high:#d9480f;--medium:#b7791f;--low:#2b6cb0}
@media (prefers-color-scheme:dark){:root{--bg:#0f1317;--card:#171c22;--text:#e8ecf0;--muted:#9aa5b1;--line:#27303a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:24px}
.wrap{max-width:1000px;margin:0 auto}h1{margin:0 0 4px;font-size:24px}
.sub{color:var(--muted);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:26px}.card span{color:var(--muted);font-size:13px}
.badge{display:inline-block;color:#fff;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700;
text-transform:uppercase}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}
.low{background:var(--low)}
.alert{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--line);
border-radius:10px;padding:14px 16px;margin-bottom:12px}
.alert.critical{border-left-color:var(--critical)}.alert.high{border-left-color:var(--high)}
.alert.medium{border-left-color:var(--medium)}.alert.low{border-left-color:var(--low)}
.alert h3{margin:6px 0 4px;font-size:16px}.meta{color:var(--muted);font-size:13px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow-x:auto;
white-space:pre-wrap;word-break:break-all;margin:8px 0 0}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted)}
a{color:var(--low)}table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:24px}
td,th{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
h2{font-size:18px;margin:24px 0 10px}
"""


def render_html(alerts: List[Alert], summary: Dict, title: str = "LogSentinel report") -> str:
    e = html.escape
    sev = summary["by_severity"]
    cards = "".join(
        f'<div class="card"><b>{n}</b><span>{label}</span></div>'
        for label, n in [("Events analysed", summary["events_total"]), ("Alerts", summary["alerts_total"]),
                         ("Critical", sev["critical"]), ("High", sev["high"]),
                         ("Medium", sev["medium"]), ("Low", sev["low"])])
    ip_rows = "".join(
        f'<tr><td><code>{e(d["ip"])}</code></td><td><span class="badge {d["worst"]}">{d["worst"]}</span></td>'
        f'<td>{d["alerts"]}</td></tr>' for d in summary["top_ips"])
    blocks = []
    for a in alerts:
        evidence = "\n".join(e(line) for line in a.evidence)
        blocks.append(
            f'<div class="alert {a.severity}">'
            f'<span class="badge {a.severity}">{a.severity}</span> '
            f'<span class="meta">{e(a.rule_id)} &middot; <code>{e(a.ip)}</code> &middot; '
            f'<a href="{_mitre_url(a.mitre_id)}" target="_blank" rel="noopener">{e(a.mitre_id)} '
            f'{e(a.mitre_name)}</a></span>'
            f'<h3>{e(a.title)}</h3>'
            f'<div>{e(a.description)}</div>'
            f'<div class="meta">{_fmt(a.first_seen)} &rarr; {_fmt(a.last_seen)} UTC &middot; {a.count} events</div>'
            + (f'<div class="meta">Sources: {e(", ".join(a.sources[:12]))}'
               f'{" ..." if len(a.sources) > 12 else ""}</div>' if a.sources else "") +
            f'<div><b>Recommended action:</b> {e(a.recommendation)}</div>'
            f'<details><summary>Evidence ({len(a.evidence)} log lines)</summary><pre>{evidence}</pre></details>'
            f'</div>')
    body = "".join(blocks) or "<p>No alerts. Nothing matched the detection rules.</p>"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{e(title)}</title><style>{_CSS}</style></head><body><div class=\"wrap\">"
        f'<h1>{e(title)}</h1><div class="sub">Generated {generated}</div>'
        f'<div class="cards">{cards}</div>'
        f'<h2>Sources ranked by severity</h2>'
        f'<table><tr><th>IP address</th><th>Worst severity</th><th>Alerts</th></tr>{ip_rows}</table>'
        f"<h2>Alerts</h2>{body}</div></body></html>")
