"""Runs all detectors, applies the allowlist, removes duplicates and sorts results."""
from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Dict, List

from .config import Config
from .detectors import DETECTORS, DISTRIBUTED_DETECTORS
from .models import Alert, Event, SEVERITIES, severity_rank


def _is_allowed(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def analyze(events: List[Event], cfg: Config) -> List[Alert]:
    networks = [ipaddress.ip_network(entry, strict=False) for entry in cfg.allowlist]
    events = [e for e in events if not _is_allowed(e.ip, networks)]

    alerts: List[Alert] = []
    for detector in DETECTORS:
        alerts.extend(detector(events, cfg))

    # Spraying is a more precise description than brute force for the same IP.
    spray_ips = {a.ip for a in alerts if a.rule_id == "SSH-SPRAY"}
    alerts = [a for a in alerts if not (a.rule_id == "SSH-BRUTE" and a.ip in spray_ips)]

    # Stage 2: distributed rules look only at failed logins that no single noisy IP explains.
    explained = {a.ip for a in alerts if a.rule_id in ("SSH-BRUTE", "SSH-SPRAY")}
    residual = [e for e in events if not (e.kind == "ssh_failed" and e.ip in explained)]
    for detector in DISTRIBUTED_DETECTORS:
        alerts.extend(detector(residual, cfg))

    alerts.sort(key=lambda a: (-severity_rank(a.severity), -a.count, a.ip))
    return alerts


def summarize(events: List[Event], alerts: List[Alert]) -> Dict:
    by_sev = Counter(a.severity for a in alerts)
    by_rule = Counter(a.rule_id for a in alerts)
    per_ip: Dict[str, Dict] = {}
    for a in alerts:
        for ip in (a.sources or [a.ip]):      # distributed alerts count for every IP involved
            entry = per_ip.setdefault(ip, {"ip": ip, "alerts": 0, "worst": "low"})
            entry["alerts"] += 1
            if severity_rank(a.severity) > severity_rank(entry["worst"]):
                entry["worst"] = a.severity
    top_ips = sorted(per_ip.values(), key=lambda d: (-severity_rank(d["worst"]), -d["alerts"], d["ip"]))
    return {
        "events_total": len(events),
        "events_auth": sum(1 for e in events if e.source == "auth"),
        "events_web": sum(1 for e in events if e.source == "web"),
        "alerts_total": len(alerts),
        "by_severity": {s: by_sev.get(s, 0) for s in reversed(SEVERITIES)},
        "by_rule": dict(by_rule),
        "top_ips": top_ips[:10],
    }
