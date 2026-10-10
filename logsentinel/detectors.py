"""Detection rules.

Every detector has the same shape: `detector(events, config) -> list[Alert]`.
To add a new rule, write one function and add it to DETECTORS at the bottom.

Most rules are "sliding window" rules: they look for N things from the same IP
inside T seconds, because speed is what separates an attack from normal use.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List, Set, Tuple
from urllib.parse import unquote_plus, urlsplit

from .config import Config
from .models import SEVERITIES, Alert, Event


# ---------------------------------------------------------------- helpers
def _by_ip(events: List[Event]) -> Dict[str, List[Event]]:
    groups: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        groups[e.ip].append(e)
    for evs in groups.values():
        evs.sort(key=lambda e: e.timestamp)
    return groups


def _by_user(events: List[Event]) -> Dict[str, List[Event]]:
    """Same idea as _by_ip, but groups by the ACCOUNT that was targeted."""
    groups: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.user is not None:
            groups[e.user].append(e)
    for evs in groups.values():
        evs.sort(key=lambda e: e.timestamp)
    return groups


def _bump(base: str, count: int, threshold: int) -> str:
    """Raise severity when activity is far above the threshold (5x -> +1, 10x -> +2)."""
    level = SEVERITIES.index(base)
    if count >= threshold * 10:
        level += 2
    elif count >= threshold * 5:
        level += 1
    return SEVERITIES[min(level, len(SEVERITIES) - 1)]


def _densest_window(evs: List[Event], seconds: int) -> Tuple[int, Tuple[int, int]]:
    """Two-pointer scan over time-sorted events.

    Returns (max_events_in_any_window, (first_index, last_index)).
    Runs in O(n) because the left pointer only ever moves forward.
    """
    best_n, best, left = 0, (0, 0), 0
    for right in range(len(evs)):
        while (evs[right].timestamp - evs[left].timestamp).total_seconds() > seconds:
            left += 1
        n = right - left + 1
        if n > best_n:
            best_n, best = n, (left, right)
    return best_n, best


def _evidence(events: List[Event], limit: int = 3) -> List[str]:
    return [e.raw[:220] for e in events[:limit]]


def _decode(text: str) -> str:
    """URL-decode up to twice, so %252e%252e/ (double encoding) is also caught."""
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def _path_only(path: str) -> str:
    try:
        return urlsplit(path).path or "/"
    except ValueError:
        return path


# ---------------------------------------------------------------- SSH rules
def detect_ssh_bruteforce(events: List[Event], cfg: Config) -> List[Alert]:
    failed = [e for e in events if e.kind == "ssh_failed"]
    alerts = []
    for ip, evs in _by_ip(failed).items():
        n, (i, j) = _densest_window(evs, cfg.bruteforce_window)
        if n < cfg.bruteforce_threshold:
            continue
        win = evs[i:j + 1]
        users = Counter(e.user for e in win)
        top_user, top_n = users.most_common(1)[0]
        alerts.append(Alert(
            rule_id="SSH-BRUTE", title="SSH brute-force attempt",
            severity=_bump("medium", n, cfg.bruteforce_threshold), ip=ip,
            first_seen=win[0].timestamp, last_seen=win[-1].timestamp, count=n,
            mitre_id="T1110.001", mitre_name="Brute Force: Password Guessing",
            description=(f"{n} failed SSH logins within {cfg.bruteforce_window}s "
                         f"({len(users)} account(s) targeted, most targeted: '{top_user}' x{top_n})."),
            recommendation="Block or rate-limit the source IP, disable password login (use SSH keys), "
                           "and deploy fail2ban or an equivalent.",
            evidence=_evidence(win)))
    return alerts


def detect_ssh_spraying(events: List[Event], cfg: Config) -> List[Alert]:
    """Spraying = many accounts, few attempts each (to stay under lockout limits)."""
    failed = [e for e in events if e.kind == "ssh_failed"]
    alerts = []
    for ip, evs in _by_ip(failed).items():
        users: Counter = Counter()
        left = 0
        best = None
        for right, ev in enumerate(evs):
            users[ev.user] += 1
            while (ev.timestamp - evs[left].timestamp).total_seconds() > cfg.spray_window:
                users[evs[left].user] -= 1
                if users[evs[left].user] == 0:
                    del users[evs[left].user]
                left += 1
            distinct, total = len(users), right - left + 1
            if distinct >= cfg.spray_min_users and total / distinct <= cfg.spray_max_attempts_per_user:
                if best is None or distinct > best[0]:
                    best = (distinct, total, left, right)
        if best:
            distinct, total, i, j = best
            win = evs[i:j + 1]
            alerts.append(Alert(
                rule_id="SSH-SPRAY", title="SSH password spraying",
                severity=_bump("high", distinct, cfg.spray_min_users), ip=ip,
                first_seen=win[0].timestamp, last_seen=win[-1].timestamp, count=total,
                mitre_id="T1110.003", mitre_name="Brute Force: Password Spraying",
                description=(f"{total} failed logins across {distinct} different accounts in "
                             f"{cfg.spray_window}s (about {total / distinct:.1f} tries per account)."),
                recommendation="Block the source IP, enforce MFA or key-only SSH, and check whether "
                               "any of the targeted accounts later logged in successfully.",
                evidence=_evidence(win)))
    return alerts


def detect_ssh_compromise(events: List[Event], cfg: Config) -> List[Alert]:
    """The most important SSH rule: a successful login right after many failures."""
    relevant = [e for e in events if e.kind in ("ssh_failed", "ssh_accepted")]
    alerts = []
    for ip, evs in _by_ip(relevant).items():
        reported: Set[str] = set()
        for idx, ev in enumerate(evs):
            if ev.kind != "ssh_accepted" or ev.user in reported:
                continue
            start = ev.timestamp - timedelta(seconds=cfg.compromise_window)
            prior = [e for e in evs[:idx] if e.kind == "ssh_failed" and e.timestamp >= start]
            if len(prior) < cfg.compromise_failures:
                continue
            reported.add(ev.user)
            same_account = sum(1 for e in prior if e.user == ev.user)
            alerts.append(Alert(
                rule_id="SSH-COMPROMISE", title="Successful SSH login after repeated failures",
                severity="critical", ip=ip,
                first_seen=prior[0].timestamp, last_seen=ev.timestamp, count=len(prior) + 1,
                mitre_id="T1078", mitre_name="Valid Accounts",
                description=(f"Login succeeded for '{ev.user}' ({ev.method}) after {len(prior)} failed "
                             f"attempts in {cfg.compromise_window}s ({same_account} against this account). "
                             "Credentials may be compromised."),
                recommendation="Treat as an incident: check what the session did, reset the account's "
                               "credentials, kill active sessions, and review other logins from this IP.",
                evidence=_evidence(prior, 2) + [ev.raw[:220]]))
    return alerts


# ------------------------------------------------- distributed SSH rules (stage 2)
# These two rules run AFTER the per-IP rules, on the failed logins that no single IP
# explains. That keeps one noisy attacker from producing three alerts for the same thing.
def detect_ssh_user_attack(events: List[Event], cfg: Config) -> List[Alert]:
    """One account attacked from several IPs, each staying under the per-IP threshold."""
    failed = [e for e in events if e.kind == "ssh_failed"]
    alerts = []
    for user, evs in _by_user(failed).items():
        n, (i, j) = _densest_window(evs, cfg.user_attack_window)
        win = evs[i:j + 1]
        ips = {e.ip for e in win}
        if n < cfg.user_attack_threshold or len(ips) < cfg.user_attack_min_ips:
            continue
        alerts.append(Alert(
            rule_id="SSH-DIST-USER", title=f"Distributed attack on one account ('{user}')",
            severity=_bump("medium", n, cfg.user_attack_threshold),
            ip=f"multiple ({len(ips)} IPs)", sources=sorted(ips),
            first_seen=win[0].timestamp, last_seen=win[-1].timestamp, count=n,
            mitre_id="T1110.001", mitre_name="Brute Force: Password Guessing",
            description=(f"{n} failed logins against '{user}' from {len(ips)} different IPs within "
                         f"{cfg.user_attack_window}s. No single IP crossed the per-IP threshold, which "
                         "is how attackers try to stay unnoticed."),
            recommendation="Do not auto-lock the account (attackers can abuse lockouts to deny service). "
                           "Tell the account owner, require MFA or key-only login, and check whether this "
                           "account had a successful login from any of these IPs.",
            evidence=_evidence(win)))
    return alerts


def detect_ssh_global_surge(events: List[Event], cfg: Config) -> List[Alert]:
    """Server-wide view: unusual volume of failed logins from many IPs at once.

    Deliberately LOW severity. Internet-facing SSH servers are scanned all day long,
    so this rule says "look at this when you have time", not "wake someone up".
    """
    failed = sorted((e for e in events if e.kind == "ssh_failed"), key=lambda e: e.timestamp)
    if not failed:
        return []
    n, (i, j) = _densest_window(failed, cfg.global_window)
    win = failed[i:j + 1]
    ips = {e.ip for e in win}
    if n < cfg.global_threshold or len(ips) < cfg.global_min_ips:
        return []
    users = {e.user for e in win}
    return [Alert(
        rule_id="SSH-DIST-GLOBAL", title="Server-wide surge of failed SSH logins",
        severity=_bump("low", n, cfg.global_threshold),
        ip=f"multiple ({len(ips)} IPs)", sources=sorted(ips),
        first_seen=win[0].timestamp, last_seen=win[-1].timestamp, count=n,
        mitre_id="T1110", mitre_name="Brute Force",
        description=(f"{n} failed logins from {len(ips)} IPs across {len(users)} accounts within "
                     f"{cfg.global_window}s. Internet-facing servers always get some background noise, "
                     "so compare with your normal level before acting."),
        recommendation="Low priority. Check whether this is above your usual level, confirm that "
                       "password login is disabled or rate limited, and consider restricting SSH to a VPN.",
        evidence=_evidence(win))]


# ---------------------------------------------------------------- web rules
def detect_web_scan(events: List[Event], cfg: Config) -> List[Alert]:
    """Content discovery tools request hundreds of pages that do not exist."""
    misses = [e for e in events if e.source == "web" and e.status == 404]
    alerts = []
    for ip, evs in _by_ip(misses).items():
        paths: Counter = Counter()
        left, best = 0, None
        for right, ev in enumerate(evs):
            paths[_path_only(ev.path or "")] += 1
            while (ev.timestamp - evs[left].timestamp).total_seconds() > cfg.scan_window:
                key = _path_only(evs[left].path or "")
                paths[key] -= 1
                if paths[key] == 0:
                    del paths[key]
                left += 1
            if len(paths) >= cfg.scan_distinct_404 and (best is None or len(paths) > best[0]):
                best = (len(paths), left, right)
        if best:
            distinct, i, j = best
            win = evs[i:j + 1]
            alerts.append(Alert(
                rule_id="WEB-SCAN", title="Web content discovery (many 404 errors)",
                severity=_bump("medium", distinct, cfg.scan_distinct_404), ip=ip,
                first_seen=win[0].timestamp, last_seen=win[-1].timestamp, count=len(win),
                mitre_id="T1595.003", mitre_name="Active Scanning: Wordlist Scanning",
                description=f"{distinct} different missing pages requested within {cfg.scan_window}s.",
                recommendation="Rate-limit or block the IP at the WAF/firewall and make sure no "
                               "forgotten files are exposed.",
                evidence=_evidence(win)))
    return alerts


PAYLOAD_SIGNATURES: Dict[str, List[str]] = {
    "SQL injection": [
        r"union[\s/*]+(all[\s/*]+)?select", r"['\"]\s*or\s+['\"\d]", r"\bor\s+\d+\s*=\s*\d+",
        r"information_schema", r"\bsleep\s*\(\s*\d+\s*\)", r"\bbenchmark\s*\(", r";\s*drop\s+table",
    ],
    "Path traversal": [r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow)", r"c:\\windows", r"boot\.ini"],
    "Cross-site scripting": [r"<\s*script", r"javascript:", r"\bon(error|load)\s*="],
    "Command injection": [
        r"(?:;|\||`|&&)\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh)(?:\s|$)",
        r"\$\(\s*(?:cat|id|whoami|curl|wget)", r"/bin/(?:ba)?sh\b",
    ],
    "Log4Shell (JNDI) lookup": [r"\$\{\s*jndi\s*:"],
    "Shellshock": [r"\(\)\s*\{\s*:\s*;\s*\}\s*;"],
}
_COMPILED = {cat: [re.compile(p, re.I) for p in pats] for cat, pats in PAYLOAD_SIGNATURES.items()}


def classify_payload(event: Event) -> Set[str]:
    """Return the attack categories whose signatures appear in the request."""
    targets = [_decode(event.path or ""), _decode(event.user_agent or "")]
    found = set()
    for category, patterns in _COMPILED.items():
        if any(p.search(t) for p in patterns for t in targets):
            found.add(category)
    return found


def detect_web_payloads(events: List[Event], cfg: Config) -> List[Alert]:
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for e in events:
        if e.source != "web":
            continue
        for category in classify_payload(e):
            groups[(e.ip, category)].append(e)
    alerts = []
    for (ip, category), evs in groups.items():
        evs.sort(key=lambda e: e.timestamp)
        ok = sum(1 for e in evs if e.status and 200 <= e.status < 300)
        note = (f" {ok} of them got a 2xx response, so check those first." if ok else
                " None returned 2xx.")
        alerts.append(Alert(
            rule_id="WEB-PAYLOAD", title=f"Web attack payload: {category}",
            severity=_bump("high", len(evs), 5), ip=ip,
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, count=len(evs),
            mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
            description=f"{len(evs)} request(s) contain {category} patterns.{note}",
            recommendation="Block the IP, review the targeted endpoints for input validation, and put a "
                           "WAF in front of the application. Check app logs for signs of success.",
            evidence=_evidence(evs)))
    return alerts


SENSITIVE_PREFIXES = (
    "/.env", "/.git", "/.aws", "/.ssh", "/.ds_store", "/wp-login.php", "/wp-admin", "/xmlrpc.php",
    "/phpmyadmin", "/pma", "/admin", "/administrator", "/server-status", "/actuator",
    "/config.php", "/backup", "/id_rsa", "/etc/passwd",
)


def detect_web_probe(events: List[Event], cfg: Config) -> List[Alert]:
    """Looks for requests to files and panels that should never be public."""
    probes = []
    for e in events:
        if e.source == "web" and _path_only(_decode(e.path or "")).lower().startswith(SENSITIVE_PREFIXES):
            probes.append(e)
    alerts = []
    for ip, evs in _by_ip(probes).items():
        distinct = {_path_only(e.path or "").lower() for e in evs}
        if len(distinct) < cfg.probe_min_paths:
            continue
        alerts.append(Alert(
            rule_id="WEB-PROBE", title="Probing for sensitive files and admin panels",
            severity=_bump("medium", len(distinct), cfg.probe_min_paths), ip=ip,
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, count=len(evs),
            mitre_id="T1595.002", mitre_name="Active Scanning: Vulnerability Scanning",
            description=f"{len(distinct)} different sensitive paths requested (e.g. "
                        f"{', '.join(sorted(distinct)[:3])}).",
            recommendation="Make sure these paths are not reachable from the internet and restrict "
                           "admin panels by IP or VPN.",
            evidence=_evidence(evs)))
    return alerts


SCANNER_USER_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "wpscan",
    "nuclei", "hydra", "acunetix", "nessus", "openvas",
)


def detect_scanner_user_agent(events: List[Event], cfg: Config) -> List[Alert]:
    hits = [e for e in events if e.source == "web" and e.user_agent
            and any(tok in e.user_agent.lower() for tok in SCANNER_USER_AGENTS)]
    alerts = []
    for ip, evs in _by_ip(hits).items():
        tools = sorted({tok for e in evs for tok in SCANNER_USER_AGENTS if tok in e.user_agent.lower()})
        alerts.append(Alert(
            rule_id="WEB-SCANNER-UA", title="Known security scanner user agent",
            severity=_bump("medium", len(evs), 10), ip=ip,
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, count=len(evs),
            mitre_id="T1595.002", mitre_name="Active Scanning: Vulnerability Scanning",
            description=f"{len(evs)} request(s) identify themselves as: {', '.join(tools)}. "
                        "Attackers can fake or hide this, so its absence proves nothing.",
            recommendation="Block the IP unless this is an authorized scan you scheduled.",
            evidence=_evidence(evs)))
    return alerts


_LOGIN_PATH = re.compile(r"(login|signin|sign-in|wp-login|xmlrpc|/auth)", re.I)


def detect_web_login_burst(events: List[Event], cfg: Config) -> List[Alert]:
    posts = [e for e in events if e.source == "web" and e.method == "POST"
             and _LOGIN_PATH.search(_path_only(e.path or ""))]
    alerts = []
    for ip, evs in _by_ip(posts).items():
        n, (i, j) = _densest_window(evs, cfg.web_login_window)
        if n < cfg.web_login_threshold:
            continue
        win = evs[i:j + 1]
        statuses = Counter(e.status for e in win)
        summary = ", ".join(f"{s}: {c}" for s, c in sorted(statuses.items()))
        alerts.append(Alert(
            rule_id="WEB-LOGIN-BURST", title="Burst of web login requests",
            severity=_bump("medium", n, cfg.web_login_threshold), ip=ip,
            first_seen=win[0].timestamp, last_seen=win[-1].timestamp, count=n,
            mitre_id="T1110", mitre_name="Brute Force",
            description=f"{n} login POST requests within {cfg.web_login_window}s (status codes -> {summary}).",
            recommendation="Add rate limiting and account lockout or CAPTCHA, and require MFA. "
                           "Check whether any request in the burst succeeded.",
            evidence=_evidence(win)))
    return alerts


DISTRIBUTED_DETECTORS = [detect_ssh_user_attack, detect_ssh_global_surge]

DETECTORS = [
    detect_ssh_bruteforce, detect_ssh_spraying, detect_ssh_compromise,
    detect_web_scan, detect_web_payloads, detect_web_probe,
    detect_scanner_user_agent, detect_web_login_burst,
]
