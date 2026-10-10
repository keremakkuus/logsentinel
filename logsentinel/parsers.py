"""Turn raw log lines into `Event` objects.

Supported formats
- OpenSSH messages in syslog format (Debian/Ubuntu /var/log/auth.log, RHEL /var/log/secure)
- Apache/Nginx "combined" access log format

Lines that are not understood return None (logs are full of unrelated noise).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional, Tuple

from .models import Event

_IP = r"[0-9A-Fa-f:.]+"
_SYSLOG = (
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+"
)
_FAILED = re.compile(
    _SYSLOG + r"Failed (?P<method>\S+) for (?P<inv>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>" + _IP + r") port \d+"
)
_ACCEPTED = re.compile(
    _SYSLOG + r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>" + _IP + r") port \d+"
)
_INVALID = re.compile(
    _SYSLOG + r"Invalid user (?P<user>\S*) from (?P<ip>" + _IP + r")"
)

_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def _syslog_time(text: str, year: int, tz: timezone) -> datetime:
    # syslog has no year, so the caller supplies it
    clean = " ".join(text.split())
    return datetime.strptime(f"{year} {clean}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz).astimezone(
        timezone.utc
    )


def parse_auth_line(line: str, year: int, tz: timezone = timezone.utc) -> Optional[Event]:
    line = line.rstrip("\n")
    m = _ACCEPTED.match(line)
    if m:
        return Event(_syslog_time(m["ts"], year, tz), "auth", m["ip"], "ssh_accepted", line,
                     user=m["user"], method=m["method"])
    m = _FAILED.match(line)
    if m:
        return Event(_syslog_time(m["ts"], year, tz), "auth", m["ip"], "ssh_failed", line,
                     user=m["user"], method=m["method"], invalid_user=bool(m["inv"]))
    m = _INVALID.match(line)
    if m:
        return Event(_syslog_time(m["ts"], year, tz), "auth", m["ip"], "ssh_invalid_user", line,
                     user=m["user"], invalid_user=True)
    return None


def parse_access_line(line: str) -> Optional[Event]:
    line = line.rstrip("\n")
    m = _ACCESS.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None
    ua = m["ua"] if m["ua"] not in (None, "-") else None
    return Event(ts, "web", m["ip"], "http", line, method=m["method"], path=m["path"],
                 status=int(m["status"]), user_agent=ua)


def parse_lines(lines: Iterable[str], parser: Callable[[str], Optional[Event]]) -> Tuple[List[Event], int]:
    """Parse many lines. Returns (events, number_of_ignored_non_empty_lines)."""
    events: List[Event] = []
    ignored = 0
    for line in lines:
        if not line.strip():
            continue
        ev = parser(line)
        if ev is None:
            ignored += 1
        else:
            events.append(ev)
    return events, ignored


def parse_file(path: str, parser: Callable[[str], Optional[Event]]) -> Tuple[List[Event], int]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, parser)
