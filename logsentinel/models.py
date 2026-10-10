"""Data structures shared by every part of the tool.

Parsers turn raw log lines into `Event` objects. Detectors turn lists of events
into `Alert` objects. Reports only ever see alerts, so each layer can be tested
and replaced on its own.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

SEVERITIES = ["low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class Event:
    """One normalized log record (either an SSH auth event or a web request)."""

    timestamp: datetime          # always timezone-aware, converted to UTC
    source: str                  # "auth" or "web"
    ip: str
    kind: str                    # ssh_failed | ssh_accepted | ssh_invalid_user | http
    raw: str                     # original log line, kept as evidence
    user: Optional[str] = None
    method: Optional[str] = None  # auth method (password/publickey) or HTTP verb
    path: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None
    invalid_user: bool = False


@dataclass
class Alert:
    """A detection result, ready to be shown to a human analyst."""

    rule_id: str
    title: str
    severity: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    mitre_id: str
    mitre_name: str
    description: str
    recommendation: str
    evidence: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)   # all attacker IPs, for distributed alerts

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "mitre": {"id": self.mitre_id, "name": self.mitre_name},
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "sources": self.sources,
        }
