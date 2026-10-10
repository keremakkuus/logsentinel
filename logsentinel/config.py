"""Detection thresholds. Defaults are conservative; override them with a JSON file."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from typing import List


@dataclass
class Config:
    # SSH brute force: N failed logins from one IP inside a time window
    bruteforce_threshold: int = 8
    bruteforce_window: int = 300
    # Password spraying: many different accounts, only a few tries each
    spray_min_users: int = 5
    spray_max_attempts_per_user: int = 3
    spray_window: int = 600
    # Success after failures (possible compromised credentials)
    compromise_failures: int = 5
    compromise_window: int = 900
    # Distributed attack on ONE account: many IPs, each too quiet to trip the per-IP rule
    user_attack_threshold: int = 10
    user_attack_min_ips: int = 2
    user_attack_window: int = 300
    # Server-wide surge: unusual volume of failed logins from many IPs (noisy, low priority)
    global_threshold: int = 100
    global_min_ips: int = 20
    global_window: int = 300
    # Web content discovery: many different missing pages (404) in a short time
    scan_distinct_404: int = 15
    scan_window: int = 120
    # Probing for sensitive files/admin panels
    probe_min_paths: int = 3
    # Burst of login POST requests (credential stuffing / brute force on a web login)
    web_login_threshold: int = 10
    web_login_window: int = 300
    # IPs or CIDR ranges that must never raise alerts (scanners you own, office, monitoring)
    allowlist: List[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")
        return cls(**data)
