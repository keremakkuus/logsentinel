# LogSentinel

A small, dependency-free Python tool that reads **SSH auth logs** and **web server access logs**,
detects common attacks, and explains each finding with a **MITRE ATT&CK** technique, evidence log
lines, and a recommended action. It writes a terminal summary, JSON, and a self-contained HTML report.

Python 3.9+ and the standard library only. No installation needed.

## Quick start

```bash
python tools/generate_sample_logs.py samples      # creates synthetic logs with planted attacks
python -m logsentinel --auth samples/auth.log --web samples/access.log --year 2026 \
       --html samples/report.html --json samples/alerts.json
python -m unittest discover -s tests -t .         # 45 tests
```

On a real server: `python -m logsentinel --auth /var/log/auth.log --web /var/log/nginx/access.log`
(read access to the logs is required; use `--allowlist` for your own office/monitoring IPs).

## What it detects

| Rule | What it looks for | MITRE ATT&CK |
|---|---|---|
| `SSH-BRUTE` | Many failed SSH logins from one IP in a short window | T1110.001 Password Guessing |
| `SSH-SPRAY` | Many different accounts, only a few tries each | T1110.003 Password Spraying |
| `SSH-COMPROMISE` | A **successful** login right after repeated failures | T1078 Valid Accounts |
| `SSH-DIST-USER` | **One account** attacked from several IPs, each under the per-IP limit | T1110.001 Password Guessing |
| `SSH-DIST-GLOBAL` | Server-wide surge of failed logins from many IPs (low priority, noisy by nature) | T1110 Brute Force |
| `WEB-SCAN` | Many different missing pages (404) in a short time | T1595.003 Wordlist Scanning |
| `WEB-PAYLOAD` | SQL injection, path traversal, XSS, command injection, Log4Shell, Shellshock in requests | T1190 Exploit Public-Facing App |
| `WEB-PROBE` | Requests for `/.env`, `/.git`, `/phpmyadmin`, admin panels | T1595.002 Vulnerability Scanning |
| `WEB-SCANNER-UA` | Known scanner tools in the user agent (sqlmap, nikto, ...) | T1595.002 Vulnerability Scanning |
| `WEB-LOGIN-BURST` | Burst of POST requests to login endpoints | T1110 Brute Force |

Alerts are sorted by severity. Severity rises automatically when activity is far above the threshold
(5x threshold = one level up, 10x = two levels).

## How it works

```
log files --> parsers.py --> Event objects --> detectors.py --> Alert objects --> report.py
                (regex)       (normalized,       (8 rules,        (severity,       (text / JSON /
                              UTC time)          sliding windows)  MITRE, evidence)  HTML)
```

- `models.py` defines `Event` and `Alert`, the only data that moves between layers.
- `parsers.py` understands OpenSSH syslog lines and the Apache/Nginx combined format. Unknown lines are skipped.
- `detectors.py` holds one function per rule. Window rules use a two-pointer scan, so they run in O(n).
- `engine.py` runs all rules in **two stages**, applies the allowlist, removes duplicates, and sorts.
- `config.py` holds thresholds; override them with `--config thresholds.json`.

## Two-stage detection

Stage 1 looks at one IP at a time (`SSH-BRUTE`, `SSH-SPRAY`, `SSH-COMPROMISE`). Stage 2 looks at what
stage 1 cannot see: attackers who spread their attempts over many IPs to stay under every per-IP limit.

- `SSH-DIST-USER` groups failed logins by the **targeted account** instead of the source IP.
- `SSH-DIST-GLOBAL` looks at the **whole server** at once.
- Stage 2 only receives failed logins from IPs that stage 1 did **not** already flag, so one loud
  attacker never produces three alerts for the same thing.
- The global rule is deliberately `low` severity and has high thresholds, because internet-facing SSH
  servers receive scanner noise all day. The sample logs include such background noise, and a test
  checks that it raises no alert.

## Design decisions

- **Time windows, not totals.** Ten failed logins in a day are normal; ten in a minute are not.
- **Spraying wins over brute force** for the same IP, so one attacker produces one clear alert.
- **Success after failure is critical.** Failed attempts are noise; a success after them is the incident.
- **Payloads are URL-decoded twice** to catch double-encoding tricks (`%252e%252e%252f`).
- **Evidence is always attached**, so an analyst can verify a finding without opening the raw logs.
- **HTML output escapes all log text**, because log content is attacker-controlled.

## Limitations (read before trusting it)

- Thresholds are fixed numbers. A production system would compare against a learned baseline
  (for example "5x the usual number of failed logins for this hour").
- The per-account rule does not lock accounts. Automatic lockout lets an attacker lock out real users
  on purpose, so the alert recommends notifying the owner and requiring MFA instead.
- An IP that stage 1 flags is removed from stage 2 for the whole log, which is simple and predictable
  but can hide a later, different attack from that same IP.
- It is a learning/portfolio tool, not a replacement for a SIEM, WAF, or fail2ban.
- Signature matching can be evaded (new encodings, slow attacks below the thresholds) and can
  produce false positives (for example a user who mistypes a password five times before succeeding).
- A `2xx` response to an attack payload does not prove the attack worked; it means "check this first".
- A scanner user agent can be faked, and its absence proves nothing.
- Syslog timestamps have no year or timezone, so `--year` is required for old logs.
- Thresholds need tuning against your own normal traffic.

## Ethics

All sample data is synthetic and uses reserved documentation IP ranges (RFC 5737). The tool only
reads logs; it never sends traffic. Only analyze logs from systems you own or are authorized to review.

## Extending

Add a detector in `logsentinel/detectors.py` with the signature `fn(events, cfg) -> list[Alert]`,
append it to `DETECTORS`, plant a matching attack in `tools/generate_sample_logs.py`, and add a test.

## Ideas for next steps

Store events in PostgreSQL, add a rules file (YAML/JSON) instead of code, enrich IPs with GeoIP,
add Windows event log support, send alerts by webhook.
