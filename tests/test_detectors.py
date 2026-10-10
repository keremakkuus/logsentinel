import unittest
from datetime import datetime, timedelta, timezone

from logsentinel.config import Config
from logsentinel.detectors import (classify_payload, detect_ssh_bruteforce, detect_ssh_compromise,
                                   detect_ssh_global_surge, detect_ssh_spraying, detect_ssh_user_attack,
                                   detect_web_login_burst, detect_web_payloads, detect_web_probe,
                                   detect_web_scan, _densest_window)
from logsentinel.engine import analyze
from logsentinel.models import Event

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


def ssh_fail(sec, user="root", ip="203.0.113.5"):
    return Event(T0 + timedelta(seconds=sec), "auth", ip, "ssh_failed", f"fail {user} {sec}", user=user, method="password")


def ssh_ok(sec, user="root", ip="203.0.113.5"):
    return Event(T0 + timedelta(seconds=sec), "auth", ip, "ssh_accepted", f"ok {user} {sec}", user=user, method="password")


def web(sec, path="/", status=200, method="GET", ip="203.0.113.9", ua="Mozilla/5.0"):
    return Event(T0 + timedelta(seconds=sec), "web", ip, "http", f"{method} {path} {status}",
                 method=method, path=path, status=status, user_agent=ua)


class WindowTests(unittest.TestCase):
    def test_densest_window_is_inclusive_and_correct(self):
        evs = [ssh_fail(s) for s in (0, 10, 20, 400, 405, 410, 415)]
        n, (i, j) = _densest_window(evs, 30)
        self.assertEqual((n, i, j), (4, 3, 6))      # the four events between 400 and 415
        n, _ = _densest_window(evs, 10)
        self.assertEqual(n, 3)                      # 400,405,410 are exactly 10s apart -> still inside


class SshTests(unittest.TestCase):
    def test_bruteforce_fires_at_threshold_not_below(self):
        cfg = Config()
        below = [ssh_fail(i) for i in range(cfg.bruteforce_threshold - 1)]
        at = [ssh_fail(i) for i in range(cfg.bruteforce_threshold)]
        self.assertEqual(detect_ssh_bruteforce(below, cfg), [])
        self.assertEqual(len(detect_ssh_bruteforce(at, cfg)), 1)

    def test_slow_attempts_outside_window_do_not_fire(self):
        cfg = Config()
        slow = [ssh_fail(i * 100) for i in range(20)]   # 1 attempt per 100s -> max 4 in 300s
        self.assertEqual(detect_ssh_bruteforce(slow, cfg), [])

    def test_severity_rises_with_volume(self):
        cfg = Config()
        alert = detect_ssh_bruteforce([ssh_fail(i) for i in range(80)], cfg)[0]
        self.assertEqual(alert.severity, "critical")

    def test_spraying_requires_many_accounts_with_few_tries(self):
        cfg = Config()
        spray = [ssh_fail(i * 10, user=f"u{i}") for i in range(10)]
        self.assertEqual(len(detect_ssh_spraying(spray, cfg)), 1)
        one_account = [ssh_fail(i) for i in range(30)]
        self.assertEqual(detect_ssh_spraying(one_account, cfg), [])

    def test_spraying_suppresses_duplicate_bruteforce_alert(self):
        events = [ssh_fail(i * 5, user=f"u{i % 10}") for i in range(20)]   # 10 users x 2 tries
        rules = {a.rule_id for a in analyze(events, Config())}
        self.assertIn("SSH-SPRAY", rules)
        self.assertNotIn("SSH-BRUTE", rules)

    def test_compromise_success_after_failures(self):
        cfg = Config()
        events = [ssh_fail(i, user="deploy") for i in range(6)] + [ssh_ok(10, user="deploy")]
        alert = detect_ssh_compromise(events, cfg)[0]
        self.assertEqual((alert.severity, alert.mitre_id), ("critical", "T1078"))

    def test_normal_typo_then_login_is_not_a_compromise(self):
        events = [ssh_fail(0, user="bob", ip="10.0.0.23"), ssh_ok(9, user="bob", ip="10.0.0.23")]
        self.assertEqual(detect_ssh_compromise(events, Config()), [])

    def test_failures_after_success_do_not_count(self):
        events = [ssh_ok(0)] + [ssh_fail(i) for i in range(1, 10)]
        self.assertEqual(detect_ssh_compromise(events, Config()), [])


def rules_of(alerts):
    return {a.rule_id for a in alerts}


class DistributedTests(unittest.TestCase):
    def test_one_account_from_many_ips_is_detected(self):
        events = [ssh_fail(i * 2 + k, user="root", ip=f"203.0.113.{100 + k}") for i in range(4) for k in range(6)]
        alert = detect_ssh_user_attack(events, Config())[0]
        self.assertEqual(alert.rule_id, "SSH-DIST-USER")
        self.assertEqual(len(alert.sources), 6)
        self.assertEqual(alert.count, 24)

    def test_user_rule_ignores_a_single_ip(self):
        events = [ssh_fail(i) for i in range(30)]            # 30 tries, only one IP
        self.assertEqual(detect_ssh_user_attack(events, Config()), [])

    def test_gap_is_closed_two_ips_just_under_the_per_ip_limit(self):
        # 2 IPs x 7 tries: each IP is below the per-IP limit of 8, the account sees 14 tries
        events = [ssh_fail(i, ip="203.0.113.1") for i in range(7)] + [ssh_fail(i, ip="203.0.113.2") for i in range(7)]
        found = rules_of(analyze(events, Config()))
        self.assertNotIn("SSH-BRUTE", found)
        self.assertIn("SSH-DIST-USER", found)

    def test_noisy_ip_does_not_cause_a_second_alert_for_the_same_attack(self):
        events = [ssh_fail(i, ip="203.0.113.1") for i in range(30)]
        events += [ssh_fail(i, ip=f"203.0.113.{10 + i}") for i in range(3)]   # 3 quiet extra IPs
        found = rules_of(analyze(events, Config()))
        self.assertIn("SSH-BRUTE", found)
        self.assertNotIn("SSH-DIST-USER", found)          # the noisy IP was removed before stage 2

    def surge_events(self, accounts=15):
        users = [f"u{n}" for n in range(accounts)]
        return [ssh_fail(k * 2, user=users[k % accounts], ip=f"198.51.100.{k % 40 + 1}") for k in range(120)]

    def test_global_surge_is_detected_and_is_low_severity(self):
        alert = detect_ssh_global_surge(self.surge_events(), Config())[0]
        self.assertEqual((alert.rule_id, alert.severity), ("SSH-DIST-GLOBAL", "low"))
        self.assertEqual(len(alert.sources), 40)

    def test_global_surge_does_not_trigger_the_other_rules(self):
        found = rules_of(analyze(self.surge_events(), Config()))
        self.assertEqual(found, {"SSH-DIST-GLOBAL"})

    def test_normal_background_noise_raises_nothing(self):
        # 100 failed logins from 100 different IPs spread over 10 hours
        events = [ssh_fail(i * 360, user="root", ip=f"203.0.113.{i + 1}") for i in range(100)]
        self.assertEqual(analyze(events, Config()), [])

    def test_summary_counts_every_source_ip_of_a_distributed_alert(self):
        from logsentinel.engine import summarize
        events = self.surge_events()
        summary = summarize(events, analyze(events, Config()))
        self.assertEqual(len(summary["top_ips"]), 10)      # capped list, but built from 40 sources


class WebTests(unittest.TestCase):
    def test_scan_needs_distinct_missing_paths(self):
        cfg = Config()
        scan = [web(i, path=f"/x{i}", status=404) for i in range(cfg.scan_distinct_404)]
        repeated = [web(i, path="/same", status=404) for i in range(50)]
        self.assertEqual(len(detect_web_scan(scan, cfg)), 1)
        self.assertEqual(detect_web_scan(repeated, cfg), [])

    def test_payload_categories(self):
        cases = {
            "/p?id=1%27%20OR%20%271%27%3D%271": "SQL injection",
            "/p?id=1%20UNION%20SELECT%20NULL": "SQL injection",
            "/f?x=../../etc/passwd": "Path traversal",
            "/f?x=%252e%252e%252fsecret": "Path traversal",     # double encoded
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E": "Cross-site scripting",
            "/?q=%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D": "Log4Shell (JNDI) lookup",
            "/run?c=1;cat%20/etc/hosts": "Command injection",
        }
        for path, category in cases.items():
            with self.subTest(path=path):
                self.assertIn(category, classify_payload(web(0, path=path)))

    def test_normal_requests_are_not_flagged(self):
        normal = ["/products?id=5&sort=price", "/search?q=cats+or+dogs", "/blog/how-to-use-sql",
                  "/items?a=1&id=7", "/static/app.js", "/about"]
        for path in normal:
            with self.subTest(path=path):
                self.assertEqual(classify_payload(web(0, path=path)), set())

    def test_payload_in_user_agent_is_caught(self):
        ev = web(0, ua="${jndi:ldap://x/a}")
        self.assertIn("Log4Shell (JNDI) lookup", classify_payload(ev))

    def test_payload_alert_notes_successful_responses(self):
        alerts = detect_web_payloads([web(0, path="/s?q=<script>", status=200)], Config())
        self.assertIn("2xx", alerts[0].description)

    def test_probe_needs_three_distinct_sensitive_paths(self):
        cfg = Config()
        two = [web(0, path="/.env", status=404), web(1, path="/.git/config", status=404)]
        three = two + [web(2, path="/wp-login.php", status=404)]
        self.assertEqual(detect_web_probe(two, cfg), [])
        self.assertEqual(len(detect_web_probe(three, cfg)), 1)

    def test_login_burst(self):
        cfg = Config()
        burst = [web(i * 3, path="/api/login", method="POST", status=401) for i in range(cfg.web_login_threshold)]
        gets = [web(i, path="/api/login", method="GET") for i in range(30)]
        self.assertEqual(len(detect_web_login_burst(burst, cfg)), 1)
        self.assertEqual(detect_web_login_burst(gets, cfg), [])


class EngineTests(unittest.TestCase):
    def test_allowlist_accepts_single_ip_and_cidr(self):
        events = [ssh_fail(i, ip="10.1.2.3") for i in range(20)] + [ssh_fail(i, ip="192.0.2.8") for i in range(20)]
        cfg = Config(allowlist=["10.0.0.0/8", "192.0.2.8"])
        self.assertEqual(analyze(events, cfg), [])

    def test_alerts_sorted_most_severe_first(self):
        events = [ssh_fail(i) for i in range(10)] + \
                 [ssh_fail(i, user="deploy", ip="203.0.113.77") for i in range(6)] + [ssh_ok(10, "deploy", "203.0.113.77")]
        alerts = analyze(events, Config())
        self.assertEqual(alerts[0].severity, "critical")

    def test_config_rejects_unknown_keys(self):
        import json, os, tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"bruteforce_treshold": 3}, fh)       # typo on purpose
        try:
            with self.assertRaises(ValueError):
                Config.from_file(fh.name)
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
