"""End-to-end test: generate planted attacks, run the whole pipeline, check results."""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from generate_sample_logs import generate  # noqa: E402

from logsentinel.cli import main  # noqa: E402
from logsentinel.config import Config  # noqa: E402
from logsentinel.engine import analyze  # noqa: E402
from logsentinel.parsers import parse_access_line, parse_auth_line, parse_file  # noqa: E402


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.auth, cls.web = generate(cls.tmp.name)
        a, _ = parse_file(cls.auth, lambda l: parse_auth_line(l, 2026))
        w, _ = parse_file(cls.web, parse_access_line)
        cls.alerts = analyze(a + w, Config())
        cls.found = {(x.rule_id, x.ip) for x in cls.alerts}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_planted_attack_is_found(self):
        expected = {
            ("SSH-BRUTE", "203.0.113.50"), ("SSH-SPRAY", "198.51.100.23"),
            ("SSH-COMPROMISE", "203.0.113.77"), ("WEB-SCAN", "198.51.100.99"),
            ("WEB-SCANNER-UA", "198.51.100.99"), ("WEB-PAYLOAD", "203.0.113.9"),
            ("WEB-PAYLOAD", "203.0.113.30"), ("WEB-PROBE", "203.0.113.120"),
            ("WEB-LOGIN-BURST", "198.51.100.200"),
        }
        self.assertTrue(expected <= self.found, f"missing: {expected - self.found}")

    def test_distributed_attacks_are_found_with_all_their_sources(self):
        by_rule = {a.rule_id: a for a in self.alerts if a.rule_id.startswith("SSH-DIST")}
        self.assertEqual(set(by_rule), {"SSH-DIST-USER", "SSH-DIST-GLOBAL"})
        self.assertEqual(by_rule["SSH-DIST-USER"].sources, [f"203.0.113.{n}" for n in range(101, 107)])
        self.assertEqual(len(by_rule["SSH-DIST-GLOBAL"].sources), 40)
        self.assertEqual(by_rule["SSH-DIST-GLOBAL"].severity, "low")

    def test_loud_attackers_are_not_reported_twice(self):
        sources = {ip for a in self.alerts if a.rule_id.startswith("SSH-DIST") for ip in a.sources}
        self.assertFalse(sources & {"203.0.113.50", "203.0.113.77", "198.51.100.23"})

    def test_background_noise_ips_never_appear_in_alerts(self):
        noisy = {f"203.0.113.{n}" for n in range(150, 250)}
        mentioned = {a.ip for a in self.alerts} | {ip for a in self.alerts for ip in a.sources}
        self.assertFalse(mentioned & noisy)

    def test_no_false_positives_on_normal_users(self):
        innocent = {"10.0.0.15", "10.0.0.23", "192.0.2.10", "192.0.2.31", "192.0.2.44", "192.0.2.58", "192.0.2.77"}
        self.assertFalse({ip for _, ip in self.found} & innocent)

    def test_compromise_is_the_top_alert(self):
        self.assertEqual(self.alerts[0].rule_id, "SSH-COMPROMISE")

    def test_cli_writes_reports_and_exit_codes(self):
        html_path = os.path.join(self.tmp.name, "r.html")
        json_path = os.path.join(self.tmp.name, "r.json")
        code = main(["--auth", self.auth, "--web", self.web, "--year", "2026", "--html", html_path,
                     "--json", json_path, "--fail-on", "critical", "--no-color"])
        self.assertEqual(code, 2)
        self.assertTrue(os.path.getsize(html_path) > 1000 and os.path.getsize(json_path) > 1000)
        quiet = main(["--auth", self.auth, "--year", "2026", "--allowlist", "203.0.113.0/24,198.51.100.0/24",
                      "--fail-on", "low", "--no-color"])
        self.assertEqual(quiet, 0)

    def test_html_report_escapes_attacker_controlled_text(self):
        from logsentinel.models import Alert
        from logsentinel.report import render_html
        from datetime import datetime, timezone
        now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        evil = Alert("X", "t", "high", "1.2.3.4", now, now, 1, "T1190", "n", "d", "r",
                     evidence=['<script>alert("xss")</script>'])
        summary = {"events_total": 1, "alerts_total": 1, "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                   "top_ips": []}
        out = render_html([evil], summary)
        self.assertNotIn("<script>alert", out)
        self.assertIn("&lt;script&gt;", out)


if __name__ == "__main__":
    unittest.main()
