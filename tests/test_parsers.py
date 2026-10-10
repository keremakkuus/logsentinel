import unittest
from datetime import datetime, timezone

from logsentinel.parsers import parse_access_line, parse_auth_line


class AuthParserTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        line = "Oct  1 08:15:02 web01 sshd[991]: Failed password for root from 203.0.113.5 port 4242 ssh2"
        ev = parse_auth_line(line, 2026)
        self.assertEqual(ev.kind, "ssh_failed")
        self.assertEqual((ev.user, ev.ip, ev.invalid_user), ("root", "203.0.113.5", False))
        self.assertEqual(ev.timestamp, datetime(2026, 10, 1, 8, 15, 2, tzinfo=timezone.utc))

    def test_failed_password_invalid_user(self):
        line = "Oct 11 08:15:02 web01 sshd[991]: Failed password for invalid user admin from 203.0.113.5 port 1 ssh2"
        ev = parse_auth_line(line, 2026)
        self.assertEqual((ev.kind, ev.user, ev.invalid_user), ("ssh_failed", "admin", True))

    def test_accepted_login_keeps_method(self):
        line = "Oct  1 08:15:02 web01 sshd[991]: Accepted publickey for alice from 10.0.0.15 port 5000 ssh2"
        ev = parse_auth_line(line, 2026)
        self.assertEqual((ev.kind, ev.user, ev.method), ("ssh_accepted", "alice", "publickey"))

    def test_invalid_user_line(self):
        line = "Oct  1 08:15:02 web01 sshd[991]: Invalid user oracle from 203.0.113.5 port 4242"
        self.assertEqual(parse_auth_line(line, 2026).kind, "ssh_invalid_user")

    def test_timezone_is_converted_to_utc(self):
        line = "Oct  1 08:00:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
        plus3 = timezone(__import__("datetime").timedelta(hours=3))
        ev = parse_auth_line(line, 2026, tz=plus3)
        self.assertEqual(ev.timestamp.hour, 5)

    def test_unrelated_and_garbage_lines_return_none(self):
        self.assertIsNone(parse_auth_line("Oct  1 08:00:00 web01 CRON[1]: (root) CMD (ls)", 2026))
        self.assertIsNone(parse_auth_line("this is not a log line", 2026))
        self.assertIsNone(parse_auth_line("", 2026))


class AccessParserTests(unittest.TestCase):
    LINE = ('203.0.113.7 - - [01/Oct/2026:10:15:32 +0000] "GET /index.php?id=1 HTTP/1.1" 404 199 '
            '"-" "sqlmap/1.7"')

    def test_combined_format(self):
        ev = parse_access_line(self.LINE)
        self.assertEqual((ev.ip, ev.method, ev.path, ev.status), ("203.0.113.7", "GET", "/index.php?id=1", 404))
        self.assertEqual(ev.user_agent, "sqlmap/1.7")

    def test_non_utc_offset_is_normalised(self):
        line = self.LINE.replace("+0000", "+0300")
        self.assertEqual(parse_access_line(line).timestamp.hour, 7)

    def test_dash_user_agent_becomes_none(self):
        line = self.LINE.replace('"sqlmap/1.7"', '"-"')
        self.assertIsNone(parse_access_line(line).user_agent)

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_access_line("not an access log line"))
        self.assertIsNone(parse_access_line('1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1'))


if __name__ == "__main__":
    unittest.main()
