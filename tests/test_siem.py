from __future__ import annotations

import json
import os
import socket
import threading
import time

from ksec.siem import formats
from ksec.siem.feeder import FeedStats, feed_line, watch_file
from tests import KsecTestCase


class FormatParseTest(KsecTestCase):
    def test_syslog_sshd_failure(self):
        raw = formats.parse_line(
            "<134>Jan  5 10:01:22 web1 sshd[2213]: Failed password for root "
            "from 203.0.113.7 port 51234 ssh2",
            source="ssh",
        )
        self.assertIsNotNone(raw)
        self.assertEqual(raw["event_type"], "auth_failure")
        self.assertEqual(raw["host"], "web1")
        self.assertEqual(raw["details"]["tag"], "sshd")
        self.assertIn("203.0.113.7", raw["details"]["message"])
        self.assertTrue(raw["event_id"])

    def test_syslog_iso_timestamp(self):
        raw = formats.parse_line(
            "2026-09-04T06:00:01Z fw01 suricata: ET SCAN Potential TCP Scan "
            "from 198.51.100.10"
        )
        self.assertIsNotNone(raw)
        self.assertEqual(raw["host"], "fw01")
        self.assertEqual(raw["event_type"], "port_scan")
        self.assertTrue(raw["occurred_at"].endswith("+00:00"))

    def test_json_line(self):
        raw = formats.parse_line(
            json.dumps({"event_id": "z-1", "event_type": "conn", "ip": "203.0.113.9"})
        )
        self.assertEqual(raw["event_id"], "z-1")
        self.assertEqual(raw["ip"], "203.0.113.9")
        self.assertEqual(raw["source"], "siem")

    def test_json_line_without_id_gets_deterministic_id(self):
        one = formats.parse_line(json.dumps({"event_type": "conn", "ip": "1.2.3.4"}))
        two = formats.parse_line(json.dumps({"event_type": "conn", "ip": "1.2.3.4"}))
        self.assertEqual(one["event_id"], two["event_id"])  # deterministic
        self.assertEqual(one["event_id"], one["event_id"][:20])

    def test_auditd_keyvalue(self):
        raw = formats.parse_line(
            'type=SYSCALL msg=audit(1725433201.123:456): pid=2213 uid=0 '
            'auid=1000 msg="su root" key=privilege'
        )
        self.assertIsNotNone(raw)
        self.assertEqual(raw["event_type"], "syscall")
        self.assertEqual(raw["details"]["key"], "privilege")
        self.assertEqual(raw["details"]["pid"], "2213")

    def test_blank_line_returns_none(self):
        self.assertIsNone(formats.parse_line("   \n"))
        self.assertIsNone(formats.parse_line(""))


class FeedPipelineTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_feed_line_runs_full_pipeline(self):
        stats = FeedStats()
        feed_line(
            self.ctx,
            "<134>Jan  5 10:01:22 web1 sshd[2213]: Failed password for root "
            "from 203.0.113.77 port 51234 ssh2",
            "ssh-test",
            stats,
        )
        self.assertEqual(stats.ingested, 1)
        event = self.ctx.soc_events.list(limit=1)[0]
        self.assertEqual(event.event_type, "auth_failure")
        self.assertEqual(event.ip, "203.0.113.77")  # extracted from message

    def test_feed_line_deduplicates_on_resend(self):
        line = "<134>Jan  5 10:01:22 web1 sshd[1]: test message"
        first = FeedStats()
        feed_line(self.ctx, line, "s", first)
        second = FeedStats()
        feed_line(self.ctx, line, "s", second)
        self.assertEqual(first.ingested, 1)
        self.assertEqual(second.duplicates, 1)
        self.assertEqual(self.ctx.soc_events.count if hasattr(self.ctx.soc_events, "count") else len(self.ctx.soc_events.list()), 1)

    def test_watch_file_once_backfills(self):
        path = os.path.join(self.tmp_dir, "auth.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "<134>Jan  5 10:01:22 web1 sshd[2213]: Failed password for root "
                "from 203.0.113.7 port 51234 ssh2\n"
                '{"event_id": "z-1", "event_type": "conn", "ip": "203.0.113.9"}\n'
            )
        stats = watch_file(self.ctx, path, once=True)
        self.assertEqual(stats.parsed, 2)
        self.assertEqual(stats.ingested, 2)
        self.assertEqual(stats.errors, 0)

    def test_watch_file_polls_appended_lines(self):
        # A long-running watch keeps its byte offset between polls, so only
        # newly appended lines are ingested. The watcher stops when the file
        # disappears (rotation/delete), which lets the test end the loop.
        path = os.path.join(self.tmp_dir, "grow.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"event_id": "grow-1", "event_type": "x"}\n')

        result: dict = {}

        def run():
            result["stats"] = watch_file(
                self.ctx, path, poll_seconds=0.05, once=False
            )

        thread = threading.Thread(target=run)
        thread.start()
        time.sleep(0.25)  # first poll reads the original line
        with open(path, "a", encoding="utf-8") as handle:
            handle.write('{"event_id": "grow-2", "event_type": "x"}\n')
        time.sleep(0.3)  # next poll picks up the appended line only
        os.remove(path)  # watcher sees the file vanish and stops
        thread.join(timeout=5)
        stats = result["stats"]
        self.assertEqual(stats.lines, 2)  # original + appended, no repeats
        ids = {e.event_id for e in self.ctx.soc_events.list(limit=10)}
        self.assertEqual(ids, {"grow-1", "grow-2"})

    def test_dry_run_parses_without_ingesting(self):
        path = os.path.join(self.tmp_dir, "dry.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"event_id": "dry-1", "event_type": "x"}\n')
        stats = watch_file(self.ctx, path, once=True, dry_run=True)
        self.assertEqual(stats.parsed, 1)
        self.assertEqual(stats.ingested, 0)
        self.assertEqual(len(self.ctx.soc_events.list()), 0)

    def test_listen_udp_receives_datagram(self):
        # Reserve a port, release it, then have the listener bind it.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        results: dict = {}

        def sender():
            time.sleep(0.4)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(
                    b'<134>Jan  5 10:01:22 web1 sshd[1]: Failed password for '
                    b'root from 203.0.113.77 port 51234 ssh2',
                    ("127.0.0.1", port),
                )
            finally:
                sock.close()

        from ksec.siem.feeder import listen_udp

        thread = threading.Thread(target=sender)
        thread.start()
        stats = listen_udp(self.ctx, host="127.0.0.1", port=port, source="udp-test", run=1)
        thread.join(timeout=5)
        self.assertEqual(stats.ingested, 1)
        self.assertEqual(stats.errors, 0)
        event = self.ctx.soc_events.list(limit=1)[0]
        self.assertEqual(event.source, "udp-test")


if __name__ == "__main__":
    import unittest

    unittest.main()
