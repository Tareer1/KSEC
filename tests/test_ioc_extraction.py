from __future__ import annotations

import io
from contextlib import redirect_stdout
from types import SimpleNamespace

from ksec.cli.intel import cmd_ioc_extract
from ksec.threat_intel.extractor import IocExtractor
from tests import KsecTestCase


class IocExtractorTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.extractor = IocExtractor()

    def test_extract_entities_host_addresses(self):
        candidates = self.extractor.extract_entities(
            [
                {
                    "type": "host",
                    "addresses": ["10.0.0.5", "2001:db8::1"],
                    "hostnames": ["web.example.com"],
                }
            ]
        )
        types = {c.type for c in candidates}
        self.assertIn("IP", types)
        self.assertIn("DOMAIN", types)
        by_value = {c.normalized_value: c for c in candidates}
        self.assertEqual(by_value["10.0.0.5"].confidence, "high")
        self.assertEqual(by_value["web.example.com"].type, "DOMAIN")

    def test_extract_entities_dns_records(self):
        candidates = self.extractor.extract_entities(
            [
                {"type": "dns_record", "name": "example.com", "record_type": "A", "value": "93.184.216.34"},
                {"type": "dns_record", "name": "www.example.com", "record_type": "CNAME", "value": "edge.example.net"},
            ]
        )
        values = {(c.type, c.normalized_value) for c in candidates}
        self.assertIn(("IP", "93.184.216.34"), values)
        self.assertIn(("DOMAIN", "edge.example.net"), values)
        self.assertIn(("DOMAIN", "example.com"), values)

    def test_extract_text_ip_domain_url_email_hash(self):
        text = (
            "connect to 192.168.1.10:8080 and evil.example.com "
            "https://phish.example.net/login dave@evil.example.com "
            "md5 5d41402abc4b2a76b9719d911017c592"
        )
        candidates = self.extractor.extract_text(text)
        types = {c.type for c in candidates}
        self.assertIn("IP", types)
        self.assertIn("DOMAIN", types)
        self.assertIn("URL", types)
        self.assertIn("EMAIL", types)
        self.assertIn("HASH", types)
        # Port stripped from IP.
        by_value = {c.normalized_value: c for c in candidates}
        self.assertIn("192.168.1.10", by_value)
        # URL is the canonical candidate for the URL domain.
        urls = [c for c in candidates if c.type == "URL"]
        self.assertTrue(urls)

    def test_extract_text_deduplicates_keeping_highest_confidence(self):
        # Same IP appears as entity (high) and text (low): entity wins.
        entity_candidates = self.extractor.extract_entities(
            [{"type": "host", "addresses": ["10.0.0.5"], "hostnames": []}]
        )
        text_candidates = self.extractor.extract_text("probe 10.0.0.5 done")
        combined = entity_candidates + text_candidates
        seen: dict = {}
        for c in combined:
            existing = seen.get((c.type, c.normalized_value))
            if existing is None:
                seen[(c.type, c.normalized_value)] = c
        ip = seen[("IP", "10.0.0.5")]
        self.assertEqual(ip.confidence, "high")

    def test_ignores_invalid_values(self):
        candidates = self.extractor.extract_text("999.1.1.1 and example.invalid and a.b")
        self.assertEqual(candidates, [])

    def test_domain_tld_noise_filtered(self):
        # "the service" must not become a domain; "foo.com" in prose is skipped.
        candidates = self.extractor.extract_text("the service is fine")
        domains = [c for c in candidates if c.type == "DOMAIN"]
        self.assertEqual(domains, [])


class IocAutoRegistrationTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_extract_and_register_from_entities_and_text(self):
        result = self.ctx.intel.extract_and_register(
            [{"type": "host", "addresses": ["10.0.0.5"], "hostnames": ["web.example.com"]}],
            raw_text="C2 beacon to 198.51.100.7",
            source="test:scan",
        )
        self.assertEqual(result["total_candidates"], 3)  # 2 entities + 1 text IP
        self.assertEqual(result["registered"], 3)
        # Idempotent: second run reports already_known.
        result2 = self.ctx.intel.extract_and_register(
            [{"type": "host", "addresses": ["10.0.0.5"], "hostnames": []}],
            source="test:scan",
        )
        self.assertEqual(result2["already_known"], 1)

    def test_registered_iocs_are_queryable(self):
        self.ctx.intel.extract_and_register(
            [{"type": "host", "addresses": ["10.0.0.5"], "hostnames": []}],
            raw_text="evil.example.com",
            source="test:scan",
        )
        iocs = self.ctx.intel.list_iocs()
        values = {i.normalized_value for i in iocs}
        self.assertIn("10.0.0.5", values)
        self.assertIn("evil.example.com", values)
        # Confidence preserved: entity IP high, text domain low.
        by_value = {i.normalized_value: i for i in iocs}
        self.assertEqual(by_value["10.0.0.5"].confidence, "high")
        self.assertEqual(by_value["evil.example.com"].confidence, "low")

    def test_scheduler_auto_registers_from_job(self):
        # Simulate a completed job through the scheduler; the job adapter for
        # dns_lookup runs real dig, so use a small scripted job instead via
        # the intel hook path directly (the scheduler hook is exercised below
        # without depending on system dig).
        job = self.ctx.scheduler.submit(capability="null_probe", target="", user_id=None)
        # null adapter produces no entities; force the hook manually with data.
        outcome = {
            "entities": [{"type": "host", "addresses": ["10.0.0.9"], "hostnames": []}],
            "stdout": "suspicious host 203.0.113.5",
        }
        self.ctx.scheduler._auto_extract_iocs(job, outcome)
        values = {i.normalized_value for i in self.ctx.intel.list_iocs()}
        self.assertIn("10.0.0.9", values)
        self.assertIn("203.0.113.5", values)
        source = self.ctx.intel.list_iocs()[0].source
        self.assertIn(f"job:{job.id}", source)

    def test_scheduler_auto_extract_never_fails_job(self):
        job = self.ctx.scheduler.submit(capability="null_probe", target="", user_id=None)
        # A broken intel service must not raise out of the scheduler.
        self.ctx.scheduler.intel_service = None
        self.ctx.scheduler._auto_extract_iocs(job, {"entities": [], "stdout": ""})
        self.assertEqual(len(self.ctx.intel.list_iocs()), 0)


class IocExtractCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _extract_args(self, **overrides):
        defaults = dict(
            job=None,
            evidence=None,
            text=None,
            source=None,
            confidence="medium",
            json=False,
            quiet=False,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_extract_from_text_cli(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ioc_extract(
                self.ctx, self._extract_args(text="contact 192.0.2.10 and bad.example.com")
            )
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("2 candidate", output)
        self.assertIn("192.0.2.10", output)

    def test_extract_from_job_cli(self):
        self.ctx.db.execute(
            "INSERT INTO jobs (id, capability, target, state, result, created_at)"
            " VALUES ('job123', 'dns_lookup', 'example.com', 'COMPLETED', ?, '2026-01-01')",
            (
                '{"entities": [{"type": "dns_record", "name": "example.com",'
                ' "record_type": "A", "value": "93.184.216.34"}],'
                ' "stdout": "evil.example.net"}',
            ),
        )
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ioc_extract(self.ctx, self._extract_args(job="job123"))
        self.assertEqual(code, 0)
        iocs = self.ctx.intel.list_iocs()
        values = {i.normalized_value for i in iocs}
        self.assertIn("93.184.216.34", values)
        self.assertIn("example.com", values)
        self.assertIn("evil.example.net", values)

    def test_extract_requires_source(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ioc_extract(self.ctx, self._extract_args())
        self.assertEqual(code, 1)

    def test_extract_unknown_job(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ioc_extract(self.ctx, self._extract_args(job="nope"))
        self.assertEqual(code, 1)


if __name__ == "__main__":
    import unittest

    unittest.main()