from __future__ import annotations

from ksec.core.errors import KSECError
from ksec.execution.command_builder import build_safe_command, validate_target
from ksec.execution.runner import run_command
from tests import KsecTestCase


class CommandBuilderTest(KsecTestCase):
    def test_builds_list_command(self):
        cmd = build_safe_command("nmap", ["-sV", "example.com"])
        self.assertEqual(cmd.as_list(), ["nmap", "-sV", "example.com"])

    def test_rejects_shell_metacharacters_in_target(self):
        for evil in ("10.0.0.1; rm -rf /", "example.com$(whoami)", "x & whoami", "a|b", "`id`"):
            with self.assertRaises(KSECError):
                validate_target(evil)

    def test_rejects_forbidden_argument(self):
        with self.assertRaises(KSECError):
            build_safe_command("nmap", ["--script", "default;evil"])

    def test_accepts_valid_targets(self):
        for target in ("10.0.0.1", "10.0.0.0/24", "example.com", "sub.example.com", "https://example.com/path"):
            self.assertEqual(validate_target(target), target)


class RunnerTest(KsecTestCase):
    def test_runs_command_and_captures_output(self):
        result = run_command("echo", ["hello world"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello world", result.stdout)
        self.assertFalse(result.timed_out)

    def test_missing_tool_raises(self):
        with self.assertRaises(KSECError):
            run_command("definitely-not-a-real-tool-xyz", [])

    def test_timeout_reported(self):
        result = run_command("sleep", ["5"], timeout=1)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)


if __name__ == "__main__":
    import unittest

    unittest.main()