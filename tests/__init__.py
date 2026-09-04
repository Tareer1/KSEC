"""Test bootstrap.

Makes ``src/`` importable without installation and provides a helper that
builds an isolated KSEC context inside a temporary directory.
"""
from __future__ import annotations

import os
import pathlib
import sys
import unittest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ksec.bootstrap import bootstrap  # noqa: E402


class KsecTestCase(unittest.TestCase):
    """Isolates KSEC state (KSEC_HOME / KSEC_CONFIG) per test."""

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = self._tmp.name
        self._saved_env = {
            "KSEC_HOME": os.environ.get("KSEC_HOME"),
            "KSEC_CONFIG": os.environ.get("KSEC_CONFIG"),
        }
        os.environ["KSEC_HOME"] = self.tmp_dir
        os.environ["KSEC_CONFIG"] = os.path.join(self.tmp_dir, "config.toml")

    def tearDown(self) -> None:
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def make_context(self, overrides: dict | None = None):
        return bootstrap(overrides)