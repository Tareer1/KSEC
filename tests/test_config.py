from __future__ import annotations

import os
from pathlib import Path

from ksec.config.loader import KsecConfig, load_config_dict
from tests import KsecTestCase


class ConfigTest(KsecTestCase):
    def test_defaults_resolve_to_home(self):
        cfg = KsecConfig.load()
        self.assertEqual(cfg.data_dir, Path(self.tmp_dir).resolve())
        self.assertEqual(cfg.db_path, Path(self.tmp_dir).resolve() / "ksec.db")
        self.assertTrue(cfg.require_authorization)
        self.assertFalse(cfg.read_only)
        self.assertTrue(cfg.audit_enabled)
        self.assertEqual(cfg.log_file, Path(self.tmp_dir).resolve() / "ksec.log")

    def test_config_file_override(self):
        cfg_path = Path(self.tmp_dir) / "config.toml"
        cfg_path.write_text("[scheduler]\nmax_concurrent_jobs = 4\n", encoding="utf-8")
        os.environ["KSEC_CONFIG"] = str(cfg_path)
        merged, source = load_config_dict()
        self.assertEqual(merged["scheduler"]["max_concurrent_jobs"], 4)
        self.assertEqual(source, cfg_path)
        cfg = KsecConfig.load()
        self.assertEqual(cfg.max_concurrent_jobs, 4)

    def test_override_wins_over_file(self):
        cfg_path = Path(self.tmp_dir) / "config.toml"
        cfg_path.write_text("[scheduler]\nmax_concurrent_jobs = 4\n", encoding="utf-8")
        os.environ["KSEC_CONFIG"] = str(cfg_path)
        cfg = KsecConfig.load(overrides={"scheduler": {"max_concurrent_jobs": 9}})
        self.assertEqual(cfg.max_concurrent_jobs, 9)

    def test_missing_config_uses_defaults(self):
        cfg = KsecConfig.load()
        self.assertIsNone(cfg.source)


if __name__ == "__main__":
    import unittest

    unittest.main()