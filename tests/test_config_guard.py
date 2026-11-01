"""Tests for the deployment config protection comparison (pure JSON)."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "deploy"))

import config_guard  # noqa: E402


def protected_config():
    return {
        "gate": {
            "enabled": True,
            "socket": "/run/sleepmgr-gate/gate.sock",
            "token_file": "/etc/sleepmgr/gate.token",
            "require_token": True,
        },
        "suspend_guard": {
            "enabled": True,
            "socket": "/run/sleepmgr-suspend-guard/guard.sock",
            "token_file": "/etc/sleepmgr/suspend-guard.token",
            "require_token": True,
            "require_gate": True,
        },
        "strata": {"config_path": "/srv/strata/Strata/strata-iq2_xs.json"},
    }


class CompareProtectionTests(unittest.TestCase):
    def test_identical_config_has_no_problems(self):
        old = protected_config()
        self.assertEqual(config_guard.compare_protection(old, old), [])

    def test_disabling_gate_is_blocking(self):
        old = protected_config()
        new = protected_config()
        new["gate"]["enabled"] = False
        problems = config_guard.compare_protection(old, new)
        self.assertTrue(config_guard.has_blocking_downgrade(problems))
        self.assertIn("gate.enabled", [p["key"] for p in problems])

    def test_removing_gate_section_is_blocking(self):
        old = protected_config()
        new = protected_config()
        del new["gate"]
        problems = config_guard.compare_protection(old, new)
        self.assertTrue(config_guard.has_blocking_downgrade(problems))

    def test_disabling_guard_is_blocking(self):
        old = protected_config()
        new = protected_config()
        new["suspend_guard"]["enabled"] = False
        problems = config_guard.compare_protection(old, new)
        self.assertTrue(config_guard.has_blocking_downgrade(problems))

    def test_removing_require_gate_is_blocking(self):
        old = protected_config()
        new = protected_config()
        del new["suspend_guard"]["require_gate"]
        problems = config_guard.compare_protection(old, new)
        self.assertIn("suspend_guard.require_gate",
                      [p["key"] for p in problems])
        self.assertTrue(config_guard.has_blocking_downgrade(problems))

    def test_removing_token_requirement_is_blocking(self):
        old = protected_config()
        new = protected_config()
        new["gate"]["require_token"] = False
        problems = config_guard.compare_protection(old, new)
        self.assertTrue(config_guard.has_blocking_downgrade(problems))

    def test_socket_change_is_a_warning_not_a_block(self):
        old = protected_config()
        new = protected_config()
        new["gate"]["socket"] = "/run/elsewhere.sock"
        problems = config_guard.compare_protection(old, new)
        self.assertFalse(config_guard.has_blocking_downgrade(problems))
        self.assertTrue(any(p["severity"] == "warn" for p in problems))

    def test_strata_pointer_change_is_surfaced(self):
        old = protected_config()
        new = protected_config()
        new["strata"]["config_path"] = "/mnt/other.json"
        problems = config_guard.compare_protection(old, new)
        self.assertIn("strata.config_path", [p["key"] for p in problems])
        self.assertFalse(config_guard.has_blocking_downgrade(problems))

    def test_enabling_protection_is_not_a_downgrade(self):
        old = protected_config()
        old["gate"]["enabled"] = False
        old["suspend_guard"]["enabled"] = False
        new = protected_config()
        self.assertEqual(config_guard.compare_protection(old, new), [])

    def test_cli_exit_codes(self):
        old = protected_config()
        new = protected_config()
        new["gate"]["enabled"] = False
        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.path.join(tmp, "old.json")
            new_path = os.path.join(tmp, "new.json")
            with open(old_path, "w", encoding="utf-8") as f:
                json.dump(old, f)
            with open(new_path, "w", encoding="utf-8") as f:
                json.dump(new, f)
            self.assertEqual(config_guard.main([old_path, new_path]), 3)
            new["gate"]["enabled"] = True
            with open(new_path, "w", encoding="utf-8") as f:
                json.dump(new, f)
            self.assertEqual(config_guard.main([old_path, new_path]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
