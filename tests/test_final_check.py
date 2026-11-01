"""Regression tests for the automatic final safety check.

The monitor's own suspend guard is expected protection.  It must not veto the
final check, while another block inhibitor or a missing polkit authorization
must still stop the flow before the gate is closed or Strata is unloaded.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors  # noqa: E402
import sleepmon  # noqa: E402
from policy import Countdown  # noqa: E402

GUARD = ('Operation inhibited by "sleepmgr-suspend-guard" (PID 123 '
         '"systemd-inhibit", user sleepuser), reason is "Strata/CUDA state unsafe or unknown".')


class TestFinalCheck(unittest.TestCase):
    def _monitor(self):
        mon = object.__new__(sleepmon.Monitor)
        mon.cfg = {"final_idle_slack_s": 2.0}
        mon.session = None
        mon.results = []
        mon.sweep = lambda *args, **kwargs: mon.results
        return mon

    def _run(self, dry_rc, dry_text, auth=True, can="challenge", require_idle=False):
        mon = self._monitor()
        countdown = Countdown(30, 5, idle_timeout_s=600)
        with mock.patch.object(detectors, "probe_idle", return_value=(900000, "test")), \
             mock.patch.object(detectors, "logind_can_suspend", return_value=can), \
             mock.patch.object(detectors, "preflight_suspend_dry_run",
                               return_value=(dry_rc, dry_text, "")), \
             mock.patch.object(detectors, "logind_suspend_authorized",
                               return_value=(auth, "polkit authorized" if auth else "authentication required")):
            return mon.final_check(countdown, require_idle=require_idle)

    def test_own_guard_is_expected_protection(self):
        ok, checks = self._run(1, GUARD)
        self.assertTrue(ok, checks)
        dry = [c for c in checks if c[0].startswith("systemctl --dry-run")][0]
        self.assertTrue(dry[1])
        self.assertIn("own suspend guard", dry[2])

    def test_unrelated_inhibitor_still_blocks(self):
        ok, checks = self._run(
            1, GUARD + '\nOperation inhibited by "backup" (PID 9 "backup", user root).')
        self.assertFalse(ok)
        dry = [c for c in checks if c[0].startswith("systemctl --dry-run")][0]
        self.assertFalse(dry[1])
        self.assertIn("backup", dry[2])

    def test_missing_authorization_blocks_before_unload(self):
        ok, checks = self._run(1, GUARD, auth=False)
        self.assertFalse(ok)
        auth_check = [c for c in checks if c[0] == "logind suspend authorization"][0]
        self.assertFalse(auth_check[1])
        self.assertIn("authentication", auth_check[2])

    def test_one_shot_is_not_idle_gated_but_still_checks_guard(self):
        ok, checks = self._run(1, GUARD, require_idle=False)
        self.assertTrue(ok, checks)
        idle = [c for c in checks if c[0] == "idle gate"][0]
        self.assertTrue(idle[1])
        self.assertIn("one-shot", idle[2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
