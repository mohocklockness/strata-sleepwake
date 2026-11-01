"""Regression tests for the supervised one-shot mode and suspend command."""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oneshot  # noqa: E402
import sleepmon  # noqa: E402


class _Flow:
    def __init__(self, ok=True, aborted=""):
        self.ok = ok
        self.aborted = aborted


class TestOneShotPolicy(unittest.TestCase):
    def test_preflight_failure_never_runs_the_cycle(self):
        calls = []
        outcome = oneshot.run_supervised_cycle(
            lambda: (False, "authorization missing"),
            lambda: calls.append("cycle") or _Flow())
        self.assertFalse(outcome.ok)
        self.assertFalse(outcome.ran)
        self.assertIn("authorization missing", outcome.reason)
        self.assertEqual(calls, [])

    def test_successful_preflight_runs_exactly_once(self):
        calls = []
        outcome = oneshot.run_supervised_cycle(
            lambda: (True, "clear"),
            lambda: calls.append("cycle") or _Flow())
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.ran)
        self.assertEqual(calls, ["cycle"])

    def test_refused_cycle_is_reported(self):
        outcome = oneshot.run_supervised_cycle(lambda: (True, "clear"), lambda: None)
        self.assertFalse(outcome.ok)
        self.assertTrue(outcome.ran)
        self.assertIn("refused", outcome.reason)

    def test_aborted_flow_is_reported(self):
        outcome = oneshot.run_supervised_cycle(
            lambda: (True, "clear"), lambda: _Flow(False, "guard release failed"))
        self.assertFalse(outcome.ok)
        self.assertTrue(outcome.ran)
        self.assertEqual(outcome.reason, "guard release failed")


class TestOneShotArguments(unittest.TestCase):
    def test_arm_once_parses(self):
        args = sleepmon.parse_args(["--arm-once"])
        self.assertTrue(args.arm_once)
        self.assertFalse(args.arm)

    def test_arm_once_rejects_other_modes(self):
        cases = [
            ["--arm-once", "--service"],
            ["--arm-once", "--once"],
            ["--arm-once", "--json"],
            ["--arm-once", "--arm"],
            ["--arm-once", "--resume-check"],
            ["--arm-once", "--reload-strata"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                conflicts = sleepmon.one_shot_conflicts(sleepmon.parse_args(argv))
                self.assertTrue(conflicts, argv)

    def test_arm_once_requires_service_lock_not_override(self):
        args = sleepmon.parse_args(["--arm-once", "--lock-file", "/tmp/other.lock"])
        self.assertTrue(args.lock_file)

    def test_main_refuses_lock_override_before_doing_work(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{}")
            path = f.name
        try:
            with mock.patch.object(sleepmon.sys, "stdin", mock.Mock(isatty=lambda: True)):
                rc = sleepmon.main(["--config", path, "--arm-once",
                                    "--lock-file", "/tmp/other.lock"])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_main_refuses_non_interactive_one_shot(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{}")
            path = f.name
        try:
            with mock.patch.object(sleepmon.sys, "stdin", mock.Mock(isatty=lambda: False)):
                rc = sleepmon.main(["--config", path, "--arm-once"])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_main_one_shot_does_not_require_allow_unattended(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"service": {"allow_unattended_suspend": false}}')
            path = f.name
        try:
            with mock.patch.object(sleepmon.sys, "stdin", mock.Mock(isatty=lambda: True)), \
                 mock.patch("builtins.input", return_value="no"):
                rc = sleepmon.main(["--config", path, "--arm-once"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)


class TestSuspendCommandSafety(unittest.TestCase):
    def test_suspend_preserves_inhibitor_check_and_has_no_force(self):
        p = subprocess.CompletedProcess([], 1, stdout="", stderr="Access denied")
        with mock.patch.object(sleepmon.subprocess, "run", return_value=p) as run:
            rc = sleepmon._run_suspend({}, log=None)
        self.assertEqual(rc, 1)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd, ["systemctl", "suspend", "--check-inhibitors=yes"])
        self.assertNotIn("-i", cmd)
        self.assertNotIn("--force", cmd)

    def test_failure_returns_code_and_logs_authorization_failure(self):
        p = subprocess.CompletedProcess([], 2, stdout="", stderr="authentication required")
        messages = []
        with mock.patch.object(sleepmon.subprocess, "run", return_value=p):
            rc = sleepmon._run_suspend({}, log=messages.append)
        self.assertEqual(rc, 2)
        self.assertTrue(any("authentication required" in m for m in messages))

    def test_success_waits_for_actual_resume(self):
        p = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        messages = []
        with mock.patch.object(sleepmon.subprocess, "run", return_value=p), \
             mock.patch.object(sleepmon.suspendflow, "wait_for_resume",
                               return_value=(True, 68.4)) as wait:
            rc = sleepmon._run_suspend({"suspend_resume_wait_s": 30},
                                       log=messages.append)
        self.assertEqual(rc, 0)
        wait.assert_called_once()
        self.assertEqual(wait.call_args.kwargs["timeout_s"], 30.0)
        self.assertTrue(any("waiting for the real resume" in m for m in messages))
        self.assertTrue(any("observed after 68.4s" in m for m in messages))

    def test_success_without_resume_is_a_failure(self):
        p = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        messages = []
        with mock.patch.object(sleepmon.subprocess, "run", return_value=p), \
             mock.patch.object(sleepmon.suspendflow, "wait_for_resume",
                               return_value=(False, "no gap")):
            rc = sleepmon._run_suspend({"suspend_resume_wait_s": 1},
                                       log=messages.append)
        self.assertEqual(rc, 1)
        self.assertTrue(any("no suspend/resume cycle" in m for m in messages))


class TestAuthorizationRule(unittest.TestCase):
    def test_prepared_rule_is_narrow_and_does_not_bypass(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "deploy", "49-sleepmgr-suspend.rules")
        with open(path) as f:
            text = f.read()
        self.assertIn('action.id == "org.freedesktop.login1.suspend"', text)
        self.assertIn('subject.user == "sleepuser"', text)
        self.assertIn("!subject.session", text)
        self.assertNotIn("org.freedesktop.login1.power-off", text)
        self.assertNotIn("org.freedesktop.login1.reboot", text)
        self.assertNotIn("--force", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
