"""Unit tests for persistent pause/timed-pause control (no system access)."""
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pause import PauseController, PauseInhibitor  # noqa: E402


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeInhibitor:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.starts = 0
        self.stops = 0
        self._alive = False

    def start(self):
        if not self.enabled:
            return False
        self.starts += 1
        self._alive = True
        return True

    def stop(self):
        if self._alive:
            self.stops += 1
        self._alive = False
        return True

    def alive(self):
        return self._alive

    def status(self):
        return {"enabled": self.enabled, "held": self._alive, "pid": 1 if self._alive else None}


class ImmediateExitProc:
    pid = 4242

    def __init__(self, stderr_text=""):
        self.stderr = io.StringIO(stderr_text)

    def poll(self):
        return 1

    def wait(self, timeout=None):
        return 1


class PauseInhibitorDiagnosticsTests(unittest.TestCase):
    def test_immediate_exit_reports_stderr_and_strips_notify_socket(self):
        messages = []
        with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/systemd/notify"}), \
             mock.patch("pause.subprocess.Popen",
                        return_value=ImmediateExitProc(
                            "Failed to inhibit: OperationInProgress")) as popen, \
             mock.patch("pause.time.sleep"):
            inh = PauseInhibitor(log=messages.append)
            self.assertFalse(inh.start())
        self.assertTrue(any("OperationInProgress" in m for m in messages))
        env = popen.call_args.kwargs["env"]
        self.assertNotIn("NOTIFY_SOCKET", env)

    def test_successful_start_keeps_child_and_reports_pid(self):
        class AliveProc:
            pid = 4343

            def poll(self):
                return None

        messages = []
        with mock.patch("pause.subprocess.Popen", return_value=AliveProc()), \
             mock.patch("pause.time.sleep"):
            inh = PauseInhibitor(log=messages.append)
            self.assertTrue(inh.start())
            self.assertTrue(inh.alive())
            self.assertEqual(inh.status()["pid"], 4343)
        self.assertTrue(any("acquired" in m for m in messages))


class PauseTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "state.json")
        self.clock = Clock()

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, inhibitor=None):
        return PauseController(self.path, inhibitor=inhibitor or FakeInhibitor(),
                               clock=self.clock, log=lambda _s: None)

    def test_missing_file_is_auto(self):
        pc = self.make()
        st = pc.load()
        self.assertEqual(st["mode"], "auto")
        self.assertFalse(st["paused"])

    def test_pause_is_persisted_and_survives_restart(self):
        inh = FakeInhibitor()
        pc = self.make(inh)
        pc.load()
        st = pc.pause(None, by="uid:1000")
        self.assertTrue(st["paused"])
        self.assertTrue(st["persisted"])
        self.assertTrue(os.path.exists(self.path))
        pc.reconcile_inhibitor()
        self.assertTrue(inh.alive())

        pc2 = self.make(FakeInhibitor())
        st2 = pc2.load()
        self.assertEqual(st2["mode"], "paused")
        self.assertTrue(st2["paused"])

    def test_timed_pause_expires(self):
        pc = self.make()
        pc.load()
        pc.pause(3600, by="uid:1000")
        self.assertTrue(pc.is_paused())
        self.clock.t = 1000 + 3600
        exp = pc.expire_if_due()
        self.assertTrue(exp["changed"])
        self.assertFalse(pc.is_paused())
        self.assertEqual(pc.status()["last_resume_reason"], "timed_expiry")

    def test_timed_pause_expired_while_stopped(self):
        pc = self.make()
        pc.load()
        pc.pause(60, by="uid:1000")
        self.clock.t = 1000 + 61
        pc2 = self.make()
        st = pc2.load()
        self.assertEqual(st["mode"], "auto")
        self.assertEqual(st["last_resume_reason"], "timed_expiry_while_stopped")

    def test_resume_persists_auto(self):
        pc = self.make()
        pc.load()
        pc.pause(None)
        pc.resume(by="uid:1000")
        self.assertFalse(pc.is_paused())
        with open(self.path) as f:
            data = json.load(f)
        self.assertEqual(data["mode"], "auto")

    def test_corrupt_main_recovers_from_backup(self):
        pc = self.make()
        pc.load()
        pc.pause(None)
        pc.resume()
        # .bak now holds the paused state; corrupt the main file.
        with open(self.path, "w") as f:
            f.write("{not json")
        pc2 = self.make()
        st = pc2.load()
        self.assertTrue(st["paused"])
        self.assertIn("recovered", pc2.load_error)

    def test_corrupt_everything_fails_safe_to_paused(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        with open(self.path + ".bak", "w") as f:
            f.write("also broken")
        pc = self.make()
        st = pc.load()
        self.assertTrue(pc.corrupt)
        self.assertEqual(st["mode"], "paused")
        self.assertTrue(st["paused"])
        self.assertIn("failing safe", st["reason"])

    def test_backup_file_is_written(self):
        pc = self.make()
        pc.load()
        pc.pause(None)
        pc.resume()
        self.assertTrue(os.path.exists(self.path + ".bak"))

    def test_manual_override_releases_and_restores_inhibitor(self):
        inh = FakeInhibitor()
        pc = self.make(inh)
        pc.load()
        pc.pause(None)
        pc.reconcile_inhibitor()
        self.assertTrue(inh.alive())
        with pc.manual_suspend_override():
            self.assertFalse(inh.alive())
        self.assertTrue(inh.alive())
        self.assertEqual(inh.starts, 2)

    def test_reconcile_matches_pause_state(self):
        inh = FakeInhibitor()
        pc = self.make(inh)
        pc.load()
        pc.reconcile_inhibitor()
        self.assertFalse(inh.alive())
        pc.pause(None)
        pc.reconcile_inhibitor()
        self.assertTrue(inh.alive())
        pc.resume()
        pc.reconcile_inhibitor()
        self.assertFalse(inh.alive())

    def test_inhibitor_disabled_is_noop(self):
        inh = FakeInhibitor(enabled=False)
        pc = PauseController(self.path, inhibitor=inh, clock=self.clock)
        pc.load()
        pc.pause(None)
        self.assertFalse(inh.alive())
        self.assertTrue(pc.is_paused())

    def test_inhibitor_wrapper_disabled(self):
        inh = PauseInhibitor(enabled=False)
        self.assertFalse(inh.start())
        self.assertFalse(inh.stop())
        self.assertFalse(inh.alive())


if __name__ == "__main__":
    unittest.main(verbosity=2)
