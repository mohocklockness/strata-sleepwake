"""Regression tests for the supervised one-shot runtime/lock path.

systemd creates /run/sleepmgr from RuntimeDirectory= and, by default, deletes
it when the service stops.  The one-shot process runs as sleepuser and cannot
recreate a directory under root-owned /run, so the unit must preserve it and
the one-shot must use the same monitor.lock as the service.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oneshot  # noqa: E402
import sleepmon  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestUnitRuntimeDirectory(unittest.TestCase):
    def test_unit_preserves_runtime_directory_on_stop(self):
        with open(os.path.join(HERE, "deploy", "sleepmgr.service")) as f:
            text = f.read()
        self.assertIn("RuntimeDirectory=sleepmgr", text)
        self.assertIn("RuntimeDirectoryMode=0755", text)
        self.assertIn("RuntimeDirectoryPreserve=yes", text)
        self.assertIn("User=sleepuser", text)

    def test_one_shot_has_no_alternate_lock_path(self):
        # --arm-once must use the configured service lock; main rejects
        # --lock-file before any work is done.
        args = sleepmon.parse_args(["--arm-once"])
        self.assertIsNone(args.lock_file)

    def test_production_config_uses_the_preserved_runtime_lock(self):
        with open(os.path.join(HERE, "config.production.json")) as f:
            cfg = json.load(f)
        self.assertEqual(cfg["service"]["lock_file"], "/run/sleepmgr/monitor.lock")
        self.assertNotIn("oneshot_lock_file", cfg.get("service", {}))


class TestOneShotMainRuntimeFailure(unittest.TestCase):
    def test_missing_runtime_directory_exits_cleanly(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "missing", "monitor.lock")
            cfg_path = os.path.join(d, "config.json")
            with open(cfg_path, "w") as f:
                json.dump({"log_dir": os.path.join(d, "logs"),
                           "service": {"lock_file": lock}}, f)
            with mock.patch.object(sleepmon.sys, "stdin", mock.Mock(isatty=lambda: True)), \
                 mock.patch("builtins.input", return_value="SUSPEND"):
                rc = sleepmon.main(["--config", cfg_path, "--arm-once"])
        self.assertEqual(rc, 2)


class TestRuntimeLockPreflight(unittest.TestCase):
    def test_existing_writable_directory_passes(self):
        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "monitor.lock")
            ok, detail = oneshot.runtime_lock_preflight(lock)
        self.assertTrue(ok, detail)
        self.assertIn("writable", detail)

    def test_missing_runtime_directory_has_actionable_error(self):
        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "missing", "monitor.lock")
            ok, detail = oneshot.runtime_lock_preflight(lock)
        self.assertFalse(ok)
        self.assertIn("RuntimeDirectoryPreserve=yes", detail)

    def test_read_only_directory_fails(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o500)
            try:
                ok, detail = oneshot.runtime_lock_preflight(os.path.join(d, "monitor.lock"))
            finally:
                os.chmod(d, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root can write read-only directories")
        self.assertFalse(ok)
        self.assertIn("not writable", detail)


class TestSharedLockMutex(unittest.TestCase):
    def test_same_path_blocks_a_second_monitor(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "monitor.lock")
            first = sleepmon.InstanceLock(path)
            second = sleepmon.InstanceLock(path)
            self.assertTrue(first.acquire()[0])
            ok, holder = second.acquire()
            self.assertFalse(ok)
            self.assertTrue(holder)
            first.release()
            self.assertTrue(second.acquire()[0])
            second.release()


if __name__ == "__main__":
    unittest.main(verbosity=2)
