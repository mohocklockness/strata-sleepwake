"""Tests for the monitor's read-only guard status reporting."""
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sleepmon import GuardStatusRefresher  # noqa: E402
from suspendguard import GuardClient, GuardError  # noqa: E402


class FakeGuard:
    enabled = True

    def __init__(self):
        self.calls = []
        self.error = None
        self.reply = {"ok": True, "state": "protected", "held": True}

    def status(self, timeout=None):
        self.calls.append(timeout)
        if self.error:
            raise self.error
        return dict(self.reply)


class GuardStatusRefresherTestCase(unittest.TestCase):
    def test_force_refresh_queries_at_startup_with_short_timeout(self):
        guard = FakeGuard()
        logs = []
        refresher = GuardStatusRefresher(
            guard, interval_s=10, timeout_s=1.25, log=logs.append,
            clock=lambda: 100.0)

        reply = refresher.refresh(force=True)

        self.assertEqual(reply["state"], "protected")
        self.assertEqual(guard.calls, [1.25])
        self.assertEqual(logs, [])

    def test_periodic_refresh_is_throttled(self):
        guard = FakeGuard()
        refresher = GuardStatusRefresher(
            guard, interval_s=10, timeout_s=1.0, clock=lambda: 100.0)

        refresher.refresh(now=100.0)
        refresher.refresh(now=109.9)
        self.assertEqual(len(guard.calls), 1)

        refresher.refresh(now=110.0)
        self.assertEqual(len(guard.calls), 2)

    def test_failure_is_contained_and_logged_once_then_recovery_logged(self):
        guard = FakeGuard()
        logs = []
        refresher = GuardStatusRefresher(
            guard, interval_s=10, timeout_s=1.0, log=logs.append,
            clock=lambda: 100.0)
        guard.error = GuardError("cannot reach suspend guard")

        self.assertIsNone(refresher.refresh(force=True))
        self.assertIn("status unavailable", logs[-1])
        self.assertEqual(len(logs), 1)

        self.assertIsNone(refresher.refresh(force=True))
        self.assertEqual(len(logs), 1)

        guard.error = None
        self.assertEqual(refresher.refresh(force=True)["state"], "protected")
        self.assertIn("recovered", logs[-1])
        self.assertEqual(len(logs), 2)

    def test_disabled_guard_is_not_polled(self):
        guard = FakeGuard()
        guard.enabled = False
        refresher = GuardStatusRefresher(
            guard, interval_s=10, timeout_s=1.0, clock=lambda: 100.0)

        self.assertIsNone(refresher.refresh(force=True))
        self.assertEqual(guard.calls, [])


class GuardClientStatusFailureTestCase(unittest.TestCase):
    def test_client_is_enabled_for_status_refresher(self):
        client = GuardClient("/tmp/nonexistent-guard.sock", timeout=0.1)
        self.assertTrue(client.enabled)

    def test_connection_failure_marks_cached_status_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "missing.sock")
            client = GuardClient(path, timeout=0.2)

            with self.assertRaises(GuardError):
                client.status(timeout=0.1)

            status = client.last_status()
            self.assertEqual(status["state"], "unknown")
            self.assertIn("cannot reach", status["error"])

    def test_status_timeout_marks_cached_status_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "slow.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            server.listen(1)
            stop = threading.Event()

            def slow_server():
                try:
                    conn, _ = server.accept()
                    stop.wait(0.5)
                    conn.close()
                except OSError:
                    pass

            thread = threading.Thread(target=slow_server, daemon=True)
            thread.start()
            client = GuardClient(path, timeout=2.0)
            started = time.monotonic()
            try:
                with self.assertRaises(GuardError):
                    client.status(timeout=0.1)
            finally:
                elapsed = time.monotonic() - started
                stop.set()
                thread.join(timeout=1.0)
                server.close()

            self.assertLess(elapsed, 0.5)
            status = client.last_status()
            self.assertEqual(status["state"], "unknown")
            self.assertIn("error", status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
