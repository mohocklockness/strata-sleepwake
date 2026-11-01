"""Tests for the GUI's pure helpers (no display required)."""
import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gui  # noqa: E402


def iso(offset):
    return (datetime.datetime.now() + datetime.timedelta(seconds=offset)).isoformat(timespec="seconds")


class FreshnessTestCase(unittest.TestCase):
    def test_recent_alive_status_is_fresh(self):
        now = datetime.datetime.now().timestamp()
        doc = {"time": iso(-10), "pid": 123}
        self.assertTrue(gui.status_is_fresh(doc, now, True, stale_s=15))

    def test_status_at_the_stale_edge(self):
        now = datetime.datetime.now().timestamp()
        self.assertTrue(gui.status_is_fresh({"time": iso(-14)}, now, True, 15))
        self.assertFalse(gui.status_is_fresh({"time": iso(-16)}, now, True, 15))

    def test_dead_pid_is_offline(self):
        now = datetime.datetime.now().timestamp()
        self.assertFalse(gui.status_is_fresh({"time": iso(0)}, now, False, 15))

    def test_stopped_and_empty_are_offline(self):
        now = datetime.datetime.now().timestamp()
        self.assertFalse(gui.status_is_fresh({"time": iso(0), "stopped": True}, now, True, 15))
        self.assertFalse(gui.status_is_fresh({}, now, True, 15))

    def test_missing_time_is_offline(self):
        now = datetime.datetime.now().timestamp()
        self.assertFalse(gui.status_is_fresh({"pid": 1}, now, True, 15))


class FormatTestCase(unittest.TestCase):
    def test_auto(self):
        self.assertEqual(gui.format_pause({"mode": "auto"}), "Automatic monitoring active")

    def test_indefinite(self):
        text = gui.format_pause({"mode": "paused", "paused": True, "paused_until": None})
        self.assertIn("indefinitely", text)

    def test_timed(self):
        now = 1000.0
        text = gui.format_pause({"mode": "paused", "paused": True, "paused_until": now + 125},
                                now=now)
        self.assertIn("timed", text)
        self.assertIn("2m05s", text)

    def test_expired_pause_is_not_paused(self):
        text = gui.format_pause({"mode": "paused", "paused": False})
        self.assertEqual(text, "Automatic monitoring active")

    def test_countdown(self):
        self.assertIn("of 600s", gui.format_countdown({"suspend_in_s": 125, "idle_timeout_s": 600}))
        self.assertEqual(gui.format_countdown({"suspend_in_s": None}), "-")


if __name__ == "__main__":
    unittest.main(verbosity=2)
