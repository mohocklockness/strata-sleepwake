"""Unit tests for the monitor's pure policy logic (no system access)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy import (ACTIVE, OK, UNKNOWN, Countdown, DetectorResult, Sustained,  # noqa: E402
                    blocker_reasons, build_suspend_command, can_suspend_ok,
                    classify_inhibitors, manual_refusal, match_any_process,
                    match_process, preflight_inhibitor_ok)

REAL_LOCKS = [
    {"what": "shutdown", "who": "Unattended Upgrades Shutdown",
     "why": "Stop ongoing upgrades or perform upgrades before shutdown", "mode": "delay",
     "uid": 0, "pid": 1511},
    {"what": "handle-power-key:handle-suspend-key:handle-hibernate-key", "who": "sleepuser",
     "why": "GNOME handling keypresses", "mode": "block", "uid": 1000, "pid": 2916},
    {"what": "sleep", "who": "sleepuser", "why": "GNOME handling keypresses", "mode": "delay",
     "uid": 1000, "pid": 2916},
    {"what": "sleep", "who": "NetworkManager", "why": "NetworkManager needs to turn off networks",
     "mode": "delay", "uid": 0, "pid": 1187},
    {"what": "sleep", "who": "GNOME Shell", "why": "GNOME needs to lock the screen", "mode": "delay",
     "uid": 1000, "pid": 2789},
]


class TestInhibitors(unittest.TestCase):
    def test_real_locks_do_not_block(self):
        blockers, notes = classify_inhibitors(REAL_LOCKS)
        self.assertEqual(blockers, [])
        self.assertTrue(any("GNOME Shell" in n for n in notes))
        self.assertTrue(any("Unattended Upgrades" in n for n in notes))

    def test_handle_keys_ignored(self):
        entries = [e for e in REAL_LOCKS if e["what"].startswith("handle-")]
        blockers, notes = classify_inhibitors(entries)
        self.assertEqual(blockers, [])
        self.assertEqual(notes, [])

    def test_block_sleep_blocks(self):
        entries = REAL_LOCKS + [{"what": "sleep", "who": "backup", "why": "rsync running",
                                 "mode": "block", "uid": 1000, "pid": 42}]
        blockers, notes = classify_inhibitors(entries)
        self.assertEqual([b["who"] for b in blockers], ["backup"])

    def test_own_lock_ignored(self):
        entries = [{"what": "sleep", "who": "sleepmgr", "why": "workload active",
                    "mode": "block", "uid": 1000, "pid": 1}]
        blockers, _ = classify_inhibitors(entries, own_markers=("sleepmgr",))
        self.assertEqual(blockers, [])


class TestCanSuspendGate(unittest.TestCase):
    def test_yes_is_ok_regardless_of_dry_run(self):
        self.assertTrue(can_suspend_ok("yes", 0))
        self.assertTrue(can_suspend_ok("yes", 1))

    def test_challenge_ok_only_with_clean_dry_run(self):
        self.assertTrue(can_suspend_ok("challenge", 0))
        self.assertFalse(can_suspend_ok("challenge", 1))

    def test_no_or_unknown_is_not_ok(self):
        self.assertFalse(can_suspend_ok("no", 0))
        self.assertFalse(can_suspend_ok(None, 0))


class TestPreflightInhibitorFilter(unittest.TestCase):
    GUARD = ('Operation inhibited by "sleepmgr-suspend-guard" (PID 123 '
             '"systemd-inhibit", user sleepuser), reason is "Strata/CUDA state unsafe or unknown".')

    def test_clean_dry_run_passes(self):
        self.assertTrue(preflight_inhibitor_ok(0, "ok")[0])

    def test_own_guard_only_passes(self):
        ok, detail = preflight_inhibitor_ok(1, self.GUARD)
        self.assertTrue(ok, detail)

    def test_unrelated_block_still_fails(self):
        ok, detail = preflight_inhibitor_ok(
            1, 'Operation inhibited by "backup" (PID 9 "backup", user root).')
        self.assertFalse(ok)
        self.assertIn("backup", detail)

    def test_guard_plus_unrelated_still_fails(self):
        ok, detail = preflight_inhibitor_ok(
            1, self.GUARD + '\nOperation inhibited by "backup" (PID 9 "backup", user root).')
        self.assertFalse(ok)
        self.assertIn("backup", detail)

    def test_authorization_or_unknown_failure_is_conservative(self):
        self.assertFalse(preflight_inhibitor_ok(
            2, "Interactive authentication required.")[0])
        self.assertFalse(preflight_inhibitor_ok(1, "")[0])


class TestProcessMatching(unittest.TestCase):
    PROCS = [
        (1, "thermald", ["/usr/sbin/thermald", "--systemd", "--dbus-enable", "--adaptive"]),
        (2, "python3", ["/usr/bin/python3",
                        "/usr/share/unattended-upgrades/unattended-upgrade-shutdown",
                        "--wait-for-signal"]),
        (3, "python3", ["/usr/bin/python3", "/usr/bin/unattended-upgrade", "-v"]),
        (4, "dpkg", ["/usr/bin/dpkg", "--unpack", "x.deb"]),
        (5, "dpkg-deb", ["/usr/bin/dpkg-deb", "-x", "a.deb", "/tmp/x"]),
        (6, "snap", ["/usr/bin/snap", "install", "foo"]),
        (7, "snapd", ["/usr/sbin/snapd"]),
        (8, "opencode-cli", ["/home/u/.config/ai.opencode.desktop/cli/opencode-cli", "serve"]),
        (9, "ai.opencode.des", ["/opt/OpenCode/ai.opencode.desktop", "--type=renderer"]),
    ]

    def hit_names(self, specs):
        return [h["pid"] for h in match_any_process(self.PROCS, specs)]

    def test_apt_does_not_match_thermald_or_snapd(self):
        self.assertEqual(self.hit_names([{"name": "apt"}]), [])
        self.assertEqual(match_process("thermald", ["/usr/sbin/thermald", "--adaptive"], {"name": "apt"}), False)

    def test_unattended_upgrade_worker_only(self):
        self.assertEqual(self.hit_names([{"name": "unattended-upgrade"}]), [3])

    def test_dpkg_not_dpkg_deb(self):
        self.assertEqual(self.hit_names([{"name": "dpkg"}]), [4])

    def test_snap_needs_subcommand(self):
        self.assertEqual(self.hit_names([{"name": "snap", "args_any": ["install", "refresh"]}]), [6])

    def test_opencode_names(self):
        specs = [{"name": "opencode-cli"}, {"name": "ai.opencode.desktop"}]
        self.assertEqual(sorted(self.hit_names(specs)), [8, 9])


class TestSustained(unittest.TestCase):
    def test_needs_n_consecutive(self):
        s = Sustained(3)
        self.assertFalse(s.add(True))
        self.assertFalse(s.add(True))
        self.assertTrue(s.add(True))
        self.assertFalse(s.add(False))
        self.assertFalse(s.value())


class TestCountdown(unittest.TestCase):
    def test_full_countdown(self):
        c = Countdown(30, 5)
        st = c.tick(0.0, 10.0, [])
        self.assertEqual((st["state"], st["remaining"]), ("countdown", 30))
        st = c.tick(5.0, 15.0, [])
        self.assertAlmostEqual(st["remaining"], 25.0)
        st = c.tick(31.0, 41.0, [])
        self.assertEqual(st["state"], "ready")

    def test_recent_input_is_active(self):
        c = Countdown(30, 5)
        self.assertEqual(c.tick(0.0, 2.0, [])["state"], "active")

    def test_input_during_countdown_resets(self):
        c = Countdown(30, 5)
        c.tick(0.0, 10.0, [])
        st = c.tick(10.0, 11.0, [])
        self.assertEqual(st["reason"], "input reset")
        self.assertEqual(st["remaining"], 30)
        self.assertEqual(c.resets, 1)

    def test_blocker_resets(self):
        c = Countdown(30, 5)
        c.tick(0.0, 10.0, [])
        st = c.tick(5.0, 15.0, ["strata: inference active"])
        self.assertEqual(st["state"], "blocked")
        st = c.tick(9.0, 19.0, [])
        self.assertEqual((st["state"], st["remaining"]), ("countdown", 30))

    def test_unknown_idle_blocks(self):
        c = Countdown(30, 5)
        self.assertEqual(c.tick(0.0, None, [])["state"], "unknown")


class TestSuspendCommand(unittest.TestCase):
    def test_dry_run_has_dry_run(self):
        cmd = build_suspend_command(True)
        self.assertEqual(cmd, ["systemctl", "suspend", "--check-inhibitors=yes", "--dry-run"])

    def test_armed_has_no_dry_run(self):
        cmd = build_suspend_command(False)
        self.assertEqual(cmd, ["systemctl", "suspend", "--check-inhibitors=yes"])
        self.assertNotIn("--dry-run", cmd)


class TestResults(unittest.TestCase):
    def test_blocking_and_reasons(self):
        r = [DetectorResult("a", OK, "fine"), DetectorResult("b", ACTIVE, "busy"),
             DetectorResult("c", UNKNOWN, "unsure")]
        self.assertEqual(blocker_reasons(r), ["b: busy", "c: unsure"])

    def test_informational_active_does_not_block(self):
        r = DetectorResult("opencode", ACTIVE, "periodic socket activity",
                           informational=True)
        self.assertFalse(r.blocking())
        self.assertEqual(blocker_reasons([r]), [])

    def test_informational_unknown_does_not_block(self):
        r = DetectorResult("opencode", UNKNOWN, "stale session db",
                           informational=True)
        self.assertFalse(r.blocking())
        self.assertEqual(blocker_reasons([r]), [])


class TestInactivityGate(unittest.TestCase):
    """The production 10-minute gate: idle_timeout_s=600, countdown 30s."""

    def test_waits_then_counts_down_then_ready(self):
        c = Countdown(30, 5, idle_timeout_s=600)
        st = c.tick(0.0, 10.0, [])
        self.assertEqual(st["state"], "waiting")
        st = c.tick(100.0, 110.0, [])
        self.assertEqual(st["state"], "waiting")
        self.assertAlmostEqual(st["suspend_in_s"], 500.0)
        st = c.tick(570.0, 580.0, [])
        self.assertEqual(st["state"], "countdown")
        self.assertAlmostEqual(st["remaining"], 30.0, places=3)
        st = c.tick(599.5, 609.5, [])
        self.assertEqual(st["state"], "countdown")
        st = c.tick(600.0, 610.0, [])
        self.assertEqual(st["state"], "ready")
        self.assertEqual(st["suspend_in_s"], 0.0)

    def test_input_restarts_the_whole_window(self):
        c = Countdown(30, 5, idle_timeout_s=600)
        c.tick(0.0, 10.0, [])
        c.tick(580.0, 590.0, [])
        self.assertEqual(c.tick(580.0, 0.0, [])["state"], "active")
        st = c.tick(600.0, 20.0, [])
        self.assertEqual(st["state"], "waiting")
        self.assertAlmostEqual(st["suspend_in_s"], 580.0, places=1)

    def test_blocker_restarts_the_window(self):
        c = Countdown(30, 5, idle_timeout_s=600)
        c.tick(0.0, 10.0, [])
        st = c.tick(590.0, 600.0, ["strata: inference active"])
        self.assertEqual(st["state"], "blocked")
        st = c.tick(591.0, 601.0, ["strata: inference active"])
        self.assertEqual(st["state"], "blocked")
        st = c.tick(600.0, 610.0, [])
        self.assertEqual(st["state"], "waiting")
        self.assertAlmostEqual(st["suspend_in_s"], 591.0, places=1)

    def test_pause_freezes_and_resume_restarts(self):
        c = Countdown(30, 5, idle_timeout_s=600)
        c.tick(0.0, 10.0, [])
        c.tick(580.0, 590.0, [])
        st = c.tick(581.0, 591.0, [], paused=True)
        self.assertEqual(st["state"], "paused")
        st = c.tick(1500.0, 1510.0, [], paused=True)
        self.assertEqual(st["state"], "paused")
        st = c.tick(1501.0, 1511.0, [])
        self.assertEqual(st["state"], "waiting")
        self.assertAlmostEqual(st["suspend_in_s"], 600.0, places=1)

    def test_unknown_idle_restarts_the_window(self):
        c = Countdown(30, 5, idle_timeout_s=600)
        c.tick(0.0, 10.0, [])
        self.assertEqual(c.tick(590.0, None, [])["state"], "unknown")
        st = c.tick(600.0, 10.0, [])
        self.assertEqual(st["state"], "waiting")

    def test_informational_opencode_activity_does_not_restart_timer(self):
        """A periodic OpenCode socket/CPU event must not reset the 90s gate."""
        c = Countdown(10, 5, idle_timeout_s=90)
        blockers = blocker_reasons([
            DetectorResult("opencode", ACTIVE, "model traffic 0 kB/s",
                           informational=True),
        ])
        self.assertEqual(blockers, [])
        self.assertEqual(c.tick(0.0, 10.0, blockers)["state"], "waiting")
        self.assertEqual(c.tick(80.0, 90.0, blockers)["state"], "countdown")
        st = c.tick(90.0, 100.0, blockers)
        self.assertEqual(st["state"], "ready")
        self.assertEqual(st["suspend_in_s"], 0.0)


class TestManualRefusal(unittest.TestCase):
    def test_critical_workloads_are_refused(self):
        results = [
            DetectorResult("input", OK, "idle"),
            DetectorResult("strata", ACTIVE, "inference active"),
            DetectorResult("updates", OK, "none"),
            DetectorResult("opencode", OK, "idle"),
            DetectorResult("transfers", OK, "none"),
            DetectorResult("streams", OK, "none"),
            DetectorResult("inhibitors", OK, "no sleep locks"),
        ]
        self.assertEqual(manual_refusal(results), ["strata: inference active"])

    def test_unknown_detector_is_refused(self):
        results = [DetectorResult("strata", UNKNOWN, "cannot read status")]
        self.assertEqual(manual_refusal(results), ["strata: cannot read status"])

    def test_opencode_is_not_a_manual_blocker(self):
        results = [
            DetectorResult("opencode", ACTIVE, "periodic socket activity",
                           informational=True),
            DetectorResult("strata", OK, "loaded but idle"),
        ]
        self.assertEqual(manual_refusal(results), [])

    def test_clear_workloads_are_allowed(self):
        results = [
            DetectorResult("input", OK, "idle"),
            DetectorResult("strata", OK, "loaded but idle"),
            DetectorResult("updates", OK, "none"),
            DetectorResult("opencode", OK, "idle"),
            DetectorResult("transfers", OK, "none"),
            DetectorResult("streams", OK, "none"),
            DetectorResult("inhibitors", OK, "no sleep locks"),
        ]
        self.assertEqual(manual_refusal(results), [])

    def test_input_is_not_a_manual_blocker(self):
        results = [DetectorResult("input", ACTIVE, "recent input"),
                   DetectorResult("strata", OK, "idle")]
        self.assertEqual(manual_refusal(results), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
