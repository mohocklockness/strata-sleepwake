"""Regression tests for detector/policy interactions that previously blocked sleep."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors  # noqa: E402
from policy import ACTIVE, OK, UNKNOWN, DetectorResult, blocker_reasons  # noqa: E402


class TestOpenCodeInformational(unittest.TestCase):
    def _probe(self, net_result=(True, 0.0, 1000), sessions=([], 0)):
        p = detectors.OpenCodeProbe({"enabled": True})
        with mock.patch.object(p, "_hits", return_value=[{"pid": 1}]), \
             mock.patch.object(p, "_cpu_pct", return_value=0.0), \
             mock.patch.object(p, "_descendant_tools", return_value=[]), \
             mock.patch.object(p, "_net", return_value=net_result), \
             mock.patch.object(p, "_sessions", return_value=sessions):
            return p.probe()

    def test_periodic_socket_activity_is_informational(self):
        """The observed 5-minute OpenCode socket event must not block sleep."""
        r = self._probe()
        self.assertEqual(r.state, ACTIVE)
        self.assertTrue(r.informational)
        self.assertIn("model traffic 0 kB/s", r.reason)
        self.assertEqual(blocker_reasons([r]), [])

    def test_stale_open_turn_is_informational(self):
        """Even a fail-safe OpenCode DB verdict must not reset the timer."""
        r = self._probe(net_result=(False, 0.0, None),
                        sessions=([{"id": "s", "title": "old turn",
                                    "time_updated": 1, "idle": True}], 0))
        self.assertEqual(r.state, UNKNOWN)
        self.assertTrue(r.informational)
        self.assertEqual(blocker_reasons([r]), [])


class TestUpdateProbe(unittest.TestCase):
    PROCESSES = [
        {"name": "apt"},
        {"name": "apt-get"},
        {"name": "dpkg"},
    ]

    def _probe(self, procs, units=None, idle_units=None, active=()):
        cfg = {"processes": self.PROCESSES,
               "units": units or [],
               "idle_units": idle_units or []}

        def fake_run(cmd, timeout=3):
            unit = cmd[-1]
            if unit in set(active):
                return 0, "active\n", ""
            return 3, "inactive\n", ""

        with mock.patch.object(detectors, "iter_procs", return_value=procs), \
             mock.patch.object(detectors, "_run", side_effect=fake_run):
            return detectors.UpdateProbe(cfg).probe()

    def test_idle_packagekit_daemon_does_not_block(self):
        """PackageKit may stay resident after apt-daily; that is not an update."""
        r = self._probe([], units=["packagekit.service"],
                        active={"packagekit.service"})
        self.assertEqual(r.state, OK)
        self.assertEqual(r.detail["units"], [])
        self.assertEqual(r.detail["idle_units"], ["packagekit.service"])
        self.assertEqual(blocker_reasons([r]), [])

    def test_idle_packagekit_configured_as_idle_does_not_block(self):
        r = self._probe([], idle_units=["packagekit.service"],
                        active={"packagekit.service"})
        self.assertEqual(r.state, OK)
        self.assertEqual(r.detail["idle_units"], ["packagekit.service"])

    def test_idle_packagekit_process_not_matched(self):
        r = self._probe([(1, "packagekitd", ["/usr/lib/packagekitd"])],
                        idle_units=["packagekit.service"],
                        active={"packagekit.service"})
        self.assertEqual(r.state, OK)
        self.assertEqual(r.detail["processes"], [])

    def test_active_apt_daily_still_blocks(self):
        r = self._probe([], units=["apt-daily.service"],
                        idle_units=["packagekit.service"],
                        active={"apt-daily.service", "packagekit.service"})
        self.assertEqual(r.state, ACTIVE)
        self.assertIn("apt-daily.service", r.reason)
        self.assertEqual(r.detail["units"], ["apt-daily.service"])
        self.assertEqual(r.detail["idle_units"], ["packagekit.service"])

    def test_apt_get_process_still_blocks(self):
        r = self._probe([(2, "apt-get", ["/usr/bin/apt-get", "install", "x"])])
        self.assertEqual(r.state, ACTIVE)
        self.assertIn("apt-get", r.reason)


class TestSuspendAuthorizationProbe(unittest.TestCase):
    def test_authorized_rc_zero(self):
        with mock.patch.object(detectors, "_run", return_value=(0, "", "")) as run:
            ok, detail = detectors.logind_suspend_authorized()
        self.assertTrue(ok, detail)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:2], ["pkcheck", "--action-id"])
        self.assertIn("org.freedesktop.login1.suspend", cmd)
        self.assertIn("--process", cmd)
        self.assertNotIn("--allow-user-interaction", cmd)

    def test_authentication_required_fails_closed(self):
        with mock.patch.object(detectors, "_run", return_value=(2, "", "authentication required")):
            ok, detail = detectors.logind_suspend_authorized()
        self.assertFalse(ok)
        self.assertIn("authentication required", detail)

    def test_missing_pkcheck_fails_closed(self):
        with mock.patch.object(detectors, "_run", return_value=(127, "", "not found: pkcheck")):
            ok, detail = detectors.logind_suspend_authorized()
        self.assertFalse(ok)
        self.assertIn("pkcheck", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
