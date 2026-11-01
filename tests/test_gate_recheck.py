"""Tests for the post-gate re-check (the actual safety argument).

The firewall only stops *new* connections, so suspending is gated on a
sustained clean re-check of Strata and the critical detectors.  These tests
drive that loop directly with fakes and a virtual clock.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy import ACTIVE, OK, UNKNOWN, DetectorResult  # noqa: E402
from sleepmon import gate_recheck  # noqa: E402
import netgate  # noqa: E402


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.0)


class FakeMon:
    def __init__(self, results_fn):
        self.session = None
        self.sweeps = 0
        self._results_fn = results_fn

    def sweep(self, session=None):
        self.sweeps += 1
        self.results = self._results_fn(self.sweeps)
        return self.results


class FakeStrataPort:
    def __init__(self, loaded=False, raises=False):
        self._loaded = loaded
        self._raises = raises
        self.calls = 0

    def loaded(self):
        self.calls += 1
        if self._raises:
            raise OSError("connection refused")
        return self._loaded


class FakeGate:
    def __init__(self, state="closed", enabled=True, raises=False):
        self.enabled = enabled
        self._state = state
        self._raises = raises
        self.checks = 0

    def status(self):
        self.checks += 1
        if self._raises:
            raise netgate.GateError("helper gone")
        if self._state == "closed":
            return {"state": "closed", "ok": True, "sealed": True,
                    "rules": 1, "verified": True, "consistent": True,
                    "actual_state": "closed"}
        return {"state": self._state, "ok": True, "consistent": True,
                "actual_state": self._state}


def clear_results(_n):
    return [
        DetectorResult("input", OK, "idle 600s"),
        DetectorResult("strata", OK, "model loaded but idle"),
        DetectorResult("updates", OK, "none"),
        DetectorResult("transfers", OK, "none"),
        DetectorResult("streams", OK, "none"),
        DetectorResult("inhibitors", OK, "no sleep locks"),
        DetectorResult("opencode", ACTIVE, "informational", informational=True),
    ]


class TestGateRecheck(unittest.TestCase):
    def test_sustained_clean_probes_pass(self):
        mon = FakeMon(clear_results)
        clock = Clock()
        ok, msg = gate_recheck(mon, FakeStrataPort(loaded=False),
                               {"verify_s": 5.0, "verify_probes": 3},
                               clock=clock, sleep=clock.sleep)
        self.assertTrue(ok, msg)
        self.assertEqual(mon.sweeps, 3)
        self.assertIn("consecutive clean", msg)

    def test_strata_busy_blocks_suspend(self):
        def results(n):
            r = clear_results(n)
            r[1] = DetectorResult("strata", ACTIVE, "inference active (busy=true, queued=1)")
            return r

        mon = FakeMon(results)
        clock = Clock()
        ok, msg = gate_recheck(mon, FakeStrataPort(), {"verify_s": 3.0, "verify_probes": 3},
                               clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("strata", msg)
        self.assertIn("busy", msg)

    def test_model_reloaded_after_unload_blocks_suspend(self):
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(loaded=True),
                               {"verify_s": 2.0, "verify_probes": 2},
                               clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("loaded again after unload", msg)

    def test_loaded_model_is_allowed_for_pre_and_post_gate_idle_checks(self):
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(loaded=True),
                               {"verify_s": 2.0, "verify_probes": 2},
                               require_unloaded=False,
                               clock=clock, sleep=clock.sleep)
        self.assertTrue(ok, msg)

    def test_unreadable_health_fails_safe(self):
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(raises=True),
                               {"verify_s": 2.0, "verify_probes": 2},
                               clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("health unreadable", msg)

    def test_unknown_input_detector_blocks(self):
        def results(n):
            r = clear_results(n)
            r[0] = DetectorResult("input", UNKNOWN, "idle source unavailable")
            return r

        clock = Clock()
        ok, msg = gate_recheck(FakeMon(results), FakeStrataPort(),
                               {"verify_s": 2.0, "verify_probes": 2},
                               clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("input", msg)

    def test_transient_race_resets_the_clean_run(self):
        """A request that surfaces mid-window must reset the streak."""
        def results(n):
            r = clear_results(n)
            if n % 2 == 0:  # every second probe sees a request again
                r[1] = DetectorResult("strata", ACTIVE, "inference active")
            return r

        clock = Clock()
        ok, msg = gate_recheck(FakeMon(results), FakeStrataPort(),
                               {"verify_s": 3.0, "verify_probes": 3},
                               clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("/3 clean probes", msg)

    def test_informational_opencode_never_blocks(self):
        clock = Clock()
        ok, _msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                                {"verify_s": 5.0, "verify_probes": 2},
                                clock=clock, sleep=clock.sleep)
        self.assertTrue(ok)

    def test_defaults_require_three_probes(self):
        mon = FakeMon(clear_results)
        clock = Clock()
        ok, msg = gate_recheck(mon, FakeStrataPort(), {}, clock=clock, sleep=clock.sleep)
        self.assertTrue(ok, msg)
        self.assertEqual(mon.sweeps, 3)

    def test_gate_must_still_be_closed(self):
        """A helper restart opens the gate; verification must notice and abort."""
        gate = FakeGate(state="open")
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                               {"verify_s": 2.0, "verify_probes": 2},
                               gate=gate, clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("expected closed", msg)
        self.assertGreater(gate.checks, 0)

    def test_closed_gate_passes(self):
        gate = FakeGate(state="closed")
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                               {"verify_s": 2.0, "verify_probes": 2},
                               gate=gate, clock=clock, sleep=clock.sleep)
        self.assertTrue(ok, msg)
        self.assertEqual(gate.checks, 2)

    def test_unreadable_gate_status_blocks(self):
        gate = FakeGate(raises=True)
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                               {"verify_s": 2.0, "verify_probes": 2},
                               gate=gate, clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("gate: status unreadable", msg)

    def test_closed_gate_without_rule_verification_blocks(self):
        """A 'closed' claim with no proof of the live rule fails safe."""
        gate = FakeGate(state="closed")
        gate.status = lambda: {"state": "closed", "ok": True, "sealed": True}
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                               {"verify_s": 2.0, "verify_probes": 2},
                               gate=gate, clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("consistent", msg)

    def test_closed_gate_with_no_blocking_rule_blocks(self):
        gate = FakeGate(state="closed")
        gate.status = lambda: {"state": "closed", "ok": True, "sealed": True,
                               "rules": 0, "verified": False,
                               "consistent": False, "actual_state": "closed"}
        clock = Clock()
        ok, msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                               {"verify_s": 2.0, "verify_probes": 2},
                               gate=gate, clock=clock, sleep=clock.sleep)
        self.assertFalse(ok)
        self.assertIn("gate:", msg)

    def test_disabled_gate_is_not_queried(self):
        gate = FakeGate(state="open", enabled=False, raises=True)
        clock = Clock()
        ok, _msg = gate_recheck(FakeMon(clear_results), FakeStrataPort(),
                                {"verify_s": 2.0, "verify_probes": 2},
                                gate=gate, clock=clock, sleep=clock.sleep)
        self.assertTrue(ok)
        self.assertEqual(gate.checks, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
