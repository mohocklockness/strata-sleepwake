"""Tests for the gate-first unload/verify/suspend/recovery sequence (fakes)."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors  # noqa: E402
from suspendflow import (run_quiesce, startup_gate_recovery,  # noqa: E402
                         startup_gate_recovery_retry, wait_for_resume,
                         StrataPort, _gate_evidence_problem,
                         verify_gate_protection)


class IndexedPause:
    """Returns True on exactly the n-th is_paused() call (1-based)."""

    def __init__(self, pause_at=None):
        self.pause_at = pause_at
        self.calls = 0

    def is_paused(self):
        self.calls += 1
        return self.calls == self.pause_at


class FakeStrata:
    def __init__(self, loaded=True, unload_ok=True, reload_ok=True, ready_ok=True):
        self.loaded_flag = loaded
        self.unload_ok = unload_ok
        self.reload_ok = reload_ok
        self.ready_ok = ready_ok
        self.unload_calls = 0
        self.reload_calls = 0
        self.ready_calls = 0

    def loaded(self, timeout=None):
        return self.loaded_flag

    def unload(self, log):
        self.unload_calls += 1
        if self.unload_ok:
            self.loaded_flag = False
        return self.unload_ok, "unloaded" if self.unload_ok else "unload failed"

    def reload(self):
        self.reload_calls += 1
        if self.reload_ok:
            self.loaded_flag = True
        return self.reload_ok, "loaded"

    def ready(self, timeout=None):
        self.ready_calls += 1
        return self.ready_ok, "inference ready" if self.ready_ok else "not ready"


class FakeGate:
    enabled = True

    def __init__(self, fail_close=False, fail_renew=False, fail_renew_after=None,
                 fail_open=False):
        self.closed = False
        self.sealed = False
        self.open_calls = 0
        self.close_calls = 0
        self.seal_calls = 0
        self.fail_close = fail_close
        self.fail_renew = fail_renew
        self.fail_renew_after = fail_renew_after
        self.fail_open = fail_open

    def close(self):
        self.close_calls += 1
        fail_renew = self.fail_renew or (
            self.fail_renew_after is not None
            and self.close_calls > self.fail_renew_after)
        if self.fail_close or fail_renew:
            raise RuntimeError("nft write failed")
        self.closed = True
        self.sealed = False
        return {"ok": True, "state": "closed", "sealed": False,
                "rules": 1, "verified": True, "consistent": True,
                "actual_state": "closed"}

    def seal(self):
        self.seal_calls += 1
        reply = self.close()
        self.sealed = True
        reply["sealed"] = True
        return reply

    def open(self):
        self.open_calls += 1
        if self.fail_open:
            raise RuntimeError("nft write failed")
        self.closed = False
        self.sealed = False
        return {"ok": True, "state": "open"}

    def status(self):
        if self.closed:
            return {"ok": True, "state": "closed", "sealed": self.sealed,
                    "rules": 1, "verified": True, "consistent": True,
                    "actual_state": "closed"}
        return {"ok": True, "state": "open", "sealed": self.sealed,
                "rules": None, "consistent": not self.sealed,
                "actual_state": "open"}


class FakeGuard:
    enabled = True

    def __init__(self, release_ok=True, acquire_ok=True, acquire_results=None):
        self.release_ok = release_ok
        self.acquire_ok = acquire_ok
        self.acquire_results = list(acquire_results or [])
        self.release_calls = 0
        self.acquire_calls = 0
        self.protected = True

    def status(self):
        return {"ok": True, "protected": self.protected,
                "state": "protected" if self.protected else "unprotected"}

    def release(self, ttl_s=None, reason=""):
        self.release_calls += 1
        if self.release_ok:
            self.protected = False
        return {"ok": self.release_ok,
                "state": "released" if self.release_ok else "protected",
                "error": "" if self.release_ok else "safety checks failed"}

    def acquire(self, reason="", timeout=None):
        self.acquire_calls += 1
        ok = self.acquire_results.pop(0) if self.acquire_results else self.acquire_ok
        if ok:
            self.protected = True
        return {"ok": ok, "state": "protected" if ok else "unknown",
                "error": "" if ok else "inhibitor acquire failed: OperationInProgress"}


def suspend_counter(rc=0):
    box = {"calls": 0, "rc": rc}

    def suspend():
        box["calls"] += 1
        return box["rc"]

    return box, suspend


class FlowCase(unittest.TestCase):
    def run_flow(self, *, gate=None, strata=None, guard=None, pause=None,
                 settle_s=0.0, pre_ok=True, post_ok=True,
                 unload_ok=True, reload_ok=True, ready_ok=True,
                 suspend_rc=0, dry_run=False):
        strata = strata or FakeStrata(unload_ok=unload_ok, reload_ok=reload_ok,
                                      ready_ok=ready_ok)
        gate = gate if gate is not None else FakeGate()
        guard = guard if guard is not None else FakeGuard()
        box, suspend = suspend_counter(suspend_rc)
        phases = []
        calls = {"pre": 0, "post": 0, "unload_verify": 0,
                 "nvidia": 0, "ready": 0}

        def pre():
            calls["pre"] += 1
            return pre_ok, "idle before gate" if pre_ok else "busy before gate"

        def post():
            calls["post"] += 1
            return post_ok, "idle after gate" if post_ok else "busy after gate"

        def unload_verify():
            calls["unload_verify"] += 1
            return True, "GPU/RAM/gate verified"

        def nvidia():
            calls["nvidia"] += 1
            return True, "nvidia-smi healthy"

        def ready():
            calls["ready"] += 1
            return strata.ready()

        res = run_quiesce(
            pause or IndexedPause(), strata, suspend, dry_run=dry_run,
            gate=gate, settle_s=settle_s,
            pre_gate_verify=pre, post_gate_verify=post,
            post_unload_verify=unload_verify,
            post_resume_verify=nvidia, readiness_verify=ready,
            guard=guard, journal=lambda rec: phases.append(rec["phase"]))
        return res, strata, gate, guard, box, phases, calls


class OrderingTests(FlowCase):
    def test_dry_run_has_no_side_effects(self):
        res, strata, gate, guard, box, phases, calls = self.run_flow(dry_run=True)
        self.assertTrue(res.ok)
        self.assertTrue(res.dry_run)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(gate.close_calls, 0)
        self.assertEqual(guard.release_calls, 0)
        self.assertEqual(box["calls"], 0)
        self.assertIn("would-close-gate", phases)

    def test_verified_order(self):
        res, strata, gate, guard, box, phases, calls = self.run_flow(settle_s=0.01)
        self.assertTrue(res.ok, res.aborted)
        self.assertTrue(res.suspended)
        self.assertTrue(res.post_unload_verified)
        self.assertTrue(res.nvidia_verified)
        self.assertTrue(res.ready)
        self.assertEqual(calls["pre"], 1)
        self.assertEqual(calls["post"], 1)
        self.assertEqual(calls["unload_verify"], 1)
        self.assertEqual(calls["nvidia"], 1)
        self.assertEqual(calls["ready"], 1)
        self.assertLess(phases.index("pre-gate-verify"), phases.index("gate-close"))
        self.assertLess(phases.index("gate-close"), phases.index("gate-settle"))
        self.assertLess(phases.index("gate-settle"), phases.index("gate-verify"))
        self.assertLess(phases.index("gate-verify"), phases.index("unload"))
        self.assertLess(phases.index("unload"), phases.index("post-unload-verify"))
        self.assertLess(phases.index("post-unload-verify"), phases.index("guard-release"))
        self.assertLess(phases.index("guard-release"), phases.index("suspend"))
        self.assertLess(phases.index("suspend"), phases.index("guard-acquire"))
        self.assertLess(phases.index("guard-acquire"), phases.index("nvidia-verify"))
        self.assertLess(phases.index("nvidia-verify"), phases.index("reload"))
        self.assertLess(phases.index("reload"), phases.index("readiness-verify"))
        self.assertLess(phases.index("readiness-verify"), phases.index("gate-open"))
        self.assertFalse(gate.closed)
        self.assertTrue(res.gate_reopened)
        self.assertGreaterEqual(gate.seal_calls, 3)  # close + pre-suspend + resume
        self.assertEqual(strata.unload_calls, 1)
        self.assertEqual(strata.reload_calls, 1)

    def test_gate_is_closed_for_unload_and_guard_release(self):
        seen = {}
        strata = FakeStrata()
        gate = FakeGate()
        guard = FakeGuard()
        box, suspend = suspend_counter()

        def pre():
            seen["pre"] = gate.closed
            return True, "idle"

        def post():
            seen["post"] = gate.closed
            return True, "idle"

        def unload_verify():
            seen["unload"] = gate.closed
            return True, "verified"

        def release(ttl_s=None, reason=""):
            seen["release"] = gate.closed
            return {"ok": True, "state": "released"}

        guard.release = release
        res = run_quiesce(IndexedPause(), strata, suspend, dry_run=False,
                          gate=gate, pre_gate_verify=pre,
                          post_gate_verify=post,
                          post_unload_verify=unload_verify,
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertTrue(res.ok, res.aborted)
        self.assertEqual(seen, {"pre": False, "post": True, "unload": True, "release": True})


class FailureTests(FlowCase):
    def test_pre_gate_verify_failure_aborts_before_close(self):
        res, strata, gate, guard, box, phases, calls = self.run_flow(pre_ok=False)
        self.assertFalse(res.ok)
        self.assertIn("pre-gate verification failed", res.aborted)
        self.assertEqual(gate.close_calls, 0)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(box["calls"], 0)

    def test_post_gate_verify_failure_keeps_gate_closed_until_ready(self):
        res, strata, gate, guard, box, phases, calls = self.run_flow(post_ok=False)
        self.assertFalse(res.ok)
        self.assertIn("post-gate verification failed", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(box["calls"], 0)
        self.assertEqual(gate.close_calls, 2)  # initial close + abort renewal
        self.assertFalse(gate.closed)           # readiness succeeded, then reopened

    def test_gate_close_failure_does_not_unload_or_reopen(self):
        gate = FakeGate(fail_close=True)
        res, strata, gate, guard, box, phases, calls = self.run_flow(gate=gate)
        self.assertFalse(res.ok)
        self.assertIn("cannot close the network gate", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(box["calls"], 0)
        self.assertEqual(gate.open_calls, 0)

    def test_unload_failure_restores_ready_gate(self):
        res, strata, gate, guard, box, phases, calls = self.run_flow(unload_ok=False)
        self.assertFalse(res.ok)
        self.assertIn("unload failed", res.aborted)
        self.assertEqual(strata.reload_calls, 0)
        self.assertFalse(gate.closed)

    def test_unload_failure_keeps_gate_closed_when_server_is_not_ready(self):
        gate = FakeGate()
        strata = FakeStrata(unload_ok=False, ready_ok=False)
        box, suspend = suspend_counter()
        res = run_quiesce(IndexedPause(), strata, suspend, dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (False, "not ready"))
        self.assertFalse(res.ok)
        self.assertTrue(res.gate_closed)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(strata.reload_calls, 0)

    def test_post_unload_verify_failure_reloads_and_reopens_only_after_ready(self):
        strata = FakeStrata()
        gate = FakeGate()
        box, suspend = suspend_counter()
        calls = {"nvidia": 0, "ready": 0}

        def unload_verify():
            return False, "VRAM still 9000 MiB"

        def nvidia():
            calls["nvidia"] += 1
            return True, "nvidia"

        def ready():
            calls["ready"] += 1
            return True, "ready"

        res = run_quiesce(IndexedPause(), strata, suspend, dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=unload_verify,
                          post_resume_verify=nvidia,
                          readiness_verify=ready)
        self.assertFalse(res.ok)
        self.assertIn("post-unload verification failed", res.aborted)
        self.assertEqual(strata.reload_calls, 1)
        self.assertEqual(calls["ready"], 1)
        self.assertFalse(gate.closed)
        # NVIDIA is intentionally not queried before suspend was attempted.
        self.assertEqual(calls["nvidia"], 0)

    def test_guard_refusal_reloads_and_reopens_after_ready(self):
        guard = FakeGuard(release_ok=False)
        res, strata, gate, guard, box, phases, calls = self.run_flow(guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("sleep guard refused release", res.aborted)
        self.assertEqual(box["calls"], 0)
        self.assertEqual(strata.reload_calls, 1)
        self.assertEqual(guard.acquire_calls, 1)
        self.assertFalse(gate.closed)

    def test_suspend_failure_reloads_and_reopens(self):
        res, strata, gate, guard, box, phases, calls = self.run_flow(suspend_rc=1)
        self.assertFalse(res.ok)
        self.assertIn("rc=1", res.aborted)
        self.assertEqual(strata.reload_calls, 1)
        self.assertEqual(guard.acquire_calls, 1)
        self.assertFalse(gate.closed)

    def test_guard_reacquire_failure_after_resume_keeps_gate_closed(self):
        strata = FakeStrata()
        gate = FakeGate()
        guard = FakeGuard(acquire_ok=False)

        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1], dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("could not reacquire the sleep guard", res.aborted)
        self.assertTrue(res.gate_closed)
        self.assertFalse(res.gate_reopened)
        # Recovery still reloads/verifies Strata, but the gate stays closed
        # because guard protection was never confirmed.
        self.assertEqual(strata.reload_calls, 1)
        self.assertTrue(res.ready)
        self.assertFalse(res.guard_reacquired)

    def test_slow_guard_acquire_consumes_the_retry_budget(self):
        """A slow logind call must not extend the guard reacquire window."""
        class SlowGuard(FakeGuard):
            def __init__(self, now, step):
                super().__init__(acquire_ok=False)
                self.now = now
                self.step = step
                self.timeouts = []

            def acquire(self, reason="", timeout=None):
                self.acquire_calls += 1
                self.timeouts.append(timeout)
                self.now[0] += self.step      # blocks inside logind
                return {"ok": False,
                        "error": "inhibitor acquire failed: OperationInProgress"}

        strata = FakeStrata()
        gate = FakeGate()
        now = [0.0]
        sleeps = []
        guard = SlowGuard(now, 2.0)
        res = run_quiesce(
            IndexedPause(), strata, suspend_counter()[1], dry_run=False,
            gate=gate,
            pre_gate_verify=lambda: (True, "idle"),
            post_gate_verify=lambda: (True, "idle"),
            post_unload_verify=lambda: (True, "verified"),
            post_resume_verify=lambda: (True, "nvidia"),
            readiness_verify=lambda: (True, "ready"),
            guard=guard, guard_acquire_timeout_s=5.0,
            guard_retry_interval_s=1.0,
            clock=lambda: now[0],
            sleep=lambda s: (sleeps.append(s), now.__setitem__(0, now[0] + s)))
        self.assertFalse(res.ok)
        # Two bounded reacquire rounds (resume, then abort cleanup), each with a
        # 5s budget: 2s acquire + 1s sleep + 2s acquire exhausts each one.
        self.assertEqual(guard.acquire_calls, 4)
        self.assertEqual(guard.timeouts, [5.0, 2.0, 5.0, 2.0])
        self.assertLessEqual(now[0], 10.0 + 0.001)
        self.assertTrue(all(s <= 1.0 for s in sleeps))
        self.assertTrue(res.gate_closed)

    def test_pre_suspend_lease_renewal_failure_aborts_before_guard_release(self):
        # Initial close succeeds; the renewal before guard release fails.
        gate = FakeGate(fail_renew_after=1)
        strata = FakeStrata()
        guard = FakeGuard()
        box, suspend = suspend_counter()

        res = run_quiesce(IndexedPause(), strata, suspend, dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("cannot renew the gate lease", res.aborted)
        self.assertTrue(res.gate_lease_lost)
        self.assertEqual(guard.release_calls, 0)
        self.assertEqual(box["calls"], 0)
        self.assertFalse(res.gate_reopened)

    def test_suspend_raises_reloads_and_reopens(self):
        strata = FakeStrata()
        gate = FakeGate()
        guard = FakeGuard()

        def boom():
            raise OSError("systemctl vanished")

        res = run_quiesce(IndexedPause(), strata, boom, dry_run=False, gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("suspend raised", res.aborted)
        self.assertEqual(strata.reload_calls, 1)
        self.assertFalse(gate.closed)


class ProtectionPreflightTests(unittest.TestCase):
    def _run(self, gate, guard):
        strata = FakeStrata()
        box, suspend = suspend_counter()
        res = run_quiesce(
            IndexedPause(), strata, suspend, dry_run=False, gate=gate,
            pre_gate_verify=lambda: (True, "idle"),
            post_gate_verify=lambda: (True, "idle"),
            post_unload_verify=lambda: (True, "verified"),
            post_resume_verify=lambda: (True, "nvidia"),
            readiness_verify=lambda: (True, "ready"),
            guard=guard)
        return res, strata, gate, guard, box

    def test_gate_status_failure_refuses_before_unload(self):
        gate = FakeGate()
        gate.status = lambda: (_ for _ in ()).throw(OSError("socket gone"))
        res, strata, gate, guard, box = self._run(gate, FakeGuard())
        self.assertFalse(res.ok)
        self.assertIn("protective preflight failed", res.aborted)
        self.assertIn("socket gone", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(gate.close_calls, 0)
        self.assertEqual(box["calls"], 0)

    def test_unknown_gate_state_refuses_before_unload(self):
        gate = FakeGate()
        gate.status = lambda: {"ok": True, "state": "unknown"}
        res, strata, gate, guard, box = self._run(gate, FakeGuard())
        self.assertFalse(res.ok)
        self.assertIn("not verifiable", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(box["calls"], 0)

    def test_guard_status_failure_refuses_before_unload(self):
        guard = FakeGuard()
        guard.status = lambda: (_ for _ in ()).throw(OSError("guard socket gone"))
        res, strata, gate, guard, box = self._run(FakeGate(), guard)
        self.assertFalse(res.ok)
        self.assertIn("suspend guard status unreadable", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(gate.close_calls, 0)

    def test_unprotected_guard_refuses_before_unload(self):
        guard = FakeGuard()
        guard.protected = False
        res, strata, gate, guard, box = self._run(FakeGate(), guard)
        self.assertFalse(res.ok)
        self.assertIn("not protected", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(box["calls"], 0)

    def test_closed_gate_without_a_rule_is_repaired_or_refused(self):
        gate = FakeGate()
        gate.status = lambda: {"ok": True, "state": "closed", "rules": 0,
                               "sealed": True, "consistent": False}
        res, strata, gate, guard, box = self._run(gate, FakeGuard())
        # FakeGate.seal() repairs the logical state, but this stub keeps
        # reporting rules=0, so the preflight must still refuse.
        self.assertFalse(res.ok)
        self.assertIn("protective preflight failed", res.aborted)
        self.assertGreaterEqual(gate.seal_calls, 1)
        self.assertEqual(strata.unload_calls, 0)

    def test_inconsistent_closed_gate_is_resealed_before_unload(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True

        def status():
            # Before the repair, the helper claims sealed but reports no
            # blocking rule.  After gate.seal() it reports a consistent table.
            if gate.seal_calls == 0:
                return {"ok": True, "state": "closed", "rules": 0,
                        "sealed": True, "consistent": False}
            return {"ok": True, "state": "closed" if gate.closed else "open",
                    "rules": 1 if gate.closed else None,
                    "sealed": gate.sealed, "consistent": True}

        gate.status = status
        res, strata, gate, guard, box = self._run(gate, FakeGuard())
        self.assertTrue(res.ok, res.aborted)
        self.assertGreaterEqual(gate.seal_calls, 2)
        self.assertEqual(strata.unload_calls, 1)

    def test_older_helper_without_rule_verification_refuses_before_unload(self):
        gate = FakeGate()
        # An older helper reports only its logical lease state: no `rules`
        # and no `consistent`, so the monitor cannot prove the real table.
        gate.status = lambda: {"ok": True, "state": "open"}
        res, strata, gate, guard, box = self._run(gate, FakeGuard())
        self.assertFalse(res.ok)
        self.assertIn("refusing to arm", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertEqual(gate.close_calls, 0)
        self.assertEqual(box["calls"], 0)

    def test_closed_gate_without_a_verified_rule_count_refuses(self):
        gate = FakeGate()
        gate.status = lambda: {"ok": True, "state": "closed", "sealed": True,
                               "consistent": True}   # claims closed, no rules
        res, strata, gate, guard, box = self._run(gate, FakeGuard())
        self.assertFalse(res.ok)
        self.assertIn("protective preflight failed", res.aborted)
        self.assertEqual(strata.unload_calls, 0)


class ResumeFailureTests(FlowCase):
    def test_nvidia_failure_keeps_gate_closed_and_does_not_reload(self):
        strata = FakeStrata()
        gate = FakeGate()
        guard = FakeGuard()

        def bad_nvidia():
            return False, "nvidia-smi timeout"

        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1], dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=bad_nvidia,
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("NVIDIA verification failed", res.aborted)
        self.assertTrue(res.gate_closed)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(strata.reload_calls, 0)
        self.assertEqual(guard.acquire_calls, 1)

    def test_reload_failure_keeps_gate_closed(self):
        strata = FakeStrata(reload_ok=False)
        gate = FakeGate()
        guard = FakeGuard()

        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1], dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("reload failed", res.aborted)
        self.assertTrue(res.gate_closed)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(strata.reload_calls, 1)
        self.assertFalse(strata.loaded_flag)

    def test_readiness_failure_keeps_gate_closed(self):
        strata = FakeStrata(ready_ok=False)
        gate = FakeGate()
        guard = FakeGuard()

        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1], dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=late_ready(strata),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("not inference-ready", res.aborted)
        self.assertTrue(res.gate_closed)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(strata.reload_calls, 1)

    def test_gate_lease_renewal_failure_after_resume_keeps_gate_closed(self):
        strata = FakeStrata()
        # Initial close + pre-suspend renewal succeed; resume renewal fails.
        gate = FakeGate(fail_renew_after=2)
        guard = FakeGuard()

        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1], dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("gate lease could not be re-established", res.aborted)
        self.assertTrue(res.gate_lease_lost)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(strata.reload_calls, 0)

    def test_gate_open_failure_after_ready_is_reported(self):
        strata = FakeStrata()
        gate = FakeGate(fail_open=True)
        guard = FakeGuard()

        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1], dry_run=False,
                          gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("could not be reopened", res.aborted)
        self.assertTrue(res.gate_closed)
        self.assertTrue(res.ready)

    def test_resume_does_not_open_when_protection_is_not_verified(self):
        strata = FakeStrata()
        gate = FakeGate()
        guard = FakeGuard()
        original = gate.status

        def status():
            # The table looks protected until the resume re-seal, then it is
            # reported empty (protection lost while the machine was asleep).
            if gate.seal_calls >= 2 and gate.closed:
                return {"ok": True, "state": "closed", "sealed": True,
                        "rules": 0, "consistent": False,
                        "actual_state": "closed"}
            return original()

        gate.status = status
        res = run_quiesce(IndexedPause(), strata, suspend_counter()[1],
                          dry_run=False, gate=gate,
                          pre_gate_verify=lambda: (True, "idle"),
                          post_gate_verify=lambda: (True, "idle"),
                          post_unload_verify=lambda: (True, "verified"),
                          post_resume_verify=lambda: (True, "nvidia"),
                          readiness_verify=lambda: (True, "ready"),
                          guard=guard)
        self.assertFalse(res.ok)
        self.assertIn("protection not verified", res.aborted)
        self.assertTrue(gate.closed)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(strata.reload_calls, 1)


def late_ready(strata):
    def fn():
        return strata.ready()
    return fn


class PauseTests(FlowCase):
    def test_pause_after_gate_close_aborts_without_unload(self):
        # start, before-pre, before-close, after-close
        res, strata, gate, guard, box, phases, calls = self.run_flow(
            pause=IndexedPause(pause_at=4))
        self.assertFalse(res.ok)
        self.assertIn("after the network gate closed", res.aborted)
        self.assertEqual(gate.close_calls, 2)
        self.assertEqual(strata.unload_calls, 0)
        self.assertFalse(gate.closed)

    def test_pause_during_settle_aborts(self):
        # start, before-pre, before-close, after-close, during-settle
        res, strata, gate, guard, box, phases, calls = self.run_flow(
            pause=IndexedPause(pause_at=5), settle_s=0.3)
        self.assertFalse(res.ok)
        self.assertIn("gate settled", res.aborted)
        self.assertEqual(strata.unload_calls, 0)
        self.assertFalse(gate.closed)

    def test_pause_after_unload_reloads_and_reopens(self):
        # without settle: start, before-pre, before-close, after-close,
        # after-gate-verify, before-unload, after-unload
        res, strata, gate, guard, box, phases, calls = self.run_flow(
            pause=IndexedPause(pause_at=7))
        self.assertFalse(res.ok)
        self.assertIn("during Strata unloading", res.aborted)
        self.assertEqual(strata.unload_calls, 1)
        self.assertEqual(strata.reload_calls, 1)
        self.assertFalse(gate.closed)

    def test_pause_before_suspend_reloads_and_reopens(self):
        # ... after-unload, before-suspend
        res, strata, gate, guard, box, phases, calls = self.run_flow(
            pause=IndexedPause(pause_at=8))
        self.assertFalse(res.ok)
        self.assertIn("immediately before suspension", res.aborted)
        self.assertEqual(box["calls"], 0)
        self.assertEqual(strata.reload_calls, 1)
        self.assertFalse(gate.closed)

    def test_pause_after_guard_release_reacquires_and_reloads(self):
        # ... before-suspend, after-guard-release
        res, strata, gate, guard, box, phases, calls = self.run_flow(
            pause=IndexedPause(pause_at=9))
        self.assertFalse(res.ok)
        self.assertIn("after the sleep guard released", res.aborted)
        self.assertEqual(box["calls"], 0)
        self.assertEqual(guard.acquire_calls, 1)
        self.assertEqual(strata.reload_calls, 1)
        self.assertFalse(gate.closed)


class FakeFlowClock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, dt):
        self.now += float(dt)


class ResumeReacquisitionTests(FlowCase):
    def run_resume_flow(self, guard, *, timeout_s, interval_s=1.0):
        strata = FakeStrata()
        gate = FakeGate()
        box, suspend = suspend_counter()
        clock = FakeFlowClock()
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock.advance(seconds)

        res = run_quiesce(
            IndexedPause(), strata, suspend, dry_run=False, gate=gate,
            settle_s=0.0,
            pre_gate_verify=lambda: (True, "idle"),
            post_gate_verify=lambda: (True, "idle"),
            post_unload_verify=lambda: (True, "verified"),
            post_resume_verify=lambda: (True, "nvidia"),
            readiness_verify=lambda: (True, "ready"),
            guard=guard,
            guard_acquire_timeout_s=timeout_s,
            guard_retry_interval_s=interval_s,
            clock=clock, sleep=fake_sleep)
        return res, strata, gate, guard, box, sleeps

    def test_delayed_guard_reacquisition_recovers_successfully(self):
        """OperationInProgress after resume is transient; retry it."""
        guard = FakeGuard(acquire_results=[False, False, True])
        res, strata, gate, guard, box, sleeps = self.run_resume_flow(
            guard, timeout_s=10)
        self.assertTrue(res.ok, res.aborted)
        self.assertTrue(res.suspended)
        self.assertTrue(res.guard_reacquired)
        self.assertEqual(guard.acquire_calls, 3)
        self.assertEqual(sleeps, [1.0, 1.0])
        self.assertEqual(box["calls"], 1)          # exactly one suspend
        self.assertEqual(strata.reload_calls, 1)
        self.assertEqual(gate.open_calls, 1)
        self.assertFalse(gate.closed)

    def test_guard_is_reacquired_before_reload_and_gate_open(self):
        guard = FakeGuard(acquire_results=[False, True])
        res, strata, gate, guard, box, sleeps = self.run_resume_flow(
            guard, timeout_s=5)
        self.assertTrue(res.ok, res.aborted)
        phases = [p["phase"] for p in res.phases]
        self.assertLess(phases.index("guard-acquire"),
                        phases.index("nvidia-verify"))
        self.assertLess(phases.index("nvidia-verify"), phases.index("reload"))
        self.assertLess(phases.index("reload"), phases.index("readiness-verify"))
        self.assertLess(phases.index("readiness-verify"), phases.index("gate-open"))
        self.assertEqual(gate.open_calls, 1)

    def test_failed_guard_reacquisition_keeps_gate_sealed_and_no_second_suspend(self):
        guard = FakeGuard(acquire_ok=False)
        res, strata, gate, guard, box, sleeps = self.run_resume_flow(
            guard, timeout_s=2)
        self.assertFalse(res.ok)
        self.assertIn("could not reacquire the sleep guard", res.aborted)
        self.assertFalse(res.guard_reacquired)
        self.assertTrue(res.gate_closed)
        self.assertFalse(res.gate_reopened)
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(box["calls"], 1)          # never a second suspend
        self.assertEqual(strata.reload_calls, 1)  # model recovered anyway
        self.assertTrue(res.ready)
        self.assertGreaterEqual(guard.acquire_calls, 2)


class StartupGateRecoveryTests(unittest.TestCase):
    class Guard:
        enabled = True

        def __init__(self, protected):
            self.protected = protected
            self.calls = 0

        def status(self, timeout=None):
            self.calls += 1
            return {"ok": True, "protected": self.protected,
                    "state": "protected" if self.protected else "unprotected"}

    def test_open_gate_is_left_alone(self):
        gate = FakeGate()
        strata = FakeStrata()
        st = startup_gate_recovery(gate, strata)
        self.assertEqual(st["state"], "open")
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(strata.ready_calls, 0)

    def test_unknown_gate_state_is_left_unchanged(self):
        gate = FakeGate()
        gate.status = lambda: {"ok": True, "state": "unknown"}
        strata = FakeStrata(loaded=True, ready_ok=True)
        st = startup_gate_recovery(gate, strata)
        self.assertEqual(st["state"], "unknown")
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(strata.ready_calls, 0)

    def test_sealed_gate_stays_closed_when_guard_is_unprotected(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        strata = FakeStrata(loaded=True, ready_ok=True)
        guard = self.Guard(protected=False)
        st = startup_gate_recovery(gate, strata, guard=guard)
        self.assertEqual(st["state"], "closed")
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(guard.calls, 1)
        self.assertEqual(strata.ready_calls, 0)

    def test_sealed_gate_stays_closed_until_strata_ready(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        strata = FakeStrata(loaded=False, ready_ok=True)
        st = startup_gate_recovery(gate, strata)
        self.assertEqual(st["state"], "closed")
        self.assertEqual(gate.open_calls, 0)
        self.assertTrue(gate.sealed)

    def test_sealed_gate_stays_closed_when_model_is_not_ready(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        strata = FakeStrata(loaded=True, ready_ok=False)
        st = startup_gate_recovery(gate, strata)
        self.assertEqual(st["state"], "closed")
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(strata.ready_calls, 1)

    def test_sealed_gate_opens_only_after_loaded_and_ready(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        strata = FakeStrata(loaded=True, ready_ok=True)
        st = startup_gate_recovery(gate, strata)
        self.assertEqual(st["state"], "open")
        self.assertEqual(gate.open_calls, 1)
        self.assertEqual(strata.ready_calls, 1)

    def test_sealed_gate_without_rule_verification_stays_closed(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        # An older helper cannot prove the live nftables table.
        gate.status = lambda: {"ok": True, "state": "closed", "sealed": True}
        strata = FakeStrata(loaded=True, ready_ok=True)
        st = startup_gate_recovery(gate, strata)
        self.assertEqual(st["state"], "closed")
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(strata.ready_calls, 0)


class _DelayedStrata:
    """``loaded()`` is always true; ``ready()`` succeeds after N calls."""

    def __init__(self, ready_after=1, loaded=True):
        self.ready_after = ready_after
        self.loaded_flag = loaded
        self.loaded_calls = 0
        self.ready_calls = 0

    def loaded(self, timeout=None):
        self.loaded_calls += 1
        return self.loaded_flag

    def ready(self, timeout=None):
        self.ready_calls += 1
        ok = self.ready_calls >= self.ready_after
        return ok, "inference ready" if ok else "still loading"


class _SlowStrata:
    """Nested probes consume the timeout they are handed (and record it)."""

    def __init__(self, clock, load_cost, ready_cost, budgets):
        self.clock = clock
        self.load_cost = load_cost
        self.ready_cost = ready_cost
        self.budgets = budgets

    def loaded(self, timeout=None):
        self.budgets["loaded"].append(timeout)
        self.clock.advance(min(self.load_cost, timeout if timeout is not None
                               else self.load_cost))
        return True

    def ready(self, timeout=None):
        self.budgets["ready"].append(timeout)
        self.clock.advance(min(self.ready_cost, timeout if timeout is not None
                               else self.ready_cost))
        return True, "inference ready"


class _SlowGuard:
    enabled = True

    def __init__(self, clock, cost, budgets):
        self.clock = clock
        self.cost = cost
        self.budgets = budgets

    def status(self, timeout=None):
        self.budgets["guard"].append(timeout)
        self.clock.advance(min(self.cost, timeout if timeout is not None
                               else self.cost))
        return {"ok": True, "protected": True, "state": "protected"}


class StartupGateRecoveryRetryTests(unittest.TestCase):
    """Bounded startup retries keep the seal until protection + readiness."""

    def _clock_and_sleep(self):
        clock = FakeFlowClock()
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock.advance(seconds)

        return clock, fake_sleep, sleeps

    def closed_gate(self):
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        return gate

    def test_delayed_success_opens_once_strata_is_ready(self):
        gate = self.closed_gate()
        strata = _DelayedStrata(ready_after=3)
        clock, sleep, sleeps = self._clock_and_sleep()
        ok, st, msg = startup_gate_recovery_retry(
            gate, strata, timeout_s=10, interval_s=1,
            clock=clock, sleep=sleep)
        self.assertTrue(ok, msg)
        self.assertEqual(st["state"], "open")
        self.assertEqual(gate.open_calls, 1)
        self.assertEqual(strata.ready_calls, 3)
        self.assertEqual(sleeps, [1, 1])
        self.assertFalse(gate.sealed)
        self.assertFalse(gate.closed)

    def test_permanent_failure_stays_sealed_and_reports_failure(self):
        gate = self.closed_gate()
        strata = _DelayedStrata(ready_after=10 ** 6)
        clock, sleep, sleeps = self._clock_and_sleep()
        ok, st, msg = startup_gate_recovery_retry(
            gate, strata, timeout_s=3, interval_s=1,
            clock=clock, sleep=sleep)
        self.assertFalse(ok)
        self.assertIn("gate recovery failed after 3s", msg)
        self.assertEqual(st["state"], "closed")
        self.assertEqual(gate.open_calls, 0)
        self.assertTrue(gate.closed)
        self.assertTrue(gate.sealed)
        self.assertEqual(sleeps, [1, 1, 1])

    def test_open_gate_returns_immediately_without_sleeping(self):
        gate = FakeGate()          # already open
        strata = _DelayedStrata(ready_after=1)
        clock, sleep, sleeps = self._clock_and_sleep()
        ok, st, msg = startup_gate_recovery_retry(
            gate, strata, timeout_s=10, interval_s=1,
            clock=clock, sleep=sleep)
        self.assertTrue(ok)
        self.assertEqual(st["state"], "open")
        self.assertEqual(sleeps, [])
        self.assertEqual(gate.open_calls, 0)
        self.assertEqual(strata.ready_calls, 0)

    def test_transient_probe_error_is_retried_then_opens(self):
        gate = self.closed_gate()
        original = gate.status
        calls = {"n": 0}

        def flaky_status():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("helper socket hiccup")
            return original()

        gate.status = flaky_status
        strata = _DelayedStrata(ready_after=1)
        clock, sleep, sleeps = self._clock_and_sleep()
        ok, st, msg = startup_gate_recovery_retry(
            gate, strata, timeout_s=5, interval_s=1,
            clock=clock, sleep=sleep)
        self.assertTrue(ok, msg)
        self.assertEqual(gate.open_calls, 1)

    def test_remaining_budget_is_passed_into_nested_probes(self):
        """Guard/loaded/ready each get only the time left in the retry budget."""
        gate = self.closed_gate()
        clock, sleep, sleeps = self._clock_and_sleep()
        budgets = {"guard": [], "loaded": [], "ready": []}
        guard = _SlowGuard(clock, 2.0, budgets)
        strata = _SlowStrata(clock, 2.0, 1.0, budgets)
        ok, st, msg = startup_gate_recovery_retry(
            gate, strata, guard=guard, timeout_s=5, interval_s=1,
            clock=clock, sleep=sleep)
        self.assertTrue(ok, msg)
        self.assertEqual(budgets["guard"], [5.0])
        self.assertAlmostEqual(budgets["loaded"][0], 3.0, places=3)
        self.assertAlmostEqual(budgets["ready"][0], 1.0, places=3)
        self.assertAlmostEqual(clock(), 5.0, places=3)
        self.assertEqual(sleeps, [])
        self.assertEqual(gate.open_calls, 1)

    def test_zero_timeout_preserves_single_attempt_behaviour(self):
        gate = self.closed_gate()
        strata = _DelayedStrata(ready_after=2)
        clock, sleep, sleeps = self._clock_and_sleep()
        ok, st, msg = startup_gate_recovery_retry(
            gate, strata, timeout_s=0, interval_s=1,
            clock=clock, sleep=sleep)
        self.assertFalse(ok)
        self.assertEqual(sleeps, [])
        self.assertEqual(gate.open_calls, 0)
        self.assertTrue(gate.sealed)


class StrataPortDeadlineTests(unittest.TestCase):
    """The adapter must forward the remaining budget, not use fixed defaults."""

    def test_loaded_forwards_timeout(self):
        seen = {}

        def fake_get(path, auth=True, timeout=None, deadline=None, clock=None):
            seen.update(path=path, auth=auth, timeout=timeout,
                        deadline=deadline, clock=clock)
            return {"loaded": False}

        port = StrataPort({"enabled": True}, clock=lambda: 100.0)
        port.probe = types.SimpleNamespace(_processes=lambda: (True, False),
                                           get=fake_get)
        self.assertFalse(port.loaded(timeout=1.25))
        self.assertEqual(seen["timeout"], 1.25)
        self.assertEqual(seen["deadline"], 101.25)
        self.assertTrue(callable(seen["clock"]))
        self.assertFalse(seen["auth"])

    def test_ready_forwards_timeout_as_deadline(self):
        seen = []

        def fake_ready(cfg, deadline_s=None):
            seen.append(deadline_s)
            return True, "ready"

        port = StrataPort({})
        port._detectors = types.SimpleNamespace(strata_readiness=fake_ready)
        self.assertEqual(port.ready(timeout=1.25), (True, "ready"))
        self.assertEqual(seen, [1.25])

    def test_ready_without_timeout_keeps_config_default(self):
        seen = []

        def fake_ready(cfg, deadline_s=None):
            seen.append(deadline_s)
            return True, "ready"

        port = StrataPort({})
        port._detectors = types.SimpleNamespace(strata_readiness=fake_ready)
        port.ready()
        self.assertEqual(seen, [None])


class SharedStrataDeadlineTests(unittest.TestCase):
    """The real adapter must spend one budget across all fallback hosts."""

    def _port(self, now):
        port = StrataPort({"enabled": True}, clock=lambda: now[0])
        probe = detectors.StrataProbe({})
        probe.info = {"host": "192.0.2.1", "port": 8080,
                      "key": "test-key", "model": "test-model"}
        probe._processes = lambda: (True, False)
        port.probe = probe
        return port

    def _fake_http(self, now, calls):
        def fake(url, headers=None, timeout=3):
            host = url.split("//", 1)[1].split(":", 1)[0]
            calls.append((host, timeout))
            now[0] += min(2.0, float(timeout))
            raise OSError("unreachable")
        return fake

    def _patch_http(self, now, calls):
        original = detectors._http_json
        detectors._http_json = self._fake_http(now, calls)
        self.addCleanup(setattr, detectors, "_http_json", original)

    def test_loaded_uses_one_deadline_across_fallback_hosts(self):
        now = [0.0]
        calls = []
        self._patch_http(now, calls)
        with self.assertRaises(OSError):
            self._port(now).loaded(timeout=5)
        self.assertAlmostEqual(now[0], 5.0, places=6)
        self.assertEqual([c[0] for c in calls],
                         ["192.0.2.1", "127.0.0.1", "localhost"])
        self.assertAlmostEqual(calls[0][1], 5.0, places=6)
        self.assertAlmostEqual(calls[1][1], 3.0, places=6)
        self.assertAlmostEqual(calls[2][1], 1.0, places=6)

    def test_no_fallback_host_starts_after_deadline(self):
        now = [0.0]
        calls = []
        self._patch_http(now, calls)
        with self.assertRaises(OSError):
            self._port(now).loaded(timeout=3)
        self.assertAlmostEqual(now[0], 3.0, places=6)
        self.assertEqual([c[0] for c in calls], ["192.0.2.1", "127.0.0.1"])

    def test_exhausted_loaded_budget_does_not_start_readiness(self):
        now = [0.0]
        calls = []
        ready = []
        self._patch_http(now, calls)
        port = self._port(now)

        def fake_ready(cfg, deadline_s=None):
            ready.append(deadline_s)
            return True, "ready"

        port._detectors = types.SimpleNamespace(strata_readiness=fake_ready)
        gate = FakeGate()
        gate.closed = True
        gate.sealed = True
        ok, _st, msg = startup_gate_recovery_retry(
            gate, port, timeout_s=3, interval_s=1,
            clock=lambda: now[0],
            sleep=lambda s: now.__setitem__(0, now[0] + s))
        self.assertFalse(ok)
        self.assertEqual(ready, [])
        self.assertEqual(gate.open_calls, 0)
        self.assertTrue(gate.sealed)
        self.assertEqual(len(calls), 2)
        self.assertIn("gate recovery failed", msg)


class GateEvidenceTests(unittest.TestCase):
    """Armed checks need ``consistent=true`` and valid rule evidence."""

    def test_closed_gate_needs_consistent_true_and_rule_evidence(self):
        self.assertEqual(_gate_evidence_problem(
            {"state": "closed", "rules": 1, "consistent": True,
             "actual_state": "closed"}), "")
        self.assertIn("consistent", _gate_evidence_problem(
            {"state": "closed", "rules": 1, "consistent": None}))
        self.assertIn("consistent", _gate_evidence_problem(
            {"state": "closed", "rules": 1}))          # field absent
        self.assertIn("blocking rule", _gate_evidence_problem(
            {"state": "closed", "rules": 0, "consistent": True}))
        self.assertIn("blocking rule", _gate_evidence_problem(
            {"state": "closed", "rules": None, "consistent": True}))
        self.assertIn("blocking rule", _gate_evidence_problem(
            {"state": "closed", "rules": True, "consistent": True}))

    def test_open_gate_evidence(self):
        self.assertEqual(_gate_evidence_problem(
            {"state": "open", "consistent": True, "actual_state": "open"}), "")
        self.assertIn("sealed", _gate_evidence_problem(
            {"state": "open", "consistent": True, "sealed": True}))
        self.assertIn("live table", _gate_evidence_problem(
            {"state": "open", "consistent": True, "actual_state": "closed"}))

    def test_actual_state_mismatch_is_refused(self):
        self.assertIn("live table", _gate_evidence_problem(
            {"state": "closed", "rules": 1, "consistent": True,
             "actual_state": "open"}))

    def test_unknown_state_is_refused(self):
        self.assertIn("not verifiable", _gate_evidence_problem(
            {"state": "unknown", "consistent": True}))

    def test_verify_gate_protection_reports_unproven_protection(self):
        gate = FakeGate()
        gate.closed = True
        gate.status = lambda: {"ok": True, "state": "closed", "rules": 0,
                               "consistent": True}
        ok, msg = verify_gate_protection(gate)
        self.assertFalse(ok)
        self.assertIn("blocking rule", msg)


class WaitForResumeTests(unittest.TestCase):
    def test_detects_real_suspend_gap(self):
        clock = FakeFlowClock()
        gaps = [0.10, 5.20]
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock.advance(seconds)

        ok, detail = wait_for_resume(
            0.10, lambda: gaps.pop(0), timeout_s=5, interval_s=0.25,
            clock=clock, sleep=fake_sleep)
        self.assertTrue(ok)
        self.assertAlmostEqual(float(detail), 5.10)
        self.assertEqual(len(sleeps), 2)

    def test_times_out_without_a_suspend(self):
        clock = FakeFlowClock()
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock.advance(seconds)

        ok, detail = wait_for_resume(
            0.10, lambda: 0.10, timeout_s=1, interval_s=0.4,
            clock=clock, sleep=fake_sleep)
        self.assertFalse(ok)
        self.assertIn("no suspend/resume gap", detail)
        self.assertGreaterEqual(len(sleeps), 2)

    def test_missing_sleep_clock_is_an_error(self):
        ok, detail = wait_for_resume(None, lambda: 0.0)
        self.assertFalse(ok)
        self.assertIn("unavailable", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
