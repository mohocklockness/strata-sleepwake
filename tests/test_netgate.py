"""Tests for the inference-arrival gate: nft scope, leases, auth, races.

Everything here is local and unprivileged.  No test runs ``nft`` for real, no
test touches production port 8080, and the mock HTTP servers bind an ephemeral
loopback port.
"""
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netgate  # noqa: E402
import nftgate_helper as helper  # noqa: E402


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------

class FakeNft:
    """In-memory stand-in for NftRunner (records the exact ruleset)."""

    def __init__(self, fail_apply=False, fail_delete=False, list_override=None):
        self.fail_apply = fail_apply
        self.fail_delete = fail_delete
        self.list_override = list_override
        self.exists = False
        self.script = None
        self.apply_calls = 0
        self.delete_calls = 0

    def apply(self, script):
        self.apply_calls += 1
        if self.fail_apply:
            return False, "apply failed"
        self.script = script
        self.exists = True
        return True, "applied"

    def delete_table(self, table):
        self.delete_calls += 1
        if self.fail_delete:
            return False, False, "delete failed"
        existed = self.exists
        self.exists = False
        return True, existed, "deleted" if existed else "absent"

    def list_table(self, table):
        if self.list_override is not None:
            return self.list_override
        if not self.exists:
            return 1, "", "No such file or directory"
        out = (f"table inet {table} {{\n"
               "\tchain input {\n"
               "\t\ttype filter hook input priority filter - 10; policy accept;\n"
               "\t\ttcp dport { 8080 } tcp flags & (syn|ack) == syn iifname != \"lo\" counter packets 7 bytes 420 drop comment \"sleepmgr: inference gate\"\n"
               "\t}\n}\n")
        return 0, out, ""


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make_gate(**kw):
    return helper.NftGate(runner=FakeNft(), ports=(8080,), **kw)


# --------------------------------------------------------------------------
# 1. the ruleset is narrowly scoped
# --------------------------------------------------------------------------

class TestNftScope(unittest.TestCase):
    def test_script_only_touches_its_own_table(self):
        script = make_gate().build_script()
        self.assertIn(f"add table inet {helper.DEFAULT_TABLE}", script)
        self.assertIn(f"add chain inet {helper.DEFAULT_TABLE} input", script)
        self.assertIn("tcp dport { 8080 }", script)
        self.assertIn("tcp flags & (syn|ack) == syn", script)
        self.assertIn('iifname != "lo"', script)
        self.assertIn("counter drop", script)
        # It must never be able to flush or edit anything else.
        self.assertNotIn("flush", script)
        self.assertNotIn("ruleset", script)
        for forbidden in ("ip ", "ip6 ", "nat", "forward", "output"):
            self.assertNotIn(f"add chain inet {helper.DEFAULT_TABLE} {forbidden}", script)

    def test_rule_is_new_connections_only(self):
        script = make_gate().build_script()
        drop_lines = [l for l in script.splitlines() if "drop" in l]
        self.assertEqual(len(drop_lines), 1)
        self.assertIn("tcp flags & (syn|ack) == syn", drop_lines[0])
        # Stateless on purpose: no conntrack dependency, so established data
        # can never be misclassified as a new flow and dropped.
        self.assertNotIn("ct state", drop_lines[0])

    def test_rule_blocks_syn_but_not_syn_ack(self):
        """The mask must match an opening SYN (SYN set, ACK clear) only."""
        rule = [l for l in make_gate().build_script().splitlines() if "drop" in l][0]
        self.assertIn("& (syn|ack) == syn", rule)
        self.assertNotIn("== syn|ack", rule)

    def test_remote_traffic_is_gated_and_loopback_is_exempt(self):
        script = make_gate().build_script()
        self.assertIn('iifname != "lo"', script)
        # meta skuid is a no-op in the input hook (measured in a netns lab),
        # so it must never appear in this rule.
        self.assertNotIn("skuid", script)
        drop = [l for l in script.splitlines() if "drop" in l]
        self.assertEqual(len(drop), 1)
        self.assertIn('iifname != "lo"', drop[0])

    def test_loopback_can_be_gated_for_labs(self):
        gate = helper.NftGate(runner=FakeNft(), ports=(8080,),
                              exempt_loopback=False)
        self.assertNotIn('iifname != "lo"', gate.build_script())

    def test_reject_action_is_an_immediate_reset(self):
        gate = make_gate(action="reject")
        rule = [l for l in gate.build_script().splitlines() if "reject" in l][0]
        self.assertIn("counter reject with tcp reset", rule)
        self.assertNotIn("counter drop", rule)

    def test_unknown_action_is_refused(self):
        with self.assertRaises(helper.GateError):
            helper.NftGate(runner=FakeNft(), ports=(8080,), action="bounce")

    def test_cli_wires_reject_and_loopback_flags(self):
        args = helper.parse_args(["--action", "reject", "--no-loopback-exemption"])
        self.assertEqual(args.action, "reject")
        self.assertTrue(args.no_loopback_exemption)

    def test_custom_table_and_ports(self):
        gate = helper.NftGate(runner=FakeNft(), ports=(9000, 9001), table="my_gate")
        script = gate.build_script()
        self.assertIn("add table inet my_gate", script)
        self.assertIn("tcp dport { 9000, 9001 }", script)
        self.assertNotIn(helper.DEFAULT_TABLE, script)

    def test_empty_ports_refused(self):
        with self.assertRaises(helper.GateError):
            helper.NftGate(runner=FakeNft(), ports=())


# --------------------------------------------------------------------------
# 2. NftGate state transitions / failures
# --------------------------------------------------------------------------

class TestNftGate(unittest.TestCase):
    def test_close_applies_scoped_script(self):
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        ok, msg = gate.close()
        self.assertTrue(ok, msg)
        self.assertEqual(runner.apply_calls, 1)
        self.assertTrue(runner.exists)
        self.assertIn("tcp dport { 8080 }", runner.script)

    def test_close_is_idempotent(self):
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        self.assertTrue(gate.close()[0])
        self.assertTrue(gate.close()[0])
        # Each close resets then re-applies, so exactly one table remains.
        self.assertTrue(runner.exists)
        self.assertEqual(runner.apply_calls, 2)

    def test_open_removes_only_its_table(self):
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        gate.close()
        ok, msg = gate.open()
        self.assertTrue(ok, msg)
        self.assertFalse(runner.exists)
        self.assertIn("removed", msg)

    def test_open_when_already_open_is_ok(self):
        ok, msg = make_gate().open()
        self.assertTrue(ok)
        self.assertIn("already open", msg)

    def test_close_failure_is_reported(self):
        gate = helper.NftGate(runner=FakeNft(fail_apply=True), ports=(8080,))
        ok, msg = gate.close()
        self.assertFalse(ok)
        self.assertIn("cannot close gate", msg)

    def test_delete_failure_blocks_open(self):
        gate = helper.NftGate(runner=FakeNft(fail_delete=True), ports=(8080,))
        ok, msg = gate.open()
        self.assertFalse(ok)
        self.assertIn("cannot open gate", msg)

    def test_close_replaces_the_table_in_one_transaction(self):
        """A re-close folds delete+add into one batch (no unprotected gap)."""
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        self.assertTrue(gate.close()[0])
        # First close: no table existed, so it is a pure add via one apply and
        # no separate delete invocation.
        self.assertEqual(runner.apply_calls, 1)
        self.assertEqual(runner.delete_calls, 0)
        # Re-close on an existing table: still a single apply, with the delete
        # folded into the same batch.
        self.assertTrue(gate.close()[0])
        self.assertEqual(runner.apply_calls, 2)
        self.assertEqual(runner.delete_calls, 0)
        self.assertIn("delete table inet", runner.script)
        self.assertIn("add table inet", runner.script)

    def test_failed_replacement_preserves_existing_protection(self):
        """A failed atomic replace must leave the previous table in place."""
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        self.assertTrue(gate.close()[0])
        before = runner.script
        runner.fail_apply = True
        ok, msg = gate.close()
        self.assertFalse(ok)
        self.assertIn("cannot close gate", msg)
        self.assertTrue(runner.exists)
        self.assertEqual(runner.script, before)

    def test_uninspectable_table_is_not_assumed_absent(self):
        runner = FakeNft(list_override=(1, "", "Operation not permitted"))
        gate = helper.NftGate(runner=runner, ports=(8080,))
        ok, msg = gate.close()
        self.assertFalse(ok)
        self.assertIn("cannot inspect the gate table", msg)
        self.assertEqual(runner.apply_calls, 0)

    def test_status_closed_parses_counter(self):
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        gate.close()
        st = gate.status()
        self.assertEqual(st["state"], "closed")
        self.assertEqual(st["dropped"], 7)

    def test_status_open_when_table_absent(self):
        st = make_gate().status()
        self.assertEqual(st["state"], "open")

    def test_status_unknown_on_unexpected_error(self):
        runner = FakeNft(list_override=(1, "", "Operation not permitted"))
        st = helper.NftGate(runner=runner, ports=(8080,)).status()
        self.assertEqual(st["state"], "unknown")
        self.assertIn("Operation not permitted", st["error"])

    def test_cleanup_stale_removes_previous_table(self):
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        gate.close()
        ok, msg = gate.cleanup_stale()
        self.assertTrue(ok)
        self.assertIn("stale", msg)
        self.assertFalse(runner.exists)

    def test_cleanup_stale_reports_clean_start(self):
        ok, msg = make_gate().cleanup_stale()
        self.assertTrue(ok)
        self.assertIn("no stale", msg)


# --------------------------------------------------------------------------
# 3. leases: crash recovery, expiry, concurrency
# --------------------------------------------------------------------------

class TestGateServiceLease(unittest.TestCase):
    def setUp(self):
        self.runner = FakeNft()
        self.gate = helper.NftGate(runner=self.runner, ports=(8080,))
        self.clock = FakeClock()
        self.svc = helper.GateService(self.gate, lease_ttl_s=60, clock=self.clock)

    def test_close_leases_and_open_releases(self):
        owner = object()
        st = self.svc.close(owner)
        self.assertEqual(st["state"], "closed")
        self.assertEqual(st["seconds_left"], 60)
        self.assertTrue(self.runner.exists)
        st = self.svc.open()
        self.assertEqual(st["state"], "open")
        self.assertFalse(self.runner.exists)

    def test_owner_disconnect_reopens_gate(self):
        """Crash recovery: the monitor dies while the gate is closed."""
        owner = object()
        self.svc.close(owner)
        self.assertTrue(self.runner.exists)
        self.svc.on_client_gone(owner)
        self.assertEqual(self.svc.status()["state"], "open")
        self.assertFalse(self.runner.exists)
        self.assertEqual(self.svc.status()["reason"], "owner disconnected")

    def test_non_owner_disconnect_does_not_reopen(self):
        owner, other = object(), object()
        self.svc.close(owner)
        self.svc.on_client_gone(other)
        self.assertEqual(self.svc.status()["state"], "closed")
        self.assertTrue(self.runner.exists)

    def test_explicit_open_after_close_survives_owner_disconnect(self):
        owner = object()
        self.svc.close(owner)
        self.svc.open()
        self.svc.on_client_gone(owner)
        self.assertEqual(self.svc.status()["state"], "open")

    def test_sealed_gate_survives_owner_disconnect(self):
        """Controlled-suspend seal must not fail open when the monitor exits."""
        owner = object()
        st = self.svc.close(owner, seal=True)
        self.assertEqual(st["state"], "closed")
        self.assertTrue(st["sealed"])
        self.assertIsNone(st["seconds_left"])
        self.assertTrue(self.runner.exists)
        st = self.svc.on_client_gone(owner)
        self.assertEqual(st["state"], "closed")
        self.assertTrue(st["sealed"])
        self.assertTrue(self.runner.exists)
        self.assertIn("remains closed", st["reason"])

    def test_sealed_gate_does_not_expire(self):
        owner = object()
        self.svc.close(owner, seal=True)
        self.clock.advance(10_000)
        self.assertIsNone(self.svc.expire())
        self.assertEqual(self.svc.status()["state"], "closed")
        self.assertTrue(self.runner.exists)

    def test_explicit_open_clears_seal(self):
        owner = object()
        self.svc.close(owner, seal=True)
        st = self.svc.open(why="recovery complete")
        self.assertEqual(st["state"], "open")
        self.assertFalse(st["sealed"])
        self.assertFalse(self.runner.exists)

    def test_reclose_by_sealed_owner_keeps_seal(self):
        owner = object()
        self.svc.close(owner, seal=True)
        st = self.svc.close(owner, ttl_s=1)
        self.assertTrue(st["sealed"])
        self.assertIsNone(st["seconds_left"])

    def test_ordinary_close_cannot_downgrade_a_seal(self):
        owner, other = object(), object()
        self.svc.close(owner, seal=True)
        st = self.svc.close(other, ttl_s=1)
        self.assertEqual(st["state"], "closed")
        self.assertTrue(st["sealed"])
        self.assertIsNone(st["seconds_left"])

    def test_seal_marker_survives_helper_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker,
                                     boot_id="boot-a")
            svc.close(object(), seal=True)
            self.assertTrue(os.path.exists(marker))
            self.assertTrue(self.runner.exists)

            # New GateService == helper restart.  It must restore the seal
            # before any stale-table cleanup could open the gate.
            restarted = helper.GateService(self.gate, lease_ttl_s=60,
                                           clock=self.clock, state_file=marker,
                                           boot_id="boot-a")
            self.assertTrue(restarted.restore_sealed())
            st = restarted.status()
            self.assertEqual(st["state"], "closed")
            self.assertTrue(st["sealed"])
            self.assertTrue(self.runner.exists)

            restarted.open(why="recovered")
            self.assertFalse(os.path.exists(marker))
            self.assertFalse(self.runner.exists)

    def test_seal_marker_records_boot_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker,
                                     boot_id="boot-a")
            svc.close(object(), seal=True)
            with open(marker, encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["boot_id"], "boot-a")
            self.assertTrue(doc["sealed"])

    def test_marker_from_previous_boot_reseals_this_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker,
                                     boot_id="boot-a")
            svc.close(object(), seal=True)
            self.assertTrue(self.runner.exists)

            # /run and nftables runtime state are gone after a reboot.  The
            # marker survived, which means the previous boot ended inside a
            # seal: this boot must re-seal, not fail open.
            self.runner.exists = False
            restarted = helper.GateService(self.gate, lease_ttl_s=60,
                                           clock=self.clock, state_file=marker,
                                           boot_id="boot-b")
            self.assertTrue(restarted.restore_sealed())
            self.assertTrue(self.runner.exists)
            st = restarted.status()
            self.assertEqual(st["state"], "closed")
            self.assertTrue(st["sealed"])
            with open(marker, encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["boot_id"], "boot-b",
                             "the marker must be rewritten for this boot")
            self.assertEqual(restarted.startup_recover(), "restored")

    def test_previous_boot_marker_with_surviving_table_is_resealed(self):
        """Even if nft state somehow survived, a stale marker must fail closed."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker,
                                     boot_id="boot-a")
            svc.close(object(), seal=True)

            restarted = helper.GateService(self.gate, lease_ttl_s=60,
                                           clock=self.clock, state_file=marker,
                                           boot_id="boot-b")
            self.assertEqual(restarted.startup_recover(), "restored")
            self.assertTrue(self.runner.exists)
            self.assertTrue(restarted.status()["sealed"])
            self.assertTrue(os.path.exists(marker))

    def test_unmarked_closed_table_is_adopted_not_deleted(self):
        """A lost marker must never make startup delete the only blocking rule."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            # Simulate an ordinary close whose marker never existed, then a
            # helper restart.
            old = helper.GateService(self.gate, lease_ttl_s=60,
                                     state_file=marker, boot_id="boot-a")
            old.close(object())
            self.assertTrue(self.runner.exists)
            self.assertFalse(os.path.exists(marker))

            restarted = helper.GateService(self.gate, lease_ttl_s=60,
                                           state_file=marker, boot_id="boot-a")
            self.assertEqual(restarted.startup_recover(), "adopted")
            self.assertTrue(self.runner.exists)
            self.assertEqual(restarted.status()["state"], "closed")
            self.assertTrue(restarted.status()["sealed"])
            self.assertTrue(os.path.exists(marker))

    def test_open_gate_starts_open_without_a_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     state_file=marker, boot_id="boot-a")
            self.assertEqual(svc.startup_recover(), "open")
            self.assertFalse(self.runner.exists)
            self.assertFalse(os.path.exists(marker))

    def test_corrupt_or_unreadable_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            with open(marker, "w", encoding="utf-8") as f:
                f.write("{not json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     state_file=marker, boot_id="boot-a")
            self.assertTrue(svc.restore_sealed())
            self.assertTrue(self.runner.exists)
            self.assertTrue(svc.status()["sealed"])

    def test_restore_does_not_reset_an_already_closed_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker,
                                     boot_id="boot-a")
            svc.close(object(), seal=True)
            apply_calls = self.runner.apply_calls
            deletes = self.runner.delete_calls
            restarted = helper.GateService(self.gate, lease_ttl_s=60,
                                           clock=self.clock, state_file=marker,
                                           boot_id="boot-a")
            self.assertTrue(restarted.restore_sealed())
            self.assertEqual(self.runner.apply_calls, apply_calls)
            self.assertEqual(self.runner.delete_calls, deletes)

    def test_restore_recloses_table_deleted_while_marker_survived(self):
        """The old ExecStopPost failure mode must self-heal on helper restart."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker,
                                     boot_id="boot-a")
            svc.close(object(), seal=True)
            self.runner.exists = False       # ExecStopPost deleted the table
            restarted = helper.GateService(self.gate, lease_ttl_s=60,
                                           clock=self.clock, state_file=marker,
                                           boot_id="boot-a")
            self.assertTrue(restarted.restore_sealed())
            self.assertTrue(self.runner.exists)
            self.assertEqual(restarted.status()["state"], "closed")

    def test_startup_reapplies_closed_table_that_lost_its_rule(self):
        """A surviving table with zero rules is not protection."""
        class RepairingNft(FakeNft):
            def __init__(self):
                super().__init__()
                self.exists = True
                self.malformed = True

            def list_table(self, table):
                if self.malformed:
                    return 0, ("table inet " + table + " {\n"
                               "\tchain input {\n"
                               "\t\ttype filter hook input priority filter - 10; policy accept;\n"
                               "\t}\n}\n"), ""
                return super().list_table(table)

            def apply(self, script):
                self.malformed = False
                return super().apply(script)

        runner = RepairingNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(gate, lease_ttl_s=60,
                                     state_file=marker, boot_id="boot-a")
            self.assertEqual(svc.startup_recover(), "adopted")
            self.assertFalse(runner.malformed)
            self.assertGreaterEqual(runner.apply_calls, 1)
            st = svc.status()
            self.assertEqual(st["state"], "closed")
            self.assertEqual(st["rules"], 1)
            self.assertTrue(st["consistent"])

    def test_status_reports_logical_actual_inconsistency(self):
        runner = FakeNft(list_override=(
            0,
            "table inet sleepmgr_gate {\n\tchain input {\n"
            "\t\ttype filter hook input priority filter - 10; policy accept;\n"
            "\t}\n}\n",
            "",
        ))
        gate = helper.NftGate(runner=runner, ports=(8080,))
        svc = helper.GateService(gate, lease_ttl_s=60, clock=self.clock)
        svc.close(object())
        st = svc.status()
        self.assertEqual(st["state"], "closed")
        self.assertEqual(st["rules"], 0)
        self.assertFalse(st["consistent"])

    def test_unknown_gate_state_aborts_startup(self):
        runner = FakeNft(list_override=(1, "", "Operation not permitted"))
        gate = helper.NftGate(runner=runner, ports=(8080,))
        svc = helper.GateService(gate, lease_ttl_s=60, boot_id="boot-a")
        with self.assertRaises(helper.GateError):
            svc.startup_recover()

    def test_startup_removes_legacy_runtime_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            legacy = os.path.join(tmp, "legacy-sealed.json")
            with open(legacy, "w", encoding="utf-8") as f:
                f.write("{}\n")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     state_file=marker, boot_id="boot-a")
            with mock.patch.object(helper, "LEGACY_SEALED_STATE", legacy):
                self.assertEqual(svc.startup_recover(), "open")
            self.assertFalse(os.path.exists(legacy))

    def test_default_marker_is_not_in_a_runtime_directory(self):
        self.assertFalse(helper.DEFAULT_SEALED_STATE.startswith("/run/"))
        self.assertEqual(helper.DEFAULT_SEALED_STATE,
                         "/var/lib/sleepmgr-gate/sealed.json")

    def test_ordinary_lease_does_not_write_seal_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "sealed.json")
            svc = helper.GateService(self.gate, lease_ttl_s=60,
                                     clock=self.clock, state_file=marker)
            svc.close(object())
            self.assertFalse(os.path.exists(marker))
            self.assertFalse(svc.status()["sealed"])

    def test_lease_expiry_reopens_gate(self):
        owner = object()
        self.svc.close(owner, ttl_s=10)
        self.clock.advance(9)
        self.assertIsNone(self.svc.expire())
        self.assertEqual(self.svc.status()["state"], "closed")
        self.clock.advance(2)
        st = self.svc.expire()
        self.assertIsNotNone(st)
        self.assertEqual(st["state"], "open")
        self.assertEqual(st["reason"], "lease expired")
        self.assertFalse(self.runner.exists)

    def test_reclose_by_owner_renews_lease(self):
        owner = object()
        self.svc.close(owner, ttl_s=10)
        self.clock.advance(8)
        st = self.svc.close(owner, ttl_s=10)
        self.assertEqual(st["seconds_left"], 10)
        self.assertEqual(self.runner.apply_calls, 1)  # no redundant nft write

    def test_last_closer_owns_the_lease(self):
        a, b = object(), object()
        self.svc.close(a)
        self.svc.close(b)
        self.svc.on_client_gone(a)
        self.assertEqual(self.svc.status()["state"], "closed")
        self.svc.on_client_gone(b)
        self.assertEqual(self.svc.status()["state"], "open")

    def test_zero_ttl_refused(self):
        with self.assertRaises(helper.GateError):
            self.svc.close(object(), ttl_s=0)

    def test_gate_failure_leaves_state_open(self):
        gate = helper.NftGate(runner=FakeNft(fail_apply=True), ports=(8080,))
        svc = helper.GateService(gate, lease_ttl_s=60, clock=self.clock)
        with self.assertRaises(helper.GateError):
            svc.close(object())
        self.assertEqual(svc.status()["state"], "open")

    def test_concurrent_close_open_is_serialized(self):
        """Request races must never interleave nft writes or corrupt state."""
        class SerialNft(FakeNft):
            def __init__(self):
                super().__init__()
                self._busy = threading.Lock()
                self.overlaps = 0

            def _enter(self):
                if not self._busy.acquire(blocking=False):
                    self.overlaps += 1
                    self._busy.acquire()

            def apply(self, script):
                self._enter()
                try:
                    return super().apply(script)
                finally:
                    self._busy.release()

            def delete_table(self, table):
                self._enter()
                try:
                    return super().delete_table(table)
                finally:
                    self._busy.release()

        runner = SerialNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        svc = helper.GateService(gate, lease_ttl_s=60)
        errors = []

        def worker():
            try:
                for _ in range(50):
                    svc.close(object(), ttl_s=60)
                    svc.status()
                    svc.open()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(errors, [])
        self.assertEqual(runner.overlaps, 0, "nft operations overlapped")
        self.assertIn(svc.status()["state"], ("open", "closed"))


# --------------------------------------------------------------------------
# 4. socket server + authentication
# --------------------------------------------------------------------------

class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "gate.sock")
        self.runner = FakeNft()
        self.gate = helper.NftGate(runner=self.runner, ports=(8080,))
        self.svc = helper.GateService(self.gate, lease_ttl_s=30)
        self.clients = []
        self.servers = []

    def tearDown(self):
        for c in self.clients:
            try:
                c.close_connection()
            except Exception:  # noqa: BLE001
                pass
        for s in self.servers:
            s.stop()
        self.tmp.cleanup()

    def start_server(self, listen_fds=None, **kw):
        kw.setdefault("allow_uids", [os.getuid()])
        kw.setdefault("group", None)
        srv = helper.GateServer(self.path, self.svc, log=lambda _s: None, **kw)
        srv.start(listen_fds=listen_fds)
        self.servers.append(srv)
        return srv

    def client(self, **kw):
        kw.setdefault("timeout", 2.0)
        c = netgate.GateClient(self.path, **kw)
        self.clients.append(c)
        return c


class TestGateServerAuth(ServerTestCase):
    def test_roundtrip(self):
        self.start_server()
        c = self.client()
        self.assertTrue(c.ping()["ok"])
        self.assertEqual(c.close()["state"], "closed")
        self.assertEqual(c.status()["state"], "closed")
        self.assertEqual(c.open()["state"], "open")
        self.assertEqual(c.last_status()["state"], "open")

    def test_disallowed_uid_refused(self):
        self.start_server(allow_uids=[424242])
        c = self.client()
        with self.assertRaises(netgate.GateError) as cm:
            c.ping()
        self.assertIn("not allowed", str(cm.exception))
        self.assertEqual(self.svc.status()["state"], "open")

    def test_token_required(self):
        self.start_server(token="s3cret", require_token=True)
        with self.assertRaises(netgate.GateError) as cm:
            self.client().ping()
        self.assertIn("bad token", str(cm.exception))
        with self.assertRaises(netgate.GateError):
            self.client(token="wrong").ping()
        self.assertTrue(self.client(token="s3cret").ping()["ok"])

    def test_require_token_without_configured_token_fails_closed(self):
        self.start_server(require_token=True)
        with self.assertRaises(netgate.GateError):
            self.client(token="anything").ping()

    def test_unknown_command(self):
        self.start_server()
        reply = self.client()._request({"cmd": "explode"})
        self.assertFalse(reply["ok"])
        self.assertIn("unknown", reply["error"])

    def test_malformed_json(self):
        self.start_server()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(self.path)
        s.sendall(b"{not json\n")
        data = b""
        while b"\n" not in data:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        s.close()
        self.assertFalse(json.loads(data.split(b"\n")[0])["ok"])

    def test_empty_command(self):
        self.start_server()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(self.path)
        s.sendall(b"\n")
        data = s.recv(1024)
        s.close()
        self.assertFalse(json.loads(data.split(b"\n")[0])["ok"])

    def test_second_helper_on_same_socket_refuses(self):
        self.start_server()
        with self.assertRaises(helper.GateError):
            helper.GateServer(self.path, self.svc, [os.getuid()], group=None,
                              log=lambda _s: None).start()

    def test_socket_removed_on_stop(self):
        srv = self.start_server()
        self.assertTrue(os.path.exists(self.path))
        srv.stop()
        self.assertFalse(os.path.exists(self.path))

    def test_listen_fds_env_requires_matching_pid(self):
        with mock.patch.dict(os.environ,
                             {"LISTEN_FDS": "1",
                              "LISTEN_PID": str(os.getpid())},
                             clear=False):
            self.assertEqual(helper.GateServer._listen_fds_from_env(), [3])
        with mock.patch.dict(os.environ,
                             {"LISTEN_FDS": "1", "LISTEN_PID": "1"},
                             clear=False):
            self.assertEqual(helper.GateServer._listen_fds_from_env(), [])

    def test_socket_activation_inherits_listener_and_does_not_unlink_it(self):
        """systemd owns the socket; the helper must not chown, chmod, or unlink.

        This is the permanent fix for the live failure where the hardened
        service (CAP_NET_ADMIN only) could not chown its socket to
        root:sleepuser.  The .socket unit creates it with that ownership.
        """
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(8)
        listener.settimeout(2)
        dup = os.dup(listener.fileno())
        messages = []
        srv = helper.GateServer(
            self.path, self.svc, [os.getuid()], group="no-such-group",
            log=messages.append)
        srv.start(listen_fds=[dup])
        self.servers.append(srv)
        self.assertTrue(any("inherited from systemd" in m for m in messages))
        self.assertTrue(os.path.exists(self.path))

        c = self.client()
        self.assertTrue(c.ping()["ok"])
        self.assertEqual(c.status()["state"], "open")

        srv.stop()
        # The service closes its duplicate, not systemd's listener or path.
        self.assertTrue(os.path.exists(self.path))
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(2)
        probe.connect(self.path)
        conn, _ = listener.accept()
        conn.close()
        probe.close()
        listener.close()


class TestClientServerRecovery(ServerTestCase):
    def test_crash_recovery_after_disconnect(self):
        """The monitor is SIGKILLed mid-quiesce: EOF must reopen the gate."""
        self.start_server()
        c = self.client()
        self.assertEqual(c.close()["state"], "closed")
        self.assertTrue(self.runner.exists)
        c.close_connection()  # simulates the monitor process dying
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and self.svc.status()["state"] != "open":
            time.sleep(0.02)
        self.assertEqual(self.svc.status()["state"], "open")
        self.assertFalse(self.runner.exists)

    def test_sealed_gate_stays_closed_after_disconnect(self):
        self.start_server()
        c = self.client()
        self.assertEqual(c.seal()["state"], "closed")
        self.assertTrue(self.runner.exists)
        c.close_connection()
        time.sleep(0.2)
        st = self.svc.status()
        self.assertEqual(st["state"], "closed")
        self.assertTrue(st["sealed"])
        self.assertTrue(self.runner.exists)
        # Only an explicit authenticated open recovers it.
        self.assertEqual(self.client().open()["state"], "open")
        self.assertFalse(self.runner.exists)

    def test_abort_reopens_without_disconnect(self):
        self.start_server()
        c = self.client()
        c.close()
        c.open()
        self.assertEqual(self.svc.status()["state"], "open")
        self.assertFalse(self.runner.exists)
        self.assertTrue(c.ping()["ok"])  # connection survived the whole sequence

    def test_lease_expiry_through_server(self):
        self.svc.lease_ttl_s = 0.2
        self.start_server()
        c = self.client(ttl_s=0.2)
        c.close()
        time.sleep(0.5)
        self.svc.expire()
        self.assertEqual(self.svc.status()["state"], "open")
        self.assertFalse(self.runner.exists)


class TestClientFailures(unittest.TestCase):
    def test_no_helper_gives_a_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            c = netgate.GateClient(os.path.join(d, "missing.sock"), timeout=0.5)
            with self.assertRaises(netgate.GateError) as cm:
                c.close()
            self.assertIn("cannot reach the gate helper", str(cm.exception))

    def test_build_gate_disabled_by_default(self):
        self.assertIsInstance(netgate.build_gate({}), netgate.NullGate)
        self.assertIsInstance(netgate.build_gate({"enabled": False}), netgate.NullGate)

    def test_build_gate_reads_token_and_ttl(self):
        with tempfile.TemporaryDirectory() as d:
            tok = os.path.join(d, "token")
            with open(tok, "w") as f:
                f.write("abc\n")
            g = netgate.build_gate({"enabled": True, "socket": "/tmp/x.sock",
                                    "token_file": tok, "lease_ttl_s": 42})
            self.assertIsInstance(g, netgate.GateClient)
            self.assertEqual(g.token, "abc")
            self.assertEqual(g.ttl_s, 42)


# --------------------------------------------------------------------------
# 5. HTTP-level race investigation (mock servers on ephemeral loopback ports)
# --------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _reply(self, obj, close):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/status":
            self._reply({"busy": self.server.busy, "queued": self.server.queued},
                        close=self.server.mode == "http10")
        else:
            self._reply({"loaded": True}, close=self.server.mode == "http10")

    def log_message(self, *_a):
        pass


class _GatedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, mode):
        self.mode = mode
        self.busy = False
        self.queued = 0
        self.gate_closed = threading.Event()
        super().__init__(("127.0.0.1", 0), _Handler)
        if mode == "http11":
            _Handler.protocol_version = "HTTP/1.1"
        else:
            _Handler.protocol_version = "HTTP/1.0"
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def verify_request(self, request, client_address):
        # Model "the nft rule drops new connections": established sockets keep
        # working, brand-new ones are refused.
        return not self.gate_closed.is_set()

    def stop(self):
        self.shutdown()
        self.server_close()


def _read_http_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1024)
        if not chunk:
            return b"", data
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    body = rest
    while len(body) < length:
        chunk = sock.recv(1024)
        if not chunk:
            break
        body += chunk
    return head, body[:length]


def _send(sock, path):
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n".encode())
    return _read_http_response(sock)


class TestHttpArrivalRace(unittest.TestCase):
    """Empirical investigation of what the firewall rule can and cannot stop."""

    def setUp(self):
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.stop()

    def _server(self, mode):
        s = _GatedServer(mode)
        self.servers.append(s)
        return s

    def test_strata_style_http10_connection_is_not_reusable(self):
        """Strata today: HTTP/1.0 + Connection: close, one request per socket."""
        srv = self._server("http10")
        s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=3)
        head, body = _send(s, "/health")
        self.assertIn(b"HTTP/1.0 200", head)
        self.assertIn(b"Connection: close", head)
        # The server closed it, so a late request has no channel to ride.
        srv.gate_closed.set()
        try:
            head2, body2 = _send(s, "/status")
            reused = b"HTTP/1." in head2
        except OSError:
            reused = False
        self.assertFalse(reused, "an HTTP/1.0 connection must not be reusable")
        s.close()

    def test_gate_blocks_brand_new_connections(self):
        srv = self._server("http10")
        srv.gate_closed.set()
        s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=3)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(2)
        try:
            data = s.recv(64)
        except OSError:
            data = b""
        self.assertEqual(data, b"", "a gated new connection must receive no response")
        s.close()

    def test_keepalive_connection_can_still_submit_after_gate_close(self):
        """Documented limitation: nft cannot revoke an established HTTP/1.1 socket.

        If Strata (or a proxy in front of it) ever enables keep-alive or HTTP/2,
        a client that already holds a connection can submit a *new* request
        after the gate closes.  This test asserts that race exists; it is the
        reason close() is always followed by settle + /status re-check and the
        reason an HTTP-aware gateway is the correct long-term fix.
        """
        srv = self._server("http11")
        s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=3)
        head, _ = _send(s, "/health")
        self.assertIn(b"HTTP/1.1 200", head)
        srv.gate_closed.set()          # the firewall rule lands...
        head2, body2 = _send(s, "/status")  # ...yet the held socket still works
        self.assertIn(b"HTTP/1.1 200", head2)
        self.assertIn(b'"busy"', body2)
        s.close()

    def test_new_request_after_gate_on_a_fresh_connection_is_blocked(self):
        srv = self._server("http11")
        srv.gate_closed.set()
        s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=3)
        s.sendall(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(2)
        try:
            data = s.recv(64)
        except OSError:
            data = b""
        self.assertEqual(data, b"")
        s.close()


class TestGateRuleVerification(unittest.TestCase):
    """Semantic verification of a live listing (ports/verdict/SYN/hook/order).

    This is the shared checker: ``NftGate.status`` and the boot script
    (``--verify-listing``) both call it, so these cases define what "the gate is
    really protecting us" means.
    """

    TABLE = helper.DEFAULT_TABLE

    def listing(self, *rules,
                spec="type filter hook input priority filter - 10; policy accept;"):
        body = [f"table inet {self.TABLE} {{", "chain input {"]
        if spec:
            body.append(spec)
        body.extend(rules)
        body.append("}")
        body.append("}")
        return "\n".join(body) + "\n"

    def verify(self, text, ports=(8080,), action="drop", exempt_loopback=True):
        return helper.verify_gate_ruleset(
            text, ports=ports, action=action,
            exempt_loopback=exempt_loopback, table=self.TABLE)

    def rule(self, dports="8080", verdict="drop", syn=True, lo=True,
             comment=True):
        parts = [f"tcp dport {{ {dports} }}"]
        if syn:
            parts.append("tcp flags & (syn|ack) == syn")
        if lo:
            parts.append('iifname != "lo"')
        parts.append("counter")
        parts.append(verdict)
        if comment:
            parts.append(f'comment "{helper.EXEMPT_RULE_COMMENT}"')
        return " ".join(parts)

    def test_correct_rule_verifies(self):
        ok, problem = self.verify(self.listing(self.rule()))
        self.assertTrue(ok, problem)

    def test_configured_ports_are_required(self):
        ok, problem = self.verify(self.listing(self.rule(dports="9999")))
        self.assertFalse(ok)
        self.assertIn("does not cover exactly", problem)

    def test_accept_rule_is_refused(self):
        ok, _problem = self.verify(self.listing(self.rule(verdict="accept")))
        self.assertFalse(ok)

    def test_reject_verdict_is_refused_when_drop_configured(self):
        ok, problem = self.verify(self.listing(self.rule(verdict="reject")))
        self.assertFalse(ok)
        self.assertIn("verdict", problem)

    def test_broad_match_is_refused(self):
        ok, problem = self.verify(self.listing(self.rule(syn=False)))
        self.assertFalse(ok)
        self.assertIn("opening SYN", problem)

    def test_missing_loopback_exemption_is_refused(self):
        ok, problem = self.verify(self.listing(self.rule(lo=False)))
        self.assertFalse(ok)
        self.assertIn("loopback", problem)

    def test_unhooked_chain_is_refused(self):
        text = ("table inet sleepmgr_gate {\n"
                "chain input {\n" + self.rule() + "\n}\n}\n")
        ok, problem = self.verify(text)
        self.assertFalse(ok)
        self.assertIn("input base chain", problem)

    def test_late_priority_chain_is_refused(self):
        ok, problem = self.verify(self.listing(
            self.rule(),
            spec="type filter hook input priority filter + 10; policy accept;"))
        self.assertFalse(ok)
        self.assertIn("priority", problem)

    def test_unconditional_earlier_accept_is_refused(self):
        ok, problem = self.verify(self.listing("accept", self.rule()))
        self.assertFalse(ok)
        self.assertIn("before the gate rule", problem)

    def test_earlier_accept_of_the_same_port_is_refused(self):
        ok, _problem = self.verify(self.listing(
            "tcp dport { 8080 } accept", self.rule()))
        self.assertFalse(ok)

    def test_unrelated_earlier_accept_is_allowed(self):
        ok, problem = self.verify(self.listing(
            "tcp dport { 22 } accept", self.rule()))
        self.assertTrue(ok, problem)

    def test_earlier_accept_in_another_input_chain_does_not_bypass(self):
        """nft evaluates every base chain; an earlier accept is not global.

        Only a drop/queue is terminal across base chains, so a later blocking
        chain still blocks the same traffic.  Rejecting this layout would be a
        false alarm (and the opposite claim is wrong).
        """
        text = ("table inet sleepmgr_gate {\n"
                "chain early {\n"
                "type filter hook input priority filter - 20; policy accept;\n"
                "tcp dport { 8080 } accept\n"
                "}\n"
                "chain input {\n"
                "type filter hook input priority filter - 10; policy accept;\n"
                + self.rule() + "\n}\n}\n")
        ok, problem = self.verify(text)
        self.assertTrue(ok, problem)

    def test_real_nft_drop_listing_verifies(self):
        """The canonical `tcp flags syn / syn,ack` form from a real kernel."""
        text = ("table inet sleepmgr_gate {\n"
                "\tchain input {\n"
                "\t\ttype filter hook input priority filter - 10; policy accept;\n"
                "\t\ttcp dport 8080 tcp flags syn / syn,ack "
                "iifname != \"lo\" counter packets 0 bytes 0 drop "
                "comment \"sleepmgr: inference gate\"\n"
                "\t}\n"
                "}\n")
        ok, problem = self.verify(text)
        self.assertTrue(ok, problem)

    def test_real_nft_reject_listing_verifies(self):
        text = ("table inet sleepmgr_gate {\n"
                "\tchain input {\n"
                "\t\ttype filter hook input priority filter - 10; policy accept;\n"
                "\t\ttcp dport { 8080 } tcp flags syn / syn,ack "
                "iifname != \"lo\" counter packets 3 bytes 180 "
                "reject with tcp reset comment \"sleepmgr: inference gate\"\n"
                "\t}\n"
                "}\n")
        ok, problem = self.verify(text, action="reject")
        self.assertTrue(ok, problem)

    def test_spaced_flag_expression_verifies(self):
        text = self.listing(self.rule(syn=False).replace(
            "counter", "tcp flags & (syn | ack) == syn counter"))
        ok, problem = self.verify(text)
        self.assertTrue(ok, problem)

    def test_extra_source_match_is_refused(self):
        """A source restriction would gate only some remote clients."""
        strict = self.rule(syn=False).replace(
            "counter", "ip saddr 10.0.0.0/8 "
                       "tcp flags syn / syn,ack counter")
        ok, problem = self.verify(self.listing(strict))
        self.assertFalse(ok)
        self.assertIn("unexpected", problem)

    def test_extra_source_port_match_is_refused(self):
        strict = self.rule(syn=False).replace(
            "counter", "tcp sport 12345 tcp flags syn / syn,ack counter")
        ok, problem = self.verify(self.listing(strict))
        self.assertFalse(ok)
        self.assertIn("unexpected", problem)

    def test_duplicate_dport_clause_is_refused(self):
        dup = self.rule(syn=False).replace(
            "counter", "tcp dport 8080 tcp flags syn / syn,ack counter")
        ok, problem = self.verify(self.listing(dup))
        self.assertFalse(ok)
        self.assertIn("repeats", problem)

    def test_absent_table_is_refused(self):
        ok, problem = self.verify("")
        self.assertFalse(ok)
        self.assertIn("absent", problem)

    def test_status_exposes_verification(self):
        runner = FakeNft()
        gate = helper.NftGate(runner=runner, ports=(8080,))
        gate.close()
        st = gate.status()
        self.assertTrue(st["verified"])
        self.assertEqual(st["rules"], 1)
        self.assertIsNone(st["problem"])

    def test_status_reports_a_wrong_rule_as_unverified(self):
        wrong = ("table inet sleepmgr_gate {\n"
                 " chain input {\n"
                 "type filter hook input priority filter - 10; policy accept;\n"
                 'tcp dport { 9999 } tcp flags & (syn|ack) == syn '
                 'iifname != "lo" counter drop\n}\n}\n')
        runner = FakeNft(list_override=(0, wrong, ""))
        st = helper.NftGate(runner=runner, ports=(8080,)).status()
        self.assertEqual(st["state"], "closed")
        self.assertFalse(st["verified"])
        self.assertIsNotNone(st["problem"])


class GateClientPassthroughTests(unittest.TestCase):
    """The client must not drop the helper's live-verification fields.

    ``netgate.GateClient._remember`` used to keep only the logical lease keys,
    which silently hid ``rules``/``consistent`` from the monitor's preflight.
    """

    def _client(self):
        return netgate.GateClient(path="/nonexistent/does/not/connect",
                                  token="t")

    def test_closed_status_keeps_rules_and_consistency(self):
        client = self._client()
        reply = client._remember({"ok": True, "state": "closed", "sealed": True,
                                  "rules": 1, "consistent": True,
                                  "actual_state": "closed"})
        self.assertEqual(reply["rules"], 1)
        self.assertIs(reply["consistent"], True)
        self.assertEqual(reply["actual_state"], "closed")
        self.assertEqual(client.last_status()["rules"], 1)
        self.assertIs(client.last_status()["consistent"], True)

    def test_inconsistent_status_is_preserved(self):
        client = self._client()
        client._remember({"ok": True, "state": "closed", "rules": 0,
                          "consistent": False})
        self.assertEqual(client.last_status()["rules"], 0)
        self.assertIs(client.last_status()["consistent"], False)

    def test_verification_problem_is_preserved(self):
        client = self._client()
        client._remember({"ok": True, "state": "closed", "sealed": True,
                          "rules": 0, "verified": False,
                          "problem": "no rule blocks the configured ports",
                          "consistent": False, "actual_state": "closed"})
        last = client.last_status()
        self.assertIs(last["verified"], False)
        self.assertIn("no rule blocks", last["problem"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
