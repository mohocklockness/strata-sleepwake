"""Unit tests for the fail-closed Strata/NVIDIA sleep guard (no system access)."""
import copy
import json
import os
import queue
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from suspendguard import (Authorizer, Guard, GuardClient, GuardControlServer,  # noqa: E402
                          evaluate_safety, parse_compute_csv, parse_gpu_csv,
                          parse_meminfo)


class Clock:
    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class FakeInhibitor:
    def __init__(self, fail_starts=0):
        self.fail_starts = int(fail_starts)
        self.starts = 0
        self.stops = 0
        self._alive = False

    def start(self):
        self.starts += 1
        if self.fail_starts > 0:
            self.fail_starts -= 1
            return False
        self._alive = True
        return True

    def stop(self):
        self.stops += 1
        self._alive = False
        return True

    def kill(self):
        """Simulate the inhibitor child dying unexpectedly."""
        self._alive = False

    def alive(self):
        return self._alive

    def status(self):
        return {"enabled": True, "held": self._alive,
                "pid": 123 if self._alive else None}


def safe_snapshot():
    return {
        "at": 100.0,
        "strata": {
            "configured": True, "server_running": True, "health_ok": True,
            "loaded": False, "status_ok": True, "busy": False, "queued": 0,
        },
        "gpu": {
            "ok": True,
            "compute_apps": [],
            "gpus": [
                {"index": 0, "utilization_pct": 0, "memory_used_mib": 10},
                {"index": 1, "utilization_pct": 0, "memory_used_mib": 10},
            ],
        },
        "ram": {"ok": True, "available_mib": 24000},
        "gate": {"enabled": True, "ok": True, "state": "closed",
                 "detail": {"ok": True, "state": "closed", "sealed": True,
                            "rules": 1, "verified": True, "consistent": True,
                            "actual_state": "closed"}},
    }


def cfg(**kw):
    out = {
        "release_ttl_s": 5.0,
        "max_release_ttl_s": 30.0,
        "poll_s": 1.0,
        "command_timeout_s": 0.5,
        "require_gate": True,
        "require_token": True,
        "allow_uids": [1000],
        "status_file": "",
    }
    out.update(kw)
    return out


class EvaluatorTestCase(unittest.TestCase):
    def assertUnsafe(self, snap, needle=None):
        result = evaluate_safety(snap, cfg())
        self.assertFalse(result["safe"])
        self.assertTrue(result["reasons"])
        if needle:
            self.assertIn(needle, " ".join(result["reasons"]))
        return result

    def test_safe_snapshot(self):
        result = evaluate_safety(safe_snapshot(), cfg())
        self.assertTrue(result["safe"], result["reasons"])
        self.assertTrue(all(c["ok"] for c in result["checks"]))
        self.assertEqual({c["name"] for c in result["checks"]},
                         {"strata", "gpu-compute", "gpu-memory", "gpu-util",
                          "ram", "gate"})

    def test_loaded_strata_is_unsafe(self):
        snap = safe_snapshot()
        snap["strata"]["loaded"] = True
        self.assertUnsafe(snap, "model is loaded")

    def test_strata_health_unknown_is_unsafe(self):
        snap = safe_snapshot()
        snap["strata"].update({"health_ok": False, "loaded": None,
                               "health_error": "timeout"})
        self.assertUnsafe(snap, "health unreadable")

    def test_strata_status_unknown_is_unsafe(self):
        snap = safe_snapshot()
        snap["strata"].update({"status_ok": False, "busy": None, "queued": None,
                               "status_error": "permission denied"})
        self.assertUnsafe(snap, "/status unreadable")

    def test_strata_busy_or_queued_is_unsafe(self):
        snap = safe_snapshot()
        snap["strata"]["busy"] = True
        self.assertUnsafe(snap, "inference active")
        snap = safe_snapshot()
        snap["strata"]["queued"] = 2
        self.assertUnsafe(snap, "inference active")

    def test_strata_process_state_unknown_is_unsafe(self):
        snap = safe_snapshot()
        snap["strata"]["server_running"] = None
        self.assertUnsafe(snap, "process state unreadable")

    def test_strata_not_running_is_safe_when_other_checks_pass(self):
        snap = safe_snapshot()
        snap["strata"] = {"configured": True, "server_running": False,
                          "health_ok": True, "loaded": False,
                          "status_ok": True, "busy": False, "queued": 0}
        self.assertTrue(evaluate_safety(snap, cfg())["safe"])

    def test_compute_client_is_unsafe(self):
        snap = safe_snapshot()
        snap["gpu"]["compute_apps"] = [{"pid": "99", "process_name": "python3"}]
        self.assertUnsafe(snap, "CUDA compute client")

    def test_high_vram_is_unsafe(self):
        snap = safe_snapshot()
        snap["gpu"]["gpus"][0]["memory_used_mib"] = 15000
        self.assertUnsafe(snap, "peak VRAM")

    def test_high_util_is_unsafe(self):
        snap = safe_snapshot()
        snap["gpu"]["gpus"][1]["utilization_pct"] = 80
        self.assertUnsafe(snap, "peak GPU util")

    def test_gpu_unreadable_is_unsafe(self):
        snap = safe_snapshot()
        snap["gpu"] = {"ok": False, "error": "nvidia-smi timeout"}
        self.assertUnsafe(snap, "nvidia-smi unreadable")

    def test_low_ram_is_unsafe(self):
        snap = safe_snapshot()
        snap["ram"] = {"ok": True, "available_mib": 900}
        self.assertUnsafe(snap, "MemAvailable")

    def test_ram_unreadable_is_unsafe(self):
        snap = safe_snapshot()
        snap["ram"] = {"ok": False, "error": "permission denied"}
        self.assertUnsafe(snap, "MemAvailable unreadable")

    def test_gate_disabled_is_unsafe_by_default(self):
        snap = safe_snapshot()
        snap["gate"] = {"enabled": False, "ok": True, "state": "disabled"}
        self.assertUnsafe(snap, "gate is disabled")

    def test_gate_open_or_unknown_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["state"] = "open"
        self.assertUnsafe(snap, "not 'closed'")
        snap = safe_snapshot()
        snap["gate"] = {"enabled": True, "ok": False, "state": "unknown",
                        "error": "socket missing"}
        self.assertUnsafe(snap, "status unreadable")

    def test_gate_closed_without_live_evidence_is_unsafe(self):
        """`state="closed"` alone is a claim, not proof of the nftables rule."""
        snap = safe_snapshot()
        snap["gate"] = {"enabled": True, "ok": True, "state": "closed"}
        self.assertUnsafe(snap, "protection is unproven")

    def test_gate_closed_with_unverified_rule_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["detail"]["verified"] = False
        self.assertUnsafe(snap, "not verified")

    def test_gate_closed_with_inconsistent_state_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["detail"]["consistent"] = False
        self.assertUnsafe(snap, "inconsistent")

    def test_gate_closed_with_wrong_actual_state_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["detail"]["actual_state"] = "open"
        self.assertUnsafe(snap, "actual")

    def test_gate_closed_without_blocking_rules_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["detail"]["rules"] = 0
        self.assertUnsafe(snap, "blocking rule")

    def test_gate_closed_but_unsealed_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["detail"]["sealed"] = False
        self.assertUnsafe(snap, "not sealed")

    def test_gate_closed_with_non_numeric_rule_count_is_unsafe(self):
        snap = safe_snapshot()
        snap["gate"]["detail"]["rules"] = "one"
        self.assertUnsafe(snap, "blocking rule")

    def test_explicit_ungated_release_opt_in(self):
        snap = safe_snapshot()
        snap["gate"] = {"enabled": False, "ok": True, "state": "disabled"}
        result = evaluate_safety(snap, cfg(require_gate=False))
        self.assertTrue(result["safe"], result["reasons"])

    def test_parsers(self):
        self.assertEqual(
            parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 2048 kB\n"),
            2.0)
        self.assertIsNone(parse_meminfo("MemTotal: 1000 kB\n"))
        gpus = parse_gpu_csv("0, 0, 12\n1, 3, 44\n")
        self.assertEqual([g["index"] for g in gpus], [0, 1])
        self.assertEqual(gpus[1]["memory_used_mib"], 44.0)
        self.assertEqual(
            parse_compute_csv("No running processes found\n"),
            [])
        self.assertEqual(
            parse_compute_csv("123, python3, 1000 MiB\n")[0]["pid"], "123")


class GuardTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.status_file = os.path.join(self.tmp.name, "status.json")
        self.clock = Clock()
        self.wall = Clock(1000.0)
        self.logs = []
        self.snapshot = safe_snapshot()
        self.inhibitor = FakeInhibitor()
        self.auth = Authorizer([1000], require_token=True,
                               token_reader=lambda: "sekret")
        self.guard = self.make_guard()

    def tearDown(self):
        self.tmp.cleanup()

    def make_guard(self, inhibitor=None, boot="boot-1"):
        return Guard(
            cfg(status_file=self.status_file),
            inhibitor or self.inhibitor,
            lambda: copy.deepcopy(self.snapshot),
            self.auth,
            clock=self.clock,
            wallclock=self.wall,
            status_writer=self._write_status,
            boot_id_reader=lambda: boot,
            log=self.logs.append,
        )

    def _write_status(self, doc):
        with open(self.status_file, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_startup_acquires_before_first_probe(self):
        seen = []

        def snapshot():
            seen.append(self.inhibitor.alive())
            return copy.deepcopy(self.snapshot)

        guard = Guard(cfg(status_file=self.status_file), self.inhibitor, snapshot,
                      self.auth, clock=self.clock, wallclock=self.wall,
                      status_writer=self._write_status, boot_id_reader=lambda: "boot-1",
                      log=self.logs.append)
        guard.startup()
        self.assertEqual(seen, [True])
        self.assertTrue(self.inhibitor.alive())
        self.assertTrue(guard.status()["protected"])
        self.assertTrue(guard.status()["safe"])

    def test_startup_inhibitor_failure_is_reported_then_recovers(self):
        self.inhibitor.fail_starts = 3   # startup, poll retry and post-probe retry
        self.guard.startup()
        st = self.guard.status()
        self.assertFalse(st["protected"])
        self.assertFalse(st["held"])
        self.assertEqual(st["state"], "unprotected")
        self.assertGreaterEqual(st["failure_count"], 1)
        self.assertIn("inhibitor acquire failed", st["last_failure"])

        self.inhibitor.fail_starts = 0
        self.guard.poll()
        st = self.guard.status()
        self.assertTrue(st["protected"])
        self.assertTrue(st["held"])
        self.assertGreaterEqual(st["failure_count"], 1)

    def test_inhibitor_death_is_detected_and_reacquired(self):
        self.guard.startup()
        self.assertTrue(self.inhibitor.alive())
        self.inhibitor.kill()
        before = self.inhibitor.starts
        self.guard.poll()
        self.assertTrue(self.inhibitor.alive())
        self.assertGreater(self.inhibitor.starts, before)
        st = self.guard.status()
        self.assertGreaterEqual(st["failure_count"], 1)
        self.assertIn("not held", st["last_failure"])
        self.assertIn("not held", " ".join(self.logs))

    def test_snapshot_failure_fails_closed(self):
        def boom():
            raise RuntimeError("probe exploded")

        guard = Guard(cfg(status_file=self.status_file), self.inhibitor, boom,
                      self.auth, clock=self.clock, wallclock=self.wall,
                      status_writer=self._write_status, boot_id_reader=lambda: "boot-1",
                      log=self.logs.append)
        guard.startup()
        st = guard.status()
        self.assertTrue(st["held"])
        self.assertFalse(st["safe"])
        self.assertIn("snapshot failed", " ".join(st["reasons"]))

    def test_release_requires_allowed_uid(self):
        self.guard.startup()
        reply = self.guard.submit({"cmd": "release", "ttl_s": 5}, uid=2000)
        self.assertFalse(reply["ok"])
        self.assertTrue(self.inhibitor.alive())
        self.assertFalse(self.guard.status()["authorized"])

    def test_release_requires_matching_token(self):
        self.guard.startup()
        reply = self.guard.submit({"cmd": "release", "ttl_s": 5, "token": "wrong"},
                                  uid=1000)
        self.assertFalse(reply["ok"])
        self.assertTrue(self.inhibitor.alive())

    def test_release_requires_all_checks(self):
        self.snapshot["gpu"]["compute_apps"] = [{"pid": "7", "process_name": "strata"}]
        self.guard.startup()
        reply = self.guard.handle_command(
            {"cmd": "release", "ttl_s": 5, "token": "sekret"}, uid=1000)
        self.assertFalse(reply["ok"])
        self.assertIn("safety checks failed", reply["error"])
        self.assertTrue(self.inhibitor.alive())
        self.assertFalse(self.guard.status()["authorized"])

    def test_release_refuses_unproven_gate_and_keeps_inhibitor(self):
        """Every missing/failed verification field must leave the inhibitor on."""
        variants = {
            "no detail": None,
            "unverified": {"verified": False},
            "inconsistent": {"consistent": False},
            "actual open": {"actual_state": "open"},
            "zero rules": {"rules": 0},
            "unsealed": {"sealed": False},
        }
        for name, patch in variants.items():
            with self.subTest(name=name):
                self.inhibitor = FakeInhibitor()
                self.guard = self.make_guard()
                self.snapshot = safe_snapshot()
                if patch is None:
                    self.snapshot["gate"].pop("detail", None)
                else:
                    self.snapshot["gate"]["detail"].update(patch)
                self.guard.startup()
                self.assertTrue(self.inhibitor.alive())
                reply = self.guard.handle_command(
                    {"cmd": "release", "ttl_s": 5, "token": "sekret"},
                    uid=1000)
                self.assertFalse(reply["ok"], name)
                self.assertIn("safety checks failed", reply["error"])
                self.assertTrue(self.inhibitor.alive(),
                                f"{name}: inhibitor was released without proof")
                self.assertFalse(self.guard.status()["authorized"])

    def test_release_with_complete_evidence_works(self):
        self.guard.startup()
        reply = self.guard.handle_command(
            {"cmd": "release", "ttl_s": 5, "token": "sekret"}, uid=1000)
        self.assertTrue(reply["ok"], reply)
        self.assertFalse(self.inhibitor.alive())
        self.assertTrue(self.guard.status()["authorized"])

    def test_release_takes_a_fresh_sample(self):
        self.guard.startup()
        self.assertTrue(self.guard.status()["safe"])
        # A load that starts after the last poll must be seen by the release
        # decision itself, not just by the cached status.
        self.snapshot["strata"]["loaded"] = True
        reply = self.guard.handle_command(
            {"cmd": "release", "ttl_s": 5, "token": "sekret"}, uid=1000)
        self.assertFalse(reply["ok"])
        self.assertIn("model is loaded", " ".join(reply["reasons"]))
        self.assertTrue(self.inhibitor.alive())
    def test_release_then_ttl_reacquires(self):
        self.guard.startup()
        reply = self.guard.handle_command(
            {"cmd": "release", "ttl_s": 5, "token": "sekret", "reason": "test"},
            uid=1000)
        self.assertTrue(reply["ok"], reply)
        self.assertFalse(self.inhibitor.alive())
        self.assertTrue(self.guard.status()["authorized"])
        self.assertEqual(reply["state"], "released")

        self.clock.advance(4.0)
        self.guard.poll()
        self.assertFalse(self.inhibitor.alive())
        self.assertTrue(self.guard.status()["authorized"])

        self.clock.advance(1.1)
        self.guard.poll()
        self.assertTrue(self.inhibitor.alive())
        self.assertFalse(self.guard.status()["authorized"])
        self.assertIn("TTL expired", " ".join(self.logs))

    def test_safety_change_during_release_reacquires(self):
        self.guard.startup()
        reply = self.guard.handle_command(
            {"cmd": "release", "ttl_s": 20, "token": "sekret"}, uid=1000)
        self.assertTrue(reply["ok"], reply)
        self.assertFalse(self.inhibitor.alive())

        self.snapshot["strata"]["loaded"] = True
        self.guard.poll()
        self.assertTrue(self.inhibitor.alive())
        self.assertFalse(self.guard.status()["authorized"])
        self.assertIn("safety changed", " ".join(self.logs))

    def test_acquire_command_reholds_and_clears_authorization(self):
        self.guard.startup()
        self.assertTrue(self.guard.handle_command(
            {"cmd": "release", "ttl_s": 20, "token": "sekret"}, uid=1000)["ok"])
        reply = self.guard.handle_command(
            {"cmd": "acquire", "token": "sekret", "reason": "test"}, uid=1000)
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(self.inhibitor.alive())
        self.assertFalse(self.guard.status()["authorized"])
        self.assertTrue(self.guard.status()["protected"])

    def test_release_ttl_bounds(self):
        self.guard.startup()
        for ttl in (0, -1, 31):
            reply = self.guard.handle_command(
                {"cmd": "release", "ttl_s": ttl, "token": "sekret"}, uid=1000)
            self.assertFalse(reply["ok"], ttl)
            self.assertTrue(self.inhibitor.alive())

    def test_missing_token_file_fails_closed(self):
        auth = Authorizer([1000], token_file=os.path.join(self.tmp.name, "missing"),
                          require_token=True)
        guard = Guard(cfg(status_file=self.status_file), self.inhibitor,
                      lambda: copy.deepcopy(self.snapshot), auth,
                      clock=self.clock, wallclock=self.wall,
                      status_writer=self._write_status, boot_id_reader=lambda: "boot-1",
                      log=self.logs.append)
        guard.startup()
        reply = guard.handle_command(
            {"cmd": "release", "ttl_s": 5, "token": "anything"}, uid=1000)
        self.assertFalse(reply["ok"])
        self.assertIn("token", reply["error"])
        self.assertTrue(self.inhibitor.alive())

    def test_restart_gap_same_boot_is_reported(self):
        self.guard.startup()
        self.wall.advance(10.0)
        guard2 = self.make_guard()
        guard2.startup()
        self.assertEqual(guard2.status()["restart_gap_s"], 10.0)

    def test_restart_gap_ignored_across_boot(self):
        self.guard.startup()
        self.wall.advance(10.0)
        guard2 = self.make_guard(boot="boot-2")
        guard2.startup()
        self.assertIsNone(guard2.status()["restart_gap_s"])

    def test_status_file_has_failure_and_heartbeat(self):
        self.inhibitor.fail_starts = 1
        self.guard.startup()
        with open(self.status_file, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["service"], "sleepmgr-suspend-guard")
        self.assertIn("heartbeat_wall", doc)
        self.assertGreaterEqual(doc["failure_count"], 1)
        self.assertIn("last_failure", doc)

    def test_command_timeout_is_reported(self):
        self.guard.startup()
        reply = self.guard.submit({"cmd": "acquire", "token": "sekret"},
                                  uid=1000, timeout=0.05)
        self.assertFalse(reply["ok"])
        self.assertIn("did not answer", reply["error"])
        # A command left in the queue is harmless; drain it for isolation.
        pending = self.guard.commands.get(timeout=1)
        self.guard.process_one(pending)


class UnitArtifactTestCase(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "deploy", "sleepmgr-suspend-guard.service")
        with open(self.path, encoding="utf-8") as f:
            self.text = f.read()

    def test_starts_without_network_and_before_sleep(self):
        self.assertIn("WantedBy=multi-user.target", self.text)
        self.assertIn("After=systemd-logind.service dbus.socket", self.text)
        self.assertIn("Before=sleepmgr.service sleep.target", self.text)
        self.assertNotIn("After=network-online.target", self.text)
        self.assertNotIn("Wants=network-online.target", self.text)

    def test_restart_and_watchdog_are_configured(self):
        self.assertIn("Type=notify", self.text)
        self.assertIn("WatchdogSec=20", self.text)
        self.assertIn("Restart=always", self.text)
        self.assertIn("RestartSec=250ms", self.text)
        self.assertIn("StartLimitIntervalSec=0", self.text)
        self.assertIn("NoNewPrivileges=yes", self.text)

    def test_runs_unprivileged_with_its_own_runtime_dir(self):
        self.assertIn("User=sleepuser", self.text)
        self.assertIn("RuntimeDirectory=sleepmgr-suspend-guard", self.text)
        self.assertNotIn("CAP_", self.text)


class SocketTestCase(unittest.TestCase):
    """End-to-end local socket + peer credential + token path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.tmp.name, "guard.sock")
        self.status_path = os.path.join(self.tmp.name, "status.json")
        self.clock = Clock()
        self.wall = Clock(1000.0)
        self.inhibitor = FakeInhibitor()
        self.auth = Authorizer([os.getuid()], require_token=True,
                               token_reader=lambda: "socket-secret")
        self.guard = Guard(
            cfg(status_file=self.status_path, command_timeout_s=2.0),
            self.inhibitor, safe_snapshot, self.auth,
            clock=self.clock, wallclock=self.wall,
            status_writer=lambda doc: None, boot_id_reader=lambda: "boot-1",
            log=lambda _s: None)
        self.guard.startup()
        self.server = GuardControlServer(self.sock_path, self.guard)
        self.server.start()
        self.stopper = threading.Event()

        def pump():
            while not self.stopper.is_set():
                try:
                    pending = self.guard.commands.get(timeout=0.05)
                except queue.Empty:
                    continue
                self.guard.process_one(pending)

        self.thread = threading.Thread(target=pump, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.stopper.set()
        self.server.stop()
        self.thread.join(timeout=1)
        self.tmp.cleanup()

    def test_socket_release_and_status(self):
        client = GuardClient(self.sock_path, token="socket-secret", timeout=2)
        reply = client.release(ttl_s=5, reason="socket test")
        self.assertTrue(reply["ok"], reply)
        self.assertFalse(self.inhibitor.alive())
        status = client.status()
        self.assertTrue(status["ok"], status)
        self.assertEqual(status["state"], "released")

    def test_acquire_forwards_remaining_timeout(self):
        client = GuardClient(self.sock_path, token="socket-secret", timeout=2)
        seen = {}

        def fake_request(cmd, timeout=None):
            seen["cmd"] = cmd
            seen["timeout"] = timeout
            return {"ok": True, "state": "protected"}

        client._request = fake_request
        reply = client.acquire(reason="test", timeout=1.25)
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(seen["timeout"], 1.25)
        self.assertEqual(seen["cmd"]["cmd"], "acquire")

    def test_socket_bad_token_is_rejected(self):
        client = GuardClient(self.sock_path, token="wrong", timeout=2)
        with self.assertRaises(Exception):
            client.release(ttl_s=5)
        self.assertTrue(self.inhibitor.alive())


if __name__ == "__main__":
    unittest.main(verbosity=2)
