"""Tests for the local Unix-socket control channel."""
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import control as control_mod  # noqa: E402
from control import ControlError, ControlServer, request  # noqa: E402
from pause import PauseController  # noqa: E402


class FakeInhibitor:
    def start(self):
        return True

    def stop(self):
        return True

    def alive(self):
        return False

    def status(self):
        return {"enabled": True, "held": False, "pid": None}


def status_doc():
    return {"ok": True, "state": "waiting", "pid": os.getpid(),
            "time": "2026-01-01T00:00:00", "mode": "dry-run"}


class ControlTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.tmp.name, "control.sock")
        self.state_path = os.path.join(self.tmp.name, "state.json")
        self.pc = PauseController(self.state_path, inhibitor=FakeInhibitor(),
                                 clock=lambda: 1000.0, log=lambda _s: None)
        self.pc.load()
        self.manual_calls = []

        def manual_fn(uid):
            self.manual_calls.append(uid)
            return {"ok": True, "queued": True, "by": uid}

        self.server = ControlServer(self.sock_path, self.pc,
                                    allow_uids=[os.getuid()],
                                    status_fn=status_doc, manual_fn=manual_fn,
                                    log=lambda _s: None)
        self.server.start()

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def test_status(self):
        reply = request(self.sock_path, {"cmd": "status"})
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["state"], "waiting")

    def test_large_status_reply_is_not_truncated(self):
        self.server.status_fn = lambda: {
            "ok": True, "state": "waiting", "guard": {"blob": "x" * 20000}}
        reply = request(self.sock_path, {"cmd": "status"})
        self.assertTrue(reply["ok"])
        self.assertEqual(len(reply["guard"]["blob"]), 20000)

    def test_missing_newline_is_rejected_as_incomplete(self):
        path, server, thread = self._raw_server(b'{"ok": true}')
        try:
            with self.assertRaises(ControlError) as ctx:
                request(path, {"cmd": "status"}, timeout=2)
            self.assertIn("missing newline", str(ctx.exception))
        finally:
            server.close()
            thread.join(timeout=1)

    def test_oversized_reply_is_rejected_without_truncating_json(self):
        payload = b'{"ok": true, "blob": "' + b"x" * 100 + b'"}\n'
        path, server, thread = self._raw_server(payload)
        try:
            with mock.patch.object(control_mod, "MAX_REPLY", 32):
                with self.assertRaises(ControlError) as ctx:
                    request(path, {"cmd": "status"}, timeout=2)
            self.assertIn("too large", str(ctx.exception))
        finally:
            server.close()
            thread.join(timeout=1)

    def _raw_server(self, payload):
        path = os.path.join(self.tmp.name, "raw.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)

        def serve():
            try:
                conn, _ = server.accept()
                try:
                    conn.recv(4096)
                    conn.sendall(payload)
                finally:
                    conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return path, server, thread

    def test_pause_and_resume_roundtrip(self):
        reply = request(self.sock_path, {"cmd": "pause", "duration_s": 3600})
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["paused"])
        self.assertTrue(self.pc.is_paused())
        reply = request(self.sock_path, {"cmd": "resume"})
        self.assertTrue(reply["ok"])
        self.assertFalse(self.pc.is_paused())

    def test_suspend_now_is_queued(self):
        reply = request(self.sock_path, {"cmd": "suspend-now"})
        self.assertTrue(reply["ok"])
        self.assertEqual(self.manual_calls, [os.getuid()])
    def test_unknown_command(self):
        reply = request(self.sock_path, {"cmd": "explode"})
        self.assertFalse(reply["ok"])
        self.assertIn("unknown", reply["error"])

    def test_missing_command(self):
        reply = request(self.sock_path, {})
        self.assertFalse(reply["ok"])

    def test_authorization(self):
        server = ControlServer(self.sock_path, self.pc, allow_uids=[4242],
                               log=lambda _s: None)
        # The real server is already bound; just test the predicate directly.
        self.assertTrue(server._allowed(4242))
        self.assertFalse(server._allowed(os.getuid()))

    def test_second_server_on_same_socket_refuses(self):
        with self.assertRaises(ControlError):
            ControlServer(self.sock_path, self.pc, allow_uids=[0],
                          log=lambda _s: None).start()

    def test_malformed_json(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(self.sock_path)
        s.sendall(b"{not json\n")
        s.shutdown(socket.SHUT_WR)
        data = b""
        while b"\n" not in data:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        s.close()
        reply = json.loads(data.split(b"\n")[0])
        self.assertFalse(reply["ok"])
        self.assertIn("bad JSON", reply["error"])

    def test_socket_removed_on_stop(self):
        path = os.path.join(self.tmp.name, "other.sock")
        srv = ControlServer(path, self.pc, allow_uids=[os.getuid()], log=lambda _s: None)
        srv.start()
        self.assertTrue(os.path.exists(path))
        srv.stop()
        self.assertFalse(os.path.exists(path))

    def test_client_error_when_missing(self):
        with self.assertRaises((ControlError, OSError)):
            request(os.path.join(self.tmp.name, "nope.sock"), {"cmd": "status"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
