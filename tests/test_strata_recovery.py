"""Offline tests for bounded post-resume /load recovery (no live services)."""
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        srv = self.server
        with srv.lock:
            loaded = srv.loaded
            queued = srv.queued
        if self.path == "/health":
            self._send(200, {"loaded": loaded})
        elif self.path == "/status":
            self._send(200, {"busy": False, "queued": queued})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        srv = self.server
        if self.path != "/load":
            self._send(404, {"error": "not found"})
            return
        mode = srv.on_load
        with srv.lock:
            srv.load_calls += 1
            if mode in ("complete", "abort-loaded"):
                srv.loaded = True
                srv.queued = 0
            elif mode == "abort-in-progress":
                # The reply is lost while the load is still waiting for the
                # engine FIFO: /status shows it queued.
                srv.queued = 1
            elif mode in ("abort-in-progress-unqueued", "abort-lost-forever"):
                # Faithful to Strata: once the load holds the engine FIFO it
                # drops out of status["queued"], so loaded=false with
                # queued=0 is also a load that is still starting the engine.
                srv.queued = 0
                srv.loaded = False
        if mode == "abort-loaded":
            # The load started and finished, but the reply is lost.  A retry
            # must observe /health loaded=true and never POST again.
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if mode in ("abort-in-progress", "abort-in-progress-unqueued"):
            # The load started but its reply is lost while it is still running.
            # A retry must not POST again (queued may already be 0).
            def finish():
                time.sleep(0.15)
                with srv.lock:
                    srv.loaded = True
                    srv.queued = 0

            threading.Thread(target=finish, daemon=True).start()
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if mode == "abort-lost-forever":
            # The reply is lost and the load never completes: the monitor must
            # still never POST a second time.
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        self._send(200, {"status": "loaded"})


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, on_load="complete"):
        super().__init__(addr, _Handler)
        self.lock = threading.Lock()
        self.loaded = False
        self.queued = 0
        self.load_calls = 0
        self.on_load = on_load


class StrataLoadRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = None
        self.thread = None

    def tearDown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
        self.tmp.cleanup()

    def _start(self, port=0, on_load="complete"):
        self.server = _Server(("127.0.0.1", port), on_load=on_load)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address[1]

    def _cfg(self, port):
        path = os.path.join(self.tmp.name, "strata.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "host": "127.0.0.1",
                "port": port,
                "api_key": "test-key",
                "model_name": "test-model",
            }, f)
        return {
            "config_path": path,
            "http_timeout_s": 0.2,
            "recovery_timeout_s": 2.0,
            "load_request_timeout_s": 0.5,
            "load_retry_interval_s": 0.05,
        }

    def test_transient_connection_refused_is_retried_and_logged(self):
        # Reserve a port, keep it closed while strata_load starts, then start
        # the fake Strata.  This is the cold-boot/NIC-not-ready shape.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        cfg = self._cfg(port)
        logs = []
        timer = threading.Timer(0.2, self._start, kwargs={"port": port})
        timer.start()
        try:
            ok, msg = detectors.strata_load(cfg, log=logs.append)
        finally:
            timer.cancel()
        self.assertTrue(ok, msg)
        self.assertGreaterEqual(self.server.load_calls, 1)
        text = "\n".join(logs)
        self.assertIn("127.0.0.1", text)
        self.assertIn("Connection refused", text)
        self.assertIn("/load accepted", text)

    def test_lost_reply_after_load_completed_does_not_duplicate(self):
        port = self._start(on_load="abort-loaded")
        ok, msg = detectors.strata_load(self._cfg(port), log=lambda _s: None)
        self.assertTrue(ok, msg)
        self.assertEqual(self.server.load_calls, 1)

    def test_lost_reply_while_load_in_progress_waits_without_second_post(self):
        port = self._start(on_load="abort-in-progress")
        ok, msg = detectors.strata_load(self._cfg(port), log=lambda _s: None)
        self.assertTrue(ok, msg)
        self.assertEqual(self.server.load_calls, 1)

    def test_lost_reply_while_load_holds_fifo_no_second_post(self):
        # Faithful to Strata: the in-progress load drops out of `queued` the
        # moment it holds the engine FIFO.  loaded=false with queued=0 is
        # therefore also a load that is still starting, not proof it is safe to
        # POST /load again.
        port = self._start(on_load="abort-in-progress-unqueued")
        ok, msg = detectors.strata_load(self._cfg(port), log=lambda _s: None)
        self.assertTrue(ok, msg)
        self.assertEqual(self.server.load_calls, 1)

    def test_lost_reply_never_completing_still_makes_no_second_post(self):
        port = self._start(on_load="abort-lost-forever")
        logs = []
        ok, msg = detectors.strata_load(self._cfg(port), log=logs.append)
        self.assertFalse(ok, msg)
        self.assertEqual(self.server.load_calls, 1)
        self.assertIn("not re-POSTing", "\n".join(logs))

    def test_already_loaded_never_posts(self):
        port = self._start()
        self.server.loaded = True
        ok, msg = detectors.strata_load(self._cfg(port), log=lambda _s: None)
        self.assertTrue(ok, msg)
        self.assertEqual(self.server.load_calls, 0)

    def test_deterministic_deadline_bounds_every_probe(self):
        cfg = self._cfg(1)
        recorded = []

        def fake_http(_url, headers=None, timeout=3):
            recorded.append(float(timeout))
            raise OSError("simulated outage")

        original = detectors._http_json
        detectors._http_json = fake_http
        now = [0.0]
        sleeps = []

        def clock():
            return now[0]

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        try:
            ok, msg = detectors.strata_load(
                cfg, deadline_s=3.0, request_timeout_s=2.0,
                probe_timeout_s=1.0, retry_interval_s=1.0,
                clock=clock, sleep=sleep)
        finally:
            detectors._http_json = original
        self.assertFalse(ok)
        self.assertIn("did not succeed", msg)
        self.assertAlmostEqual(now[0], 3.0, places=2)
        self.assertTrue(recorded, "probes were never attempted")
        self.assertLessEqual(max(recorded), 1.0)

    def test_slow_probes_consume_the_deadline_across_hosts(self):
        """A probe that blocks until its timeout still respects the deadline.

        Each host gets only the *remaining* budget, so a slow first candidate
        cannot push the whole multi-host attempt past ``recovery_timeout_s``.
        """
        cfg = self._cfg(1)
        recorded = []
        original = detectors._http_json
        now = [0.0]

        def fake_http(_url, headers=None, timeout=3):
            recorded.append(float(timeout))
            now[0] += float(timeout)      # blocks until its own timeout
            raise OSError("simulated outage")

        def clock():
            return now[0]

        def sleep(seconds):
            now[0] += seconds

        detectors._http_json = fake_http
        try:
            ok, msg = detectors.strata_load(
                cfg, deadline_s=3.0, request_timeout_s=2.0,
                probe_timeout_s=1.0, retry_interval_s=1.0,
                clock=clock, sleep=sleep)
        finally:
            detectors._http_json = original
        self.assertFalse(ok)
        self.assertIn("did not succeed", msg)
        self.assertLessEqual(now[0], 3.0 + 0.001)
        self.assertTrue(recorded, "probes were never attempted")
        self.assertLessEqual(max(recorded), 1.0)

    def test_status_success_on_a_later_host_still_allows_a_post(self):
        """A valid /status on a fallback host must not be shadowed by errors."""
        port = self._start(on_load="complete")
        cfg = self._cfg(port)
        # Point the configured host at an address nothing is listening on, so
        # the first candidate fails and a later loopback fallback answers.
        with open(cfg["config_path"], encoding="utf-8") as f:
            doc = json.load(f)
        doc["host"] = "127.0.0.2"
        with open(cfg["config_path"], "w", encoding="utf-8") as f:
            json.dump(doc, f)
        logs = []
        ok, msg = detectors.strata_load(cfg, log=logs.append)
        self.assertTrue(ok, msg)
        self.assertGreaterEqual(self.server.load_calls, 1)
        self.assertIn("127.0.0.1", "\n".join(logs))

    def test_status_auth_error_is_fatal_even_when_another_host_answers(self):
        """A token mismatch must never be hidden by an answering fallback."""
        cfg = self._cfg(1)
        with open(cfg["config_path"], encoding="utf-8") as f:
            doc = json.load(f)
        doc["host"] = "127.0.0.2"
        with open(cfg["config_path"], "w", encoding="utf-8") as f:
            json.dump(doc, f)

        def fake_http(url, headers=None, timeout=3):
            if "/health" in url:
                return {"loaded": False}
            if "127.0.0.2" in url:
                raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)
            return {"busy": False, "queued": 0}

        original = detectors._http_json
        detectors._http_json = fake_http
        try:
            ok, msg = detectors.strata_load(cfg, log=lambda _s: None)
        finally:
            detectors._http_json = original
        self.assertFalse(ok)
        self.assertIn("authorization failed", msg)

    def test_deadline_is_bounded_and_reports_each_host(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        cfg = self._cfg(port)
        cfg["recovery_timeout_s"] = 0.25
        logs = []
        started = time.monotonic()
        ok, msg = detectors.strata_load(cfg, log=logs.append)
        elapsed = time.monotonic() - started
        self.assertFalse(ok)
        self.assertIn("did not succeed", msg)
        self.assertLess(elapsed, 3.0)
        text = "\n".join(logs)
        self.assertIn("127.0.0.1", text)
        self.assertIn("localhost", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
