"""Offline HTTP tests for the post-resume inference readiness probe."""
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest

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
        self.server.requests.append(("GET", self.path,
                                     self.headers.get("Authorization")))
        if self.path == "/health":
            self._send(200, {"loaded": self.server.loaded})
        elif self.path == "/status":
            self._send(200, {"busy": self.server.busy,
                             "queued": self.server.queued})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        self.server.requests.append(("POST", self.path,
                                     self.headers.get("Authorization")))
        self.server.chat_body = json.loads(raw or b"{}")
        if self.path != "/v1/chat/completions":
            self._send(404, {"error": "not found"})
        elif not self.server.choices:
            self._send(200, {"choices": []})
        else:
            self._send(200, {"choices": [{"message": {"content": "OK"}}]})


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.requests = []
        self.server.chat_body = None
        self.server.loaded = True
        self.server.busy = False
        self.server.queued = 0
        self.server.choices = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self.tmp = tempfile.TemporaryDirectory()
        self.cfg_path = os.path.join(self.tmp.name, "strata.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump({
                "host": "127.0.0.1",
                "port": self.server.server_address[1],
                "api_key": "test-key",
                "model_name": "test-model",
            }, f)
        self.cfg = {"config_path": self.cfg_path, "readiness_timeout_s": 5}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def test_success_exercises_a_real_completion(self):
        ok, msg = detectors.strata_readiness(self.cfg)
        self.assertTrue(ok, msg)
        self.assertEqual(self.server.chat_body["model"], "test-model")
        self.assertEqual(self.server.chat_body["max_tokens"], 1)
        auth = [r[2] for r in self.server.requests if r[0] == "POST"][0]
        self.assertEqual(auth, "Bearer test-key")

    def test_unloaded_model_is_not_ready(self):
        self.server.loaded = False
        ok, msg = detectors.strata_readiness(self.cfg)
        self.assertFalse(ok)
        self.assertIn("loaded=false", msg)
        self.assertFalse([r for r in self.server.requests if r[0] == "POST"])

    def test_busy_model_is_not_ready(self):
        self.server.busy = True
        ok, msg = detectors.strata_readiness(self.cfg)
        self.assertFalse(ok)
        self.assertIn("busy", msg)
        self.assertFalse([r for r in self.server.requests if r[0] == "POST"])

    def test_empty_completion_is_not_ready(self):
        self.server.choices = False
        ok, msg = detectors.strata_readiness(self.cfg)
        self.assertFalse(ok)
        self.assertIn("no choices", msg)

    def test_absent_deadline_key_uses_a_bounded_default(self):
        """The preserved live config has no new key; it must still be bounded."""
        cfg = dict(self.cfg)
        cfg.pop("readiness_deadline_s", None)
        now = [0.0]

        def fake_http(_url, headers=None, timeout=3):
            now[0] += detectors.DEFAULT_READINESS_DEADLINE_S + 1.0
            return {"loaded": True}

        original = detectors._http_json
        detectors._http_json = fake_http
        try:
            ok, msg = detectors.strata_readiness(cfg, clock=lambda: now[0])
        finally:
            detectors._http_json = original
        self.assertFalse(ok)
        self.assertIn("deadline", msg)
        self.assertFalse([r for r in self.server.requests if r[0] == "POST"])

    def test_readiness_deadline_bounds_each_probe(self):
        """A slow probe consumes the budget; the next step is refused."""
        now = [0.0]

        def fake_http(_url, headers=None, timeout=3):
            now[0] += float(timeout)      # blocks until its own timeout
            return {"loaded": True}

        original = detectors._http_json
        detectors._http_json = fake_http
        try:
            ok, msg = detectors.strata_readiness(
                self.cfg, deadline_s=1.0, probe_timeout_s=1.0,
                clock=lambda: now[0])
        finally:
            detectors._http_json = original
        self.assertFalse(ok)
        self.assertIn("deadline", msg)
        self.assertFalse([r for r in self.server.requests if r[0] == "POST"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
