"""Real-nft integration test in a throwaway user+network namespace.

This is the only test that executes ``nft`` against a real kernel ruleset, and
it does so inside ``unshare -Urn``: a private user namespace (so we hold
CAP_NET_ADMIN) and a private network namespace (so production networking is
completely untouched).  Nothing here sees or changes the host's firewall.

It proves the properties the design depends on:

* closing the gate drops *new* TCP arrivals on the gated port;
* an already-established connection keeps delivering data (so an in-flight
  request can drain) -- this is why the rule matches SYN, not ``ct state new``;
* opening the gate restores new arrivals and removes the table.

The test is skipped when user namespaces or ``nft``/``ip`` are unavailable.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

subprocess.run(["ip", "link", "set", "lo", "up"], check=False)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
port = srv.getsockname()[1]
srv.listen(5)
srv.settimeout(0.2)
accepted = []
stop = {"v": False}


def acc():
    while not stop["v"]:
        try:
            c, _ = srv.accept()
            c.settimeout(2)
            accepted.append(c)
        except socket.timeout:
            continue
        except OSError:
            break


threading.Thread(target=acc, daemon=True).start()


def try_connect(timeout=0.6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


out = {"port": port}
c1 = socket.create_connection(("127.0.0.1", port), timeout=1)
deadline = time.time() + 2
while not accepted and time.time() < deadline:
    time.sleep(0.01)
out["established_before_gate"] = bool(accepted)

import nftgate_helper as h
g = h.NftGate(h.NftRunner(), ports=(port,),
              exempt_loopback=False, action="drop")
out["close"] = g.close()
out["status_closed"] = g.status()


def real_listing():
    return subprocess.run(
        ["nft", "list", "table", "inet", "sleepmgr_gate"],
        capture_output=True, text=True, check=True).stdout


def verify_listing(text, action, exempt_loopback):
    argv = [sys.executable, h.__file__, "--verify-listing",
            "--table", "sleepmgr_gate", "--port", str(port),
            "--action", action]
    if not exempt_loopback:
        argv.append("--no-loopback-exemption")
    p = subprocess.run(argv, input=text, capture_output=True, text=True)
    return {"rc": p.returncode, "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip()}


drop_text = real_listing()
out["drop_listing_text"] = drop_text
out["drop_verify"] = verify_listing(drop_text, "drop", False)
# A source restriction on the *real* listing must be refused: it would gate
# only some remote clients.
tampered = drop_text.replace("tcp flags", "ip saddr 10.0.0.0/8 tcp flags", 1)
out["tampered_verify"] = verify_listing(tampered, "drop", False)

c1.sendall(b"x")
try:
    out["established_delivered"] = accepted[0].recv(1) == b"x"
except Exception as e:
    out["established_delivered"] = False
    out["established_error"] = type(e).__name__

out["new_blocked_after_close"] = not try_connect()
out["open"] = g.open()
out["status_after_open"] = g.status()
out["new_allowed_after_open"] = try_connect(1.0)

# And with the production scoping: loopback is exempt, so the monitor's
# local health check still works while the gate is closed.
g2 = h.NftGate(h.NftRunner(), ports=(port,), exempt_loopback=True,
               action="drop")
out["loopback_gate_close"] = g2.close()
out["loopback_status"] = g2.status()
out["loopback_exempt_local_allowed"] = try_connect(1.0)
out["loopback_gate_open"] = g2.open()

# Reject variant on a real kernel table, then verify the exact listing the
# kernel prints (nft canonicalises the flags expression).
g3 = h.NftGate(h.NftRunner(), ports=(port,), exempt_loopback=True,
               action="reject")
out["reject_gate_close"] = g3.close()
out["reject_status"] = g3.status()
out["reject_listing_text"] = real_listing()
out["reject_verify"] = verify_listing(out["reject_listing_text"], "reject", True)
out["reject_gate_open"] = g3.open()

c1.close()
stop["v"] = True
srv.close()
print(json.dumps(out))
"""


def _namespace_available():
    if not shutil.which("unshare"):
        return False, "unshare not found"
    if not shutil.which("nft"):
        return False, "nft not found"
    if not shutil.which("ip"):
        return False, "ip not found"
    try:
        p = subprocess.run(["unshare", "-Urn", "true"], capture_output=True,
                           timeout=10)
    except Exception as e:  # noqa: BLE001
        return False, f"unshare failed: {e}"
    if p.returncode != 0:
        return False, (p.stderr.decode("utf-8", "replace").strip()[:200]
                       or "user namespaces are not permitted")
    return True, ""


AVAILABLE, REASON = _namespace_available()


@unittest.skipUnless(AVAILABLE, f"real-nft netns test skipped: {REASON}")
class TestRealNftInNamespace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            ["unshare", "-Urn", sys.executable, "-c", CHILD],
            capture_output=True, text=True, timeout=90, env=env)
        if proc.returncode != 0:
            raise AssertionError(
                "netns lab failed:\nstdout:\n%s\nstderr:\n%s"
                % (proc.stdout, proc.stderr))
        lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
        cls.result = json.loads(lines[-1])

    def test_close_blocks_new_connections(self):
        self.assertTrue(self.result["close"][0], self.result)
        self.assertTrue(self.result["new_blocked_after_close"], self.result)
        self.assertEqual(self.result["status_closed"]["state"], "closed")
        self.assertIs(self.result["status_closed"]["verified"], True,
                      self.result["status_closed"])

    def test_verify_listing_accepts_real_drop_and_reject_output(self):
        drop = self.result["drop_verify"]
        self.assertEqual(drop["rc"], 0, drop)
        self.assertEqual(drop["stdout"], "verified", drop)
        reject = self.result["reject_verify"]
        self.assertEqual(reject["rc"], 0, reject)
        self.assertEqual(reject["stdout"], "verified", reject)
        self.assertIs(self.result["reject_status"]["verified"], True,
                      self.result["reject_status"])
        self.assertIs(self.result["loopback_status"]["verified"], True,
                      self.result["loopback_status"])
        # Prove the fixture is genuinely kernel-shaped, not generator-shaped.
        self.assertIn("tcp flags syn / syn,ack",
                      self.result["drop_listing_text"])
        self.assertNotIn("(syn|ack)", self.result["drop_listing_text"])

    def test_verify_listing_rejects_an_extra_source_restriction(self):
        tampered = self.result["tampered_verify"]
        self.assertNotEqual(tampered["rc"], 0, tampered)
        self.assertIn("unexpected", tampered["stderr"])

    def test_established_connection_still_drains(self):
        self.assertTrue(self.result["established_before_gate"], self.result)
        self.assertTrue(self.result["established_delivered"], self.result)

    def test_open_restores_arrivals_and_removes_table(self):
        self.assertTrue(self.result["open"][0], self.result)
        self.assertTrue(self.result["new_allowed_after_open"], self.result)
        self.assertEqual(self.result["status_after_open"]["state"], "open")

    def test_production_scoping_keeps_loopback_health_check_working(self):
        self.assertTrue(self.result["loopback_gate_close"][0], self.result)
        self.assertTrue(self.result["loopback_exempt_local_allowed"], self.result)
        self.assertTrue(self.result["loopback_gate_open"][0], self.result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
