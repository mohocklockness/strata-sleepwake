"""Two-namespace real-nft test: remote gating, loopback health, other ports.

Everything runs inside one outer ``unshare -Urn`` (private user + network
namespace).  A veth pair and a nested network namespace simulate a real remote
client at 10.0.0.2 connecting to the server at 10.0.0.1.  The host's firewall
and networking are never touched.

This pins the properties the supervised live test must confirm:

* remote new TCP/8080 is blocked (drop and reject variants);
* the host's own LAN address is still reachable locally (loopback path);
* SSH-like (2222) and Sunshine-like (47989) ports are unaffected;
* an established remote connection still drains after the gate closes;
* deleting the table restores remote connectivity immediately.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r'''
import json
import os
import socket
import subprocess
import sys
import threading
import time

TABLE = "labgate"
STOP = {"v": False}
OUT = {}


def run(cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def setup():
    run(["ip", "link", "add", "veth-s", "type", "veth", "peer", "name", "veth-c"])
    run(["ip", "addr", "add", "10.0.0.1/24", "dev", "veth-s"])
    run(["ip", "link", "set", "veth-s", "up"])
    run(["ip", "link", "set", "lo", "up"])
    child = subprocess.Popen(["unshare", "-n", "sleep", "300"])
    time.sleep(0.3)
    run(["ip", "link", "set", "veth-c", "netns", str(child.pid)])
    for cmd in (["ip", "addr", "add", "10.0.0.2/24", "dev", "veth-c"],
                ["ip", "link", "set", "veth-c", "up"],
                ["ip", "link", "set", "lo", "up"]):
        run(["nsenter", "-t", str(child.pid), "-n"] + cmd)
    return child


def echo(conn):
    conn.settimeout(5)
    try:
        data = conn.recv(1)
        if data:
            conn.sendall(data)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(20)
    s.settimeout(0.2)
    while not STOP["v"]:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=echo, args=(c,), daemon=True).start()
    s.close()


PROBE = """
import json, socket, sys, time
port = int(sys.argv[1]); timeout = float(sys.argv[2])
t0 = time.monotonic()
try:
    s = socket.create_connection(("10.0.0.1", port), timeout=timeout)
    s.close()
    print(json.dumps({"ok": True, "elapsed": round(time.monotonic()-t0, 3)}))
except Exception as e:
    print(json.dumps({"ok": False, "error": type(e).__name__,
                      "elapsed": round(time.monotonic()-t0, 3)}))
"""

HELD = """
import json, socket, sys, time
port = int(sys.argv[1]); delay = float(sys.argv[2])
s = socket.create_connection(("10.0.0.1", port), timeout=2)
print("connected", flush=True)
time.sleep(delay)
try:
    s.sendall(b"x"); s.settimeout(3)
    print(json.dumps({"delivered": s.recv(1) == b"x"}), flush=True)
except Exception as e:
    print(json.dumps({"delivered": False, "error": type(e).__name__}), flush=True)
"""


def remote(port, timeout=0.7):
    cmd = ["nsenter", "-t", str(CHILD.pid), "-n", sys.executable, "-c",
           PROBE, str(port), str(timeout)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    return json.loads(lines[-1]) if lines else {"ok": False, "error": "no output"}


def remote_held(port, delay=1.0):
    cmd = ["nsenter", "-t", str(CHILD.pid), "-n", sys.executable, "-c",
           HELD, str(port), str(delay)]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    first = p.stdout.readline().strip()
    if not first:
        raise RuntimeError("held client did not connect: " + p.stderr.read())
    return p, first


def local(host, port=8080, timeout=0.7):
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return {"ok": True, "elapsed": round(time.monotonic() - t0, 3)}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__,
                "elapsed": round(time.monotonic() - t0, 3)}


def apply(rule):
    subprocess.run(["nft", "delete", "table", "inet", TABLE],
                   capture_output=True)
    script = (
        f"add table inet {TABLE}\n"
        f"add chain inet {TABLE} input {{ type filter hook input priority "
        "filter - 10 ; policy accept ; }\n"
        f"add rule inet {TABLE} input {rule}\n"
    )
    p = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True,
                       text=True)
    if p.returncode != 0:
        raise RuntimeError("nft apply failed: " + (p.stderr or p.stdout))


def clear():
    subprocess.run(["nft", "delete", "table", "inet", TABLE],
                   capture_output=True)


DROP = ('tcp dport { 8080 } tcp flags & (syn|ack) == syn '
        'iifname != "lo" counter drop '
        'comment "sleepmgr: inference gate"')
REJECT = ('tcp dport { 8080 } tcp flags & (syn|ack) == syn '
          'iifname != "lo" counter reject with tcp reset '
          'comment "sleepmgr: inference gate"')


def main():
    global CHILD
    CHILD = setup()
    for port in (8080, 2222, 47989):
        threading.Thread(target=serve, args=(port,), daemon=True).start()
    time.sleep(0.3)
    try:
        OUT["baseline_remote_8080"] = remote(8080)
        OUT["baseline_remote_2222"] = remote(2222)
        OUT["baseline_remote_47989"] = remote(47989)
        OUT["baseline_local_8080"] = local("127.0.0.1")
        OUT["baseline_local_hostip_8080"] = local("10.0.0.1")

        for name, rule in (("drop", DROP), ("reject", REJECT)):
            apply(rule)
            OUT[name] = {
                "remote_8080": remote(8080),
                "remote_2222": remote(2222),
                "remote_47989": remote(47989),
                "local_127_8080": local("127.0.0.1"),
                "local_hostip_8080": local("10.0.0.1"),
            }
            listing = run(["nft", "list", "table", "inet", TABLE]).stdout
            import nftgate_helper as helper
            OUT[name]["verify"] = helper.verify_gate_ruleset(
                listing, ports=(8080,), action=name,
                exempt_loopback=True, table=TABLE)
            clear()
            OUT[name + "_reopen_remote_8080"] = remote(8080)

            p, connected = remote_held(8080)
            apply(rule)
            out, _err = p.communicate(timeout=15)
            lines = [l for l in out.splitlines() if l.strip()]
            OUT[name + "_established"] = {
                "connected": connected,
                "after_close": json.loads(lines[-1]) if lines else None,
                "new_remote_while_closed": remote(8080),
            }
            clear()
            OUT[name + "_reopen_after_established"] = remote(8080)
    finally:
        STOP["v"] = True
        clear()
        try:
            CHILD.terminate()
        except Exception:
            pass
        subprocess.run(["ip", "link", "del", "veth-s"], capture_output=True)
        print(json.dumps(OUT, sort_keys=True))


main()
'''


def _available():
    for exe in ("unshare", "nft", "ip", "nsenter"):
        if not shutil.which(exe):
            return False, f"{exe} not found"
    try:
        p = subprocess.run(["unshare", "-Urn", "true"], capture_output=True,
                           timeout=10)
    except Exception as e:  # noqa: BLE001
        return False, f"unshare failed: {e}"
    if p.returncode != 0:
        return False, (p.stderr.decode("utf-8", "replace").strip()[:200]
                       or "user namespaces are not permitted")
    return True, ""


AVAILABLE, REASON = _available()


@unittest.skipUnless(AVAILABLE, f"two-netns real-nft test skipped: {REASON}")
class TestRemoteGateInNamespaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            ["unshare", "-Urn", sys.executable, "-c", CHILD],
            capture_output=True, text=True, timeout=90, env=env)
        if proc.returncode != 0:
            raise AssertionError(
                "two-netns lab failed:\nstdout:\n%s\nstderr:\n%s"
                % (proc.stdout, proc.stderr))
        lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
        cls.result = json.loads(lines[-1])

    def test_baseline_remote_and_local_connect(self):
        for key in ("baseline_remote_8080", "baseline_remote_2222",
                    "baseline_remote_47989", "baseline_local_8080",
                    "baseline_local_hostip_8080"):
            self.assertTrue(self.result[key]["ok"], (key, self.result[key]))

    def test_drop_blocks_remote_but_not_loopback_or_other_ports(self):
        r = self.result["drop"]
        self.assertTrue(r["verify"][0], r["verify"])
        self.assertFalse(r["remote_8080"]["ok"], r["remote_8080"])
        self.assertIn(r["remote_8080"]["error"], ("TimeoutError", "socket.timeout"))
        self.assertTrue(r["local_127_8080"]["ok"], r["local_127_8080"])
        self.assertTrue(r["local_hostip_8080"]["ok"], r["local_hostip_8080"])
        self.assertTrue(r["remote_2222"]["ok"], r["remote_2222"])
        self.assertTrue(r["remote_47989"]["ok"], r["remote_47989"])

    def test_reject_fails_remote_fast_but_not_loopback_or_other_ports(self):
        r = self.result["reject"]
        self.assertTrue(r["verify"][0], r["verify"])
        self.assertFalse(r["remote_8080"]["ok"], r["remote_8080"])
        self.assertEqual(r["remote_8080"]["error"], "ConnectionRefusedError")
        self.assertLess(r["remote_8080"]["elapsed"], 0.5)
        self.assertTrue(r["local_127_8080"]["ok"], r["local_127_8080"])
        self.assertTrue(r["local_hostip_8080"]["ok"], r["local_hostip_8080"])
        self.assertTrue(r["remote_2222"]["ok"], r["remote_2222"])
        self.assertTrue(r["remote_47989"]["ok"], r["remote_47989"])

    def test_established_remote_connection_drains_under_both_actions(self):
        for name in ("drop", "reject"):
            e = self.result[name + "_established"]
            self.assertEqual(e["connected"], "connected", e)
            self.assertTrue(e["after_close"]["delivered"], e)
            self.assertFalse(e["new_remote_while_closed"]["ok"], e)

    def test_deleting_the_table_restores_remote_connectivity(self):
        for key in ("drop_reopen_remote_8080", "reject_reopen_remote_8080",
                    "drop_reopen_after_established",
                    "reject_reopen_after_established"):
            self.assertTrue(self.result[key]["ok"], (key, self.result[key]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
