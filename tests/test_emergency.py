"""The emergency rollback must be independent of the helper and the monitor."""
import os
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "deploy", "sleepmgr-gate-emergency-open.sh")


class TestEmergencyRollbackScript(unittest.TestCase):
    def test_shell_syntax(self):
        p = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_is_independent_of_helper_and_monitor(self):
        with open(SCRIPT, encoding="utf-8") as fh:
            text = fh.read()
        # It must be usable when the helper socket/monitor are wedged.
        self.assertNotIn("gate.sock", text)
        self.assertNotIn("nftgate_helper", text)
        self.assertNotIn("netgate", text)
        self.assertIn('TABLE="sleepmgr_gate"', text)
        self.assertIn(
            'SLEEPMGR_GATE_SEALED_STATE:-/var/lib/sleepmgr-gate/sealed.json', text)
        self.assertIn(
            'SLEEPMGR_GATE_LEGACY_SEALED_STATE:-/run/sleepmgr-gate/sealed.json',
            text)
        self.assertIn('"$NFT" delete table inet "$TABLE"', text)
        self.assertIn('rm -f "$SEALED_STATE" "$LEGACY_SEALED_STATE"', text)
        # The marker must only be cleared after the table is provably gone, so
        # a failed delete/inspection leaves it in place (fail closed).
        self.assertLess(text.index('list table inet "$TABLE"'),
                        text.index('rm -f "$SEALED_STATE"'))
        self.assertIn("UNKNOWN", text)

    def test_dry_run_changes_nothing_and_shows_the_table_delete(self):
        p = subprocess.run([SCRIPT, "--dry-run"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("delete table inet sleepmgr_gate", p.stdout)
        self.assertIn("would verify", p.stdout)


class TestEmergencyRollbackBehaviour(unittest.TestCase):
    """Drive the real script with fake ``nft``/``id``/``curl``.

    Nothing here touches the real firewall or the real seal marker: the table is
    a log file and the marker paths are temporary.  The fake ``id`` only
    satisfies the script's friendly root precheck; ``nft`` itself is fake, so no
    privilege is assumed.
    """

    FAKE_NFT = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_NFT_LOG"
case "$1" in
  delete)
    if [ -n "${FAKE_DELETE_ERROR:-}" ]; then
      echo "$FAKE_DELETE_ERROR" >&2
      exit 1
    fi
    exit 0
    ;;
  list)
    if [ "${FAKE_LIST_PRESENT:-0}" = "1" ]; then
      echo "table inet sleepmgr_gate { }"
      exit 0
    fi
    if [ -n "${FAKE_LIST_ERROR:-}" ]; then
      echo "$FAKE_LIST_ERROR" >&2
      exit 1
    fi
    echo "Error: No such file or directory" >&2
    exit 1
    ;;
esac
exit 0
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.marker = os.path.join(d, "sealed.json")
        self.legacy = os.path.join(d, "legacy-sealed.json")
        open(self.marker, "w").close()
        open(self.legacy, "w").close()
        self.log = os.path.join(d, "nft.log")
        open(self.log, "w").close()
        self.fake_nft = self._write("fake-nft", self.FAKE_NFT)
        self.fakebin = os.path.join(d, "bin")
        os.makedirs(self.fakebin)
        self._write("id", "#!/bin/sh\necho 0\n", self.fakebin)
        self._write("curl", "#!/bin/sh\nexit 1\n", self.fakebin)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, body, directory=None):
        path = os.path.join(directory or self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(path, 0o755)
        return path

    def run_script(self, **over):
        env = dict(os.environ)
        env.update({
            "PATH": self.fakebin + os.pathsep + env.get("PATH", ""),
            "NFT": self.fake_nft,
            "FAKE_NFT_LOG": self.log,
            "SLEEPMGR_GATE_SEALED_STATE": self.marker,
            "SLEEPMGR_GATE_LEGACY_SEALED_STATE": self.legacy,
        })
        env.update({k: str(v) for k, v in over.items()})
        return subprocess.run(["bash", SCRIPT, "--nft-only"], env=env,
                              capture_output=True, text=True, timeout=30)

    def test_success_clears_the_marker_after_verified_absence(self):
        p = self.run_script()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.exists(self.marker))
        self.assertFalse(os.path.exists(self.legacy))

    def test_delete_failure_preserves_the_marker(self):
        p = self.run_script(FAKE_DELETE_ERROR="Operation not permitted")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(os.path.exists(self.marker))
        self.assertIn("UNKNOWN", p.stderr)

    def test_inspection_failure_is_unknown_and_preserves_the_marker(self):
        p = self.run_script(FAKE_LIST_ERROR="Operation not permitted")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(os.path.exists(self.marker))
        self.assertIn("cannot determine", p.stderr)

    def test_surviving_table_preserves_the_marker(self):
        p = self.run_script(FAKE_LIST_PRESENT="1")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(os.path.exists(self.marker))
        self.assertIn("still exists", p.stderr)

    def test_already_absent_table_is_success(self):
        p = self.run_script(
            FAKE_DELETE_ERROR="Error: No such file or directory")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.exists(self.marker))


class TestGateUnitArtifact(unittest.TestCase):
    UNIT = os.path.join(REPO, "deploy", "sleepmgr-gate.service")
    SOCKET = os.path.join(REPO, "deploy", "sleepmgr-gate.socket")

    def _text(self):
        with open(self.UNIT, encoding="utf-8") as fh:
            return fh.read()

    def _socket_text(self):
        with open(self.SOCKET, encoding="utf-8") as fh:
            return fh.read()

    def test_unit_uses_loopback_scope_and_reject(self):
        text = self._text()
        self.assertIn("--action reject", text)
        self.assertIn("--allow-uid 1000", text)
        self.assertIn("--group sleepuser", text)
        self.assertNotIn("--exempt-uid", text)
        self.assertIn("CAP_NET_ADMIN", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", text)

    def test_unit_preserves_seal_and_no_new_privileges(self):
        text = self._text()
        # A forced ExecStopPost delete would fail open a controlled-suspend
        # seal before the restarted helper can restore its marker.
        self.assertNotIn("ExecStopPost=", text)
        self.assertIn("durable boot-scoped seal", text)
        # Persistent state, not RuntimeDirectory=/run.  Stopping the service or
        # cleaning a runtime directory must not delete the seal.
        self.assertIn("StateDirectory=sleepmgr-gate", text)
        self.assertIn("--sealed-state /var/lib/sleepmgr-gate/sealed.json", text)
        self.assertIn("ReadWritePaths=/var/lib/sleepmgr-gate", text)
        self.assertNotIn("ReadWritePaths=/run/sleepmgr-gate", text)
        self.assertIn("NoNewPrivileges=yes", text)

    def test_socket_unit_creates_llm_machine_listener(self):
        text = self._socket_text()
        self.assertIn("ListenStream=/run/sleepmgr-gate/gate.sock", text)
        self.assertIn("SocketGroup=sleepuser", text)
        self.assertIn("SocketMode=0660", text)
        self.assertIn("RemoveOnStop=yes", text)
        self.assertIn("PartOf=sleepmgr-gate.service", text)
        self.assertIn("Service=sleepmgr-gate.service", text)
        # RemoveOnStop removes the socket node, not the persistent seal marker.
        self.assertIn("durable seal marker is deliberately NOT in this runtime directory",
                      text)

    def test_service_uses_socket_activation_without_cap_chown(self):
        text = self._text()
        self.assertIn("Requires=sleepmgr-gate.socket", text)
        self.assertIn("After=network.target sleepmgr-gate.socket", text)
        caps = [ln.strip() for ln in text.splitlines()
                if ln.strip().startswith("CapabilityBoundingSet=")]
        self.assertEqual(caps, ["CapabilityBoundingSet=CAP_NET_ADMIN"])
        self.assertNotIn("RuntimeDirectory=sleepmgr-gate", text)


if __name__ == "__main__":
    unittest.main()
