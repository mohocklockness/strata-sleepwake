"""Static checks for the selective-deployment artifacts (no system access)."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class DeployArtifactTests(unittest.TestCase):
    def test_monitor_unit_orders_after_the_gate_socket(self):
        with open(os.path.join(ROOT, "deploy", "sleepmgr.service"),
                  encoding="utf-8") as f:
            unit = f.read()
        self.assertIn("Wants=sleepmgr-gate.socket", unit)
        self.assertIn("After=sleepmgr-gate.socket", unit)

    def test_installer_preserves_config_and_supports_selective_gate(self):
        with open(os.path.join(ROOT, "deploy", "install.sh"),
                  encoding="utf-8") as f:
            script = f.read()
        self.assertIn("--with-gate", script)
        self.assertIn("config_guard.py", script)
        self.assertIn("config.json.new", script)
        self.assertIn("preserved existing", script)
        self.assertIn("sleepmgr-gate.socket", script)
        self.assertIn("sleepmgr-gate-boot.service", script)
        self.assertIn("strata.service.d/10-sleepmgr-gate-boot.conf", script)

    def test_gate_boot_failclosed_unit_and_script_exist(self):
        unit_path = os.path.join(ROOT, "deploy", "sleepmgr-gate-boot.service")
        script_path = os.path.join(ROOT, "deploy", "sleepmgr-gate-boot.sh")
        self.assertTrue(os.path.isfile(unit_path))
        self.assertTrue(os.path.isfile(script_path))
        with open(unit_path, encoding="utf-8") as f:
            unit = f.read()
        self.assertIn("Before=network-pre.target", unit)
        # The unit must always run and succeed on a clean boot so its own
        # success can be a hard prerequisite for Strata; a condition-based skip
        # would make "no marker" indistinguishable from "not evaluated".
        self.assertNotIn("ConditionPathExists", unit)
        with open(script_path, encoding="utf-8") as f:
            script = f.read()
        # Reuse the helper's ruleset builder so the boot rule cannot drift.
        self.assertIn("--print-script", script)
        self.assertIn("sealed.json", script)
        # Explicit, non-pipelined failure checks for generator and nft.
        self.assertIn("rule generation failed", script)
        self.assertIn("nft failed to apply", script)
        self.assertNotIn("| nft", script)
        # Verify the intended rule, not merely table existence.
        self.assertIn("verify_rules", script)
        self.assertIn("delete table inet", script)

    def test_strata_dropin_requires_the_boot_seal(self):
        dropin = os.path.join(ROOT, "deploy", "strata.service.d",
                              "10-sleepmgr-gate-boot.conf")
        self.assertTrue(os.path.isfile(dropin))
        with open(dropin, encoding="utf-8") as f:
            conf = f.read()
        # A failed boot seal must stop Strata (remote inference), so the
        # dependency is Requires= (ordering alone would not block it).
        self.assertIn("Requires=sleepmgr-gate-boot.service", conf)
        self.assertIn("After=sleepmgr-gate-boot.service", conf)

    def test_deployment_doc_covers_backup_and_enablement_state(self):
        with open(os.path.join(ROOT, "docs", "deploy-selective.md"),
                  encoding="utf-8") as f:
            doc = f.read()
        self.assertIn("Backups", doc)
        self.assertIn("enablement", doc.lower())
        self.assertIn("systemctl enable", doc)

    def test_rollback_doc_is_correct_and_surgical(self):
        with open(os.path.join(ROOT, "docs", "deploy-selective.md"),
                  encoding="utf-8") as f:
            doc = f.read()
        # The emergency opener has no `--status` mode.
        self.assertNotIn("sleepmgr-gate-emergency-open --status", doc)
        self.assertIn("sleepmgr-gate-emergency-open --dry-run", doc)
        # Never delete a whole Strata drop-in directory; only the tracked file.
        self.assertNotIn("rm -rf /etc/systemd/system/strata.service.d", doc)
        self.assertIn("strata.service.d/10-sleepmgr-gate-boot.conf", doc)
        # Stopping the boot unit also stops dependent Strata is called out.
        self.assertIn("Requires=sleepmgr-gate-boot.service", doc)
        # `--now` behaviour is reconciled with install.sh.
        self.assertIn("enable --now sleepmgr-gate.socket", doc)
        self.assertIn("enable sleepmgr-gate-boot.service", doc)

    def test_rollback_checks_guard_and_strata_properly(self):
        with open(os.path.join(ROOT, "docs", "deploy-selective.md"),
                  encoding="utf-8") as f:
            doc = f.read()
        # A running unit does not prove the inhibitor is held.
        self.assertNotIn(
            "is-active sleepmgr-suspend-guard.service   # guard protected", doc)
        self.assertIn("/run/sleepmgr-suspend-guard/status.json", doc)
        self.assertIn('doc.get("held")', doc)
        self.assertIn('doc.get("protected")', doc)
        # The LAN-bound Strata instance needs its configured, authenticated
        # endpoint; an unauthenticated loopback /status check proves nothing.
        self.assertNotIn("curl -fsS http://127.0.0.1:8080/status", doc)
        self.assertIn("detectors.strata_readiness", doc)
        self.assertIn("config_path", doc)
        self.assertIn("/health", doc)
        # This server reports loaded via /health, not /status; /status is
        # authenticated and supplies busy/queued only.
        self.assertIn('health.get("loaded")', doc)
        self.assertIn('status.get("busy")', doc)
        self.assertIn('status.get("queued")', doc)
        self.assertNotIn('status.get("loaded")', doc)
        self.assertNotIn("status.get('loaded')", doc)

    def test_emergency_opener_preserves_the_marker_on_failure(self):
        with open(os.path.join(ROOT, "deploy", "sleepmgr-gate-emergency-open.sh"),
                  encoding="utf-8") as f:
            script = f.read()
        self.assertIn("leaving", script)
        self.assertIn("UNKNOWN", script)
        # The marker is removed only after the table is provably gone.
        self.assertLess(script.index('list table inet "$TABLE"'),
                        script.index('rm -f "$SEALED_STATE"'))

    def test_production_config_has_bounded_recovery_keys(self):
        with open(os.path.join(ROOT, "config.production.json"),
                  encoding="utf-8") as f:
            cfg = json.load(f)
        strata = cfg["strata"]
        self.assertIn("recovery_timeout_s", strata)
        self.assertIn("load_request_timeout_s", strata)
        self.assertIn("load_retry_interval_s", strata)
        self.assertGreater(float(strata["recovery_timeout_s"]), 0)
        self.assertGreater(float(strata["load_request_timeout_s"]), 0)
        gate = cfg["gate"]
        self.assertIn("startup_recovery_timeout_s", gate)
        self.assertIn("startup_recovery_interval_s", gate)
        self.assertGreater(float(gate["startup_recovery_timeout_s"]), 0)
        self.assertGreater(float(gate["startup_recovery_interval_s"]), 0)

    def test_monitor_uses_bounded_startup_recovery(self):
        with open(os.path.join(ROOT, "sleepmon.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn("startup_gate_recovery_retry", src)
        self.assertIn("startup_recovery_timeout_s", src)
        self.assertIn('"recovery-failed"', src)
        self.assertIn('"gate_recovery"', src)

    def test_selective_deployment_doc_exists(self):
        path = os.path.join(ROOT, "docs", "deploy-selective.md")
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8") as f:
            doc = f.read()
        self.assertIn("Rollback", doc)
        self.assertIn("boot", doc.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
