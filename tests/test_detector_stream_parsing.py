"""Focused tests for the fail-closed ``ss`` parsing in ``detectors.py``.

The deployed detector replaced a loose regex port scan with strict row parsing
and now reports ``UNKNOWN`` when connection evidence is missing or malformed.
These tests pin that behaviour using mocked command results only; they never
run ``ss`` or touch the network.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors  # noqa: E402
import policy  # noqa: E402
from policy import ACTIVE, OK, UNKNOWN, Countdown, DetectorResult  # noqa: E402

SS_CMD = ["ss", "-Htn", "state", "established"]


def probe_with(rc, out, err="", cfg=None):
    """Run StreamProbe.probe() against a mocked ``_run`` result."""
    conf = {"enabled": True, "ports": [47984, 47989, 48010]}
    if cfg:
        conf.update(cfg)
    with mock.patch.object(detectors, "_run", return_value=(rc, out, err)) as run:
        result = detectors.StreamProbe(conf).probe()
    return result, run


class EndpointPortTests(unittest.TestCase):
    def test_valid_ipv4_endpoint(self):
        self.assertEqual(detectors._endpoint_port("192.0.2.10:47984"), 47984)

    def test_valid_ipv6_endpoint(self):
        self.assertEqual(detectors._endpoint_port("[2001:db8::1]:8080"), 8080)

    def test_bare_ipv6_is_not_a_port(self):
        self.assertIsNone(detectors._endpoint_port("2001:db8::1"))

    def test_unbracketed_ipv6_with_port_is_rejected(self):
        self.assertIsNone(detectors._endpoint_port("::1:8080"))

    def test_non_numeric_port_is_rejected(self):
        self.assertIsNone(detectors._endpoint_port("192.0.2.10:http"))

    def test_out_of_range_ports_are_rejected(self):
        self.assertIsNone(detectors._endpoint_port("192.0.2.10:0"))
        self.assertIsNone(detectors._endpoint_port("192.0.2.10:65536"))

    def test_non_ip_host_is_rejected(self):
        self.assertIsNone(detectors._endpoint_port("host.example:8080"))


class ParseSsRowTests(unittest.TestCase):
    def test_valid_row(self):
        self.assertEqual(
            detectors._parse_ss_row("0 0 192.0.2.10:47984 192.0.2.50:51000"),
            (0, 0, 47984, 51000))

    def test_valid_row_with_nonzero_queues(self):
        self.assertEqual(
            detectors._parse_ss_row("12 34 192.0.2.10:47984 192.0.2.50:51000"),
            (12, 34, 47984, 51000))

    def test_wrong_field_count_is_rejected(self):
        self.assertIsNone(detectors._parse_ss_row("0 0 192.0.2.10:47984"))
        self.assertIsNone(
            detectors._parse_ss_row("0 0 192.0.2.10:47984 192.0.2.50:51000 extra"))

    def test_non_numeric_queue_is_rejected(self):
        self.assertIsNone(
            detectors._parse_ss_row("x 0 192.0.2.10:47984 192.0.2.50:51000"))

    def test_negative_queue_is_rejected(self):
        self.assertIsNone(
            detectors._parse_ss_row("-1 0 192.0.2.10:47984 192.0.2.50:51000"))

    def test_bad_endpoint_is_rejected(self):
        self.assertIsNone(
            detectors._parse_ss_row("0 0 192.0.2.10: 192.0.2.50:51000"))


class StreamProbeIdleTests(unittest.TestCase):
    def test_no_established_connections_is_ok(self):
        result, run = probe_with(0, "")
        self.assertEqual(result.state, OK)
        self.assertEqual(result.detail["ports"], [])
        self.assertTrue(result.detail["ss_ok"])
        self.assertTrue(result.detail["ss_rows_valid"])
        run.assert_called_once_with(SS_CMD, 4)

    def test_unrelated_ports_are_ok(self):
        out = ("0 0 192.0.2.10:22 192.0.2.50:51000\n"
               "0 0 192.0.2.10:631 192.0.2.50:51001\n")
        result, _ = probe_with(0, out)
        self.assertEqual(result.state, OK)
        self.assertEqual(result.detail["ports"], [])

    def test_disabled_probe_does_not_call_ss(self):
        with mock.patch.object(detectors, "_run") as run:
            result = detectors.StreamProbe({"enabled": False}).probe()
        self.assertEqual(result.state, OK)
        run.assert_not_called()


class StreamProbeBusyTests(unittest.TestCase):
    def test_local_sunshine_port_is_active(self):
        out = "0 0 192.0.2.10:47984 192.0.2.50:51000\n"
        result, _ = probe_with(0, out)
        self.assertEqual(result.state, ACTIVE)
        self.assertEqual(result.detail["ports"], [47984])

    def test_peer_sunshine_port_is_active(self):
        out = "0 0 192.0.2.10:51000 192.0.2.50:47989\n"
        result, _ = probe_with(0, out)
        self.assertEqual(result.state, ACTIVE)
        self.assertEqual(result.detail["ports"], [47989])

    def test_ipv6_stream_is_active(self):
        out = "0 0 [2001:db8::1]:48010 [2001:db8::2]:51000\n"
        result, _ = probe_with(0, out)
        self.assertEqual(result.state, ACTIVE)
        self.assertEqual(result.detail["ports"], [48010])

    def test_multiple_ports_are_reported_sorted(self):
        out = ("0 0 192.0.2.10:48010 192.0.2.50:51000\n"
               "0 0 192.0.2.10:47984 192.0.2.50:51001\n")
        result, _ = probe_with(0, out)
        self.assertEqual(result.state, ACTIVE)
        self.assertEqual(result.detail["ports"], [47984, 48010])

    def test_sunshine_log_client_is_active(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("CLIENT CONNECTED\n")
            path = fh.name
        self.addCleanup(os.unlink, path)
        result, _ = probe_with(0, "", cfg={"log_path": path})
        self.assertEqual(result.state, ACTIVE)
        self.assertIs(result.detail["client_from_log"], True)


class StreamProbeUncertainTests(unittest.TestCase):
    """Uncertain evidence must never read as OK."""

    def test_ss_failure_is_unknown(self):
        result, _ = probe_with(1, "", "ss: command failed")
        self.assertEqual(result.state, UNKNOWN)
        self.assertFalse(result.detail["ss_ok"])
        self.assertIn("ss: command failed", result.detail["ss_error"])

    def test_ss_failure_without_stderr_reports_exit_code(self):
        result, _ = probe_with(2, "", "")
        self.assertEqual(result.state, UNKNOWN)
        self.assertIn("ss exited 2", result.detail["ss_error"])

    def test_undecodable_ss_output_is_unknown(self):
        with mock.patch.object(
                detectors, "_run",
                side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
            result = detectors.StreamProbe(
                {"enabled": True, "ports": [47984]}).probe()
        self.assertEqual(result.state, UNKNOWN)
        self.assertFalse(result.detail["ss_ok"])
        self.assertIn("could not be decoded", result.detail["ss_error"])

    def test_malformed_row_is_unknown(self):
        result, _ = probe_with(0, "0 0 192.0.2.10:47984\n")
        self.assertEqual(result.state, UNKNOWN)
        self.assertFalse(result.detail["ss_rows_valid"])
        self.assertIn("malformed", result.detail["ss_error"])

    def test_truncated_row_is_unknown(self):
        result, _ = probe_with(0, "0 0 192.0.2.10:479")
        self.assertEqual(result.state, UNKNOWN)
        self.assertFalse(result.detail["ss_rows_valid"])

    def test_garbage_row_is_unknown(self):
        result, _ = probe_with(0, "not-an-ss-row\n")
        self.assertEqual(result.state, UNKNOWN)
        self.assertFalse(result.detail["ss_rows_valid"])

    def test_malformed_row_does_not_hide_a_real_stream(self):
        out = ("0 0 192.0.2.10:47984 192.0.2.50:51000\n"
               "garbage\n")
        result, _ = probe_with(0, out)
        self.assertEqual(result.state, ACTIVE)
        self.assertEqual(result.detail["ports"], [47984])
        self.assertFalse(result.detail["ss_rows_valid"])


class UncertainCannotAuthorizeSleepTests(unittest.TestCase):
    """The inactivity gate must not count down while a detector is UNKNOWN."""

    def _unknown_streams_result(self):
        result, _ = probe_with(1, "", "ss failed")
        self.assertEqual(result.state, UNKNOWN)
        return result

    def test_unknown_streams_result_blocks(self):
        self.assertTrue(self._unknown_streams_result().blocking())

    def test_blocker_reasons_names_the_detector(self):
        reasons = policy.blocker_reasons([self._unknown_streams_result()])
        self.assertTrue(reasons)
        self.assertIn("streams:", reasons[0])

    def test_gate_stays_blocked_with_unknown_detection(self):
        gate = Countdown(seconds=30, idle_timeout_s=600)
        tick = gate.tick(now=10_000.0, idle_s=10_000.0,
                         blockers=policy.blocker_reasons(
                             [self._unknown_streams_result()]))
        self.assertEqual(tick["state"], "blocked")
        self.assertIsNone(tick["suspend_in_s"])
        self.assertIsNone(tick["remaining"])

    def test_ok_streams_result_does_not_block(self):
        result, _ = probe_with(0, "")
        self.assertFalse(result.blocking())
        self.assertEqual(policy.blocker_reasons([result]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
