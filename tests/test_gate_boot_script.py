"""Behavioural tests for deploy/sleepmgr-gate-boot.sh with fake commands.

These run the real boot script in a throwaway environment with fake ``nft`` and
``python3`` executables on the configured paths.  Nothing here touches the real
firewall, the real helper, or live state: the "table" is a text file and the
generator is a shell stub.  File-existence checks alone would not verify the
script's control flow, so every case asserts an exit code and/or an observable
effect.
"""
import os
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "deploy", "sleepmgr-gate-boot.sh")

FAKE_NFT = r"""#!/bin/sh
# Fake 'nft'.  FAKE_NFT_STATE holds a file whose content is the listing that
# 'list table' prints, or the literal token __ABSENT__.
state="${FAKE_NFT_STATE:?}"
log="${FAKE_NFT_LOG:-/dev/null}"
printf '%s\n' "$*" >> "$log"
cmd="${1:-}"
case "$cmd" in
  list)
    if [ -n "${FAKE_NFT_LIST_ERROR:-}" ]; then
      echo "$FAKE_NFT_LIST_ERROR" >&2
      exit 1
    fi
    current="$(cat "$state" 2>/dev/null || true)"
    if [ "$current" = "__ABSENT__" ] || [ ! -s "$state" ]; then
      echo "Error: No such file or directory" >&2
      exit 1
    fi
    cat "$state"
    exit 0
    ;;
  delete)
    printf '__ABSENT__' > "$state"
    exit 0
    ;;
  -f)
    if [ "${FAKE_NFT_FAIL_APPLY:-0}" = "1" ]; then
      echo "Error: apply failed" >&2
      exit 1
    fi
    file="$2"
    [ -n "${FAKE_NFT_APPLIED:-}" ] && cat "$file" > "$FAKE_NFT_APPLIED"
    tbl="$(sed -n 's/^add table inet \([^ ]*\).*/\1/p' "$file" | head -n1)"
    rule="$(sed -n 's/^add rule inet [^ ]* input //p' "$file" | head -n1)"
    {
      printf 'table inet %s {\n' "$tbl"
      printf '\tchain input {\n'
      printf '\t\ttype filter hook input priority filter - 10; policy accept;\n'
      [ -n "$rule" ] && printf '\t\t%s\n' "$rule"
      printf '\t}\n}\n'
    } > "$state"
    exit 0
    ;;
esac
exit 0
"""

FAKE_PYTHON = r"""#!/bin/sh
# Fake ruleset generator/verifier.  `--print-script` emits the rule the boot
# script applies; `--verify-listing` delegates to the *real* helper so the boot
# script is exercised against the shared semantic checker.
for a in "$@"; do
  if [ "$a" = "--verify-listing" ]; then
    # The boot script invokes us as `python3 <helper> <args>`; drop the script
    # path and run the real helper with the remaining arguments.
    [ "$1" = "$SLEEPMGR_GATE_HELPER" ] && shift
    exec python3 "$SLEEPMGR_GATE_HELPER" "$@"
  fi
done
if [ "$1" = "$SLEEPMGR_GATE_HELPER" ]; then
  shift
fi
if [ "${FAKE_GEN_FAIL:-0}" = "1" ]; then
  echo "generator exploded" >&2
  exit 1
fi
table=""; action="reject"; ports=""
while [ $# -gt 0 ]; do
  case "$1" in
    --table) table="$2"; shift 2 ;;
    --port) ports="$ports $2"; shift 2 ;;
    --action) action="$2"; shift 2 ;;
    *) shift ;;
  esac
done
join="$(printf '%s' "$ports" | sed 's/^ *//; s/  */, /g')"
verdict="reject with tcp reset"
[ "$action" = "drop" ] && verdict="drop"
printf 'add table inet %s\n' "$table"
printf 'add chain inet %s input { type filter hook input priority filter - 10 ; policy accept ; }\n' "$table"
printf 'add rule inet %s input tcp dport { %s } tcp flags & (syn|ack) == syn iifname != "lo" counter %s comment "sleepmgr: inference gate"\n' \
  "$table" "$join" "$verdict"
"""

CORRECT_RULE = ("tcp dport { 8080 } tcp flags & (syn|ack) == syn "
                'iifname != "lo" counter packets 0 bytes 0 reject with tcp reset '
                'comment "sleepmgr: inference gate"')


def table_listing(rule):
    body = ("table inet sleepmgr_gate {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority filter - 10; policy accept;\n")
    if rule:
        body += "\t\t" + rule + "\n"
    return body + "\t}\n}\n"


class GateBootScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.marker = os.path.join(self.dir, "sealed.json")
        self.state = os.path.join(self.dir, "nft-state")
        self.nft_log = os.path.join(self.dir, "nft.log")
        self.applied_file = os.path.join(self.dir, "nft-applied")
        # Verify the boot script against the *real* helper's shared checker:
        # the fake python below delegates `--verify-listing` to this file.
        self.helper = os.path.join(ROOT, "nftgate_helper.py")
        self.fake_nft = self._write("fake-nft", FAKE_NFT)
        self.fake_python = self._write("fake-python3", FAKE_PYTHON)
        open(self.nft_log, "w").close()
        self.write_marker()

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------------ utils
    def _write(self, name, body):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP)
        return path

    def write_marker(self):
        with open(self.marker, "w", encoding="utf-8") as f:
            f.write('{"sealed": true}\n')

    def write_state(self, text):
        with open(self.state, "w", encoding="utf-8") as f:
            f.write(text)

    def env(self, **over):
        env = dict(os.environ)
        env.update({
            "SLEEPMGR_GATE_NFT": self.fake_nft,
            "SLEEPMGR_GATE_PYTHON": self.fake_python,
            "SLEEPMGR_GATE_HELPER": self.helper,
            "SLEEPMGR_GATE_SEALED_STATE": self.marker,
            "SLEEPMGR_GATE_TABLE": "sleepmgr_gate",
            "SLEEPMGR_GATE_PORTS": "8080",
            "SLEEPMGR_GATE_ACTION": "reject",
            "FAKE_NFT_STATE": self.state,
            "FAKE_NFT_LOG": self.nft_log,
            "FAKE_NFT_APPLIED": self.applied_file,
        })
        for key, value in over.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = str(value)
        return env

    def run_script(self, **over):
        return subprocess.run(["sh", SCRIPT], env=self.env(**over),
                              capture_output=True, text=True, timeout=30)

    def nft_calls(self):
        with open(self.nft_log, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]

    def applied(self):
        return any(c.startswith("-f ") for c in self.nft_calls())

    def state_text(self):
        with open(self.state, encoding="utf-8") as f:
            return f.read()

    def applied_text(self):
        try:
            with open(self.applied_file, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    # ------------------------------------------------------------------ cases
    def test_no_marker_is_a_clean_success_without_touching_nft(self):
        os.unlink(self.marker)
        self.write_state(table_listing(CORRECT_RULE))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.nft_calls(), [])
        self.assertFalse(self.applied())

    def test_missing_nft_tool_fails_closed(self):
        self.write_state(table_listing(CORRECT_RULE))
        result = self.run_script(SLEEPMGR_GATE_NFT=os.path.join(self.dir, "nope"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nft", result.stderr)

    def test_missing_helper_fails_closed(self):
        self.write_state(table_listing(CORRECT_RULE))
        result = self.run_script(
            SLEEPMGR_GATE_HELPER=os.path.join(self.dir, "missing-helper.py"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unreadable", result.stderr)

    def test_generator_failure_aborts_before_nft_runs(self):
        self.write_state("__ABSENT__")
        result = self.run_script(FAKE_GEN_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rule generation failed", result.stderr)
        self.assertFalse(self.applied(), "nft must not run after a failed generator")

    def test_nft_apply_failure_fails_closed(self):
        self.write_state("__ABSENT__")
        result = self.run_script(FAKE_NFT_FAIL_APPLY="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nft failed to apply", result.stderr)
        self.assertTrue(self.applied())

    def test_existing_correct_table_is_left_untouched(self):
        self.write_state(table_listing(CORRECT_RULE))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.applied())
        self.assertIn("already in place", result.stdout)

    def test_absent_table_is_created(self):
        self.write_state("__ABSENT__")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())
        self.assertIn("tcp dport { 8080 }", self.state_text())
        # Nothing to delete: the restore is a pure add, still one transaction.
        self.assertNotIn("delete table inet sleepmgr_gate", self.applied_text())

    def test_empty_existing_table_is_restored_atomically(self):
        self.write_state(table_listing(""))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())
        self.assertIn("tcp dport { 8080 }", self.state_text())
        # The existing (empty) table is deleted and re-added in the same batch,
        # so remote packets never see an unprotected gap.
        applied = self.applied_text()
        self.assertIn("delete table inet sleepmgr_gate", applied)
        self.assertIn("add table inet sleepmgr_gate", applied)

    def test_wrong_port_table_is_restored(self):
        wrong = ('tcp dport { 9999 } tcp flags & (syn|ack) == syn '
                 'iifname != "lo" counter reject with tcp reset '
                 'comment "sleepmgr: inference gate"')
        self.write_state(table_listing(wrong))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())
        self.assertIn("tcp dport { 8080 }", self.state_text())

    def test_wrong_verdict_table_is_restored(self):
        wrong = ('tcp dport { 8080 } tcp flags & (syn|ack) == syn '
                 'iifname != "lo" counter drop '
                 'comment "sleepmgr: inference gate"')
        self.write_state(table_listing(wrong))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())
        self.assertIn("reject with tcp reset", self.state_text())

    def test_missing_comment_table_is_restored(self):
        wrong = ('tcp dport { 8080 } tcp flags & (syn|ack) == syn '
                 'iifname != "lo" counter reject with tcp reset')
        self.write_state(table_listing(wrong))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())

    def test_missing_loopback_exemption_is_restored(self):
        wrong = ('tcp dport { 8080 } tcp flags & (syn|ack) == syn '
                 'counter reject with tcp reset '
                 'comment "sleepmgr: inference gate"')
        self.write_state(table_listing(wrong))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())

    def test_uninspectable_table_is_unknown_and_fails_closed(self):
        self.write_state(table_listing(CORRECT_RULE))
        result = self.run_script(FAKE_NFT_LIST_ERROR="Operation not permitted")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot inspect", result.stderr)
        self.assertFalse(self.applied(),
                         "an uninspectable table must never be replaced on a guess")

    def test_bypassing_earlier_accept_is_restored(self):
        listing = ("table inet sleepmgr_gate {\n"
                   "\tchain input {\n"
                   "\t\ttype filter hook input priority filter - 10; policy accept;\n"
                   "\t\ttcp dport { 8080 } accept\n"
                   "\t\t" + CORRECT_RULE + "\n"
                   "\t}\n}\n")
        self.write_state(listing)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())
        self.assertIn("tcp dport { 8080 }", self.state_text())

    def test_unhooked_chain_is_restored(self):
        listing = ("table inet sleepmgr_gate {\n"
                   "\tchain input {\n"
                   "\t\t" + CORRECT_RULE + "\n"
                   "\t}\n}\n")
        self.write_state(listing)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())

    def test_multiple_ports_are_all_required(self):
        self.write_state("__ABSENT__")
        result = self.run_script(SLEEPMGR_GATE_PORTS="8080,8081")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.state_text()
        self.assertIn("8080", text)
        self.assertIn("8081", text)
        # A table that only covers one of two ports must be treated as wrong.
        one_only = ('tcp dport { 8080 } tcp flags & (syn|ack) == syn '
                    'iifname != "lo" counter reject with tcp reset '
                    'comment "sleepmgr: inference gate"')
        self.write_state(table_listing(one_only))
        open(self.nft_log, "w").close()
        result = self.run_script(SLEEPMGR_GATE_PORTS="8080,8081")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.applied())


if __name__ == "__main__":
    unittest.main(verbosity=2)
