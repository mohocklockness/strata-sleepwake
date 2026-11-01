#!/bin/sh
# Fail closed at boot after an interrupted sealed recovery.
#
# The durable seal marker (/var/lib/sleepmgr-gate/sealed.json) survives only a
# controlled-suspend seal that never reached a completed recovery: a successful
# recovery clears it through the gate's `open`.  nftables runtime state does not
# survive a reboot, so if the marker is present when this boot reaches the
# firewall phase, the previous boot ended sealed and this boot must not admit
# remote inference before the monitor verifies readiness.
#
# This script is the ExecStart of sleepmgr-gate-boot.service, which runs before
# network-pre.target so the rule is in place before any remote packet can
# arrive.  strata.service is made to depend on a *successful* run via
# deploy/strata.service.d/10-sleepmgr-gate-boot.conf, so a required seal that
# cannot be established stops Strata from accepting remote inference.  Only the
# configured inference port is gated; host networking (SSH, etc.) is untouched
# and stays available for troubleshooting.  The monitor/helper later adopt the
# closed table and only open it after the guard is protected and Strata is
# loaded and ready.
#
# Behaviour:
#   * no seal marker   -> exit 0: a clean boot requires no boot seal
#   * marker present   -> prove the *intended* blocking rule is live, using the
#     same semantic checker the helper uses at runtime
#     (`nftgate_helper.py --verify-listing`).  Merely finding the table is not
#     protection, so an empty or wrong table is replaced by atomically restoring
#     the owned ruleset in one `nft -f` transaction (delete + add together, so
#     there is never an unprotected gap)
#   * missing tool, generator failure or nft failure -> exit non-zero
#   * a table that cannot be *inspected* is unknown, never absence, and fails
#     closed rather than being replaced on a guess
#
# Every external command (nft, python3, the helper) is explicit so its exit
# status is checked.  Rule generation is *not* piped into nft: a pipeline could
# hide a failed generator behind a successful nft.
set -eu

MARKER="${SLEEPMGR_GATE_SEALED_STATE:-/var/lib/sleepmgr-gate/sealed.json}"
TABLE="${SLEEPMGR_GATE_TABLE:-sleepmgr_gate}"
PORTS="${SLEEPMGR_GATE_PORTS:-8080}"
ACTION="${SLEEPMGR_GATE_ACTION:-reject}"
HELPER="${SLEEPMGR_GATE_HELPER:-/opt/sleepmgr/nftgate_helper.py}"
NFT="${SLEEPMGR_GATE_NFT:-/usr/sbin/nft}"
PYTHON="${SLEEPMGR_GATE_PYTHON:-/usr/bin/python3}"

fail() {
    echo "sleepmgr-gate-boot: $*" >&2
    exit 1
}

# A clean boot has no marker: no boot seal is required, so this unit succeeds
# without touching the firewall (host networking and Strata proceed normally).
[ -e "$MARKER" ] || exit 0

command -v "$NFT" >/dev/null 2>&1 || fail "nft ($NFT) is not available"
command -v "$PYTHON" >/dev/null 2>&1 || fail "python3 ($PYTHON) is not available"
[ -r "$HELPER" ] || fail "seal marker present but $HELPER is unreadable"

PORT_ARGS=""
for p in $(printf '%s' "$PORTS" | tr ',;' '  '); do
    [ -n "$p" ] && PORT_ARGS="$PORT_ARGS --port $p"
done
[ -n "$PORT_ARGS" ] || fail "no inference ports configured"

LIST="$(mktemp)" || fail "cannot create a temporary file for the gate listing"
LIST_ERR="${LIST}.err"
trap 'rm -f "$LIST" "$LIST_ERR"' EXIT HUP INT TERM

# Set to 1 only when the table is *provably* absent (a "no such file" error),
# so the restore knows whether a `delete table` line is needed.
INSPECT_MISSING=0

# Prove the live table carries the intended blocking rule.  The decision is made
# by the shared checker in the helper (ports, blocking verdict, SYN match,
# loopback exemption, base-chain hook/order, no bypassing earlier rule), so the
# boot and runtime paths cannot drift.  Exit statuses: 0 verified, 1
# present-but-wrong or provably absent, 2 cannot inspect (unknown).
verify_rules() {
    INSPECT_MISSING=0
    if "$NFT" list table inet "$TABLE" > "$LIST" 2> "$LIST_ERR"; then
        "$PYTHON" "$HELPER" --table "$TABLE" --action "$ACTION" $PORT_ARGS \
            --verify-listing < "$LIST"
        return $?
    fi
    if grep -Eqi 'no such file|does not exist' "$LIST_ERR"; then
        INSPECT_MISSING=1
        return 1
    fi
    return 2
}

if verify_rules; then
    echo "sleepmgr-gate-boot: the intended fail-closed rule is already in place"
    exit 0
else
    VERIFY_RC=$?
fi
if [ "$VERIFY_RC" -eq 2 ]; then
    fail "cannot inspect table inet $TABLE ($(cat "$LIST_ERR")); refusing to guess"
fi

TMP="$(mktemp)" || fail "cannot create a temporary ruleset file"
trap 'rm -f "$TMP" "$LIST" "$LIST_ERR"' EXIT HUP INT TERM

# Atomically restore the owned ruleset.  The delete (only when the table
# already exists) and the freshly generated table go into one file, so a single
# `nft -f` transaction applies them together.  The generator's status is
# checked explicitly and nft is never run if generation fails.  The subshell is
# deliberate: a failed generator aborts the subshell *before* nft runs, and the
# outer `|| fail` reports it (an `exit` inside `{ }` would skip that message).
(
    if [ "$INSPECT_MISSING" -eq 0 ]; then
        printf 'delete table inet %s\n' "$TABLE"
    fi
    "$PYTHON" "$HELPER" --table "$TABLE" --action "$ACTION" \
        $PORT_ARGS --print-script || exit 1
) > "$TMP" || fail "rule generation failed"

"$NFT" -f "$TMP" || fail "nft failed to apply the fail-closed rule"

# Re-inspect with the same checker.  An inspection failure here is also a
# failure: it must never be mistaken for a verified rule.
if verify_rules; then
    :
else
    RESTORE_RC=$?
    if [ "$RESTORE_RC" -eq 2 ]; then
        fail "cannot inspect table inet $TABLE after applying the rule"
    fi
    fail "the fail-closed rule is still not verified after applying it"
fi

echo "sleepmgr-gate-boot: re-sealed $TABLE before network (interrupted sealed recovery)"
