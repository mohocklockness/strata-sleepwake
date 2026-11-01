#!/usr/bin/env bash
# Emergency, independent rollback for the sleepmgr inference gate.
#
# This script does NOT use the helper's Unix socket and does NOT import any
# sleepmgr code.  It stops the services that could re-close the gate and then
# removes the one nftables table directly.  It is safe to run repeatedly and is
# intended to be usable over SSH or from a local console when the helper or
# monitor is wedged.
#
# Usage:
#   sudo sleepmgr-gate-emergency-open            # stop services + open the gate
#   sudo sleepmgr-gate-emergency-open --nft-only # only delete the table
#   sleepmgr-gate-emergency-open --dry-run       # print, change nothing
#
# Exit status: 0 if the table is provably absent at the end, 1 otherwise.  If
# the table cannot be removed or inspected, the durable seal marker is left in
# place so a restarted helper cannot silently reopen an unprotected gate.
set -u

TABLE="sleepmgr_gate"
SEALED_STATE="${SLEEPMGR_GATE_SEALED_STATE:-/var/lib/sleepmgr-gate/sealed.json}"
LEGACY_SEALED_STATE="${SLEEPMGR_GATE_LEGACY_SEALED_STATE:-/run/sleepmgr-gate/sealed.json}"
NFT="${NFT:-$(command -v nft || true)}"
DRY_RUN=0
NFT_ONLY=0

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --nft-only) NFT_ONLY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$NFT" ]; then
    echo "ERROR: nft not found" >&2
    exit 1
fi
if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (or use --dry-run)" >&2
    exit 1
fi

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '+ %s\n' "$*"
    else
        "$@"
    fi
}

if [ "$DRY_RUN" -eq 1 ]; then
    if [ "$NFT_ONLY" -eq 0 ]; then
        printf '+ systemctl stop %s\n' "sleepmgr.service"
        printf '+ systemctl stop %s\n' "sleepmgr-gate.service"
    fi
    printf '+ %s delete table inet %s\n' "$NFT" "$TABLE"
    printf '+ rm -f %s %s\n' "$SEALED_STATE" "$LEGACY_SEALED_STATE"
    echo "dry-run: would verify that table inet $TABLE is absent"
    exit 0
fi

if [ "$NFT_ONLY" -eq 0 ]; then
    # Stop the monitor first: if it is mid-quiesce, stopping it releases the
    # helper lease (an ordinary lease opens; a controlled-suspend seal does
    # not).  Then stop the helper.  In every case the direct nft delete and
    # seal-marker removal below are the independent backstop.
    run systemctl stop sleepmgr.service || true
    if ! run timeout 10 systemctl stop sleepmgr-gate.service; then
        run systemctl kill -s SIGKILL sleepmgr-gate.service || true
    fi
fi

NFT_ERR="$(mktemp)" || { echo "ERROR: cannot create a temporary file" >&2; exit 1; }
trap 'rm -f "$NFT_ERR"' EXIT HUP INT TERM

# Remove exactly our table.  "does not exist" is success; any other failure is
# *unknown*, so we preserve the seal marker and fail closed rather than pretend
# the gate is open.
if "$NFT" delete table inet "$TABLE" 2> "$NFT_ERR"; then
    :
elif grep -Eqi 'no such file|does not exist' "$NFT_ERR"; then
    :
else
    echo "ERROR: cannot remove table inet $TABLE: $(cat "$NFT_ERR")" >&2
    echo "       leaving $SEALED_STATE in place; the gate state is UNKNOWN" >&2
    exit 1
fi

# Prove absence explicitly.  A failed listing is unknown, not absence.
if "$NFT" list table inet "$TABLE" >/dev/null 2> "$NFT_ERR"; then
    echo "ERROR: table inet $TABLE still exists" >&2
    exit 1
fi
if ! grep -Eqi 'no such file|does not exist' "$NFT_ERR"; then
    echo "ERROR: cannot determine whether table inet $TABLE is gone: $(cat "$NFT_ERR")" >&2
    echo "       leaving $SEALED_STATE in place; the gate state is UNKNOWN" >&2
    exit 1
fi

# The table is provably gone, so the seal marker may now be cleared.  Removing
# it is essential: otherwise a restarted helper would restore the seal and close
# the gate again.  The legacy /run path is removed too so a pre-upgrade marker
# cannot be mistaken for a seal by an older helper.
rm -f "$SEALED_STATE" "$LEGACY_SEALED_STATE"
echo "gate open: table inet $TABLE is absent"

# Advisory only: Strata may be unloaded and slow to answer, but the gate is open
# regardless.  Never fail the rollback because of this check.  Use curl if
# present, otherwise the system Python (curl is not installed on every host).
health_ok=0
if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1 && health_ok=1
elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2)' >/dev/null 2>&1 && health_ok=1
fi
if [ "$health_ok" -eq 1 ]; then
    echo "local /health: OK"
else
    echo "local /health: no response (gate is open; check Strata separately)"
fi
