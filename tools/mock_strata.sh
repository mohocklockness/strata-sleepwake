#!/usr/bin/env bash
# Lab-only helper: run and stop the tiny mock Strata server safely.
#
# Lesson learned (2026-10-19 13:41): the mock was cleaned up with a broad
#   pgrep -f "[S]trata/serve/server.py"
# which ALSO matched the real Strata server's command line
#   /srv/strata/Strata/.venv/bin/python /srv/strata/Strata/serve/server.py ...
# and SIGTERM'd it (same uid, so the signal was permitted).  The mock exists
# only to exercise the monitor's refusal paths; it must never be able to touch
# the real service.
#
# Rules enforced here:
#   1. The mock always records its own PID in a PID file when started.
#   2. Stop reads that PID and kills ONLY that PID, and only after confirming
#      its cmdline contains the exact mock path (never a substring shared with
#      the real server).
set -euo pipefail

MOCK_PATH="${MOCK_PATH:-/tmp/opencode/sleepmgr-it/Strata/serve/server.py}"
PID_FILE="${MOCK_PID_FILE:-/tmp/opencode/sleepmgr-it/mock-strata.pid}"
PORT="${MOCK_PORT:-18080}"
LOG_FILE="${MOCK_LOG:-/tmp/opencode/sleepmgr-it/mock-strata.log}"

usage() { echo "usage: $0 {start|stop|status}" >&2; exit 2; }

start() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "mock already running: pid $(cat "$PID_FILE")"
    return 0
  fi
  [ -f "$MOCK_PATH" ] || { echo "mock source not found: $MOCK_PATH" >&2; exit 1; }
  mkdir -p "$(dirname "$PID_FILE")"
  # Start detached, record the real pid, and confirm it is up.
  nohup python3 "$MOCK_PATH" >"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 0.5
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || { echo "mock failed to start; see $LOG_FILE" >&2; exit 1; }
  echo "mock started: pid $(cat "$PID_FILE") on 127.0.0.1:$PORT"
}

stop() {
  if [ ! -f "$PID_FILE" ]; then
    echo "no pid file ($PID_FILE); nothing to stop"
    return 0
  fi
  local pid cmd
  pid="$(cat "$PID_FILE")"
  if [ -z "$pid" ]; then
    rm -f "$PID_FILE"
    echo "empty pid file; removed"
    return 0
  fi
  if [ ! -e "/proc/$pid" ]; then
    rm -f "$PID_FILE"
    echo "pid $pid is not running; removed stale pid file"
    return 0
  fi
  cmd="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
  case "$cmd" in
    *"$MOCK_PATH"*)
      kill -TERM "$pid" && echo "stopped mock pid $pid"
      rm -f "$PID_FILE"
      ;;
    *)
      # Leave the pid file intact: it may still track the real mock, and we
      # must never drop our only handle on it because of a foreign pid.
      echo "REFUSING to kill pid $pid: cmdline does not contain the exact mock path" >&2
      echo "  cmdline: $cmd" >&2
      ;;
  esac
}

status() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "mock running: pid $(cat "$PID_FILE")"
  else
    echo "mock not running"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) usage ;;
esac
