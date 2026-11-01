# Supervised one-shot suspend/resume

`--arm-once` is a foreground, interactive mode that runs **one** real
gate-first suspend/resume cycle and exits.  It is not a service mode and does
not change `allow_unattended_suspend`.

## Safety properties

- Requires an interactive terminal.  Non-interactive execution returns `2`.
- Requires the configured service lock.  If the installed monitor (or any
  other monitor using that lock) is running, it exits with code `3`; there is no
  second gate owner.
- Uses exactly the same `service.lock_file` as the regular monitor.  It does
  not create a second, independent lock.  `--lock-file` is rejected in this
  mode so the caller cannot redirect the lock and run alongside the service.
- The service unit sets `RuntimeDirectoryPreserve=yes`.  `/run/sleepmgr` is a
  systemd `RuntimeDirectory`; with the default `RuntimeDirectoryPreserve=no`,
  systemd deletes it when the service stops.  Because `/run` is root-owned,
  sleepuser cannot recreate it.  Preserving the directory keeps the same
  `monitor.lock` available to the foreground one-shot.
- If the directory is still missing, the one-shot refuses with an actionable
  preflight error instead of a raw `PermissionError`.
- It cannot be combined with `--service`, `--arm`, `--once`, `--resume-check`
  or `--reload-strata`.
- It does not start the control socket.  The operator types `SUSPEND` at the
  prompt; after the cycle the process exits.
- It runs the same `final_check` as the automatic path (fresh workload sweep,
  pause check, polkit authorization, own-guard-tolerant inhibitor check,
  `CanSuspend`), except that the idle threshold is explicitly overridden by
  the operator trigger.
- It then runs `suspendflow.run_quiesce` with the same gate-first ordering:
  pre-gate idle -> seal gate -> settle/post-gate idle -> unload -> verify
  GPU/CUDA/RAM/gate -> release guard -> `systemctl suspend
  --check-inhibitors=yes` -> wait for the real resume -> reacquire guard
  (bounded retry) -> NVIDIA -> reload -> readiness -> reopen gate.
- `systemctl suspend` is asynchronous: it returns after logind enqueues the
  operation, not after wake.  The monitor therefore waits for a real
  suspend/resume time gap before attempting recovery.  This avoids racing
  logind while it is still finishing the suspend operation.  The wait is capped
  by `suspend_resume_wait_s` (default 120 s of awake time; the cap does not
  expire while the process is frozen).
- Guard reacquisition is retried for `suspend_guard.post_resume_acquire_timeout_s`
  (default 90 s).  Logind can reject a new inhibitor with
  `OperationInProgress` for several seconds after resume; that is transient and
  must not abort recovery.
- The post-resume `POST /load` is retried for
  `strata.recovery_timeout_s` (default 180 s) with each request bounded by
  `strata.load_request_timeout_s` (default 120 s).  A lost reply is not assumed
  to be a failed load: `/health` and `/status queued` are re-read first, so an
  already-running load is waited for instead of posted twice.  Every attempted
  host and its actual error is logged.
- The gate is sealed rather than leased for the whole suspend window.  If
  recovery cannot confirm guard protection and Strata readiness, the gate stays
  closed even after the one-shot process exits.  The process exits nonzero; it
  does not leave a monitor running.

## Prerequisites

1. The updated unit is installed and has been started/stopped once so
   `RuntimeDirectoryPreserve=yes` has preserved `/run/sleepmgr`, and the
   service is stopped (do not run this while the service holds
   `/run/sleepmgr/monitor.lock`).  If the directory is absent, start the
   service once, stop it, and retry; do not create it as root or use a
   different lock path.
2. `allow_unattended_suspend=false` remains in `/etc/sleepmgr/config.json`.
3. The guard is active/protected, the gate is healthy or intentionally closed,
   and Strata is healthy in its current loaded state.
4. The terminal is the active local session (tty2 in the current setup), so
   polkit's `allow_active=yes` applies.  The service authorization rule is not
   required for this supervised path, but it should still be approved before
   unattended use.
5. Run the monitor itself as `sleepuser`, not with `sudo`: root cannot use
   the GNOME/Mutter idle probe and the Strata/OpenCode files are owned by the
   desktop user.  Use `sudo` only for the service stop/start commands.

## Deployment note

Install the updated `deploy/sleepmgr.service` and run `systemctl
daemon-reload`.  Start the service once in dry-run mode, then stop it: that
creates `/run/sleepmgr` and exercises the `RuntimeDirectoryPreserve=yes`
setting.  The one-shot still uses the same `monitor.lock`; do not replace it
with a per-user or temporary lock.

The updated `netgate.py` and `nftgate_helper.py` must be deployed together.
The monitor uses the new `seal` protocol; an older helper will refuse it, and
the monitor will abort **before** unloading Strata rather than fall back to an
ordinary lease.  The gate unit also needs `StateDirectory=sleepmgr-gate` and
`ReadWritePaths=/var/lib/sleepmgr-gate` so the boot-scoped seal marker is
writable under `ProtectSystem=strict` and survives runtime-directory cleanup.
The marker is in persistent state, not `/run`; a full reboot changes the boot
id, so a stale marker is ignored (nftables state is gone too).

## Run (after separate deployment approval)

```bash
sudo systemctl stop sleepmgr.service
systemctl is-active sleepmgr.service     # expect: inactive
/usr/bin/python3 /opt/sleepmgr/sleepmon.py \
    --config /etc/sleepmgr/config.json --arm-once
```

At the prompt type `SUSPEND`.  Do not type it in a non-interactive wrapper.

After the cycle, inspect:

```bash
tail -n 80 /var/log/sleepmgr/monitor.log
tail -n 20 /var/log/sleepmgr/suspend.jsonl
cat /run/sleepmgr/status.json
```

The successful journal should show gate close before unload, guard release only
after post-unload verification, guard reacquisition and NVIDIA/readiness checks
after resume, and gate reopen last.

## Abort / recovery

If preflight fails, nothing is unloaded and the gate is unchanged.  If the
cycle aborts after the gate closes, the monitor seals the gate, attempts a
bounded guard reacquisition, reloads Strata when safe, and reopens only after
both guard protection and inference readiness are confirmed.  If it cannot, the
gate stays sealed after the one-shot process exits; it does not fail open.
Use the independent emergency opener only after verifying that Strata is not
active and after restoring guard protection:

```bash
# Review before running; this is the independent fallback, not a monitor call.
sudo sleepmgr/deploy/sleepmgr-gate-emergency-open.sh
```

Do not start the installed service while a one-shot process is running.  Do not
enable unattended suspension as part of this test.
