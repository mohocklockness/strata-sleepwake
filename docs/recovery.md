# Recovery

The system is designed to **fail closed**: if it cannot prove that sleeping is
safe, it does not sleep; if it cannot prove that waking finished, it keeps the
request gate closed. Recovery therefore means restoring evidence, not forcing a
state.

## Decide which failure you have

| symptom | likely cause | first check |
|---|---|---|
| no suspend ever happens | a detector reports `UNKNOWN`, a pause is active, or the gate is closed | `sleepmgr-ctl status`, `journalctl -u sleepmgr.service` |
| suspend aborted during quiesce | unload or verification failed | `journalctl -u sleepmgr.service`, `POST /health` |
| host resumed but inference is refused | gate still sealed or Strata not ready | `ss -ltn`, `GET /health`, gate status |
| everything is blocked and you need service now | gate/helper wedged | emergency opener (below) |
| monitor will not start | lock held, config invalid | `monitor.lock`, `config_guard.py` output |

## Monitor crash or stop

- The gate's ordinary `close` is a **lease** bound to the monitor's socket. On
  EOF the helper reopens the gate. Check with `systemctl status
  sleepmgr-gate.service` and the helper log.
- The sleep guard is **independent**. It keeps its logind block inhibitor, so
  the host cannot suspend while the monitor is down. That is intentional.
- Restart the monitor:

  ```bash
  sudo systemctl restart sleepmgr.service
  sleepmgr-ctl status
  ```

## Request gate sealed after a crash or reboot

A controlled-suspend seal is durable for the boot. After a reboot the marker
belongs to the previous boot and is re-evaluated at boot:

- `sleepmgr-gate-boot.service` runs before `network-pre.target`, re-seals when a
  marker survives, and exits 0 on a clean boot.
- `strata.service` has `Requires=` + `After=` on that unit, so a boot that
  cannot establish the seal does not start Strata. Host networking is
  untouched: SSH and local troubleshooting still work.

Inspect without changing anything:

```bash
systemctl status sleepmgr-gate-boot.service
journalctl -u sleepmgr-gate-boot.service -n 50 --no-pager
nft list table inet sleepmgr_gate          # root
```

## Emergency: reopen the gate now

The opener is deliberately independent of the helper and the monitor (it does
not use the control socket, `netgate.py` or `nftgate_helper.py`).

```bash
sudo /usr/local/sbin/sleepmgr-gate-emergency-open --dry-run   # print, change nothing
sudo /usr/local/sbin/sleepmgr-gate-emergency-open             # delete the table, clear markers
sudo /usr/local/sbin/sleepmgr-gate-emergency-open --nft-only  # table only, leave markers
```

It removes the marker **only after** the table is provably gone. If the delete
or the verification fails, it exits non-zero and leaves the marker in place —
that is the fail-closed behaviour, not a bug.

> Reopening the gate does not make it safe to suspend. It restores service.

## Suspend aborted mid-quiesce

Expected order: seal gate → re-check idle → unload → verify → release guard →
suspend. If any step fails, the coordinator aborts and reloads Strata.

```bash
journalctl -u sleepmgr.service -n 100 --no-pager
python3 /opt/sleepmgr/sleepmon.py --resume-check
```

If the model is unloaded and the gate is sealed after an aborted cycle, use the
normal `--arm-once` path or the emergency opener — do not hand-edit state files.

## Resumed but not ready

The gate stays closed until recovery verifies:

1. guard reacquired (bounded retry; logind can report `OperationInProgress`);
2. `POST /load` succeeded, or a running load was detected and waited for;
3. `/health.loaded == true` and `/status` is not busy/queued;
4. GPU/RAM checks pass.

Check the actual state rather than restarting blindly:

```bash
python3 /opt/sleepmgr/sleepmon.py --resume-check
systemctl status sleepmgr-suspend-guard.service sleepmgr-gate.service
```

A restart of `sleepmgr-gate.service` does **not** open a sealed gate.

## Guard will not release

The guard releases only after fresh read-only samples show: Strata not busy,
no compute clients, low VRAM and GPU utilisation, enough available RAM, and a
reachable, closed gate.

```bash
systemctl status sleepmgr-suspend-guard.service
cat /run/sleepmgr-suspend-guard/status.json      # if readable
nvidia-smi
python3 /opt/sleepmgr/sleepmon.py --once --json
```

A guard restart is not a safe event; it records the unprotected gap. Never
`systemctl stop` the guard to force a suspend.

## Pause is stuck

Pause state is atomic with a `.bak`; a corrupt file fails **safe** to paused.

```bash
sleepmgr-ctl status
sleepmgr-ctl resume
```

If the control socket is unavailable, check that the monitor is running; the
state file is at `/var/lib/sleepmgr/state.json` (`/tmp/opencode/sleepmgr/` in
the development config).

## Full rollback

`docs/deploy-selective.md` documents selective deployment and rollback in
detail, including backups of installed code, units, config and unit
enablement. The short version:

```bash
sudo systemctl disable --now sleepmgr.service sleepmgr-gate.socket
sudo rm /etc/systemd/system/strata.service.d/10-sleepmgr-gate-boot.conf
sudo rm /etc/systemd/system/sleepmgr*.service /etc/systemd/system/sleepmgr*.socket
sudo rm /etc/systemd/system/sleepmgr-gate-boot.service
sudo systemctl daemon-reload
```

Remove only the `strata.service.d` drop-in, not the whole directory, if other
drop-ins exist. Restore files from your backup, then verify Strata starts and
serves again.

## What recovery cannot do

- It cannot preserve VRAM across S3; the model is always reloaded.
- It cannot revoke an already-established inference connection.
- It cannot fix a firmware/kernel suspend hang. Power-cycle, then verify the
  gate and guard state before re-arming.
