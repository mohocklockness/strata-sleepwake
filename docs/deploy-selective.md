# Selective deployment and rollback

This document describes a **source-only** deployment procedure.  It does not
arm the monitor, enable unattended suspension, or change `/etc/sleepmgr/config.json`
unless the operator explicitly asks for it and the proposed change preserves
gate/guard protection.

## Boot policy (proposed)

1. `sleepmgr-gate.socket` is enabled at boot and creates
   `/run/sleepmgr-gate/gate.sock` as `root:sleepuser 0660`.
2. `sleepmgr-gate-boot.service` is enabled at boot.  It is an `nftables.service`
   style one-shot (`DefaultDependencies=no`, `Before=network-pre.target`,
   `WantedBy=sysinit.target`) that runs `deploy/sleepmgr-gate-boot.sh`.  It is
   deliberately **not** skipped by a `ConditionPathExists` on a clean boot: it
   always runs and exits 0 when there is no seal marker, so its own success can
   be depended on.  If the durable seal marker survived the reboot, the previous
   boot ended inside a controlled suspend seal, so the script **verifies the
   intended blocking rule** with the *same semantic checker* the helper uses at
   runtime (`nftgate_helper.py --verify-listing`): the actual configured ports,
   a blocking verdict (`drop`/`reject`), a SYN-only match, the loopback
   exemption, an input *base chain* hooked early enough to be effective, the
   ownership comment, no *extra* match restriction (such as a source address),
   and no earlier rule **in that chain** that accepts or skips the gated
   traffic.  (An accept in another base chain does not bypass a later drop
   chain: every base chain for the hook is evaluated and any drop wins.)  Merely finding the table, or a
   line containing `tcp dport`, is not protection.  When the table is missing,
   empty or wrong it **atomically restores** the owned ruleset in one `nft -f`
   transaction before the network is usable.  Every external command is explicit
   and its exit status is checked, so a missing tool, a failed generator or a
   failed `nft` makes the unit fail rather than silently passing.  A table that
   cannot be *inspected* (any error other than "no such file") is treated as
   **unknown, never as absence**, and fails the unit closed.
   - The installer drops in
     `/etc/systemd/system/strata.service.d/10-sleepmgr-gate-boot.conf`
     (`Requires=`/`After=sleepmgr-gate-boot.service`) so a boot that cannot
     establish the required seal also stops `strata.service` (which is enabled
     and `After=network-online.target`) from accepting remote inference.  Only
     the configured inference port is gated, so **host networking stays up** for
     troubleshooting.
3. `sleepmgr.service` has `Wants=sleepmgr-gate.socket` and
   `After=sleepmgr-gate.socket`.  The socket listener therefore exists before
   the monitor's startup preflight; the privileged helper starts on the first
   authenticated connection, not unconditionally as root.
4. On cold boot, the helper's `startup_recover()` is fail-closed:
   - a seal marker from **this boot** is restored and the table is re-applied
     if it is missing;
   - a seal marker from an **earlier boot** is not discarded: it is the
     surviving evidence that the previous boot ended inside a seal, so this
     boot is re-sealed and the marker is rewritten with the current boot id;
   - a surviving closed table without a marker is adopted as sealed;
   - after any of these paths, the helper compares its logical state with the
     actual nftables table.  A closed/sealed gate with zero blocking rules is
     re-applied, and startup aborts if it still cannot be proven blocking.
5. The monitor does not treat a socket path or a running process as readiness.
   Before arming/unloading it calls the helper's `status` (derived from a live
   nftables query) and the guard's `status`, and refuses to unload if either is
   unverifiable.  It also requires the helper to report live **rule
   verification** (`consistent` must be the boolean `true`, `verified` must not
   be `false`, and `rules` must be a positive integer when closed; a mismatched
   `actual_state` is refused).  The helper derives that from the semantic check
   above, so a wrong-port, accept, unhooked or bypassed rule is refused even
   though the table exists.  An older helper that reports only its logical lease
   state, or that merely names the fields without proven values, is refused
   rather than trusted.  The monitor's sustained post-gate re-check
   (`gate_recheck`) and the seal/unload path (`run_quiesce`) both use this same
   proof, so a gate that is only *claimed* closed cannot pass the safety
   argument or be released.  A sealed gate is opened only after the guard is
   protected and Strata passes both the loaded/status check and the one-token
   inference smoke test.  The same protection proof is repeated **before
   reopening after resume**, so a gate is never opened merely because an
   earlier `seal` reply claimed success.
6. Monitor startup recovery is **bounded and retried**
   (`gate.startup_recovery_timeout_s`, default 180 s;
   `gate.startup_recovery_interval_s`, default 2 s).  While it retries it keeps
   the seal and the guard inhibitor; a permanent failure leaves the gate sealed
   and records `gate_recovery.state = "recovery-failed"` in the status document.
7. If `gate.enabled=true` but the gate helper is missing, the monitor fails
   closed and will not unload or open the gate.  The safe fix is to install the
   gate units and token, or deliberately set `gate.enabled=false` while keeping
   the monitor dry-run.

## Preserve the live configuration

`deploy/install.sh` now:

- leaves an existing `/etc/sleepmgr/config.json` untouched by default and writes
  the proposed file to `config.json.new`;
- compares the existing and proposed files with `deploy/config_guard.py`;
- refuses a replacement that disables `gate.enabled`, disables
  `suspend_guard.enabled`, removes `suspend_guard.require_gate`, or removes a
  control-token requirement, unless
  `--allow-protection-downgrade` is also given;
- never edits Strata's own config.  Strata keeps its current bind address; this
  change deliberately probes the configured host plus loopback fallbacks rather
  than rebinding Strata to `127.0.0.1`.

To replace the live config intentionally:

```bash
sudo python3 /home/sleepuser/strata-sleepwake/deploy/config_guard.py \
  /etc/sleepmgr/config.json /etc/sleepmgr/config.json.new
sudo /home/sleepuser/strata-sleepwake/deploy/install.sh \
  --apply --replace-config
```

Only add `--allow-protection-downgrade` when the downgrade is an explicit,
reviewed decision.  Keep a backup:

```bash
sudo cp -a /etc/sleepmgr/config.json /etc/sleepmgr/config.json.bak.$(date +%Y%m%dT%H%M%S)
```

## Backups (before any deployment)

Capture everything the install touches, so a rollback is byte-exact.  Do this
as root and keep the archive off the machine you are changing:

```bash
STAMP=$(date +%Y%m%dT%H%M%S)
BK=/root/sleepmgr-backup-$STAMP
sudo install -d -m 0700 "$BK"
# 1. installed code and units (copy per file: a not-yet-installed unit must not
#    abort the whole copy)
sudo cp -a /opt/sleepmgr "$BK/opt-sleepmgr"
for f in /etc/systemd/system/sleepmgr.service \
         /etc/systemd/system/sleepmgr-gate.service \
         /etc/systemd/system/sleepmgr-gate.socket \
         /etc/systemd/system/sleepmgr-gate-boot.service \
         /etc/systemd/system/sleepmgr-suspend-guard.service; do
  sudo cp -a "$f" "$BK/" 2>/dev/null || true
done
# The drop-in that makes strata.service depend on the boot seal (installed only
# with --with-gate).  A rollback that forgets it leaves Strata bound to a
# removed/older boot unit.
sudo cp -a /etc/systemd/system/strata.service.d "$BK/strata.service.d" \
  2>/dev/null || true
for f in /usr/local/sbin/sleepmgr-gate-emergency-open \
         /usr/local/sbin/sleepmgr-gate-boot \
         /usr/local/bin/sleepmgr-gui /usr/local/bin/sleepmgr-ctl; do
  sudo cp -a "$f" "$BK/" 2>/dev/null || true
done
# 2. configuration (the live file plus the seal marker's directory)
sudo cp -a /etc/sleepmgr "$BK/etc-sleepmgr"
sudo cp -a /var/lib/sleepmgr-gate "$BK/var-lib-sleepmgr-gate" 2>/dev/null || true
# 3. unit enablement state (what will start at boot), unit by unit
for u in sleepmgr.service sleepmgr-gate.service sleepmgr-gate.socket \
         sleepmgr-gate-boot.service sleepmgr-suspend-guard.service; do
  printf '%s = %s\n' "$u" "$(systemctl is-enabled "$u" 2>&1)" \
    >> "$BK/enablement.txt"
done
sudo find /etc/systemd/system -maxdepth 2 \
  \( -path '*multi-user.target.wants*' -o -path '*sockets.target.wants*' \
     -o -path '*sysinit.target.wants*' \) -name 'sleepmgr*' -printf '%p -> %l\n' \
  >> "$BK/enablement.txt" 2>/dev/null || true
sudo tar -C / -czf "$BK.tgz" "$BK" && echo "backup: $BK.tgz"
```

The enablement snapshot is what lets you restore *exactly* which units were
disabled before, without enabling more than was enabled.

## Selective source deployment

Dry-run first (the default changes nothing):

```bash
cd "/home/sleepuser/strata-sleepwake"
./deploy/install.sh --with-gate
```

Install the monitor, preserve the existing config, and install but do not
enable the gate units:

```bash
sudo ./deploy/install.sh --apply --with-gate
```

Install and enable the gate socket at boot (the monitor service is enabled but
remains dry-run because the shipped unit has no `--arm`):

```bash
sudo ./deploy/install.sh --apply --with-gate --enable
```

That is equivalent to:

```bash
sudo systemctl enable --now sleepmgr-gate.socket
sudo systemctl enable sleepmgr-gate-boot.service   # deliberately no --now
sudo systemctl enable --now sleepmgr.service
```

`enable` records the boot policy.  `--now` is used for the socket (so the
listener exists immediately for the supervised live test) and for the monitor,
but it is deliberately **omitted** for the boot one-shot: running it mid-install
would execute the firewall phase outside its boot ordering.  When the monitor is
later armed, `sleepmgr-gate-boot.service` will already be enabled and will run
in the right place at the next boot.  `sleepmgr.service` remains dry-run because
the shipped unit has no `--arm`.

Required one-time gate token (never commit it):

```bash
sudo install -m 0640 -o root -g sleepuser /dev/null /etc/sleepmgr/gate.token
sudo sh -c 'head -c 32 /dev/urandom | base64 > /etc/sleepmgr/gate.token'
```

Then run the supervised live test in `docs/gate-live-test.md` before setting
`gate.enabled=true`.

## Rollback

1. Stop the monitor first, then the gate listener/helper, so no recovery is in
   flight.  **`strata.service` has `Requires=sleepmgr-gate-boot.service`**, so
   stopping (or `disable --now`) that unit also stops Strata.  Remove the drop-in
   first if you want Strata to keep running:
   ```bash
   sudo systemctl stop sleepmgr.service
   sudo systemctl stop sleepmgr-gate.socket sleepmgr-gate.service
   sudo rm -f /etc/systemd/system/strata.service.d/10-sleepmgr-gate-boot.conf
   sudo systemctl daemon-reload
   sudo systemctl disable sleepmgr-gate-boot.service
   # Only now, and only if you no longer need the boot seal, stop the unit
   # without dragging Strata down with it.
   sudo systemctl stop sleepmgr-gate-boot.service 2>/dev/null || true
   ```
2. Restore **tracked files** from the backup and remove only the files this
   deployment introduced.  Do not delete a whole directory: preserve unrelated
   Strata drop-ins.
   ```bash
   BK=/root/sleepmgr-backup-<stamp>
   # Files that existed in the backup are restored byte-for-byte.
   [ -d "$BK/opt-sleepmgr" ] && sudo cp -a "$BK/opt-sleepmgr/." /opt/sleepmgr/
   [ -d "$BK/etc-sleepmgr" ] && sudo cp -a "$BK/etc-sleepmgr/." /etc/sleepmgr/
   for f in "$BK"/sleepmgr*.service "$BK"/sleepmgr*.socket; do
     [ -e "$f" ] && sudo cp -a "$f" /etc/systemd/system/
   done
   for f in sleepmgr-gate-emergency-open sleepmgr-gate-boot; do
     [ -e "$BK/$f" ] && sudo cp -a "$BK/$f" /usr/local/sbin/
   done
   # Restore only the drop-in we track; other strata.service.d files are left
   # exactly as they are.
   if [ -e "$BK/strata.service.d/10-sleepmgr-gate-boot.conf" ]; then
     sudo install -d /etc/systemd/system/strata.service.d
     sudo cp -a "$BK/strata.service.d/10-sleepmgr-gate-boot.conf" \
       /etc/systemd/system/strata.service.d/
   else
     # Newly introduced: remove just this file, then the directory only if it
     # is empty (an unrelated Strata drop-in keeps it in place).
     sudo rm -f /etc/systemd/system/strata.service.d/10-sleepmgr-gate-boot.conf
     sudo rmdir /etc/systemd/system/strata.service.d 2>/dev/null || true
   fi
   # Newly installed files the backup does not contain are removed.
   for f in sleepmgr-gate-boot sleepmgr-gate-emergency-open; do
     [ -e "$BK/$f" ] || sudo rm -f "/usr/local/sbin/$f"
   done
   for u in sleepmgr-gate.service sleepmgr-gate.socket sleepmgr-gate-boot.service; do
     [ -e "$BK/$u" ] || sudo rm -f "/etc/systemd/system/$u"
   done
   ```
3. Restore the **unit enablement** recorded in `$BK/enablement.txt` exactly:
   enable/disable each unit to match the snapshot rather than assuming.  For a
   revert to a gate-less install that means
   `sudo systemctl disable sleepmgr-gate.socket` and
   `sudo systemctl disable sleepmgr-gate-boot.service` (use plain `disable`, not
   `--now`, for the boot unit unless you have already removed the drop-in in
   step 1, because stopping it stops Strata).
4. If the gate was sealed, confirm the guard and Strata first, then open it.
   The emergency opener has no `--status` mode; use `--dry-run` to see what it
   would do.  **A running unit is not proof that the inhibitor is held** —
   read the guard's own status document (rewritten on every poll) and require
   `held`, `protected` and no active authorization:
   ```bash
   sudo python3 - <<'PY'
   import json, sys
   doc = json.load(open("/run/sleepmgr-suspend-guard/status.json"))
   held = bool(doc.get("held")) and bool(doc.get("protected"))
   print(f"guard: held={doc.get('held')} protected={doc.get('protected')} "
         f"authorized={doc.get('authorized')} state={doc.get('state')}")
   sys.exit(0 if held and not doc.get("authorized") else 1)
   PY
   ```
   If `suspend_guard.enabled` is false there is no independent inhibitor to
   check; record that explicitly rather than treating the gate seal alone as
   equivalent to guard protection.

   Check the **configured** Strata endpoint.  This instance is LAN-bound and
   `/status` requires the API key, so an unauthenticated loopback `/status`
   proves nothing about the loaded model.  The shipped probe reads
   `strata.config_path`, uses that host/port/Bearer key, and exercises a
   one-token inference request:
   ```bash
   sudo python3 - <<'PY'
   import json, sys
   sys.path.insert(0, "/opt/sleepmgr")
   import detectors
   full = json.load(open("/etc/sleepmgr/config.json"))
   cfg = full.get("strata") or {}
   probe = detectors.StrataProbe(cfg)
   health = probe.get("/health", auth=False)
   status = probe.get("/status")
   loaded = health.get("loaded") is True
   idle = status.get("busy") is False and int(status.get("queued") or 0) == 0
   print(f"strata: health.loaded={loaded} status.busy={status.get('busy')} "
         f"status.queued={status.get('queued')}")
   ok, msg = detectors.strata_readiness(cfg, deadline_s=30)
   print(("ready: " if ok else "NOT ready: ") + msg)
   sys.exit(0 if loaded and idle and ok else 1)
   PY
   ```
   `/health` is the endpoint that reports `loaded` on this server; `/status`
   is used for authenticated `busy`/`queued`, not for `loaded`.  The one-token
   readiness call proves the model can actually answer, not merely that the
   process is up.

   Only after both checks pass should the gate be opened:
   ```bash
   sudo /usr/local/sbin/sleepmgr-gate-emergency-open --dry-run
   sudo /usr/local/sbin/sleepmgr-gate-emergency-open
   ```
   The opener only clears the seal marker after the table is provably removed;
   if it cannot remove or inspect the table it keeps the marker and exits
   non-zero.
5. Reload and restart the monitor:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start sleepmgr.service
   ```
6. Do not delete `/var/lib/sleepmgr-gate/sealed.json` as a shortcut.  A seal is
   authoritative; delete it only after the gate has been explicitly opened and
   the model is verified loaded and ready.

## Verification after a source-only change

```bash
python3 -m unittest discover -s tests
systemctl --no-pager status sleepmgr-gate.socket sleepmgr-gate.service sleepmgr.service
journalctl -u sleepmgr-gate.service -b --no-pager
```
