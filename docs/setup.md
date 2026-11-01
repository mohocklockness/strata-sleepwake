# Setup

This is the setup path for a host that already runs Strata. Nothing here is
required to read the code; the examples are safe defaults (dry-run, gate off,
unattended suspension off).

## Assumptions

- Ubuntu-like host with systemd, logind, Python 3, and a graphical session for
  Mutter idle detection (a headless host falls back to the logind idle hint).
- A GPU host that already runs Strata. The reference host has two Tesla T4
  GPUs, 16 cores and 62.5 GiB RAM; a single GPU works the same way.
- Strata installed at `/srv/strata/Strata` and listening on the LAN address,
  e.g. `192.0.2.10:8080`. Its `/health` endpoint is unauthenticated; `/status`
  requires the API key from the Strata config.
- The **control center** (wake gateway) is a separate machine and is **not**
  installed by this repository. See [`wake-gateway.md`](wake-gateway.md).
- A dedicated unprivileged account for the service. The packaged units and the
  installer assume `sleepuser` (uid 1000); change `User=`, `Group=`,
  `SocketGroup=`, `pause.group` and `suspend_guard.group` if your account
  differs. **The installer hard-codes `/home/sleepuser` and uid 1000 for the
  desktop entry — adjust `deploy/install.sh` for a different account.**
- NVIDIA driver and `nvidia-smi` available to that account.

## 0. Restore executable bits (browser upload only)

A drag-and-drop upload to GitHub does not preserve the executable bit. Run the
command below once in the repository root before the steps in this guide.

Git clone preserves executable permissions recorded in the repository. For this
browser-uploaded version, run the chmod command below after cloning or
downloading; cloning alone does not restore the original executable flags.

```bash
chmod +x \
  deploy/config_guard.py \
  deploy/install.sh \
  deploy/sleepmgr-ctl \
  deploy/sleepmgr-gate-emergency-open.sh \
  deploy/sleepmgr-gui \
  tools/mock_strata.sh \
  tools/send_strata_prompt.py
```

## 1. Review, do not install

```bash
./deploy/install.sh            # prints the plan, changes nothing
```

The installer never arms the monitor. `--apply` is required to write files, and
`--enable` to enable the unit.

## 2. Install the monitor (dry-run)

```bash
sudo ./deploy/install.sh --apply
```

This installs:

| path | content |
|---|---|
| `/opt/sleepmgr/` | the Python modules and README |
| `/etc/sleepmgr/config.json` | the production example (existing files are preserved; a proposal is written to `config.json.new`) |
| `/etc/systemd/system/sleepmgr.service` | the monitor unit (dry-run) |
| `/etc/polkit-1/rules.d/00-sleepmgr-inhibit.rules` | allows the monitor to take its own inhibitor |
| `/usr/local/bin/sleepmgr-{ctl,gui}` | control entry points |

`deploy/config_guard.py` refuses to replace a live config that removes gate or
guard protection unless `--replace-config --allow-protection-downgrade` is
given explicitly.

Start it without enabling it:

```bash
sudo systemctl start sleepmgr.service
systemctl status sleepmgr.service
sleepmgr-ctl status
```

It will report "would suspend" but never suspend.

## 3. Configure

Edit `/etc/sleepmgr/config.json`. The important safe switches:

```json
"service": { "allow_unattended_suspend": false },
"gate":    { "enabled": false },
"suspend_guard": { "enabled": true, "require_token": true }
```

Paths that are specific to your machine:

| key | meaning |
|---|---|
| `strata.config_path` | Strata's model config, used to read the API key at runtime |
| `strata.server_cmdline_substrings` / `engine_cmdline_substrings` | how the monitor recognises Strata processes |
| `opencode.db_path` | agent-job database (read-only) |
| `streams.log_path` | Sunshine log (read-only) |
| `transfers.net_ifaces` / `disk_devices` | interfaces and disks for throughput detection |
| `pause.group`, `suspend_guard.group` | group allowed to use the control sockets |

Then:

```bash
sudo systemctl restart sleepmgr.service
python3 /opt/sleepmgr/sleepmon.py --once --json
```

## 4. Optional: the request gate

The gate is a **separate privilege decision**. Read
[`inference-gate.md`](inference-gate.md) and
[`gate-live-test.md`](gate-live-test.md) first.

```bash
sudo ./deploy/install.sh --apply --with-gate
sudo install -m 0640 -o root -g sleepuser /dev/null /etc/sleepmgr/gate.token
sudo sh -c 'head -c 32 /dev/urandom | base64 > /etc/sleepmgr/gate.token'
sudo chmod 0640 /etc/sleepmgr/gate.token
sudo systemctl enable --now sleepmgr-gate.socket
```

The `.socket` unit creates `/run/sleepmgr-gate/gate.sock` as
`root:sleepuser 0660`; the helper inherits the listening fd and keeps only
`CAP_NET_ADMIN`. Then set `gate.enabled: true` and restart the monitor.

Do **not** enable the gate on a production host without running the supervised
live test: the nft ruleset and packet behaviour were validated only in
throwaway network namespaces and a controlled test, not on every kernel.

## 5. Optional: arming unattended suspension

Two independent switches must agree:

1. `service.allow_unattended_suspend: true` in `/etc/sleepmgr/config.json`;
2. `--arm` on the command line.

The packaged unit has no `--arm`. A local drop-in is the usual way to arm:

```ini
# /etc/systemd/system/sleepmgr.service.d/90-auto-suspend.conf
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /opt/sleepmgr/sleepmon.py --config /etc/sleepmgr/config.json --service --arm
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart sleepmgr.service
```

Arming is a deliberate operational decision. Verify the gate, the guard and a
supervised `--arm-once` cycle first (see [`one-shot.md`](one-shot.md)). The
author's live host uses exactly this drop-in; it is intentionally not shipped.

## 6. Verify

```bash
systemctl is-active sleepmgr.service sleepmgr-suspend-guard.service
sleepmgr-ctl status
python3 /opt/sleepmgr/sleepmon.py --resume-check
journalctl -u sleepmgr.service -n 50 --no-pager
```

For a real end-to-end check, use the supervised one-shot mode from a terminal
(`python3 sleepmon.py --arm-once`) rather than restarting the service. See
[`validation.md`](validation.md).
