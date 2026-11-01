# strata-sleepwake

Workload-aware automatic suspend/resume for a GPU inference host that serves
models through [Strata](https://github.com/Niko1221/Strata).

The machine should be able to sleep after ten minutes of *genuinely* safe
inactivity, and wake up serving again — without cutting off an inference
request, a file transfer, an update, or an interactive session.

> **Name.** The repository is `strata-sleepwake`; the implementation keeps its
> original internal name `sleepmgr` (`/opt/sleepmgr`, `/etc/sleepmgr`,
> `sleepmgr.service`). Nothing was renamed, so the packaged files match what
> actually runs.

## Machine roles

This repository is the **GPU host** side. It does not contain the wake gateway.

| role | host (example) | what runs there | in this repo? |
|---|---|---|---|
| **GPU host** | `gpu-host` / `192.0.2.10` | Strata, the model, `sleepmgr` coordinator, sleep guard, request gate | **yes** — everything here |
| **Control center** | `control-center` / `192.0.2.11` | Wake-on-LAN / wake gateway that wakes the GPU host and tracks model readiness | **no** — external, not available for inspection |
| **Inference clients** | LAN | send requests to Strata on the GPU host | no |

The reference deployment has two NVIDIA Tesla T4 GPUs (15,360 MiB each), 16
CPU cores, 62.5 GiB RAM and 8 GiB swap, running Ubuntu 24.04. The model is
loaded across both GPUs. See [`docs/wake-gateway.md`](docs/wake-gateway.md) for
what is and is not known about the control-center side.

## The problem

A GPU host that serves a local LLM burns hundreds of watts while idle. Suspending
it is not simply `systemctl suspend`:

1. **S3 does not preserve VRAM** on this class of host, so a loaded model cannot
   survive suspend. It must be unloaded first and reloaded after resume.
2. **Requests arrive asynchronously.** Between "model unloaded" and "machine
   suspended" a new inference request can arrive, reload the model, start GPU
   work, and then be frozen mid-request by the suspend.
3. **"Idle" is not the same as "safe".** Updates, transfers, agent jobs, remote
   streaming sessions and inhibitors all need to veto sleep.
4. **A resume is not finished when the kernel returns.** logind, NVIDIA and
   Strata all need bounded, verified recovery before the service is usable
   again.

This repository packages the system that handles those four problems.

## What it does today

```
idle 600 s ──► final gate ──► seal request gate ──► unload model
    ──► verify GPU/RAM/gate ──► release sleep guard ──► suspend
    ──► resume ──► reacquire guard ──► NVIDIA ──► reload model
    ──► readiness checks ──► reopen gate
```

- **Inactivity gate** — 600 s measured from the last activity, with a 30 s
  countdown at the end. Any input, workload, unknown idle source, pause or
  resume restarts the whole window.
- **Detectors** (read-only): session idle (Mutter, logind fallback),
  inhibitors, Strata busy/queued + GPU utilisation, OpenCode agent jobs,
  updates, transfers, Sunshine streams. A detector that cannot answer reports
  `UNKNOWN` and blocks sleep.
- **Pause / timed pause** — persistent across restarts, enforced with a logind
  `sleep` block inhibitor so a menu Suspend cannot override it.
- **Final gate** — fresh sweep, pause re-check, `CanSuspend`, and
  `systemctl --dry-run --check-inhibitors=yes suspend`, tolerating only the
  system's own sleep guard.
- **Quiesce** — seal the request gate, wait, re-check idle, unload Strata,
  verify the model is gone, then release the guard and suspend.
- **Recovery** — wait for a real resume, reacquire the guard (bounded retry),
  reload Strata, verify readiness, reopen the gate. If recovery cannot verify
  protection and readiness, the gate stays **closed**.
- **Request gate** — a privileged helper owning exactly one nftables table,
  refusing *new* remote TCP connections to the inference port while the
  coordinator settles. It is deliberately narrow: no other firewall state is
  read or written.
- **Sleep guard** — an independent fail-closed logind inhibitor that releases
  only after fresh read-only samples show no Strata work, no compute clients,
  low VRAM/GPU use, enough RAM, and a closed gate.

Two optional paths are documented but **not** enabled by the example
configuration: the nft request gate and unattended (armed) suspension.

## Safety defaults

The packaged configuration is deliberately inert:

| setting | example value | effect |
|---|---|---|
| `service.allow_unattended_suspend` | `false` | the service never suspends on its own |
| `gate.enabled` | `false` | the nft helper is not contacted or required |
| `--arm` on the command line | not present | the shipped unit runs in dry-run |

The author's live machine runs an armed configuration through a local systemd
drop-in that is **not** part of this repository. Do not copy an armed setup
without reading `docs/setup.md` and `docs/limitations.md` first.

## Repository layout

| path | contents |
|---|---|
| `sleepmon.py` | coordinator: detection loop, gates, countdown, service mode |
| `detectors.py` | read-only probes and fail-closed classification |
| `policy.py` | pure policy: classification, gates, suspend command |
| `pause.py` | persistent pause state + logind block lock |
| `control.py` | local AF_UNIX control channel |
| `suspendflow.py` | gate-first quiesce, suspend, resume and recovery |
| `oneshot.py` | supervised single-cycle mode (`--arm-once`) |
| `netgate.py` | unprivileged client for the request gate |
| `nftgate_helper.py` | privileged nft gate helper (not installed by default) |
| `suspendguard.py` | fail-closed logind sleep guard |
| `gui.py`, `sleepmgr_ctl.py` | GTK4 control panel and terminal control |
| `config.json` | development example (temporary paths) |
| `config.production.json` | service example (`/etc`, `/var`, `/run`), gate and arming off |
| `deploy/` | systemd units, drop-ins, nftables rules, installer, emergency opener |
| `docs/` | architecture notes, setup, recovery, validation, limitations |
| `tests/` | unit tests (no live-service or power-state changes) |
| `tools/` | mock Strata server and helper drivers |

## Restore executable bits after a browser upload

Git records which files are executable, but a drag-and-drop upload to GitHub
does not. Run the command below once in the repository root **before** using
the scripts in this repository.

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

## Quick start (read-only)

No installation and no power-state change is required to look at the system:

```bash
python3 sleepmon.py --once --json     # one machine-readable snapshot
python3 sleepmon.py --resume-check    # post-resume health report (read-only)
```

A live dry-run display (Ctrl-C to stop) is also safe — without `--arm` it can
never suspend:

```bash
python3 sleepmon.py --idle-timeout 60
```

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — components and data flow
- [`docs/setup.md`](docs/setup.md) — installation and configuration
- [`docs/recovery.md`](docs/recovery.md) — failure modes and rollback
- [`docs/validation.md`](docs/validation.md) — what was tested, when, and what is unknown
- [`docs/limitations.md`](docs/limitations.md) — known gaps, stated plainly
- [`docs/wake-gateway.md`](docs/wake-gateway.md) — wake path and the control-center gap
- [`docs/inference-gate.md`](docs/inference-gate.md) — request-gate design and guarantees
- [`docs/deploy-selective.md`](docs/deploy-selective.md) — selective deployment and rollback
- [`docs/one-shot.md`](docs/one-shot.md) — supervised single suspend/resume cycle
- [`docs/source-vs-deployed.md`](docs/source-vs-deployed.md) — source vs. deployed differences

## Provenance and licensing

This is a packaged snapshot of a private working system, sanitized for
publication. Machine names, user names, addresses and paths were replaced with
examples; credentials, tokens, logs, backups, model weights and Git history are
not included. See [`THIRD-PARTY.md`](THIRD-PARTY.md) for third-party components
and their notices — in particular, **no license has been chosen for this
repository itself**, and the Strata project and its model weights are separate
works with their own terms.
