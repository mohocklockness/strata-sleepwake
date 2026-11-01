# Validation

This page separates three different kinds of evidence:

1. **Historical** — results recorded on the author's host at the time.
2. **Newly verified** — checks run while packaging this repository (read-only,
   no service, network, GPU or power-state changes).
3. **Unknown** — things nobody has proved yet.

Do not treat a unit test as proof that suspend is safe on your hardware.

## How to run the checks safely

The unit tests are designed to touch nothing live: they use mocks, fake
`nft`/`systemctl` shims in temporary directories, and loopback sockets on
ephemeral ports. Two modules are different and are **excluded by default**:

| module | why excluded |
|---|---|
| `tests/test_netns_nft.py` | creates a user+network namespace and applies real nft rules |
| `tests/test_netns_remote.py` | creates namespaces and drives remote/local clients through them |

They do not touch host networking, but they do create namespaces, so run them
only on a disposable lab host.

Run the safe subset:

```bash
cd strata-sleepwake
for f in tests/test_*.py; do
  case "$f" in *test_netns_*) continue;; esac
  python3 "$f" || echo "FAILED: $f"
done
```

No test starts, stops or restarts a service; none suspends, unloads a model or
changes a firewall.

## Newly verified while packaging

- **Unit tests**: 446 tests across 20 modules passed; the two netns modules were
  skipped (see above).
- **Python syntax**: every module compiles (`python3 -m py_compile`).
- **Configuration**: `config.json` and `config.production.json` are valid JSON
  and contain no credentials (only token *file paths*).
- **Installed units** were inspected read-only with `systemctl cat` and compared
  with `deploy/`. Differences are listed in
  [`source-vs-deployed.md`](source-vs-deployed.md).
- **Host identity and hardware** were verified from DMI, `hostnamectl`,
  `/proc`, `lspci` and `nvidia-smi`: a desktop board, 16 cores, 62.5 GiB RAM,
  8 GiB swap, **two Tesla T4 GPUs** (15,360 MiB each, both in use), Ubuntu
  24.04.5. This host is the **GPU host**; the control center is a separate LAN
  machine.
- **Effective service configuration**: `systemctl show` reports the drop-in
  `/etc/systemd/system/sleepmgr.service.d/90-auto-suspend.conf` and an
  `ExecStart` ending in `--service --arm`; `/etc/sleepmgr/config.json` has
  `allow_unattended_suspend: true` and `gate.enabled: true`. So the installed
  configuration **is armed**.
- **Actual current arming**: `status.json` reported `mode: armed`,
  `state: blocked` (blocker: `strata: inference active (busy=True,
  queued=0)`), `service.armed: true`, `gate.state: open`, `guard.state:
  protected`. Armed ≠ about to suspend: the workload currently vetoes it.
- **Observed live cycle (not induced by this packaging pass).** The monitor log
  and `/var/log/sleepmgr/suspend.jsonl` show a real armed cycle on 2026-11-01:
  quiesce started 12:32:04, gate closed 12:32:07, unload and post-unload
  verification 12:32:21–23, guard released 12:32:24, suspend 12:32:24, resume
  detected 15:30:42, guard reacquired after three bounded retries 15:30:47,
  NVIDIA verified, model reloaded 15:31:27, readiness verified 15:31:28, gate
  reopened 15:31:28. The wake source is **unknown** — it was not the 601 s RTC
  backup.
- **Strata API**: `GET /health` returned HTTP 200 with `loaded: true`;
  `GET /status` returned HTTP 401 without the API key, as expected.

Nothing was installed, deployed, restarted, unloaded, suspended or rebooted by
this packaging pass.

## Historical results (author's host, not reproduced here)

Two supervised real suspend/resume cycles were recorded:

| date (UTC) | mode | result |
|---|---|---|
| 2026-10-23 06:05 | `--arm-once`, RTC backup alarm 601 s | one-shot exit 0; kernel `PM: suspend entry (deep)` → `PM: suspend exit` after ~53 s; monitor back `active`, gate `open`, guard `protected` |
| 2026-10-24 05:49 | `--arm-once`, RTC backup alarm 601 s | one-shot exit 0; suspend entry/exit after ~59 s; monitor back `active`, gate `open`, guard `protected` |

Both cycles used the supervised single-shot mode, not unattended service
suspension. Earlier development reported a full suite of 299 tests passing; the
suite has grown since and the number above (446) is the current one.

The gate ruleset and packet behaviour were validated in throwaway network
namespaces: new remote connections blocked, loopback and the host's own LAN
address still served, established connections drained, reopen immediate, and
`meta skuid` proven to be a silent no-op in the input hook.

## Test inventory

| module | tests | what it proves | touches |
|---|---:|---|---|
| `test_policy.py` | 39 | classification, inactivity gate, suspend command | pure |
| `test_suspendflow.py` | 64 | gate-first quiesce ordering and abort paths | mocks |
| `test_netgate.py` | 100 | gate auth, leases, seals, crash recovery, races | mocks + fake nft |
| `test_suspendguard.py` | 49 | fail-closed guard release rules | mocks |
| `test_gate_boot_script.py` | 16 | boot seal script, fail-closed paths | fake `nft`, temp state |
| `test_gate_recheck.py` | 15 | post-gate re-check refuses to proceed | mocks |
| `test_oneshot.py` | 15 | one-shot refusal/ordering policy | pure |
| `test_pause.py` | 14 | pause persistence, corruption, timed pause | temp dirs |
| `test_control.py` | 13 | AF_UNIX control channel | temp socket |
| `test_emergency.py` | 12 | emergency opener independence and fail-closed | fake `nft`, temp state |
| `test_deploy_artifacts.py` | 11 | unit/installer/doc invariants | files only |
| `test_strata_recovery.py` | 11 | reload/readiness retry logic | loopback sockets |
| `test_config_guard.py` | 10 | config downgrade protection | pure |
| `test_detectors.py` | 10 | detector parsing and fail-closed behaviour | mocked `_run` |
| `test_detector_stream_parsing.py` | 32 | strict `ss` parsing, malformed/truncated output, UNKNOWN blocks the gate | mocked `_run` |
| `test_gui_logic.py` | 10 | status formatting | pure |
| `test_oneshot_runtime.py` | 8 | shared lock and runtime-directory handling | temp dirs |
| `test_guard_status_reporting.py` | 7 | guard status propagation | mocks |
| `test_strata_readiness.py` | 6 | `/health` + `/status` readiness | loopback sockets |
| `test_final_check.py` | 4 | own-guard-tolerant inhibitor check | mocks |

## Unknowns

- **Real suspend on this repository's default configuration** — not attempted.
  The recorded cycles used the author's live configuration.
- **nft gate on every kernel/firmware combination** — validated in namespaces
  and one supervised test, not universally.
- **The control-center wake gateway** — on a separate machine that was not
  accessible (no SSH listener; no local references). Its wake logic and
  readiness polling are unverified. See
  [`wake-gateway.md`](wake-gateway.md).
- **The wake source of the observed 2026-11-01 cycle** — the host resumed long
  after the 601 s RTC backup, consistent with an external WoL wake, but the
  source was not observed.
- **Wake-on-LAN** — readiness is partial; the `Wake-on: g` bit and firmware
  support were never proven.
- **RTC alarm reliability** — used as a backup wake source, not measured over
  long sleeps.
- **Established HTTP connections** — cannot be revoked by nft; see
  [`inference-gate.md`](inference-gate.md).
- **Behaviour on other GPUs, drivers or Strata models** — untested.
- **The deployed `detectors.py` stream-parsing fix** — newer than the original
  test suite, but now covered by
  `tests/test_detector_stream_parsing.py` (mocked `ss` output). It is still
  unproven against a live kernel's exact `ss` formatting.
