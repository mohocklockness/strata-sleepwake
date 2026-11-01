# Known limitations

Stated plainly, because the failure modes matter more than the happy path.

## Power and hardware

- **S3 does not preserve GPU VRAM** on this class of host
  (`NVreg PreserveVideoMemoryAllocations=0`). A loaded model cannot survive
  suspend, so the model is always unloaded and reloaded. Changing the driver
  parameter is out of scope.
- **Hibernate is unavailable** (swap is much smaller than RAM); only S3
  (`mem_sleep=deep`) is supported.
- **Wake-on-LAN is partial.** Driver wakeup, ACPI `GLAN` and NetworkManager
  `wake-on-lan=default` are configured, but the `Wake-on: g` bit needs root and
  firmware support is unproven. Treat WoL as best-effort.
- **The RTC alarm is a backup**, not a guarantee. It is armed before suspend so
  a forgotten host comes back, but long-sleep reliability was not measured.
- A firmware or kernel suspend hang cannot be fixed by this software. Recovery
  is a power cycle followed by a state check.

## The request gate

- **New connections only.** A client holding an established keep-alive or
  HTTP/2 connection can send another request after the gate closes. nft cannot
  revoke it.
- **Already-delivered requests** (accept queue, socket buffer) are still
  processed.
- **In-flight responses are allowed by design** so a request that started
  before the gate can finish.
- **The gate is remote-only** (`iifname != "lo"`). Local processes are not
  gated; that is the coordinator's trust domain.
- **No HTTP awareness.** The correct long-term fix is an HTTP-aware proxy that
  can drain and prove the queue is empty; it is sketched in
  [`inference-gate.md`](inference-gate.md) and not implemented.
- **Validated in namespaces, not universally.** Kernel and firmware behaviour
  may differ.

## Detection

- **Idle detection needs a session bus.** Mutter answers only its owning uid; a
  root service cannot read it. If no source answers, the monitor reports
  `UNKNOWN` and never suspends.
- **Transfer detection is heuristic** (process names plus sustained
  throughput). A browser download is caught only by the throughput threshold.
- **Stream detection** relies on `ss` parsing plus a Sunshine log tail. The
  deployed version now fails closed when `ss` output is missing or malformed;
  that change is newer than this repository's tests.
- **The GPU threshold is a sample**, not a proof: a burst between polls can be
  missed.
- **The GNOME/logind competition check is read-only.** The monitor warns; the
  pause block lock is what actually prevents a competing suspend.

## Recovery and state

- **The guard restart gap.** If `suspendguard.py` dies, there is a short window
  with no inhibitor. The unit restarts it in 250 ms and records the gap, but a
  restart is not a fail-safe event.
- **Status heartbeat.** The GUI treats a status older than 15 s as offline;
  during a long real quiesce the status is written less often, so the panel can
  briefly show offline.
- **Recovery is bounded.** If the guard cannot be reacquired or Strata cannot
  be verified within the configured timeouts, the gate stays closed. Service is
  restored by an operator, not by retrying forever.
- **Pause state is fail-safe, not fail-open.** A corrupt `state.json` means
  "paused" until fixed.

## Scope

- **Single host, multiple GPUs.** The reference host has two Tesla T4 GPUs; the
  coordinator treats them as one workload. Multi-host coordination is not
  implemented.
- **The control-center wake gateway is not part of this repository.** The GPU
  host can be woken by WoL/RTC, but the component that sends the wake and
  tracks readiness lives on a separate machine that was not available for
  inspection. See [`wake-gateway.md`](wake-gateway.md).
- **Strata-specific API.** Unload/reload/readiness assume Strata's HTTP
  endpoints; another server needs a different adapter.
- **No metrics or dashboard.** Logs and a JSON status file only.
- **No package or container.** Installation is a shell script and systemd
  units.
- **Portability.** The units, installer and examples assume the account
  `sleepuser`, uid 1000, `/opt/sleepmgr`, `/etc/sleepmgr` and a LAN-bound Strata
  on port 8080. Adjust before using elsewhere.

## Redistribution

- **No license has been chosen for this repository.** Do not assume it is
  open source until one is added.
- Strata and its model weights are separate works with their own terms; no
  weights are included here. See [`THIRD-PARTY.md`](../THIRD-PARTY.md).
