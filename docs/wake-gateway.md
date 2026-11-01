# Wake path and the control-center gap

The wake path spans two machines. Only one of them is in this repository.

## Roles

| role | example address | status |
|---|---|---|
| GPU host (`sleepmgr`, Strata, model) | `192.0.2.10` | inspected read-only; fully covered here |
| Control center (wake gateway, WoL sender, readiness polling) | `192.0.2.11` | **not accessible at packaging time** |

The control-center host is reachable on the LAN but had no SSH listener when
checked, and no file, unit, script or configuration on the GPU host references
it. There was no upstream URL to cite. **No replacement was written**, because
inventing one would misrepresent the system.

## What the GPU host actually provides

These are the pieces the wake path depends on, and they are real:

- **Wake-on-LAN readiness (partial).** The active NetworkManager connection for
  `eno1` has `wake-on-lan=magic`, and
  `/sys/class/net/eno1/device/power/wakeup` reports `enabled`. The `Wake-on: g`
  bit and firmware support were never proven.
- **RTC backup wake.** `rtcwake` is installed and supervised cycles armed an RTC
  backup alarm (601 s in the recorded runs). It is a backup, not the primary
  wake source.
- **Resume handling.** The coordinator waits for a real suspend/resume time gap
  before touching the guard, NVIDIA or Strata.
- **Model-readiness checks (these exist and are packaged):**
  - `GET /health` — unauthenticated, returns `loaded`, `model`, `status`;
  - `GET /status` — authenticated, returns `busy` / `queued`;
  - `detectors.strata_readiness` and the post-resume `readiness-verify`,
    `nvidia-verify` and `protection-verify-before-open` phases;
  - recovery only reopens the request gate after all of them pass.

## What is missing

- The control-center's wake gateway: how it decides to wake, what it sends, how
  it authenticates, how it polls readiness, and how it handles a failed wake.
- Any sanitized integration script or configuration for that side. None exists
  on the GPU host, so none is included.
- An upstream reference for the gateway. None was available.

A real suspend on 2026-11-01 resumed after roughly three hours — far longer than
the 601 s RTC backup — which is consistent with an external wake, but the wake
source was **not** observed and is recorded as unknown.

## Interface a gateway would need (not an implementation)

This is the minimum contract implied by the GPU-host side. It is documented so
the missing component can be described honestly, not as a substitute for it:

1. Wake the host (magic packet; optionally verify the NIC/firmware accepts it).
2. Distinguish a cold boot from a resume — readiness is not the same path.
3. Poll `GET /health` until `loaded == true`, with a bounded timeout.
4. Optionally poll `GET /status` with the API key for `busy` / `queued`.
5. Report failure explicitly; never assume a host is ready because it answered
   a ping.

## To close the gap

Export the control-center unit/script/config read-only, sanitize the same way as
this repository (user names, addresses, paths, credentials), and add it under
`integrations/control-center/` with its own README and tests. Until then this
page is the accurate description: GPU-host wake readiness is covered, the
gateway is not.
