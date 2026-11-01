# Source vs. deployed

The running host and the working source tree had drifted. This page records
what was compared and what was chosen for the package.

## What was compared

- **Deployed**: `/opt/sleepmgr` (installed code) and
  `/etc/systemd/system/sleepmgr*.service`, `sleepmgr-gate.socket`,
  `sleepmgr-gate-boot.service`, `strata.service.d/10-sleepmgr-gate-boot.conf`.
- **Source tree**: the author's working copy of `sleepmgr`.
- **Private live config**: `/etc/sleepmgr/config.json` (read only, **not**
  packaged).

## Identical files

`control.py`, `gui.py`, `netgate.py`, `nftgate_helper.py`, `oneshot.py`,
`pause.py`, `policy.py`, `sleepmgr_ctl.py`, `sleepmon.py`, `suspendflow.py`,
`suspendguard.py`, `deploy/sleepmgr.service`, `deploy/sleepmgr-gate.socket`,
`deploy/sleepmgr-suspend-guard.service`, `deploy/sleepmgr-gate-boot.service`,
`deploy/strata.service.d/10-sleepmgr-gate-boot.conf`.

## Differences

| item | difference | packaged as |
|---|---|---|
| `detectors.py` | **Deployed is newer** (61,360 vs 58,936 bytes). It replaces a regex port scan with strict `ss` row parsing (`_endpoint_port`, `_parse_ss_row`) and reports `UNKNOWN` (fail closed) when `ss` fails or returns malformed rows, instead of assuming "no stream". | deployed version |
| `README.md` | Source tree is newer/longer (14,820 vs 10,253 bytes); the deployed copy still describes the request gate as "future/not implemented". | newly written `README.md` |
| `deploy/sleepmgr-gate.service` | Source is newer, **comments only**: it documents reboot re-seal semantics; behaviour comes from `nftgate_helper.py`, which is identical. | source version |
| `deploy/sleepmgr-resume.service` | Present in `deploy/` but **not installed** (`systemctl is-enabled` → `not-found`). | included as a definition |
| `sleepmgr.service.d/90-auto-suspend.conf` | Installed locally, adds `--arm`; not in the source tree. This is the author's deliberate armed override. | **excluded**; shown as an example in `docs/setup.md` |
| `/etc/sleepmgr/config.json` | Live config enables the gate and unattended suspension and contains host paths. | **excluded**; replaced by sanitized examples |
| `sleepmgr-gate.service` state | `disabled` but `active` — started on demand by `sleepmgr-gate.socket`. | documented |

## Consequences

- The package ships the **deployed** `detectors.py`, so it is the code that
  actually runs, not the older source copy.
- The newer fail-closed `ss` parsing is covered by
  `tests/test_detector_stream_parsing.py` (32 mocked tests); it is still not
  exercised against a live kernel's exact `ss` output.
- The deployed README was stale relative to the code; the new `README.md` and
  `ARCHITECTURE.md` describe the implemented gate, not the "future" one.
- The live config is materially different from the examples. Never copy it
  blindly: it arms unattended suspension and enables the gate.

## Reproducing the comparison

```bash
cd /opt/sleepmgr
for f in *.py README.md; do
  cmp -s "$f" "/path/to/source/$f" && echo "same $f" || echo "DIFF $f"
done
```

```bash
for u in sleepmgr.service sleepmgr-gate.service sleepmgr-gate.socket \
         sleepmgr-suspend-guard.service sleepmgr-gate-boot.service; do
  systemctl cat "$u"
done
```
