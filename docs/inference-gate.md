# The inference-arrival gate

Status: **implemented, tested, and disabled.** `gate.enabled` is `false` in both
`config.json` and `config.production.json`. Nothing in this repository installs,
enables or starts the privileged helper, and the installer
(`deploy/install.sh`) deliberately skips `nftgate_helper.py`.

## The problem

The machine is suspended only after `POST /unload` releases Strata's model from
VRAM, because S3 does not preserve VRAM. Between "model unloaded" and "system
suspended" a new inference request could arrive; Strata would reload the model
and start GPU work, and the machine would then suspend mid-inference.

The gate removes the bulk of that window by refusing **new** TCP connections to
the inference port while the monitor settles, drains and re-checks.

## Architecture

```
  sleepmgr.service                      sleepmgr-gate.service
  (user sleepuser,                    (root, CAP_NET_ADMIN only)
   NoNewPrivileges=yes)                 +-----------------------------+
        |                               | nftgate_helper.py           |
        |  AF_UNIX /run/sleepmgr-gate/gate.sock  nft table:           |
        |  JSON lines, SO_PEERCRED +    |   inet sleepmgr_gate        |
        +------------------------------>|   (one chain, one SYN rule) |
            close / open / status       +-----------------------------+
```

- The monitor never runs `nft` and never gains privilege; it only talks to the
  helper over a local Unix socket. `netgate.GateClient` is the client;
  `netgate.build_gate()` returns a `NullGate` unless `gate.enabled` is true.
- The helper owns **exactly one** table (`inet sleepmgr_gate`), one input chain
  and one rule. `open()` is `delete table inet sleepmgr_gate` and nothing else.
  It cannot read, flush or edit any other firewall state.
- The rule is scoped with `iifname != "lo"`: it gates arrivals from outside the
  host and leaves loopback alone. The monitor's probes to `127.0.0.1` or to the
  host's own LAN address take the local route and arrive on `lo`, so the
  post-gate `/status` and `/health` checks keep working.
- `meta skuid` is **not** used. In a real netns lab it matched 0 packets in the
  input hook, silently turning the gate into a no-op; see below.

### Authentication

Every request is authenticated by the kernel with `SO_PEERCRED`: the helper
accepts only the configured uids (uid 0 plus `--allow-uid`, the monitor's uid).
An alternative/grades-of-defence token (`--token-file`, `--require-token`)
compared with `hmac.compare_digest` can be layered on top. A request from a
disallowed uid is refused and cannot change the gate.

### The ordinary lease, the controlled-suspend seal, and recovery

An ordinary `close` is a **lease** tied to the requesting connection:

| event | result |
|---|---|
| monitor sends `close` | gate closes; helper records the leasing connection |
| monitor sends `open` (abort/resume) | gate opens; lease released |
| monitor process dies (socket EOF) | helper reopens an ordinary lease — **crash recovery** |
| monitor hangs but stays connected | `lease_ttl_s` (default 900 s) reopens an ordinary lease |
| helper restarts, ordinary lease | a surviving table is **adopted as sealed**, not deleted |
| helper restarts, sealed | durable boot-scoped seal marker restores/re-applies the seal; gate stays closed |
| helper restarts mid-quiesce | the surviving table stays closed; verify requires it closed |
| helper exits (SIGTERM/SIGINT), ordinary | a closed gate stays closed; explicit open required |
| helper exits (SIGTERM/SIGINT), sealed | shutdown cleanup skipped; marker and table remain |

The controlled suspend flow uses `seal` instead. A sealed gate has:

- no lease expiry;
- no reopen on monitor disconnect;
- no reopen on helper expiry processing;
- only an explicit authenticated `open` clears it.

That distinction is deliberate. The monitor may exit after a failed recovery
(especially the foreground one-shot), and it must not leave an unloaded Strata
reachable just because the gate lease connection closed. The normal `close`
lease remains available for callers that want crash recovery.

The seal marker is stored in persistent state, not in a runtime directory:

```
/var/lib/sleepmgr-gate/sealed.json
```

The gate unit uses `StateDirectory=sleepmgr-gate`, so the marker survives
`systemctl stop/restart sleepmgr-gate.service`, helper crashes and
`RuntimeDirectory` cleanup. The marker contains the kernel boot id. `/run` and
nftables runtime state do not survive a full reboot, so a marker from an
**earlier** boot is the surviving evidence that the previous boot ended inside a
controlled-suspend seal; it is **not** discarded. This boot re-seals before
network traffic arrives:

- `deploy/sleepmgr-gate-boot.service` runs `deploy/sleepmgr-gate-boot.sh` in the
  firewall phase (`Before=network-pre.target`). With no marker it exits 0
  (a clean boot needs no boot seal). With a marker it proves the *intended*
  blocking rule is live (the ports, the SYN-only match, the loopback exemption,
  the verdict and the shared comment) and, if the table is missing, empty or
  wrong, atomically restores the owned ruleset in one `nft -f` transaction.
  A missing tool, generator failure or `nft` failure makes the unit fail.
- A failed unit also stops `strata.service`: the installer drops in
  `deploy/strata.service.d/10-sleepmgr-gate-boot.conf`
  (`Requires=`/`After=sleepmgr-gate-boot.service`) so a boot that cannot
  establish the required seal cannot accept remote inference. Only the inference
  port is gated, so host networking stays up for troubleshooting.

When the helper starts it also re-seals a marker from an earlier boot and
rewrites the current boot id. If a table somehow survives without a valid
current-boot marker, the helper **adopts it as sealed** instead of deleting it.
It cannot know whether Strata is loaded or unloaded, so deleting is never a safe
guess. Only an explicit authenticated `open` clears an adopted or controlled
suspend seal.

`run_quiesce` seals the gate before unload and re-seals it before guard release
and again after resume. On every abort after the gate is closed it reloads and
readiness-checks Strata when safe, but reopens only when the guard is confirmed
protected **and** the model is ready. A failed renewal is recorded as
`gate_lease_lost`; the monitor never treats that as permission to open the
gate. If the helper itself is unreachable, the monitor cannot prove the gate is
blocked, so it aborts before unload.

Monitor startup is also fail-closed for recovery. If it finds the gate closed
or sealed, it opens it only after the sleep guard is confirmed protected and
Strata reports loaded and inference-ready. Startup uses **bounded retries**
(`gate.startup_recovery_timeout_s`, default 180 s; `gate.startup_recovery_interval_s`,
default 2 s): Strata can take minutes to load after a boot, so the gate stays
sealed and the pause inhibitor stays held while the monitor retries. It never
deletes or reopens a surviving table on a guess. After the deadline a permanent
failure leaves the gate sealed and the status document records
`gate_recovery.state = "recovery-failed"` with the reason. A normal open gate is
left alone: after a reboot there is no table and no current-boot seal, and a
remote request may legitimately load the model. The one-shot does not perform
this startup normalization at all.

## What the gate can and cannot guarantee

This is the crux. nftables operates on **packets**, not HTTP requests.

1. **New connections — covered.** A stateless `tcp flags & (syn|ack) == syn`
   drop rule stops a fresh TCP connection from reaching Strata.
2. **Established connections — NOT covered.** A client holding an open socket
   can send another HTTP request on it after the rule lands. That is the classic
   keep-alive / HTTP-2-multiplexing race, and a firewall cannot revoke it.
3. **Already-delivered requests — NOT covered.** Bytes that already reached
   Strata (accept queue or socket buffer) will be processed regardless.
4. **In-flight responses — allowed by design.** Established packets keep flowing
   so a request that started before the gate can finish.

### Why SYN matching, not `ct state new`

The first implementation used `ct state new`. A packet-level lab in a throwaway
`unshare -Urn` namespace showed a sharp edge: if conntrack was **not already
tracking** the flow when the rule landed, the next data packet of an established
connection was classified as a new flow and dropped (5 packets counted), aborting
an in-flight request. Warming conntrack first made the same rule behave
correctly. On a production host conntrack is usually already active, but relying
on that is fragile and unnecessary.

The shipped rule is therefore stateless. The recommended action is an immediate
TCP reset; `--action drop` is the fallback:

```
tcp dport { 8080 } tcp flags & (syn|ack) == syn iifname != "lo" \
    counter reject with tcp reset
```

It matches only connection-opening SYNs (SYN set, ACK clear), so established
data can never be misclassified, and it has no conntrack dependency. The
loopback scope keeps the monitor's health checks working. Verified with real
kernel rulesets by `tests/test_netns_nft.py` (local blocking, drain, reopen,
loopback exemption) and `tests/test_netns_remote.py` (two namespaces: remote
blocked, local LAN address allowed, SSH/Sunshine-like ports allowed, established
drain, reopen), all inside private network namespaces. No host firewall state is
touched.

The *runtime* and *boot* paths both verify the live table semantically with the
same checker (`nftgate_helper.verify_gate_ruleset`, exposed as
`nftgate_helper.py --verify-listing`).  It does not merely count `tcp dport`
lines: it requires the actual configured ports, a blocking verdict
(`drop`/`reject with tcp reset`), a SYN-only match, the loopback exemption, the
ownership comment, an input *base chain* hooked early enough to be effective,
and no earlier rule **in that chain** that accepts or skips the gate.  Any
*extra* match restriction — a source address, source port, mark, interface and
so on — is refused: such a rule would gate only some remote clients while
looking closed.  A wrong-port, `accept`, unhooked or bypassed rule is refused
even though the table exists, and the helper's `status` exposes the result as
`verified`/`problem` alongside `consistent`/`rules`.  A table that cannot be
*inspected* is treated as unknown, never as absence, by both the helper and the
boot/rollback scripts.

nft does not preserve the rule text: it prints the SYN match canonically as
`tcp flags syn / syn,ack` (meaning `(flags & (syn|ack)) == syn`) and collapses a
single-port set to `tcp dport 8080`.  The checker parses the `syn / syn,ack`
form, the `& (syn|ack) == syn` form and spaced variants such as
`& (syn | ack) == syn`; the real-kernel tests feed it the exact listing the
kernel prints for both `drop` and `reject`.

An `accept` in a *different* input base chain does **not** bypass a later
blocking base chain.  nft evaluates every base chain for the hook, so a drop in
any of them still drops the packet; only an accept within the same chain is
terminal for that chain.  Requiring an early priority is therefore a
defence-in-depth ordering choice, not a claim that another chain's accept wins.

### Why not `meta skuid` (important)

The first version tried to exempt the monitor by uid:

```
... tcp flags & (syn|ack) == syn meta skuid != 1000 counter drop
```

In a two-namespace lab this rule matched **0 packets** in the input hook. Both
the remote client and a local uid-0 client connected successfully while the gate
reported `closed`. `meta skuid` is only meaningful for locally generated
packets; in the input hook it is not a reliable match. This means the uid
version would have been a **silent no-op in production** — the worst possible
failure mode for a gate.

It is also unsafe to exempt uid 0: the `meta skuid != 0` variant let remote
traffic through in the same lab, so uid 0 must never be used as an exemption.
The helper no longer accepts a uid exemption at all. The loopback interface is
the correct scope: it is kernel-supplied metadata, cannot be spoofed by a remote
packet, and matches the actual requirement ("block remote arrivals, keep local
health checks"). Local processes are inside the monitor's trust domain and are
not gated by this rule.

### Drop or reject?

Measured in the same two-namespace lab:

| action | remote new connection | established request | other ports |
|---|---|---|---|
| `counter drop` | times out (SYN retransmits) | drains normally | unaffected |
| `counter reject with tcp reset` | `ECONNREFUSED` in ~1 ms | drains normally | unaffected |

Recommendation: **reject**. It fails fast, makes a closed gate observable, and
avoids clients hanging in SYN retransmit. Because the rule matches SYN only, a
reset cannot touch an established connection. `--action drop` remains available
if a specific client misbehaves with RSTs; the helper unit uses reject for the
supervised test.


### Measured behaviour of Strata (2026-10-19)

A read-only raw-socket `GET /health` to `192.0.2.10:8080` returned:

```
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.12.3
Connection: close
```

and a second request on the same connection was **refused** (the server closed
it). Strata is `http.server`-based HTTP/1.0 with `Connection: close` and no
keep-alive. Therefore **one request == one TCP connection today**, so a
new-connection block covers essentially every arrival — a stronger result than
the generic "firewall can't stop keep-alive" caveat. `tests/test_netgate.py`
pins both halves of this down:

- `TestHttpArrivalRace.test_strata_style_http10_connection_is_not_reusable`
- `TestHttpArrivalRace.test_keepalive_connection_can_still_submit_after_gate_close`
  (a mock HTTP/1.1 server proves the residual race *would* exist).

This property is a behaviour of the current Strata build, **not a guarantee**.
It would silently disappear if Strata ever enabled keep-alive/HTTP-2 or if a
reverse proxy were placed in front of it. The gate must therefore never be
treated as proof on its own.

### The mitigation that carries the real weight

The monitor now uses a gate-first quiesce. `run_quiesce` takes
`pre_gate_verify`, `post_gate_verify`, `post_unload_verify`,
`post_resume_verify` and `readiness_verify`:

1. **pre-gate verify**: require a sustained clean sweep and idle Strata
   (critical detectors clear, `/status` `busy=false`/`queued=0`) while the gate
   is still open;
2. gate closes (new connections dropped);
3. **settle** for `gate.settle_s` (default 10 s) so a raced/queued request can
   surface; a pause here aborts;
4. **post-gate verify**: repeat the sustained idle/detector check, require the
   gate to *still* be `closed`, and allow Strata to stay loaded at this point;
5. unload Strata, then **post-unload verify** a fresh snapshot: no CUDA compute
   clients, VRAM under the limit, RAM above the minimum, and the gate closed;
6. release the sleep guard and suspend with
   `systemctl suspend --check-inhibitors=yes`;
7. on resume: reacquire the sleep guard, re-close/re-lease the gate, verify
   NVIDIA, reload Strata, run a one-token inference readiness check, and only
   then reopen the gate.

Any failure aborts. If the gate was closed, an abort re-leases it, reloads
Strata when safe, verifies readiness, and reopens only on success; otherwise
the gate stays closed. On resume, NVIDIA failure or a failed reload/readiness
check leaves the gate closed. The gate is a *filter*; the settle, sustained
re-checks, post-unload snapshot and resume readiness check are the actual
safety argument. None of this claims to revoke a request that is already inside
the server — that is the residual limitation below.

## Proposed HTTP-aware gateway (recommended long-term fix)

nft alone cannot guarantee safe request handling. The correct fix is to put an
HTTP-aware component on port 8080 that can stop accepting requests and prove the
queue is drained. Sketch:

- A small reverse proxy in front of Strata, owning the public 8080 listener;
  Strata moves to a loopback/unix upstream.
- Proxy control surface (`drain`/`resume`) on the same authenticated Unix-socket
  model as the helper: `drain` stops accepting new requests and returns once all
  in-flight requests have completed and the queue is empty; `resume` restores it.
- The monitor then: `unload` → `proxy.drain` (blocking, with timeout) →
  guarantee "no new request can be admitted and none is running" → `suspend`.
- Acceptance criteria: a request submitted (a) on a fresh connection, (b) on a
  reused keep-alive connection, and (c) racing the drain call, must all be
  either served before drain returns or rejected with a clear 503 — never left
  half-processed across a suspend.

This needs a change on the Strata side (or in front of it) and is out of scope
for this repository; it is recorded here so the nft gate is not mistaken for a
complete solution.

## Configuration

```json
"gate": {
  "enabled": false,
  "socket": "/run/sleepmgr-gate/gate.sock",
  "port": 8080,
  "allow_uid": 1000,
  "token_file": "/etc/sleepmgr/gate.token",
  "timeout_s": 3,
  "settle_s": 10.0,
  "verify_s": 5.0,
  "verify_probes": 3,
  "lease_ttl_s": 900,
  "startup_recovery_timeout_s": 180,
  "startup_recovery_interval_s": 2
}
```

Monitor startup recovery is bounded: it retries opening a sealed gate while it
keeps the seal and the guard inhibitor, and leaves the gate sealed with
`gate_recovery.state = "recovery-failed"` if readiness never arrives.  Each
attempt hands the *remaining* budget to the guard status, loaded check and
readiness smoke test, so one slow probe cannot extend the retry window, and the
guard reacquire path passes its remaining budget to each `acquire` call too.
Post-resume Strata recovery similarly carries the remaining deadline through
each candidate host, the health/status probes and the readiness smoke test
(`strata.readiness_deadline_s`).  When that key is absent — as in a preserved
pre-upgrade config — the bounded default is 300 s rather than "no deadline".

The monitor passes `gate` + `settle_s` + `post_gate_verify` to both quiesce call
sites (automatic and manual "Suspend now"). In dry-run the gate branch is never
reached, so enabling `gate.enabled` changes nothing until the service is armed.
`port` and `allow_uid` document the helper unit's `--port`/`--allow-uid`; the
helper takes them from its unit, not from this JSON. `allow_uid` is now only the
*socket authentication* uid — there is no nft uid exemption. The helper unit
sets `--action reject` (recommended) and the loopback scope is the default; the
emergency rollback script is `deploy/sleepmgr-gate-emergency-open.sh`.
`sleepmgr-gate.socket` creates the control socket as `root:sleepuser 0660`
and the helper inherits the fd via `LISTEN_FDS`, so the helper's capability set
stays `CAP_NET_ADMIN` only (`CAP_CHOWN` is deliberately not granted).

## Enabling checklist (NOT performed)

1. Approve the supervised live test in `docs/gate-live-test.md`.
2. Install the helper, `sleepmgr-gate.socket` + `sleepmgr-gate.service`, the
   emergency rollback script and the token with
   `deploy/install.sh --apply --with-gate [--enable]` (see
   `docs/deploy-selective.md`).  Deploy `netgate.py`, `nftgate_helper.py` and
   the updated gate unit together: the monitor's `seal` request is refused by
   an older helper, and the unit needs `StateDirectory=sleepmgr-gate` plus
   `ReadWritePaths=/var/lib/sleepmgr-gate` for the persistent boot-scoped seal
   marker.  Never use `ExecStopPost` to force-delete the table; that would
   defeat the seal.  `--enable` is the boot policy: enable
   `sleepmgr-gate.socket`; the helper starts on demand and
   `sleepmgr.service` orders after the socket.
3. `systemctl start sleepmgr-gate.socket` (or enable it at boot as above);
   the helper starts on first connection.  Confirm the socket is
   `root:sleepuser 0660` (systemd owns it; the helper must not need
   `CAP_CHOWN`), then confirm
   `nft list table inet sleepmgr_gate` reports "no such table" while idle and
   `nft list table inet sleepmgr_gate` contains exactly one
   `iifname != "lo"` SYN rule when a test lease closes it.
4. Verify `sleepmgr_ctl status` shows `gate: open` and stays `open` when idle;
   verify a local `/health` still works while a test lease holds the gate closed.
5. Run the live test (remote block, drain, reopen, SSH/Sunshine, emergency
   rollback). Keep the monitor unarmed throughout; do not unload Strata.
6. Only then set `gate.enabled=true` in `/etc/sleepmgr/config.json`, and only
   later consider arming. A supervised armed suspend/wake has passed once;
   unattended deployment still requires separate approval.

## Test coverage

`tests/test_gate_recheck.py` covers the sustained gate checks;
`tests/test_suspendflow.py` covers gate-first ordering, pre/post-gate idle
verification, post-unload verification, guard/lease failures, resume
NVIDIA/reload/readiness failures, and dry-run safety.
`tests/test_strata_readiness.py` exercises the one-token completion against an
ephemeral local mock. The real-kernel netns tests are skipped automatically
when user namespaces/`nft`/`nsenter` are unavailable; they never touch host
networking.

| area | tests |
|---|---|
| rule scope (own table only, SYN match, loopback scope, drop/reject) | `TestNftScope` |
| gate state, idempotency, nft failures, status parsing, stale cleanup | `TestNftGate` |
| lease lifecycle, crash recovery, ttl expiry, last-closer, concurrent races | `TestGateServiceLease` |
| controlled-suspend seal, disconnect persistence, no expiry, persistent boot-scoped marker, fail-closed adoption of an unmarked table | `TestGateServiceLease` |
| real-resume detection, delayed guard reacquisition, permanent failure, no second suspend | `test_suspendflow` |
| socket auth (uid allow-list, token), malformed/empty/unknown requests | `TestGateServerAuth` |
| crash/abort recovery over a real socket | `TestClientServerRecovery` |
| no helper, disabled-by-default, token/ttl wiring | `TestClientFailures` |
| HTTP/1.0 vs keep-alive arrival race (ephemeral mock, never 8080) | `TestHttpArrivalRace` |
| **real nft**, one netns: block new, drain established, reopen, loopback exempt | `TestRealNftInNamespace` |
| **real nft**, two netns: remote block (drop/reject), local LAN health, SSH/Sunshine-like ports, drain, reopen | `TestRemoteGateInNamespaces` |
| emergency rollback script: syntax, independence, dry-run | `TestEmergencyRollbackScript` |
| gate unit artifacts: reject, no uid exemption, sandbox, persistent `StateDirectory` seal path, socket-owned listener | `TestGateUnitArtifact` |
| sustained post-gate re-check: clean streak, busy/queued, reload, fail-safe, gate-still-closed | `TestGateRecheck` |
| quiesce: gate-first order, pre/post-gate idle, post-unload GPU/RAM/gate, guard refusal, suspend failure, NVIDIA/reload/readiness failure, lease loss, dry-run never closes | `test_suspendflow` |

Run: `python3 -m unittest discover -s tests`.

## Remaining limitations

- **Established-connection / already-delivered requests** are not revoked by
  nft. Mitigated (not eliminated) by settle + sustained re-check; fully solved
  only by the HTTP-aware gateway above.
- **The gate is remote-only by design.** The `iifname != "lo"` scope leaves all
  local processes ungated, including a local inference client. That is the
  monitor's trust domain. It is deliberate: the alternative (`meta skuid`)
  silently failed to match in the input hook, and a uid-based exemption would
  have been both ineffective remotely and bypassable locally.
- **Strata's HTTP/1.0 `Connection: close` is load-bearing** for how strong the
  new-connection block is; it is a build behaviour, not a contract.
- **The rule is stateless SYN matching.** It blocks connection *setup*; a
  non-SYN packet cannot start a TCP connection, but this also means it does not
  inspect HTTP at all. It intentionally does not touch established flows.
- **Helper is not installed or enabled.** The ruleset has been executed and
  packet-tested for real only inside throwaway `unshare -Urn` namespaces
  (`tests/test_netns_nft.py`, `tests/test_netns_remote.py`), never on the host's
  live firewall. The supervised plan is `docs/gate-live-test.md`.
- **GUI may briefly show offline during a real quiesce** (status is written less
  often); unrelated to the gate but still open.
