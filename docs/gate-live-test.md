# Supervised live-network test: inference gate

Status: **plan only — not executed.** No production networking has been changed.
Keep the monitor **unarmed** and **do not unload Strata** during this test.

This plan validates the gate itself (helper + real kernel) without exercising
suspension. It uses a short-lived **test lease client** instead of the monitor's
quiesce path, so a failure cannot suspend the machine.

## What is being proved

1. A remote new TCP connection to `192.0.2.10:8080` is blocked while the gate
   is closed (the unit uses `--action reject`, so it fails fast).
2. A request that was already in flight when the gate closed can still finish.
3. Reopening restores remote connectivity immediately.
4. SSH (if a listener exists) and Sunshine keep working.
5. The emergency script can remove the gate independently of the helper and
   monitor, including after a helper SIGKILL.
6. The monitor's local `/status`/`/health` probes still work while the gate is
   closed (loopback scope).

## Host facts measured before planning

- Strata: `192.0.2.10:8080`, `/health` HTTP 200, `loaded=true`, PID <pid>.
- Sunshine: user service `app-dev.lizardbyte.app.Sunshine.service`, PID <pid>;
  TCP listeners `47984`, `47989`, `47990`, `48010`.
- **No sshd listener on TCP/22 at planning time** (`ss -ltn` and `ps` checked).
  The SSH step is therefore conditional: if SSH is not enabled before the test,
  record "no listener before/after" and do not start it just for the test
  without separate approval.
- Monitor: dry-run, unarmed. Helper: not installed.
- The host has **no `curl`**; `python3`, `nc`, `wget`, `ssh`, `ss` and `nft` are
  present. The check helpers below use `python3`, so they work on the host and
  on a typical remote laptop without installing anything.

## Check helpers (create on the host and on the remote machine)

`curl` is not installed on the host, so use these tiny Python checks. They print
the status/exception and the elapsed time; an expected refusal exits non-zero,
which is fine for a manual test.

```bash
cat > /tmp/httpcheck.py <<'PY'
import sys
import time
import urllib.request

url = sys.argv[1]
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
t0 = time.monotonic()
try:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        body = r.read(200).decode("utf-8", "replace")
        print("HTTP", r.status, "in", round(time.monotonic() - t0, 3), "s", body[:120])
except Exception as e:  # noqa: BLE001
    print(type(e).__name__, "in", round(time.monotonic() - t0, 3), "s:", e)
    sys.exit(1)
PY

cat > /tmp/portcheck.py <<'PY'
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
t0 = time.monotonic()
try:
    s = socket.create_connection((host, port), timeout=timeout)
    s.close()
    print("open", host, port, "in", round(time.monotonic() - t0, 3), "s")
except Exception as e:  # noqa: BLE001
    print(type(e).__name__, host, port, "in", round(time.monotonic() - t0, 3), "s:", e)
    sys.exit(1)
PY
```

## Preconditions and approvals

- Explicit approval for a maintenance window and for temporarily installing the
  helper.
- Physical/local console access, in case remote access is affected.
- No inference workloads; GPU idle. Strata stays **loaded** throughout.
- A second machine on the LAN for the "remote" probes (a laptop is fine).
- The monitor stays in dry-run and unarmed:
  `sleepmgr_ctl status`, `systemctl show sleepmgr.service -p ExecStart -p NRestarts`.
- Capture a baseline (store under a timestamped directory):
  ```bash
  LIVE=/tmp/opencode/live-gate-$(date +%Y%m%d-%H%M%S)
  mkdir -p "$LIVE" && cd "$LIVE"
  ss -ltn  > baseline-ss-tcp.txt
  ss -lun  > baseline-ss-udp.txt
  sudo nft list tables 2>&1 | tee baseline-nft.txt
  systemctl status sleepmgr.service --no-pager | tee baseline-monitor.txt
  python3 /tmp/httpcheck.py http://127.0.0.1:8080/health
  python3 /tmp/httpcheck.py http://192.0.2.10:8080/health
  ```
  Expected: no `sleepmgr_gate` table; both `/health` calls print `HTTP 200`.

## Install (temporary, for the test; not enabled at boot)

### If a temporary helper is already running

Stop it and verify it actually stopped before replacing the socket. A stop
failure must abort the update; never use `systemctl stop ... || true` here,
because the old helper may still own the socket and table.

```bash
if sudo systemctl stop sleepmgr-gate.service; then
  state="$(systemctl show -p ActiveState --value sleepmgr-gate.service)"
  substate="$(systemctl show -p SubState --value sleepmgr-gate.service)"
  printf 'sleepmgr-gate.service: ActiveState=%s SubState=%s\n' "$state" "$substate"
  if [ "$state" != "inactive" ] || [ "$substate" != "dead" ]; then
    echo "ERROR: sleepmgr-gate.service did not stop cleanly" >&2
  else
    sudo rm -f /run/sleepmgr-gate/gate.sock
  fi
else
  echo "ERROR: systemctl stop failed; not deleting the socket" >&2
fi
```

Do not continue to the install block if this prints an error.

Then install the updated units:

```bash
cd "/home/sleepuser/strata-sleepwake"

# helper + units + emergency script (reviewed files from this repo)
sudo install -m 0755 nftgate_helper.py /opt/sleepmgr/nftgate_helper.py
sudo install -m 0644 deploy/sleepmgr-gate.service \
     deploy/sleepmgr-gate.socket /etc/systemd/system/
sudo install -m 0755 deploy/sleepmgr-gate-emergency-open.sh \
     /usr/local/sbin/sleepmgr-gate-emergency-open

# token: root-owned, readable by the monitor group
sudo install -d -m 0755 -o root -g root /etc/sleepmgr
head -c 32 /dev/urandom | base64 | sudo tee /etc/sleepmgr/gate.token >/dev/null
sudo chown root:sleepuser /etc/sleepmgr/gate.token
sudo chmod 0640 /etc/sleepmgr/gate.token

sudo systemctl daemon-reload
sudo systemctl start sleepmgr-gate.socket sleepmgr-gate.service
sudo systemctl status sleepmgr-gate.service sleepmgr-gate.socket --no-pager
sudo journalctl -u sleepmgr-gate.service -n 30 --no-pager
sudo nft list table inet sleepmgr_gate   # expected: "No such file or directory"

# socket activation: systemd creates the listener; no chgrp/chown by hand
stat -c '%U:%G %a' /run/sleepmgr-gate/gate.sock
# expected: root:sleepuser 660
ls -l /run/sleepmgr-gate/gate.sock

# prove ownership/startup survive a helper restart
sudo systemctl restart sleepmgr-gate.service
stat -c '%U:%G %a' /run/sleepmgr-gate/gate.sock   # still root:sleepuser 660
sudo nft list table inet sleepmgr_gate           # still absent
```

The `.socket` unit creates `/run/sleepmgr-gate/gate.sock` as
`root:sleepuser 0660`; the helper inherits the listening fd and never calls
`chown`, so the service keeps `CapabilityBoundingSet=CAP_NET_ADMIN` and
`NoNewPrivileges=yes` (an earlier revision tried to chown the socket itself and
failed with `EPERM` because `CAP_CHOWN` is not granted). Do **not** run
`systemctl enable sleepmgr-gate.service` or `sleepmgr-gate.socket` yet. The
helper starts with the table absent; it only adds it when a lease sends `close`.

The installed `/opt/sleepmgr` monitor is still the pre-gate build. That is fine:
the test lease client imports `netgate.py` from this repository:

```bash
sudo -u sleepuser env PYTHONPATH="/home/sleepuser/strata-sleepwake" \
  python3 -c 'import netgate; print(netgate.GateClient)'
```

## Test lease client (holds the gate closed)

Run in a dedicated terminal. It is **not** the monitor and never suspends.
`ttl_s=120` bounds a forgotten lease; killing the terminal (EOF) also opens it.
Write it to a file first (a heredoc would consume stdin, so `input()` would not
wait for you).

```bash
cat > /tmp/gate-lease.py <<'PY'
from netgate import GateClient

token = open("/etc/sleepmgr/gate.token").read().strip()
c = GateClient("/run/sleepmgr-gate/gate.sock", timeout=3, token=token, ttl_s=120)
print("close:", c.close())
input("gate closed; press Enter to reopen\n")
print("open:", c.open())
PY

sudo -u sleepuser env PYTHONPATH="/home/sleepuser/strata-sleepwake" \
  python3 /tmp/gate-lease.py
```

Expected close reply: `{'ok': True, 'state': 'closed', 'reason': 'leased', ...}`.

## Test sequence

Use a remote client (`REMOTE=192.0.2.10`) for steps marked **remote**.

### 1. Remote block (gate closed)

```bash
# on the remote machine
python3 /tmp/httpcheck.py http://192.0.2.10:8080/health
python3 /tmp/portcheck.py 192.0.2.10 8080
```

Expected with `--action reject`: `URLError`/`ConnectionRefusedError` in <0.5 s.
Record both outputs. If the connection succeeds or hangs >1 s, **abort**.

### 2. Local health still works (gate closed)

```bash
# on the host
python3 /tmp/httpcheck.py http://127.0.0.1:8080/health
python3 /tmp/httpcheck.py http://192.0.2.10:8080/health
```

Expected: both print `HTTP 200`. This proves the loopback scope and that the
monitor's post-gate re-check path is still usable. If either fails, **abort**.

### 3. SSH (conditional)

```bash
# on the host: is there a listener?
ss -ltn | grep -E ':22\b' || echo "no sshd listener"

# on the remote machine, only if the baseline had one
python3 /tmp/portcheck.py 192.0.2.10 22
ssh -o ConnectTimeout=3 -o BatchMode=yes sleepuser@192.0.2.10 true
```

Expected: listener state identical to baseline; the port check and `ssh`
succeed. If there was no listener before, record "not applicable (no listener
before/after)" — do not start sshd for this test without separate approval.

### 4. Sunshine (gate closed)

```bash
# on the remote machine
for p in 47984 47989 47990 48010; do
  python3 /tmp/portcheck.py 192.0.2.10 "$p"
done
```

Expected: all four TCP connects print `open`. UDP ports are not touched by a
TCP/8080 rule; verify `ss -lun` is unchanged from baseline. Optionally start one
Moonlight session during the test; the gate must not affect it.

### 5. Existing request finishes after the gate closes

Run this **before** closing the gate, on the remote machine. It opens a
connection and sends a partial `GET /health` (no final CRLF), then waits:

```bash
cat > /tmp/health-partial.py <<'PY'
import socket
s = socket.create_connection(("192.0.2.10", 8080), timeout=3)
s.sendall(b"GET /health HTTP/1.0\r\nHost: 192.0.2.10\r\n")
print("connected and partial request sent")
input("close the gate now, then press Enter to finish the request\n")
s.sendall(b"\r\n")
print(s.recv(4096).decode("utf-8", "replace"))
PY
python3 /tmp/health-partial.py
```

Sequence:

1. Start the script on the remote machine; it prints "connected...".
2. In the lease terminal, confirm `state=closed`.
3. Press Enter in the remote script.
4. Expected: `HTTP/1.0 200 OK` and a health JSON body. This is an **already
   in-flight** request finishing after the rule landed; it uses `/health`, not
   inference.

Do not use this step to submit a *new* inference request on an established
connection. That residual keep-alive race exists by design in a packet filter;
it is covered by `TestHttpArrivalRace` and is the reason the HTTP-aware gateway
is proposed.

### 6. Remote block re-check

Repeat step 1. Expected: still refused. Record.

### 7. Reopen restores connectivity immediately

In the lease terminal, press Enter (`open`). Then, on the remote machine:

```bash
python3 /tmp/httpcheck.py http://192.0.2.10:8080/health
python3 /tmp/portcheck.py 192.0.2.10 8080
```

Expected: `HTTP 200` in well under 1 s; the port check prints `open`. On the
host, `sudo nft list table inet sleepmgr_gate` must report "No such file or
directory".

### 8. Emergency rollback — independent, table only

Close the gate again with the lease client, confirm remote refuses, then on the
host:

```bash
sudo /usr/local/sbin/sleepmgr-gate-emergency-open --nft-only
```

Expected:

```
gate open: table inet sleepmgr_gate is absent
local /health: OK
```

Remote `httpcheck.py` must immediately print `HTTP 200`. This path uses only
`nft`; it does not need the helper socket or monitor. The lease client's later
`open` is a no-op.

### 9. Emergency rollback — full script (services)

Close the gate again, then:

```bash
sudo /usr/local/sbin/sleepmgr-gate-emergency-open
```

Expected: monitor and helper stopped, table absent, remote 200. Because the
monitor is unarmed/dry-run, stopping it does not suspend or unload Strata.
Afterwards restart it in dry-run:

```bash
sudo systemctl start sleepmgr.service
sleepmgr_ctl status              # armed=false, mode=dry-run
```

The lease client's helper socket is gone after the full script; press Ctrl-C to
exit it (its later `open` would fail). The gate is already open.

### 10. Helper SIGKILL + emergency backstop

Stop the systemd helper first (otherwise it owns the socket and table), then run
a **manual** helper so systemd does not auto-restart it after SIGKILL:

```bash
sudo systemctl stop sleepmgr-gate.service
sudo /usr/bin/python3 /opt/sleepmgr/nftgate_helper.py \
  --socket /run/sleepmgr-gate/gate.sock --table sleepmgr_gate --port 8080 \
  --allow-uid 1000 --group sleepuser --action reject \
  --token-file /etc/sleepmgr/gate.token --require-token \
  --lease-ttl-s 900 &
sleep 1
sudo pgrep -f 'python3 /opt/sleepmgr/nftgate_helper.py' \
  | tee /tmp/opencode/manual-gate.pid
```

Find the **Python** PID with `pgrep` (not `$!`, which is the `sudo` PID).

Close it with the lease client (same client, or a second one). Confirm remote
refuses. Then:

```bash
sudo kill -9 "$(cat /tmp/opencode/manual-gate.pid)"
sudo nft list table inet sleepmgr_gate    # table must still exist
python3 /tmp/httpcheck.py http://192.0.2.10:8080/health   # still refused
sudo /usr/local/sbin/sleepmgr-gate-emergency-open --nft-only
python3 /tmp/httpcheck.py http://192.0.2.10:8080/health   # HTTP 200
```

This is the "helper failed" scenario: SIGKILL leaves the table behind, and the
emergency script removes it without the helper or monitor.

### 11. Stop/cleanup

```bash
# ensure the gate is open
sudo /usr/local/sbin/sleepmgr-gate-emergency-open --nft-only
sudo systemctl stop sleepmgr-gate.service sleepmgr-gate.socket
sudo systemctl disable sleepmgr-gate.service sleepmgr-gate.socket  # if enabled
sudo nft list table inet sleepmgr_gate         # must be absent

# restore/verify the monitor remains dry-run and unarmed
sleepmgr_ctl status
systemctl show sleepmgr.service -p NRestarts --value
python3 /tmp/httpcheck.py http://192.0.2.10:8080/health
```

Leave Strata loaded; do not arm; do not enable automatic suspension. If the
helper was installed only for the test, remove the unit/script/token per the
rollback below, or leave them installed but disabled with explicit approval.

## Expected-results summary

| # | test | expected |
|---|---|---|
| 1 | remote new TCP/8080, gate closed | refused fast (<0.5 s) |
| 2 | local 127.0.0.1 + host LAN IP | HTTP 200 |
| 3 | SSH (if listener exists) | unchanged / success |
| 4 | Sunshine TCP 47984/47989/47990/48010 | all succeed |
| 5 | in-flight `/health` started before close | HTTP 200 after close |
| 6 | remote new TCP/8080 re-check | still refused |
| 7 | reopen | remote 200 immediately; table absent |
| 8 | `--nft-only` rollback | table absent; remote 200 |
| 9 | full rollback | services stopped; table absent; remote 200 |
| 10 | helper SIGKILL + rollback | table persists, then removed; remote 200 |

## Abort criteria (execute rollback immediately)

- Any remote 8080 success while the gate is closed.
- Local `/health` fails while the gate is closed (loopback scope wrong).
- SSH or Sunshine is affected.
- The gate cannot be reopened, or the table persists after `open`.
- Any Strata error, GPU activity, or sign that the monitor started a quiesce.
- Any unintended service restart or automatic suspension attempt.

If remote access is lost, use the physical console. The rule matches only
TCP/8080, so SSH/Sunshine should be unaffected by construction; the emergency
script is the first response if they are not.

## Rollback mechanism (independent of helper and monitor)

Installed as `/usr/local/sbin/sleepmgr-gate-emergency-open`:

```bash
sudo sleepmgr-gate-emergency-open            # stop monitor + helper, delete table, verify
sudo sleepmgr-gate-emergency-open --nft-only # delete table only
sudo sleepmgr-gate-emergency-open --dry-run  # print only
```

It performs, in order:

1. `systemctl stop sleepmgr.service` (aborts any quiesce; safe when unarmed).
2. `systemctl stop sleepmgr-gate.service` with a 10 s timeout; SIGKILL on hang.
3. `nft delete table inet sleepmgr_gate` (the independent core).
4. Verifies `nft list table inet sleepmgr_gate` reports absent.
5. Advisory local `/health` check (never fails the rollback).

Manual equivalent, if the script itself is unavailable:

```bash
sudo systemctl stop sleepmgr.service
sudo systemctl stop sleepmgr-gate.service
sudo nft delete table inet sleepmgr_gate
sudo nft list tables | grep sleepmgr_gate || echo "gate absent"
```

A reboot also clears the table, but is not required.

## What this test does not do

- It does **not** unload Strata.
- It does **not** arm the monitor or suspend the machine.
- It does **not** submit an inference request; all HTTP checks use `/health`.
- It does **not** prove the HTTP keep-alive race is solved; that requires the
  proposed HTTP-aware gateway.
