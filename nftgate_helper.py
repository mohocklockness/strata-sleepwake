#!/usr/bin/env python3
"""Privileged inference-arrival gate helper (root-owned, CAP_NET_ADMIN).

This process is the *only* thing that touches the firewall.  It owns exactly
one nftables table (``inet sleepmgr_gate`` by default) and one input-chain rule
that drops *new* TCP connections to the configured inference port(s).  It never
reads, flushes or modifies any other table, chain or rule -- ``open()`` is
``delete table inet sleepmgr_gate`` and nothing more.

Why an nft gate at all
----------------------
Strata is suspended only after ``POST /unload`` releases the model's VRAM (S3
does not preserve VRAM).  A request that arrives between "model unloaded" and
"system suspended" would make the server reload the model and start GPU work,
and then the machine suspends mid-inference.  The gate removes the window by
refusing new arrivals to the inference port while the monitor settles, drains
and re-checks.

What the gate can and cannot do
-------------------------------
See ``docs/inference-gate.md``.  Short version: blocking *new* connections
cannot revoke a request that a client sends on an *already established*
connection (HTTP keep-alive / HTTP/2 multiplexing), nor a request whose bytes
already reached the server.  That is why the monitor always follows the close
with a settle/drain window and a fresh ``/status`` re-check, and why an
HTTP-aware gateway is the correct long-term fix.  As of this writing Strata is
HTTP/1.0 with ``Connection: close`` and no keep-alive, so one request == one
connection and the new-connection block covers essentially all arrivals; the
gate + settle + re-check is still mandatory because that property is not
guaranteed forever.

Safety properties implemented here
----------------------------------
* **Narrow scope** -- one table, one chain, one rule; the port set, the loopback
  exemption and the table name are explicit.  The rule matches SYN only and is
  scoped with ``iifname != "lo"``; ``meta skuid`` is deliberately not used
  because it is a no-op in the input hook (measured).
* **Authentication** -- SO_PEERCRED uid allow-list plus an optional shared
  token (constant-time compare) read from a root-readable file.
* **Cleanup** -- startup never deletes a surviving gate table merely because a
  seal marker is missing.  A closed table is adopted as sealed and remains
  blocking until an explicit authenticated ``open``.  SIGTERM/SIGINT leave a
  closed gate closed.  The seal marker is boot-scoped and lives in persistent
  state, so a failed recovery cannot fail open merely because systemd restarted
  the helper or cleaned a runtime directory.
* **Recovery** -- an ordinary ``close`` is a *lease* tied to the requesting
  connection; if the monitor dies (socket closes) the helper reopens the gate,
  and a ``ttl_s`` cap reopens it even if the monitor merely hangs.
* **Controlled-suspend seal** -- ``seal`` closes the gate with no expiry and
  keeps it closed across monitor disconnect.  The monitor uses this for the
  suspend window so a failed resume cannot expose an unloaded Strata.  Only an
  explicit authenticated ``open`` clears the seal.

This program is **not installed, enabled or started** by anything in this repo
yet.  ``deploy/sleepmgr-gate.service`` is provided for review only; the
installer deliberately does not copy it.
"""
from __future__ import annotations

import argparse
import grp
import hmac
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

PROTO = 1
DEFAULT_TABLE = "sleepmgr_gate"
DEFAULT_SOCKET = "/run/sleepmgr-gate/gate.sock"
# Persistent state, not /run.  systemd may remove a RuntimeDirectory (and a
# reboot always clears /run), but losing the marker while a table is still
# installed must never cause the helper to delete that table and fail open.
# The marker records the boot id; a marker from an earlier boot is stale because
# nftables runtime state did not survive the reboot.
DEFAULT_SEALED_STATE = "/var/lib/sleepmgr-gate/sealed.json"
LEGACY_SEALED_STATE = "/run/sleepmgr-gate/sealed.json"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
MAX_LINE = 4096
EXEMPT_RULE_COMMENT = "sleepmgr: inference gate"


class GateError(RuntimeError):
    pass


def read_boot_id():
    """Return the current kernel boot id, or '' when it is unavailable."""
    try:
        with open(BOOT_ID_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


# --------------------------------------------------------------------------
# nft plumbing
# --------------------------------------------------------------------------

class NftRunner:
    """Runs ``nft``.  ``dry_run`` never executes anything (safe, unprivileged)."""

    def __init__(self, nft="nft", dry_run=False, log=None, timeout=10):
        self.nft = nft
        self.dry_run = bool(dry_run)
        self.timeout = timeout
        self.log = log or (lambda _s: None)

    def _run(self, argv, text=None):
        if self.dry_run:
            shown = " ".join(argv)
            self.log("[dry-run] " + shown + ((" <<<\n" + text.rstrip()) if text else ""))
            return 0, "", ""
        try:
            p = subprocess.run(argv, input=text, capture_output=True, text=True,
                               timeout=self.timeout)
            return p.returncode, p.stdout or "", p.stderr or ""
        except FileNotFoundError as e:
            return 127, "", f"nft not found: {e}"
        except subprocess.TimeoutExpired:
            return 124, "", f"nft timed out after {self.timeout}s"
        except OSError as e:  # noqa: BLE001 - report, never crash the helper
            return 126, "", str(e)

    def apply(self, script):
        rc, out, err = self._run([self.nft, "-f", "-"], script)
        if rc == 0:
            return True, "applied"
        return False, ((err or out).strip()[:300] or f"nft rc={rc}")

    def delete_table(self, table):
        """Best-effort delete.  Returns (ok, existed, message)."""
        rc, out, err = self._run([self.nft, "delete", "table", "inet", table])
        if rc == 0:
            return True, True, "deleted"
        blob = (err + out).lower()
        if "no such file or directory" in blob or "does not exist" in blob \
                or "no such file" in blob:
            return True, False, "absent"
        return False, False, ((err or out).strip()[:300] or f"nft rc={rc}")

    def list_table(self, table):
        return self._run([self.nft, "list", "table", "inet", table])

    def check_available(self):
        rc, _out, err = self._run([self.nft, "list", "tables"])
        if self.dry_run:
            return True, "dry-run (nft not executed)"
        return (rc == 0), (err.strip()[:200] or "ok")


# --------------------------------------------------------------------------
# semantic rule verification (shared by the runtime and the boot script)
# --------------------------------------------------------------------------

def _normalize_nft_line(line):
    """Collapse nft's column padding so checks never depend on spacing."""
    return re.sub(r"\s+", " ", (line or "").strip())


_FLAGLIST = r"[a-z]+(?:\s*[|,]\s*[a-z]+)*"

# Clauses the generator may emit.  The scanner consumes them one at a time;
# anything left over is an unexpected restriction (for example an added
# ``ip saddr`` match that would gate only some remote clients).
_GATE_CLAUSES = (
    ("comment", re.compile(r'comment\s+"([^"]*)"')),
    ("comment", re.compile(r"comment\s+(\S+)")),
    ("counter", re.compile(r"counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?")),
    ("dport", re.compile(r"tcp\s+dport\s+(\{[^}]*\}|\d+)")),
    ("flags_expr", re.compile(r"tcp\s+flags\s*&\s*\(\s*(" + _FLAGLIST
                              + r")\s*\)\s*==\s*(" + _FLAGLIST + r")")),
    ("flags_real", re.compile(r"tcp\s+flags\s+(" + _FLAGLIST + r")\s*/\s*("
                              + _FLAGLIST + r")")),
    ("loopback", re.compile(r'iifname\s*!=\s*"?lo"?')),
    # Only our own target is accepted; any other `reject with ...` leaves
    # tokens behind and is refused by the strict target check.  jump/goto/return
    # are recognised so an earlier skipping rule can be detected.
    ("verdict", re.compile(r"(drop|accept|reject(?:\s+with\s+tcp\s+reset)?"
                           r"|jump|goto|return)\b")),
)


def _flag_set(text):
    return {t for t in re.split(r"[|,\s]+", (text or "").strip().lower())
            if t}


def _ports_from_text(body):
    body = (body or "").strip()
    if body.startswith("{"):
        if not body.endswith("}"):
            return None
        body = body[1:-1]
    ports = set()
    for tok in body.replace(",", " ").split():
        if not tok.isdigit():
            return None
        ports.add(int(tok))
    return ports or None


def _scan_gate_rule(rule):
    """Split one normalised nft rule into the clauses sleepmgr owns.

    Returns a dict with ``ports``, ``flags`` (set, mask), ``loopback``,
    ``verdict``/``verdict_text``, ``comment``, ``counter``, plus
    ``duplicates`` and ``extra`` tokens.  ``extra`` is non-empty for any match
    or target the generator would not have written (a source address, source
    port, mark, interface, different reject target, ...).
    """
    text = _normalize_nft_line(rule)
    out = {"ports": None, "flags": None, "loopback": False, "verdict": None,
           "verdict_text": "", "comment": None, "counter": 0,
           "duplicates": [], "extra": []}
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        rest = text[pos:]
        for name, pattern in _GATE_CLAUSES:
            m = pattern.match(rest)
            if not m:
                continue
            if name == "comment":
                if out["comment"] is not None:
                    out["duplicates"].append("comment")
                out["comment"] = m.group(1)
            elif name == "counter":
                out["counter"] += 1
            elif name == "dport":
                if out["ports"] is not None:
                    out["duplicates"].append("tcp dport")
                out["ports"] = _ports_from_text(m.group(1))
            elif name in ("flags_expr", "flags_real"):
                if out["flags"] is not None:
                    out["duplicates"].append("tcp flags")
                if name == "flags_expr":
                    mask, wanted = m.group(1), m.group(2)
                else:
                    wanted, mask = m.group(1), m.group(2)
                out["flags"] = (_flag_set(wanted), _flag_set(mask))
            elif name == "loopback":
                if out["loopback"]:
                    out["duplicates"].append("iifname")
                out["loopback"] = True
            else:  # verdict
                if out["verdict"] is not None:
                    out["duplicates"].append("verdict")
                vtext = m.group(1).strip()
                out["verdict_text"] = vtext
                out["verdict"] = vtext.split()[0]
            pos += m.end()
            break
        else:
            token = re.match(r"\S+", rest).group(0)
            out["extra"].append(token)
            pos += len(token)
    return out


def _parse_dports(rule):
    """Return the set of TCP dports a normalised rule gates, or ``None``."""
    return _scan_gate_rule(rule)["ports"]


def _rule_has_syn_match(rule):
    """True only for a match on an opening SYN (SYN set, ACK clear).

    Accepts both forms nft can print: the canonical ``tcp flags syn / syn,ack``
    and the rule text ``tcp flags & (syn | ack) == syn`` (spacing is free).
    """
    flags = _scan_gate_rule(rule)["flags"]
    return bool(flags and flags[0] == {"syn"} and flags[1] == {"syn", "ack"})


def _rule_verdict(rule):
    """The terminal verdict of a rule, or ``None`` when it has none."""
    return _scan_gate_rule(rule)["verdict"]


def _rule_exempts_loopback(rule):
    return _scan_gate_rule(rule)["loopback"]


def _parse_priority(spec):
    """Numeric priority from a chain spec like ``priority filter - 10``."""
    m = re.search(r"\bpriority\s+([^;]+)", spec or "")
    if not m:
        return None
    toks = m.group(1).strip().split()
    if not toks:
        return None
    if toks[0] == "filter":
        toks = toks[1:]
        if not toks:
            return 0
    try:
        if len(toks) == 1:
            return int(toks[0])
        if len(toks) == 2 and toks[0] in ("+", "-"):
            value = int(toks[1])
            return -value if toks[0] == "-" else value
    except (TypeError, ValueError):
        return None
    return None


def parse_gate_table(text, table=DEFAULT_TABLE):
    """Parse ``nft list table inet <table>`` output into a small structure.

    Returns ``{"table": name, "chains": [{"name", "spec", "rules"}]}`` for the
    named table, or ``None`` when it is not present in the listing.  Rules are
    whitespace-normalised; the base-chain spec line is kept apart from them.
    """
    result = None
    chain = None
    in_table = False
    for raw in (text or "").splitlines():
        line = _normalize_nft_line(raw)
        if not line:
            continue
        if not in_table:
            m = re.match(r"^table inet (\S+?)\s*\{?$", line)
            if m and m.group(1) == table:
                result = {"table": table, "chains": []}
                in_table = True
            continue
        if chain is None:
            m = re.match(r"^chain (\S+?)\s*\{?$", line)
            if m:
                chain = {"name": m.group(1), "spec": None, "rules": []}
                result["chains"].append(chain)
                continue
            if line == "}":
                in_table = False
            continue
        if line == "}":
            chain = None
            continue
        if chain["spec"] is None and line.startswith("type "):
            chain["spec"] = line
            continue
        chain["rules"].append(line)
    return result


def verify_gate_ruleset(text, *, ports, action="drop", exempt_loopback=True,
                        table=DEFAULT_TABLE):
    """Semantically verify a live ``nft list table`` listing.

    This is the single source of truth shared by the runtime ``NftGate.status``
    and the boot script (``--verify-listing``).  A table merely existing, or a
    line containing ``tcp dport``, is *not* protection.  The listing must prove
    an input *base chain* (``type filter hook input``) with a priority that runs
    before the default filter chains; a rule that gates exactly the configured
    ports; a match on only opening SYNs (SYN set, ACK clear) in either form nft
    prints; the configured loopback exemption; the configured verdict (``drop``
    or ``reject with tcp reset``); the ownership comment; and *nothing else* —
    an added source-address/source-port/mark restriction would gate only some
    remote clients and is refused.

    Earlier rules in the *same* chain must not accept or skip the gate rule.
    An accept in a different base chain does **not** bypass a later blocking
    base chain: nft evaluates every base chain for the hook, and a drop in any
    of them still drops the packet (only accept within the same chain is
    terminal for that chain).

    Returns ``(ok, problem)``; ``problem`` is empty when ``ok`` is true.
    """
    want = sorted({int(p) for p in (ports or ())})
    want_set = set(want)
    if not want_set:
        return False, "no inference ports were configured to verify"
    parsed = parse_gate_table(text, table)
    if not parsed:
        return False, f"table inet {table} is absent"
    inputs = [c for c in parsed["chains"]
              if "hook input" in (c.get("spec") or "")]
    if not inputs:
        return False, ("no input base chain is hooked (an unhooked or "
                       "non-input chain cannot block arrivals)")

    # Prefer the input chain that carries the intended rule (ports, verdict and
    # SYN match); an unrelated earlier chain must not mask the real gate rule.
    chain = None
    idx = None
    fallback = None
    for candidate in inputs:
        for i, rule in enumerate(candidate["rules"]):
            if _parse_dports(rule) != want_set:
                continue
            if fallback is None:
                fallback = (candidate, i)
            if (_rule_verdict(rule) == action and _rule_has_syn_match(rule)):
                chain, idx = candidate, i
                break
        if chain is not None:
            break
    if chain is None and fallback is not None:
        chain, idx = fallback
    if chain is None:
        seen = sorted({tuple(sorted(d)) for c in inputs
                       for d in (_parse_dports(r) for r in c["rules"]) if d})
        if seen:
            return False, ("the gate rule does not cover exactly the "
                           f"configured ports {want} (found {seen})")
        return False, ("no rule blocks new connections to the configured "
                       f"ports {want}")

    spec = chain.get("spec") or ""
    if "type filter" not in spec:
        return False, f"the input chain is not a filter base chain ({spec})"
    prio = _parse_priority(spec)
    if prio is None:
        return False, f"cannot read the input chain priority ({spec})"
    if prio > 0:
        return False, (f"the input chain priority ({prio}) runs after the "
                       "default filter chains; the gate must be evaluated "
                       "before other input policy")

    rules = chain["rules"]
    for rule in rules[:idx]:
        verdict = _rule_verdict(rule)
        if verdict in ("jump", "goto", "return"):
            return False, (f"a rule before the gate rule ({verdict}) can "
                           "skip it")
        if verdict == "accept":
            dports = _parse_dports(rule)
            if dports is None or (dports & want_set):
                return False, ("a rule before the gate rule accepts the gated "
                               "traffic, so the gate would not block it")

    target = rules[idx]
    comp = _scan_gate_rule(target)
    if comp["extra"]:
        return False, ("the gate rule has unexpected match/target terms "
                       f"({' '.join(comp['extra'][:6])}); it would gate only "
                       "some clients")
    if comp["duplicates"]:
        return False, ("the gate rule repeats "
                       + ", ".join(sorted(set(comp["duplicates"])))
                       + "; refusing an ambiguous rule")
    if not _rule_has_syn_match(target):
        return False, "the gate rule does not match only opening SYNs"
    verdict = comp["verdict"]
    if verdict != action:
        return False, f"the gate rule verdict is {verdict!r}, not {action!r}"
    if action == "reject" and comp["verdict_text"] not in (
            "reject", "reject with tcp reset"):
        return False, (f"the gate rule reject target {comp['verdict_text']!r} "
                       "is not the configured 'reject with tcp reset'")
    if comp["loopback"] != bool(exempt_loopback):
        if exempt_loopback:
            return False, ("the gate rule does not exempt loopback, so the "
                           "monitor's local probes would be blocked")
        return False, ("the gate rule exempts loopback, but the configuration "
                       "does not")
    if comp["comment"] != EXEMPT_RULE_COMMENT:
        return False, ("the gate rule is not marked as owned by sleepmgr "
                       "(comment missing or different)")
    return True, ""


class NftGate:
    """The narrowly scoped firewall state machine (no sockets here)."""

    def __init__(self, runner=None, ports=(8080,), exempt_loopback=True,
                 action="drop", table=DEFAULT_TABLE, log=None):
        self.runner = runner or NftRunner()
        self.ports = sorted({int(p) for p in (ports or ())})
        if not self.ports:
            raise GateError("at least one inference port is required")
        self.exempt_loopback = bool(exempt_loopback)
        action = (action or "drop").lower()
        if action not in ("drop", "reject"):
            raise GateError(f"unsupported gate action: {action!r}")
        self.action = action
        self.table = table
        self.log = log or (lambda _s: None)

    # ------------------------------------------------------------------ script
    def build_script(self):
        """The complete, self-contained ruleset for our one table.

        It is intentionally impossible for this script to touch anything else:
        every line names ``inet <table>`` explicitly and the only flush-like
        operation is the separate, targeted ``delete table``.
        """
        ports = ", ".join(str(p) for p in self.ports)
        lines = [
            f"add table inet {self.table}",
            (f"add chain inet {self.table} input "
             "{ type filter hook input priority filter - 10 ; policy accept ; }"),
        ]
        # Match only connection-opening SYNs (SYN set, ACK clear).  This is
        # stateless on purpose: `ct state new` depends on conntrack already
        # tracking the flow.  If conntrack was cold when the rule landed, an
        # established connection's next data packet can be classified as "new"
        # and dropped (measured in a throwaway netns), which would abort an
        # in-flight request instead of letting it drain.  The SYN match blocks
        # new arrivals and provably leaves established traffic alone.
        #
        # Do NOT use meta skuid here.  It is only meaningful for locally
        # generated packets; in the input hook it matched 0 packets in a real
        # netns lab, i.e. "meta skuid != 1000" silently turned the gate into a
        # no-op (remote and local traffic both passed).  The gate must therefore
        # be scoped by interface, not uid.
        #
        # `iifname != "lo"` blocks only arrivals from outside the host.  The
        # monitor's probes to 127.0.0.1 or to the host's own LAN address take
        # the local route and arrive on lo, so the post-gate /status and /health
        # checks keep working (verified in the two-namespace lab).  All local
        # processes are inside the monitor's trust domain; this gate is about
        # remote inference arrivals.  Other ports (SSH, Sunshine) are untouched
        # because the rule matches only the configured inference ports.
        scope = 'iifname != "lo" ' if self.exempt_loopback else ""
        verdict = "reject with tcp reset" if self.action == "reject" else "drop"
        lines.append(f"add rule inet {self.table} input tcp dport {{ {ports} }} "
                     f"tcp flags & (syn|ack) == syn {scope}counter {verdict} "
                     f'comment "{EXEMPT_RULE_COMMENT}"')
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------ state
    def close(self):
        """Atomically replace the owned table with the fail-closed ruleset.

        A ``delete table`` (only when the table already exists) and the fresh
        definition go into a *single* ``nft -f`` batch.  nft applies a batch
        atomically, so if the new table cannot be installed the transaction is
        rolled back and any existing protection -- and the seal that depends on
        it -- is left untouched instead of being deleted first and lost.

        A table that cannot be inspected is treated as *unknown*, never as
        absent: guessing could either fail open or clobber live protection.
        """
        script = self.build_script()
        rc, out, err = self.runner.list_table(self.table)
        if rc == 0:
            script = f"delete table inet {self.table}\n" + script
        else:
            blob = (err + out).lower()
            absent = ("no such file" in blob or "does not exist" in blob)
            if not absent:
                return False, ("cannot inspect the gate table before replacing "
                               "it: "
                               + ((err or out).strip()[:200] or f"nft rc={rc}"))
        ok, msg = self.runner.apply(script)
        if not ok:
            return False, f"cannot close gate: {msg}"
        return True, "closed"

    def open(self):
        ok, existed, msg = self.runner.delete_table(self.table)
        if not ok:
            return False, f"cannot open gate: {msg}"
        return True, ("opened (removed gate table)" if existed else "already open")

    def status(self):
        if getattr(self.runner, "dry_run", False):
            # The dry-run wrapper cannot observe the real table, so never claim
            # a verified state (callers fail closed on unknown).
            return {"state": "unknown", "table": self.table,
                    "ports": self.ports,
                    "error": "dry-run (nft not executed)"}
        rc, out, err = self.runner.list_table(self.table)
        if rc == 0:
            ok, problem = verify_gate_ruleset(
                out, ports=self.ports, action=self.action,
                exempt_loopback=self.exempt_loopback, table=self.table)
            parsed = parse_gate_table(out, self.table) or {"chains": []}
            rules = 0
            for chain in parsed["chains"]:
                for rule in chain["rules"]:
                    if _parse_dports(rule) and _rule_verdict(rule) in ("drop",
                                                                       "reject"):
                        rules += 1
            dropped = None
            m = re.search(r"counter\s+packets\s+(\d+)", out)
            if m:
                dropped = int(m.group(1))
            return {"state": "closed", "rules": rules, "verified": bool(ok),
                    "problem": problem or None, "dropped": dropped,
                    "table": self.table, "ports": self.ports}
        blob = (err + out).lower()
        if "no such file" in blob or "does not exist" in blob:
            return {"state": "open", "table": self.table, "ports": self.ports}
        return {"state": "unknown", "table": self.table,
                "error": (err or out).strip()[:200] or f"nft rc={rc}"}

    def cleanup_stale(self):
        """Explicitly delete the gate table.

        This is deliberately **not** called by helper startup.  A surviving
        table may be the only protection for an unloaded Strata model, so the
        helper adopts it as sealed instead (see ``GateService.startup_recover``).
        The method remains available for explicit operator/lab use.
        """
        ok, existed, msg = self.runner.delete_table(self.table)
        if ok and existed:
            return True, "removed a stale gate table from a previous run"
        if ok:
            return True, "no stale gate table"
        return False, f"cannot clear a stale gate table: {msg}"


# --------------------------------------------------------------------------
# lease state machine (transport agnostic, so it is easy to unit-test)
# --------------------------------------------------------------------------

class GateService:
    """Keeps the lease bookkeeping in one lock-protected place.

    ``owner`` is the connection object that requested ``close``.  It is compared
    by identity: when that connection goes away the gate is reopened, which is
    how a crashed monitor is recovered.
    """

    def __init__(self, gate, lease_ttl_s=900, clock=time.monotonic, log=None,
                 state_file=None, boot_id=None):
        self.gate = gate
        self.lease_ttl_s = float(lease_ttl_s)
        self.clock = clock
        self.log = log or (lambda _s: None)
        self.state_file = state_file or None
        self.boot_id = read_boot_id() if boot_id is None else str(boot_id)
        self._lock = threading.RLock()
        self.state = "open"
        self.owner = None
        self.expiry = None
        self.sealed = False
        self.reason = "startup"

    # ------------------------------------------------------- seal persistence
    def _write_sealed(self, reason="controlled suspend; explicit open required"):
        """Persist the seal before applying it, so a restart cannot fail open."""
        if not self.state_file:
            return
        parent = os.path.dirname(self.state_file) or "."
        os.makedirs(parent, mode=0o755, exist_ok=True)
        tmp = f"{self.state_file}.{os.getpid()}.tmp"
        doc = {"sealed": True, "pid": os.getpid(), "at": time.time(),
               "boot_id": self.boot_id, "reason": reason}
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, sort_keys=True)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.state_file)
            # Make the rename itself durable; the seal outlives a crash.
            try:
                dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            except OSError:
                dfd = None
            if dfd is not None:
                try:
                    try:
                        os.fsync(dfd)
                    except OSError as e:
                        # Some filesystems reject directory fsync.  The marker
                        # is already renamed into place; log and continue.
                        self.log(f"cannot fsync seal marker directory {parent}: {e}")
                finally:
                    os.close(dfd)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _clear_sealed(self):
        if not self.state_file:
            return
        try:
            os.unlink(self.state_file)
        except FileNotFoundError:
            pass
        except OSError as e:
            self.log(f"cannot clear seal marker {self.state_file}: {e}")

    def _marker_boot_id(self):
        """Read the boot id recorded in the marker, or None if unavailable.

        A missing/corrupt document is deliberately treated as *not stale* by
        the caller: a marker we cannot understand must fail closed, not fail
        open.
        """
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            self.log(f"cannot parse seal marker {self.state_file}: "
                     f"{type(e).__name__}: {e}; treating it as sealed")
            return None
        if isinstance(doc, dict) and doc.get("boot_id"):
            return str(doc.get("boot_id"))
        return None

    def restore_sealed(self):
        """If a durable seal marker exists, restore and enforce it.

        Returns True when the helper started in the sealed state.  A marker
        records the boot id it was written under.  A marker from a *previous*
        boot is not discarded: it is the surviving evidence that the previous
        boot ended inside a controlled-suspend seal (a completed recovery
        clears the marker with ``open``), i.e. an interrupted sealed recovery.
        nftables runtime state does not survive reboot, so this boot re-seals
        before anything can be admitted.  Any marker from this boot (including
        an unparseable one) also forces a closed gate.
        """
        if not self.state_file or not os.path.exists(self.state_file):
            return False
        marker_boot = self._marker_boot_id()
        stale = bool(marker_boot and self.boot_id and marker_boot != self.boot_id)
        if stale:
            self.log(f"seal marker is from a previous boot "
                     f"({marker_boot[:8]} -> {self.boot_id[:8]}); "
                     "treating it as an interrupted sealed recovery and "
                     "re-sealing this boot")
        with self._lock:
            if stale:
                # Persist this boot's marker before proving the table, so a
                # crash between the two cannot fail open.
                self._write_sealed(
                    reason="interrupted sealed recovery (marker from previous "
                           "boot); explicit open required")
            # Do not delete/reapply an already closed table: that would create
            # a tiny fail-open window before this helper starts serving.
            st = self.gate.status()
            if st.get("state") != "closed":
                ok, msg = self.gate.close()
                if not ok:
                    raise GateError(f"cannot restore sealed gate: {msg}")
            self.state = "closed"
            self.owner = None
            self.expiry = None
            self.sealed = True
            self.reason = ("sealed (interrupted sealed recovery; explicit open "
                           "required)" if stale
                           else "sealed (restored after helper restart)")
            self.log("gate sealed state restored; explicit open required")
            return True

    def adopt_closed_gate(self, reason="closed gate table at startup"):
        """Fail closed when a table survived but its marker did not.

        The helper cannot distinguish an ordinary crashed lease from a sealed
        controlled-suspend window, and it does not know whether Strata is
        loaded.  Deleting the table would therefore be an unsafe guess.
        """
        with self._lock:
            # Persist first, then prove the table is really closed.  If it
            # vanished between status and marker write, close it again.
            self._write_sealed(reason)
            st = self.gate.status()
            if st.get("state") != "closed":
                ok, msg = self.gate.close()
                if not ok:
                    raise GateError(f"cannot adopt closed gate table: {msg}")
            self.state = "closed"
            self.owner = None
            self.expiry = None
            self.sealed = True
            self.reason = "sealed (adopted after helper restart)"
            self.log("existing closed gate table had no valid seal marker; "
                     "adopted it as sealed; explicit open required")
            return True

    def _clear_legacy_sealed(self):
        """Remove a pre-upgrade /run marker so it cannot confuse an operator.

        The new helper never reads it, but leaving a stale file that looks like
        a seal is misleading.  Removal is best-effort; it cannot affect the
        authoritative persistent marker.
        """
        if not LEGACY_SEALED_STATE or LEGACY_SEALED_STATE == self.state_file:
            return
        try:
            os.unlink(LEGACY_SEALED_STATE)
            self.log(f"removed legacy seal marker {LEGACY_SEALED_STATE}")
        except FileNotFoundError:
            pass
        except OSError as e:
            self.log(f"cannot remove legacy seal marker {LEGACY_SEALED_STATE}: {e}")

    @staticmethod
    def _closed_table_ok(status):
        """True only when the live table is closed and *verified* blocking.

        The helper's ``status`` derives ``verified`` from a semantic check of
        the real rule (ports, SYN match, loopback exemption, verdict, chain
        hook/order).  Older test doubles that report neither ``verified`` nor
        ``rules`` fall back to the logical state; anything that reports a
        negative verification is refused.
        """
        if not isinstance(status, dict) or status.get("state") != "closed":
            return False
        if "verified" in status:
            return status.get("verified") is True
        if "rules" not in status:
            return True       # older fake/helper: logical state is all we have
        try:
            return int(status.get("rules")) >= 1
        except (TypeError, ValueError):
            return False

    def _verify_reconciled(self):
        """Prove logical state and actual nftables state agree at startup.

        A marker can survive while the table is missing, and a table can
        survive with zero rules.  Both are fail-open for a sealed gate.  Re-apply
        once if the table is missing/malformed, then abort startup if it still
        cannot be proven blocking.
        """
        st = self.gate.status()
        if self.state == "closed":
            if not self._closed_table_ok(st):
                ok, msg = self.gate.close()
                if not ok:
                    raise GateError(f"cannot reconcile sealed gate at startup: {msg}")
                st = self.gate.status()
                if not self._closed_table_ok(st):
                    problem = st.get("problem") if isinstance(st, dict) else None
                    raise GateError(
                        "sealed gate still cannot be proven blocking after "
                        "reconciliation" + (f": {problem}" if problem else ""))
        elif self.state == "open":
            if st.get("state") != "open":
                raise GateError(f"logical gate is open but actual state is {st.get('state')!r}")
        self.log("startup: logical gate state and actual nftables state agree")

    def startup_recover(self):
        """Fail-closed helper startup.

        Returns ``"restored"``, ``"adopted"`` or ``"open"``.  A surviving
        closed table is never removed just because the marker is missing.  A
        marker from a previous boot means the last boot ended inside a seal and
        is re-sealed, not discarded.  An unknown nft state aborts startup
        rather than guessing.
        """
        self._clear_legacy_sealed()
        if self.restore_sealed():
            self._verify_reconciled()
            return "restored"
        st = self.gate.status()
        state = st.get("state")
        if state == "closed":
            self.adopt_closed_gate()
            self._verify_reconciled()
            return "adopted"
        if state != "open":
            raise GateError(f"cannot determine gate state at startup: {st}")
        self._verify_reconciled()
        return "open"

    def _snapshot(self):
        left = None
        if self.state == "closed" and self.expiry is not None:
            left = max(0.0, self.expiry - self.clock())
        actual = self.gate.status()
        actual_state = actual.get("state") if isinstance(actual, dict) else None
        rules = actual.get("rules") if isinstance(actual, dict) else None
        verified = actual.get("verified") if isinstance(actual, dict) else None
        problem = actual.get("problem") if isinstance(actual, dict) else None
        if self.state == "closed":
            consistent = self._closed_table_ok(actual)
        elif self.state == "open":
            consistent = actual_state == "open" and not self.sealed
        else:
            consistent = False
        return {"state": self.state, "reason": self.reason,
                "seconds_left": left, "lease_ttl_s": self.lease_ttl_s,
                "sealed": bool(self.sealed), "rules": rules,
                "verified": verified, "problem": problem,
                "actual_state": actual_state, "consistent": consistent,
                "actual_error": (actual.get("error")
                                 if isinstance(actual, dict) else None)}

    def status(self):
        with self._lock:
            return self._snapshot()

    def close(self, conn, ttl_s=None, seal=False):
        """Close the gate as a lease, or seal it with no automatic reopen.

        A lease is the compatibility/crash-recovery behaviour used by ordinary
        callers.  ``seal=True`` is used by the controlled suspend flow: the gate
        must remain closed until the monitor has reacquired the guard, loaded
        Strata and verified readiness.  A sealed gate is never reopened by
        disconnect or expiry; only an explicit ``open`` clears it.
        """
        if not seal:
            ttl = self.lease_ttl_s if ttl_s is None else float(ttl_s)
            if ttl <= 0:
                raise GateError("lease ttl_s must be positive")
        with self._lock:
            if self.state == "closed" and self.sealed:
                # Only an explicit open may clear a seal.  In particular, an
                # ordinary close must not silently downgrade it to a lease.
                # Re-apply the table if it vanished or lost its rule while the
                # seal marker survived; a sealed marker with no rule is not
                # protection.
                if not self._closed_table_ok(self.gate.status()):
                    ok, msg = self.gate.close()
                    if not ok:
                        raise GateError(f"cannot re-apply sealed gate: {msg}")
                return self._snapshot()
            if self.state == "closed" and self.owner is conn:
                if seal:
                    self._write_sealed()
                    self.sealed = True
                    self.expiry = None
                    self.reason = "sealed (renewed)"
                else:
                    # Idempotent re-close by the same owner: just extend the
                    # lease.  Repair a table that disappeared in the meantime.
                    if not self._closed_table_ok(self.gate.status()):
                        ok, msg = self.gate.close()
                        if not ok:
                            raise GateError(f"cannot re-apply leased gate: {msg}")
                    self.expiry = self.clock() + ttl
                    self.reason = "leased (renewed)"
                return self._snapshot()
            if seal:
                self._write_sealed()
            try:
                ok, msg = self.gate.close()
            except Exception:
                if seal:
                    self._clear_sealed()
                raise
            if not ok:
                if seal:
                    self._clear_sealed()
                raise GateError(msg)
            self.state = "closed"
            self.owner = conn
            self.sealed = bool(seal)
            self.expiry = None if seal else self.clock() + ttl
            self.reason = "sealed" if seal else "leased"
            if seal:
                self.log("gate sealed (no lease expiry; explicit open required)")
            else:
                self.log(f"gate closed (lease {ttl:.0f}s)")
            return self._snapshot()

    def open(self, conn=None, why="requested"):
        with self._lock:
            ok, msg = self.gate.open()
            if not ok:
                raise GateError(msg)
            self.state = "open"
            self.owner = None
            self.expiry = None
            self.sealed = False
            self.reason = why
            self._clear_sealed()
            self.log(f"gate opened ({why})")
            return self._snapshot()

    def on_client_gone(self, conn, why="owner disconnected"):
        """Release a lease on disconnect; keep a sealed gate closed."""
        with self._lock:
            if self.owner is not conn:
                return self._snapshot()
            if self.sealed:
                # The monitor exited before recovery completed.  Fail closed:
                # keep the firewall rule until an explicit authenticated open.
                self.owner = None
                self.reason = "sealed (owner disconnected; remains closed)"
                self.log("gate remains sealed after monitor disconnect")
                return self._snapshot()
            try:
                ok, msg = self.gate.open()
            except Exception as e:  # noqa: BLE001 - must never take the helper down
                self.log(f"recovery reopen failed: {type(e).__name__}: {e}")
                return self._snapshot()
            if not ok:
                self.log(f"recovery reopen failed: {msg}")
                return self._snapshot()
            self.state = "open"
            self.owner = None
            self.expiry = None
            self.sealed = False
            self.reason = why
            self.log(f"gate reopened ({why})")
            return self._snapshot()

    def expire(self):
        """Reopen an overrun lease.  Safe to call often from a watchdog thread."""
        with self._lock:
            if self.state != "closed" or self.expiry is None or self.sealed:
                return None
            if self.clock() < self.expiry:
                return None
            try:
                ok, msg = self.gate.open()
            except Exception as e:  # noqa: BLE001
                self.log(f"lease expiry reopen failed: {type(e).__name__}: {e}")
                return None
            if not ok:
                self.log(f"lease expiry reopen failed: {msg}")
                return None
            self.state = "open"
            self.owner = None
            self.expiry = None
            self.reason = "lease expired"
            self.log("gate reopened (lease expired)")
            return self._snapshot()


# --------------------------------------------------------------------------
# socket server + authentication
# --------------------------------------------------------------------------

def peer_credentials(conn):
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return pid, uid, gid


class GateServer:
    def __init__(self, path, service, allow_uids, token=None, require_token=False,
                 group=None, log=None):
        self.path = path
        self.service = service
        self.allow_uids = {int(u) for u in (allow_uids or [])}
        self.token = token or None
        self.require_token = bool(require_token)
        self.group = group
        self.log = log or (lambda _s: None)
        self.sock = None
        self.thread = None
        self.bound = False
        self._stop = threading.Event()

    # -------------------------------------------------------------- auth
    def _auth(self, conn, cmd):
        try:
            _pid, uid, _gid = peer_credentials(conn)
        except OSError as e:
            return False, f"peer credentials: {e}"
        if int(uid) not in self.allow_uids:
            return False, f"uid {uid} is not allowed"
        if self.require_token:
            if not self.token:
                return False, "helper has no token configured but requires one"
            supplied = str(cmd.get("token") or "")
            if not hmac.compare_digest(supplied, self.token):
                return False, "bad token"
        return True, ""

    # -------------------------------------------------------------- lifecycle
    @staticmethod
    def _listen_fds_from_env():
        """Return the listening FDs passed by systemd socket activation.

        systemd sets LISTEN_PID to the service PID and LISTEN_FDS to the
        number of descriptors starting at fd 3.  Ignore the variables if the
        PID is not ours (for example a stale environment inherited through a
        shell), so a manually started helper still binds its own socket.
        """
        try:
            count = int(os.environ.get("LISTEN_FDS", "0"))
            pid = int(os.environ.get("LISTEN_PID", "0"))
        except (TypeError, ValueError):
            return []
        if count < 1 or pid != os.getpid():
            return []
        return list(range(3, 3 + count))

    def start(self, listen_fds=None):
        fds = self._listen_fds_from_env() if listen_fds is None else \
            [int(fd) for fd in listen_fds]
        if fds:
            if len(fds) != 1:
                raise GateError(
                    f"expected exactly one socket-activated fd, got {fds}")
            try:
                s = socket.socket(fileno=fds[0])
            except OSError as e:
                raise GateError(f"cannot use socket-activated fd {fds[0]}: {e}")
            if s.family != socket.AF_UNIX or \
                    (s.type & socket.SOCK_STREAM) != socket.SOCK_STREAM:
                s.close()
                raise GateError(
                    f"socket-activated fd {fds[0]} is not a Unix stream socket")
            if not s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                s.listen(8)
            s.settimeout(1.0)
            self.sock = s
            # systemd owns the filesystem socket: do not unlink it on stop.
            self.bound = False
            self.thread = threading.Thread(target=self._accept_loop,
                                           name="gate-accept", daemon=True)
            self.thread.start()
            self.log(f"gate helper socket inherited from systemd: {self.path} "
                     f"(allowed uids: "
                     f"{', '.join(str(u) for u in sorted(self.allow_uids)) or 'none'}"
                     + (", token required" if self.require_token else "") + ")")
            return self

        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, mode=0o755, exist_ok=True)
        if os.path.exists(self.path):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.5)
            try:
                probe.connect(self.path)
            except OSError:
                try:
                    os.unlink(self.path)
                except OSError:
                    pass
            else:
                probe.close()
                raise GateError(f"another gate helper is already listening on {self.path}")
            finally:
                try:
                    probe.close()
                except OSError:
                    pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self.path)
        self.bound = True
        os.chmod(self.path, 0o660)
        if os.geteuid() == 0:
            gid = None
            if self.group:
                try:
                    gid = grp.getgrnam(self.group).gr_gid
                except KeyError:
                    self.log(f"group {self.group!r} does not exist; socket stays root-only")
                    gid = 0
            try:
                os.chown(self.path, 0, gid if gid is not None else 0)
            except OSError as e:
                self.log(f"cannot chown gate socket: {e}")
        s.listen(8)
        s.settimeout(1.0)
        self.sock = s
        self.thread = threading.Thread(target=self._accept_loop, name="gate-accept",
                                       daemon=True)
        self.thread.start()
        self.log(f"gate helper socket ready: {self.path} (allowed uids: "
                 f"{', '.join(str(u) for u in sorted(self.allow_uids)) or 'none'}"
                 + (", token required" if self.require_token else "") + ")")
        return self

    def stop(self):
        self._stop.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        if self.thread is not None:
            self.thread.join(timeout=1.5)
        if self.bound:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self.bound = False

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True,
                             name="gate-client").start()

    @staticmethod
    def _send(conn, obj):
        try:
            conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        except OSError:
            pass

    def _handle(self, conn):
        """Serve many commands on one connection; EOF releases a close lease.

        The monitor keeps this connection open while the gate is closed, so the
        *same* connection can later send ``open`` (normal abort/resume) and its
        eventual EOF is the crash-recovery signal.
        """
        with conn:
            # Blocking is intentional: for a leased connection, silence is not
            # an error, and only a real EOF means the monitor went away.  The
            # peer uid allow-list keeps this to local, trusted processes.
            conn.settimeout(None)
            buf = b""
            while not self._stop.is_set():
                try:
                    while b"\n" not in buf:
                        chunk = conn.recv(1024)
                        if not chunk:
                            self.service.on_client_gone(
                                conn, "monitor connection closed (crash recovery)")
                            return
                        buf += chunk
                        if len(buf) > MAX_LINE:
                            self._send(conn, {"ok": False, "error": "command too long"})
                            return
                except OSError:
                    self.service.on_client_gone(
                        conn, "monitor connection closed (crash recovery)")
                    return
                line, _sep, buf = buf.partition(b"\n")
                line = line.strip()
                if not line:
                    self._send(conn, {"ok": False, "error": "empty command"})
                    continue
                try:
                    cmd = json.loads(line.decode("utf-8"))
                except ValueError as e:
                    self._send(conn, {"ok": False, "error": f"bad JSON: {e}"})
                    continue
                if not isinstance(cmd, dict) or not cmd.get("cmd"):
                    self._send(conn, {"ok": False, "error": "missing cmd"})
                    continue
                ok, why = self._auth(conn, cmd)
                if not ok:
                    self.log(f"gate command refused: {why}")
                    self._send(conn, {"ok": False, "error": why})
                    continue
                name = cmd["cmd"]
                try:
                    if name == "ping":
                        reply = {"ok": True, "proto": PROTO}
                        reply.update(self.service.status())
                    elif name == "status":
                        reply = {"ok": True}
                        reply.update(self.service.status())
                    elif name == "close":
                        reply = {"ok": True}
                        reply.update(self.service.close(
                            conn, cmd.get("ttl_s"), seal=bool(cmd.get("seal"))))
                    elif name == "seal":
                        reply = {"ok": True}
                        reply.update(self.service.close(conn, seal=True))
                    elif name == "open":
                        reply = {"ok": True}
                        reply.update(self.service.open(conn))
                    else:
                        reply = {"ok": False, "error": f"unknown command {name!r}"}
                except GateError as e:
                    reply = {"ok": False, "error": str(e)}
                except Exception as e:  # noqa: BLE001 - never take the helper down
                    self.log(f"gate command {name!r} failed: {type(e).__name__}: {e}")
                    reply = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                self._send(conn, reply)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _read_token_file(path):
    if not path:
        return None
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--socket", default=DEFAULT_SOCKET)
    p.add_argument("--table", default=DEFAULT_TABLE)
    p.add_argument("--port", action="append", type=int, default=None,
                   help="inference TCP port to gate (repeatable; default 8080)")
    p.add_argument("--allow-uid", action="append", type=int, default=None,
                   help="uid allowed to talk to the gate socket (repeatable); "
                        "uid 0 is always allowed")
    p.add_argument("--action", choices=["drop", "reject"], default="drop",
                   help="new-connection verdict: silent drop (default) or "
                        "immediate TCP reset (reject with tcp reset)")
    p.add_argument("--no-loopback-exemption", action="store_true",
                   help="also gate loopback traffic (tests/labs only; this "
                        "breaks the monitor's local /status re-check)")
    p.add_argument("--token-file", default=None)
    p.add_argument("--require-token", action="store_true")
    p.add_argument("--group", default="sleepuser",
                   help="group that may connect to the socket")
    p.add_argument("--lease-ttl-s", type=float, default=900.0)
    p.add_argument("--dry-run", action="store_true",
                   help="never execute nft; print what would be done")
    p.add_argument("--print-script", action="store_true",
                   help="print the nft ruleset this helper would apply, then exit")
    p.add_argument("--verify-listing", action="store_true",
                   help="read an `nft list table` listing on stdin and exit 0 "
                        "only when it proves the intended blocking rule; the "
                        "boot script uses this so both sides share one checker")
    p.add_argument("--check", action="store_true",
                   help="verify nft is usable (and, in dry-run, that it would be), then exit")
    p.add_argument("--no-cleanup", action="store_true",
                   help="accepted for compatibility; helper startup never deletes "
                        "a surviving gate table anyway")
    p.add_argument("--sealed-state", default=DEFAULT_SEALED_STATE,
                   help="durable boot-scoped seal marker; survives helper restart "
                        "and runtime-directory cleanup")
    p.add_argument("--oneshot", choices=["open", "close", "status"], default=None)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    log = lambda s: print(s, flush=True)  # noqa: E731
    runner = NftRunner(dry_run=args.dry_run, log=log)
    ports = args.port or [8080]
    allow_uids = set(args.allow_uid or [])
    allow_uids.add(0)
    gate = NftGate(runner=runner, ports=ports,
                   exempt_loopback=not args.no_loopback_exemption,
                   action=args.action, table=args.table, log=log)

    if args.print_script:
        sys.stdout.write(gate.build_script())
        return 0
    if args.verify_listing:
        listing = sys.stdin.read()
        ok, problem = verify_gate_ruleset(
            listing, ports=ports, action=args.action,
            exempt_loopback=not args.no_loopback_exemption, table=args.table)
        if not ok:
            print("not verified: " + problem, file=sys.stderr)
            return 1
        print("verified")
        return 0
    if args.check:
        ok, msg = runner.check_available()
        print(("nft available: " if ok else "nft NOT usable: ") + msg)
        return 0 if ok else 1

    token = _read_token_file(args.token_file)
    service = GateService(gate, lease_ttl_s=args.lease_ttl_s, log=log,
                          state_file=args.sealed_state)

    if args.oneshot:
        try:
            if args.oneshot == "open":
                print(json.dumps(service.open(None, "oneshot")))
            elif args.oneshot == "close":
                print(json.dumps(service.close(None, args.lease_ttl_s)))
                # A oneshot close has no connection to lease it; reopen at once.
                print(json.dumps(service.open(None, "oneshot close is not a lease")))
            else:
                print(json.dumps(service.status()))
        except GateError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        return 0

    if args.dry_run:
        # Never let a dry-run create a seal marker or adopt a table.  The
        # dry-run nft wrapper cannot observe the real table state.
        log("startup: dry-run; seal-state recovery skipped")
    else:
        try:
            startup = service.startup_recover()
        except GateError as e:
            log(f"startup gate recovery FAILED: {e}")
            return 1
        if startup == "restored":
            log("startup: durable gate seal restored; leaving the gate closed")
        elif startup == "adopted":
            log("startup: adopted a surviving closed gate table as sealed")
        else:
            log("startup: gate is open")

    stopping = {"flag": False}

    def on_signal(_sig, _frame):
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    server = GateServer(args.socket, service, allow_uids, token=token,
                        require_token=args.require_token, group=args.group, log=log)
    server.start()
    log(f"gate helper ready: ports={ports} action={args.action} "
        f"loopback_exempt={not args.no_loopback_exemption} "
        f"table={args.table} dry_run={args.dry_run}")

    def watchdog():
        while not stopping["flag"]:
            service.expire()
            time.sleep(0.5)

    threading.Thread(target=watchdog, name="gate-lease-watchdog", daemon=True).start()

    try:
        while not stopping["flag"]:
            time.sleep(0.5)
    finally:
        try:
            server.stop()
        except Exception:  # noqa: BLE001
            pass
        # A closed gate is never cleared automatically on shutdown.  It may be
        # a controlled-suspend seal, or a surviving table that was adopted
        # fail-closed because its marker was lost.  Only an explicit
        # authenticated open may clear it.  An already-open gate is a no-op.
        if service.state == "closed":
            log("shutdown cleanup skipped: gate is closed; explicit open required")
        else:
            try:
                ok, msg = gate.open()
                log(("shutdown cleanup: " if ok else "shutdown cleanup FAILED: ") + msg)
            except Exception as e:  # noqa: BLE001
                log(f"shutdown cleanup failed: {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
