"""Pure policy logic for the workload-aware sleep monitor.

Everything here is deterministic and free of I/O, subprocesses and clocks so it
can be unit-tested without touching the running machine.  The detectors in
``detectors.py`` produce plain data; this module classifies it.
"""
from __future__ import annotations

import os.path
import re
from collections import deque
from dataclasses import dataclass, field

OK = "ok"
ACTIVE = "active"
UNKNOWN = "unknown"

SLEEP = "sleep"
SHUTDOWN = "shutdown"
IDLE = "idle"
HANDLE_PREFIX = "handle-"

# argv[0] basenames that mean "the real program is argv[1]" (a script with a
# shebang, e.g. /usr/bin/python3 /usr/bin/unattended-upgrade ...).
INTERPRETERS = {
    "python", "python3", "python3.10", "python3.11", "python3.12", "python3.13",
    "sh", "bash", "dash", "perl", "node", "nodejs", "ruby", "env",
}


@dataclass
class DetectorResult:
    """One detector's verdict.

    ACTIVE and UNKNOWN normally block sleep.  A detector may instead be marked
    informational: it is still reported in status, but its state never resets
    the inactivity timer or refuses a manual suspend.
    """

    name: str
    state: str = OK
    reason: str = ""
    detail: dict = field(default_factory=dict)
    informational: bool = False

    def blocking(self) -> bool:
        return not self.informational and self.state in (ACTIVE, UNKNOWN)

    def tag(self) -> str:
        return {OK: "ok ", ACTIVE: "!! ", UNKNOWN: "?? "}.get(self.state, "?  ")


def blocker_reasons(results) -> list:
    """Human reasons for every detector that prevents sleep."""
    out = []
    for r in results:
        if r.blocking():
            out.append(f"{r.name}: {r.reason or r.state}")
    return out


def summarize(results) -> str:
    return ", ".join(f"{r.name}={r.state}" for r in results)


# --------------------------------------------------------------------------
# systemd / login1 inhibitors
# --------------------------------------------------------------------------

def split_what(what) -> set:
    return {p for p in (what or "").split(":") if p}


def can_suspend_ok(can, preflight_rc):
    """Interpret logind's CanSuspend together with the systemd dry-run.

    ``CanSuspend`` returns "challenge" for a sessionless system service when
    normal delay inhibitors are present.  That is not a refusal: systemd
    honours delay locks and ``systemctl --dry-run --check-inhibitors=yes`` is
    the authoritative check for actual block locks.  Only accept "challenge"
    when that dry-run succeeds; "no" or an unavailable answer always fails.
    """
    if can == "yes":
        return True
    return can == "challenge" and preflight_rc == 0


def preflight_inhibitor_ok(rc, output, own_markers=("sleepmgr-suspend-guard",)):
    """Interpret the systemd dry-run, allowing only our own guard's lock.

    The monitor deliberately holds a block ``sleep`` inhibitor while Strata is
    loaded.  ``systemctl --dry-run --check-inhibitors=yes`` therefore fails
    with "Operation inhibited by sleepmgr-suspend-guard" even though the guard
    is expected protection.  This helper accepts exactly that case and only
    when every reported inhibiting owner is one of ``own_markers``.  A clean
    dry-run, a different inhibitor, an unparseable failure, or an authorization
    failure all behave conservatively.
    """
    if rc == 0:
        return True, "systemctl dry-run passed"
    text = output or ""
    names = re.findall(r'Operation inhibited by\s+"([^"]+)"', text, re.IGNORECASE)
    if names and all(any(marker.lower() in name.lower() for marker in own_markers)
                     for name in names):
        return True, "systemctl dry-run passed for our own suspend guard"
    if names:
        return False, "blocking inhibitor(s): " + ", ".join(names[:4])
    detail = text.strip().replace("\n", " ")[:200] or f"systemctl dry-run rc={rc}"
    return False, detail


def classify_inhibitors(entries, own_markers=()):
    """Split logind inhibitor locks into (blockers, notes).

    ``entries`` items are dicts with what/who/why/mode/uid/pid.  Only a
    ``block`` lock whose ``what`` names ``sleep`` prevents suspension:
    ``delay`` locks (GNOME lock screen, NetworkManager, UPower, ...) are
    honoured by systemd itself and must not be reported as blockers, and the
    permanent ``shutdown`` delay lock held by unattended-upgrades is not a
    sleep lock at all.  ``handle-*`` locks only concern power keys.
    """
    blockers, notes = [], []
    for e in entries or []:
        what = split_what(e.get("what"))
        mode = e.get("mode")
        who = e.get("who", "") or ""
        why = e.get("why", "") or ""
        if any(m and m in f"{who} {why}" for m in own_markers):
            continue
        if what and all(w.startswith(HANDLE_PREFIX) for w in what):
            continue
        if SLEEP in what and mode == "block":
            blockers.append({"who": who, "why": why, "mode": mode, "pid": e.get("pid")})
        elif SLEEP in what and mode == "delay":
            notes.append(f"delay lock honoured: {who} ({why})")
        elif SHUTDOWN in what and mode == "delay":
            notes.append(f"shutdown-delay (not a sleep blocker): {who}")
        elif SHUTDOWN in what and mode == "block":
            notes.append(f"shutdown-block (not a sleep blocker): {who}")
        elif IDLE in what and mode == "block":
            notes.append(f"idle-block reported: {who}")
    return blockers, notes


# --------------------------------------------------------------------------
# process matching (exact names, so "thermald --adaptive" is not "apt")
# --------------------------------------------------------------------------

def _args_ok(argv, spec) -> bool:
    toks = spec.get("args_any")
    if not toks:
        return True
    return any(t in argv for t in toks)


def match_process(comm, argv, spec) -> bool:
    name = spec.get("name")
    if not name:
        return False
    argv = argv or []
    if comm == name:
        return _args_ok(argv, spec)
    if not argv:
        return False
    base0 = os.path.basename(argv[0])
    if base0 == name:
        return _args_ok(argv, spec)
    if base0 in INTERPRETERS:
        for a in argv[1:]:
            if os.path.basename(a) == name:
                return _args_ok(argv, spec)
    return False


def match_any_process(procs, specs):
    """procs: iterable of (pid, comm, argv).  Returns hits as dicts."""
    hits = []
    for pid, comm, argv in procs:
        for spec in specs or []:
            if match_process(comm, argv, spec):
                hits.append({"pid": pid, "comm": comm, "argv0": argv[0] if argv else "",
                             "matched": spec.get("name")})
                break
    return hits


# --------------------------------------------------------------------------
# sustained-signal helper (GPU utilisation, network/disk throughput, CPU)
# --------------------------------------------------------------------------

class Sustained:
    """True only after ``n`` consecutive True samples (damped thresholds)."""

    def __init__(self, n):
        self.n = max(1, int(n))
        self.buf = deque(maxlen=self.n)

    def add(self, flag) -> bool:
        self.buf.append(bool(flag))
        return self.value()

    def value(self) -> bool:
        return len(self.buf) == self.n and all(self.buf)

    def reset(self):
        self.buf.clear()


# --------------------------------------------------------------------------
# the countdown
# --------------------------------------------------------------------------

class Countdown:
    """The inactivity gate.

    In legacy mode (``idle_timeout_s=None``) the countdown starts as soon as
    everything has been quiet for ``idle_grace_s`` and ``seconds`` is the whole
    window; this preserves the original demo behaviour and its tests.

    In production mode ``idle_timeout_s`` is the time from the last *activity*
    to suspension (for example 600 s), and ``seconds`` is the final countdown
    (for example 30 s).  The final countdown therefore starts at
    ``idle_timeout_s - seconds``.  Any input, blocker, unknown idle source,
    pause, resume, or explicit ``mark_activity`` restarts the whole window.
    """

    def __init__(self, seconds, idle_grace_s=5.0, input_tolerance_s=1.5,
                 idle_timeout_s=None):
        self.seconds = float(seconds)
        self.grace = float(idle_grace_s)
        self.input_tolerance = float(input_tolerance_s)
        self.idle_timeout = float(idle_timeout_s) if idle_timeout_s else None
        self.started = None
        self.resets = 0
        self.cycles = 0
        self.last_reset_reason = ""
        self.last_activity = None
        self._prev_idle = None
        self.was_paused = False

    def _end(self, why):
        if self.started is not None:
            self.resets += 1
            self.last_reset_reason = why
        self.started = None

    def reset(self, why="reset"):
        self._end(why)

    def consumed(self, why="suspend attempt"):
        """A suspend attempt (real or dry-run) finished; the next cycle starts fresh."""
        self.cycles += 1
        self.started = None
        self.last_activity = None
        self._prev_idle = None
        self.last_reset_reason = why

    def mark_activity(self, now, why="activity"):
        """Explicitly restart the full inactivity window (resume, pause, SIGHUP)."""
        self._end(why)
        self.last_activity = now
        self._prev_idle = None
        self.last_reset_reason = why

    def _inactive_s(self, now):
        if self.last_activity is None:
            self.last_activity = now
        return max(0.0, now - self.last_activity)

    def tick(self, now, idle_s, blockers, paused=False):
        if paused:
            self._end("paused")
            self.last_activity = now
            self._prev_idle = idle_s
            self.was_paused = True
            return {"state": "paused", "remaining": None, "reason": "pause requested",
                    "inactive_s": 0.0, "suspend_in_s": None}
        if self.was_paused:
            # resume: the paused ticks kept last_activity current, but make it
            # explicit so the next tick cannot suspend immediately.
            self.was_paused = False
            self.last_activity = now
            self.last_reset_reason = "resume"
        if blockers:
            self._end("blocker: " + blockers[0])
            self.last_activity = now
            self._prev_idle = idle_s
            return {"state": "blocked", "remaining": None, "reason": blockers[0],
                    "inactive_s": 0.0, "suspend_in_s": None}
        if idle_s is None:
            self._end("idle source unavailable")
            self.last_activity = now
            self._prev_idle = None
            return {"state": "unknown", "remaining": None, "reason": "idle source unavailable",
                    "inactive_s": 0.0, "suspend_in_s": None}

        input_now = idle_s < self.grace
        input_drop = (self._prev_idle is not None
                      and idle_s < self._prev_idle - 0.5)
        self._prev_idle = idle_s
        if input_now or input_drop:
            self._end("input")
            self.last_activity = now
            return {"state": "active", "remaining": None, "reason": "recent input",
                    "inactive_s": 0.0, "suspend_in_s": None}

        if self.idle_timeout is None:
            if self.started is None:
                self.started = now
                return {"state": "countdown", "remaining": self.seconds, "reason": ""}
            if idle_s < (now - self.started) + self.grace - self.input_tolerance:
                self._end("input during countdown")
                self.started = now
                return {"state": "countdown", "remaining": self.seconds, "reason": "input reset"}
            remaining = self.seconds - (now - self.started)
            if remaining <= 0:
                return {"state": "ready", "remaining": 0.0, "reason": "",
                        "inactive_s": max(0.0, now - (self.last_activity or now)),
                        "suspend_in_s": 0.0}
            return {"state": "countdown", "remaining": remaining, "reason": "",
                    "inactive_s": max(0.0, now - (self.last_activity or now)),
                    "suspend_in_s": remaining}

        inactive = self._inactive_s(now)
        start_at = max(self.grace, self.idle_timeout - self.seconds)
        suspend_in = max(0.0, self.idle_timeout - inactive)
        if inactive < start_at:
            self._end("waiting")
            return {"state": "waiting", "remaining": None, "reason": "",
                    "inactive_s": inactive, "suspend_in_s": suspend_in,
                    "waiting_s": start_at - inactive}
        if self.started is None:
            self.started = now
        # The idle clock is the authoritative source for input that happened
        # before the countdown began; this check covers input inside it.
        if idle_s < (now - self.started) + self.grace - self.input_tolerance:
            self._end("input during countdown")
            self.last_activity = now
            self.started = None
            return {"state": "active", "remaining": None, "reason": "input reset",
                    "inactive_s": 0.0, "suspend_in_s": None}
        remaining = self.idle_timeout - inactive
        if remaining <= 0:
            return {"state": "ready", "remaining": 0.0, "reason": "",
                    "inactive_s": inactive, "suspend_in_s": 0.0}
        return {"state": "countdown", "remaining": remaining, "reason": "",
                "inactive_s": inactive, "suspend_in_s": remaining}


# --------------------------------------------------------------------------
# manual "Suspend now" policy
# --------------------------------------------------------------------------

# These detectors protect work that must never be interrupted by a manual
# suspend either.  A confirmation dialog is not an override: the fresh sweep
# must be clear.  "input" is deliberately absent (a human is present when they
# click Suspend now) and pause state is handled by the caller.
#
# Local OpenCode is a maintenance tool on this dedicated Strata host.  Its
# detector stays visible in status, but it is marked informational and is not a
# sleep or manual-suspend blocker.
MANUAL_BLOCKING_DETECTORS = {
    "strata", "updates", "transfers", "streams", "inhibitors",
}


def manual_refusal(results) -> list:
    """Reasons a manual suspend must be refused, from a fresh sweep."""
    reasons = []
    for r in results:
        if r.name in MANUAL_BLOCKING_DETECTORS and r.blocking():
            reasons.append(f"{r.name}: {r.reason or r.state}")
        elif r.name == "input" and r.state == UNKNOWN:
            reasons.append(f"input: {r.reason or r.state}")
    return reasons


# --------------------------------------------------------------------------
# the suspend command (kept here so the dry-run guarantee is unit-tested)
# --------------------------------------------------------------------------

def build_suspend_command(dry_run: bool, check_inhibitors: bool = True):
    """The only place a suspend command is built.

    ``--dry-run`` is appended for the dry-run mode, and the caller refuses to
    run the armed form unless the operator explicitly armed it.
    """
    cmd = ["systemctl", "suspend"]
    if check_inhibitors:
        cmd.append("--check-inhibitors=yes")
    if dry_run:
        cmd.append("--dry-run")
    return cmd
