#!/usr/bin/env python3
"""Workload-aware automatic sleep monitor.

Dry-run by default: it detects input idleness and protected workloads, runs the
inactivity gate and countdown, performs a final safety check, and *reports*
that it would suspend.  It only ever calls `systemctl suspend` when started
with --arm (and, for a service, when the config explicitly allows unattended
suspension); the dry-run code path cannot reach it.

Pause / Resume is provided over a local Unix socket and a GTK control panel.
The pause state is persistent (survives restarts and reboots) and is checked
before Strata unloading and immediately before suspension.

Usage:
    python3 sleepmon.py                     # live dry-run display
    python3 sleepmon.py --once              # one check, human summary
    python3 sleepmon.py --once --json       # one check, JSON
    python3 sleepmon.py --resume-check      # post-resume health report
    python3 sleepmon.py --reload-strata     # POST /load and exit
    python3 sleepmon.py --service           # non-interactive, for systemd
    python3 sleepmon.py --arm               # ARMED (interactive confirmation)
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import os
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import control as control_mod  # noqa: E402
import detectors  # noqa: E402
import netgate  # noqa: E402
import pause as pause_mod  # noqa: E402
import suspendflow  # noqa: E402
import suspendguard  # noqa: E402
from policy import (ACTIVE, OK, UNKNOWN, Countdown, DetectorResult,  # noqa: E402
                    blocker_reasons, build_suspend_command, can_suspend_ok,
                    classify_inhibitors, manual_refusal,
                    preflight_inhibitor_ok)
import oneshot  # noqa: E402

DEFAULT_CONFIG = os.path.join(HERE, "config.json")
VERSION = "2"


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------

class EventLog:
    """Append-only, size-rotated event log with full ISO timestamps."""

    def __init__(self, path=None, max_bytes=10 * 1024 * 1024, backups=5):
        self.path = path
        self.max_bytes = int(max_bytes)
        self.backups = int(backups)
        self.lines = []
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)

    def _rotate(self):
        if not self.path:
            return
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        try:
            for i in range(self.backups - 1, 0, -1):
                src = f"{self.path}.{i}"
                dst = f"{self.path}.{i + 1}"
                if os.path.exists(src):
                    os.replace(src, dst)
            os.replace(self.path, f"{self.path}.1")
        except OSError:
            pass

    def add(self, text, echo=False):
        line = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {text}"
        self.lines.append(line)
        if self.path:
            try:
                self._rotate()
                with open(self.path, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass
        if echo:
            print(line, flush=True)

    def tail(self, n=8):
        return "\n".join(self.lines[-n:])


class JsonlLog:
    """One JSON object per line (quiesce/suspend forensic journal)."""

    def __init__(self, path):
        self.path = path
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)

    def add(self, obj):
        if not self.path:
            return
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(obj, sort_keys=True) + "\n")
        except OSError:
            pass


# --------------------------------------------------------------------------
# single instance
# --------------------------------------------------------------------------

class InstanceLock:
    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self):
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            info = self.read_info()
            os.close(self.fd)
            self.fd = None
            return False, info
        info = {"pid": os.getpid(), "started": datetime.datetime.now().isoformat(timespec="seconds"),
                "version": VERSION}
        os.ftruncate(self.fd, 0)
        os.write(self.fd, (json.dumps(info) + "\n").encode())
        os.fsync(self.fd)
        return True, info

    def read_info(self):
        try:
            with open(self.path) as f:
                return json.loads(f.read() or "{}")
        except (OSError, ValueError):
            return {}

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


# --------------------------------------------------------------------------
# the monitor: detectors + the inactivity gate + the final gate
# --------------------------------------------------------------------------

class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.strata = detectors.StrataProbe(cfg.get("strata", {}))
        self.opencode = detectors.OpenCodeProbe(cfg.get("opencode", {}))
        self.updates = detectors.UpdateProbe(cfg.get("updates", {}))
        self.transfers = detectors.TransferProbe(cfg.get("transfers", {}))
        self.streams = detectors.StreamProbe(cfg.get("streams", {}))
        self.inhib = detectors.InhibitorProbe()
        self.idle_ms = None
        self.idle_source = None
        self.session = None
        self.results = []
        self.notes = []
        self.sweep_seq = 0            # cycle ID: one per detector sweep
        self.sweep_time = None        # wall clock of that sweep

    def sweep(self, idle_ms=None, idle_source=None, session=None):
        if session is not None:
            self.session = session
        if idle_ms is None and idle_source is None:
            idle_ms, idle_source = detectors.probe_idle(session=self.session)
        self.idle_ms, self.idle_source = idle_ms, idle_source
        self.sweep_seq += 1
        self.sweep_time = datetime.datetime.now().isoformat(timespec="milliseconds")
        results = []
        if idle_ms is None:
            results.append(DetectorResult("input", UNKNOWN,
                                          "idle source unavailable (Mutter/logind) - failing safe"))
        else:
            results.append(DetectorResult("input", OK, f"idle {idle_ms / 1000:.0f}s ({idle_source})"))

        entries, err = self.inhib.entries()
        if err:
            results.append(DetectorResult("inhibitors", UNKNOWN, f"cannot list inhibitors ({err}) - failing safe"))
        else:
            blockers, notes = classify_inhibitors(entries, own_markers=("sleepmgr",))
            gnome = self.inhib.gnome(session=self.session)
            if gnome.get("suspend"):
                blockers.append({"who": "GNOME session", "why": "an application holds a suspend inhibitor"})
            elif gnome.get("suspend") is None:
                notes.append("GNOME session inhibit state unknown")
            if gnome.get("idle"):
                notes.append("an application holds an idle inhibitor (media playback?)")
            self.notes = notes
            if blockers:
                who = ", ".join(f"{b['who']} ({b['why']})" for b in blockers[:3])
                results.append(DetectorResult("inhibitors", ACTIVE, f"block lock held: {who}",
                                              {"blockers": blockers, "notes": notes}))
            else:
                note = f"{len(notes)} delay lock(s) honoured" if notes else "no sleep locks"
                results.append(DetectorResult("inhibitors", OK, note, {"blockers": [], "notes": notes}))

        results.append(self.strata.probe())
        results.append(self.opencode.probe())
        results.append(self.updates.probe())
        results.append(self.transfers.probe())
        results.append(self.streams.probe())
        self.results = results
        return results

    def final_check(self, countdown, paused_fn=None, inactive_s=None,
                    require_idle=True):
        """Last gate immediately before a suspend attempt.  Every check is
        reported; any failure cancels the countdown.

        ``require_idle=False`` is only for the supervised one-shot mode, where
        an operator explicitly triggers one cycle.  The fresh workload sweep,
        pause check, authorization check, inhibitor check and guard ordering
        are unchanged.
        """
        checks = []
        idle_ms, idle_source = detectors.probe_idle(session=self.session)
        self.sweep(idle_ms, idle_source, session=self.session)
        blk = blocker_reasons(self.results)
        checks.append(("fresh detector sweep", not blk, "; ".join(blk) if blk else "all clear"))
        if paused_fn is not None:
            is_paused = bool(paused_fn())
            checks.append(("pause re-check before unload", not is_paused,
                           "pause requested" if is_paused else "auto"))
        auth_ok, auth_detail = detectors.logind_suspend_authorized()
        checks.append(("logind suspend authorization", auth_ok, auth_detail))
        can = detectors.logind_can_suspend()
        rc, out, err = detectors.preflight_suspend_dry_run()
        preflight_ok, preflight_detail = preflight_inhibitor_ok(rc, out + err)
        # A "challenge" from logind is acceptable only when the dry-run itself
        # is clean once our own guard's expected block lock is excluded.
        checks.append(("logind CanSuspend safe",
                       can_suspend_ok(can, 0 if preflight_ok else rc), str(can)))
        checks.append(("systemctl --dry-run --check-inhibitors=yes suspend",
                       preflight_ok, preflight_detail[:200]))
        if not require_idle:
            checks.append(("idle gate", True, "explicit supervised one-shot trigger"))
        elif idle_ms is None:
            checks.append(("idle known", False, "idle source unavailable"))
        elif countdown.idle_timeout is not None:
            need = max(0.0, countdown.idle_timeout - self.cfg.get("final_idle_slack_s", 2.0))
            have = float(inactive_s or 0.0)
            checks.append((f"inactive >= {need:.0f}s", have >= need, f"inactive {have:.0f}s"))
        else:
            need = max(0.0, countdown.seconds - self.cfg.get("final_idle_slack_s", 2.0))
            checks.append((f"idle >= {need:.0f}s", idle_ms / 1000.0 >= need,
                           f"idle {idle_ms / 1000:.0f}s"))
        if paused_fn is not None:
            is_paused = bool(paused_fn())
            checks.append(("pause re-check before suspend", not is_paused,
                           "pause requested" if is_paused else "auto"))
        return all(c[1] for c in checks), checks


# --------------------------------------------------------------------------
# display
# --------------------------------------------------------------------------

def _fmt_seconds(sec):
    if sec is None:
        return "-"
    sec = int(max(0, sec))
    return f"{sec // 60}m{sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def render(cfg, args, mon, countdown, st, would, dry_run, sweep_ran, pause_state=None, force=False):
    if getattr(args, "service", False):
        return
    tty = sys.stdout.isatty() and not args.plain
    if not tty and not sweep_ran and not force:
        return
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    idle = f"{mon.idle_ms / 1000:6.1f}s" if mon.idle_ms is not None else "   ?   "
    blockers = blocker_reasons(mon.results)
    state = st["state"]
    remaining = st.get("remaining")
    suspend_in = st.get("suspend_in_s")
    mode = "DRY RUN" if dry_run else "ARMED"
    pause_line = "pause      : none"
    if pause_state and pause_state.get("paused"):
        until = pause_state.get("paused_until")
        if until:
            pause_line = ("pause      : timed, until "
                          + datetime.datetime.fromtimestamp(until).strftime("%H:%M:%S")
                          + f" ({_fmt_seconds(pause_state.get('remaining_s'))} left)")
        else:
            pause_line = "pause      : indefinite (Pause active)"
    if tty:
        lines = [f"Sleep monitor [{mode}]   {ts}",
                 f"input idle : {idle} ({mon.idle_source or 'unknown'})      state: {state.upper()}",
                 (f"suspend in : {_fmt_seconds(suspend_in)}"
                  + (f"   (countdown {remaining:4.1f}s)" if remaining is not None else "")),
                 pause_line,
                 f"resets: {countdown.resets}   dry-run suspend events: {would}",
                 "-" * 76]
        for r in mon.results:
            if r.name == "input":
                continue
            lines.append(f"[{r.tag()}] {r.name:<10} {r.reason}")
        for n in mon.notes[:4]:
            lines.append(f"     ~ {n}")
        lines.append("-" * 76)
        lines.append("PREVENTING SLEEP: " + "; ".join(blockers) if blockers else "All clear - safe to sleep.")
        if pause_state and pause_state.get("paused"):
            lines.append("Paused: automatic unload/suspend is disabled until Resume.")
        lines.append("Dry run: it will never suspend. Ctrl-C stops it." if dry_run else
                     "ARMED: a real suspend is possible.")
        sys.stdout.write("\033[H\033[J" + "\n".join(lines) + "\n")
    else:
        sys.stdout.write(f"[{ts}] idle={idle} state={state} suspend_in={_fmt_seconds(suspend_in)} "
                         f"paused={bool(pause_state and pause_state.get('paused'))} "
                         f"blockers={'; '.join(blockers) or 'none'}\n")
    sys.stdout.flush()


class GuardStatusRefresher:
    """Poll the guard's read-only status without affecting control paths.

    The monitor must never change suspension behaviour because a cosmetic
    status probe failed.  ``refresh`` therefore catches every failure, keeps
    the client's cached status as ``unknown`` (GuardClient does that), and
    logs only when the error state changes.
    """

    def __init__(self, guard, interval_s=10.0, timeout_s=1.5, log=None,
                 clock=time.monotonic):
        self.guard = guard
        self.interval = max(1.0, float(interval_s))
        self.timeout = max(0.1, float(timeout_s))
        self.log = log or (lambda _s: None)
        self.clock = clock
        self.next_refresh = 0.0
        self.last_error = ""

    def refresh(self, now=None, force=False):
        if not getattr(self.guard, "enabled", False):
            return None
        now = self.clock() if now is None else float(now)
        if not force and now < self.next_refresh:
            return None
        self.next_refresh = now + self.interval
        try:
            reply = self.guard.status(timeout=self.timeout)
            if not isinstance(reply, dict):
                raise RuntimeError("guard status is not an object")
            if reply.get("ok") is False:
                raise RuntimeError(str(reply.get("error") or "guard status refused"))
        except Exception as e:  # noqa: BLE001 - status reporting must never escape
            msg = f"{type(e).__name__}: {e}"
            if msg != self.last_error:
                self.last_error = msg
                self.log(f"suspend guard status unavailable: {msg}")
            return None
        if self.last_error:
            self.log("suspend guard status reporting recovered")
            self.last_error = ""
        return reply


def status_document(mon, st, countdown, would, dry_run, extra=None):
    doc = {
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "version": VERSION,
        "mode": "dry-run" if dry_run else "armed",
        "pid": os.getpid(),
        "sweep": mon.sweep_seq,
        "sweep_time": mon.sweep_time,
        "state": st["state"],
        "remaining_s": st.get("remaining"),
        "idle_s": (mon.idle_ms / 1000.0) if mon.idle_ms is not None else None,
        "idle_source": mon.idle_source,
        "idle_timeout_s": countdown.idle_timeout,
        "countdown_s": countdown.seconds,
        "inactive_s": st.get("inactive_s"),
        "suspend_in_s": st.get("suspend_in_s"),
        "waiting_s": st.get("waiting_s"),
        "resets": countdown.resets,
        "dry_run_suspend_events": would,
        "blockers": blocker_reasons(mon.results),
        "notes": mon.notes,
        "detectors": [{"name": r.name, "state": r.state, "reason": r.reason,
                       "informational": r.informational, "detail": r.detail}
                      for r in mon.results],
    }
    if extra:
        doc.update(extra)
    return doc


def write_status(path, doc):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# post-resume report
# --------------------------------------------------------------------------

def resume_check(cfg):
    print("=== post-resume check ===")
    print(f"time: {datetime.datetime.now().isoformat(timespec='seconds')}")
    rc, out, err = detectors._run(["uptime"], 5)
    print(f"\n-- uptime\n  {out.strip() or err.strip()}")

    print("\n-- GPUs")
    rc, out, err = detectors.nvidia_snapshot()
    print(f"  nvidia-smi rc={rc}")
    print("  " + (out.strip().replace("\n", "\n  ") if out.strip() else err.strip()))

    print("\n-- nvidia kernel messages")
    hits = detectors.kernel_nvidia_errors()
    print("  " + ("\n  ".join(hits) if hits else "no nvidia errors this boot"))

    print("\n-- Strata")
    probe = detectors.StrataProbe(cfg.get("strata", {}))
    server, engine = probe._processes()
    print(f"  server process: {server}   engine process: {engine}")
    for path, auth in (("/health", False), ("/status", True)):
        try:
            print(f"  {path}: {json.dumps(probe.get(path, auth=auth))[:220]}")
        except Exception as e:  # noqa: BLE001
            print(f"  {path}: unreachable ({e})")

    print("\n-- network")
    for iface in cfg.get("transfers", {}).get("net_ifaces", []):
        print(f"  {iface}: operstate={detectors.iface_state(iface)}")

    print("\n-- OpenCode")
    oc = detectors.OpenCodeProbe(cfg.get("opencode", {}))
    print(f"  {oc.probe()}")

    print("\n-- Sunshine")
    print(f"  {detectors.StreamProbe(cfg.get('streams', {})).probe()}")
    print("\nIf Strata's model was unloaded, it reloads on the next request, or run "
          "`sleepmon.py --reload-strata`.")


def reload_strata(cfg):
    ok, msg = detectors.strata_load(cfg.get("strata", {}), log=print)
    print(("reloaded: " if ok else "reload failed: ") + msg)
    return 0 if ok else 1


# --------------------------------------------------------------------------
# config / args
# --------------------------------------------------------------------------

DEFAULT_CFG = {}


def load_config(path):
    global DEFAULT_CFG
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        print(f"cannot read config {path}: {e}", file=sys.stderr)
        sys.exit(2)
    DEFAULT_CFG = cfg
    return cfg


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Workload-aware automatic sleep monitor (dry-run by default).")
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("--once", action="store_true", help="run one check and exit")
    p.add_argument("--json", action="store_true", help="JSON output for --once")
    p.add_argument("--plain", action="store_true", help="append status lines instead of a live display")
    p.add_argument("--no-color", action="store_true", help="accepted for symmetry; output is already plain")
    p.add_argument("--interval", type=float, default=None, help="seconds between workload sweeps")
    p.add_argument("--idle-interval", type=float, default=None, help="seconds between idle checks")
    p.add_argument("--countdown", type=float, default=None, help="final countdown seconds")
    p.add_argument("--idle-timeout", type=float, default=None,
                   help="seconds of inactivity before suspension (0 = legacy countdown)")
    p.add_argument("--max-seconds", type=float, default=None, help="stop after this long")
    p.add_argument("--log-dir", default=None)
    p.add_argument("--no-log", action="store_true")
    p.add_argument("--status-file", default=None)
    p.add_argument("--state-file", default=None, help="persistent pause state file")
    p.add_argument("--socket", default=None, help="control socket path")
    p.add_argument("--lock-file", default=None, help="single-instance lock file")
    p.add_argument("--no-pause-inhibitor", action="store_true",
                   help="do not hold a logind block lock while paused (tests)")
    p.add_argument("--service", action="store_true", help="non-interactive systemd mode")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--arm", action="store_true",
                   help="allow a REAL `systemctl suspend` after the countdown")
    p.add_argument("--arm-once", action="store_true",
                   help="interactive supervised mode: run exactly one real suspend/resume cycle and exit")
    p.add_argument("--resume-check", action="store_true", help="print a post-resume health report and exit")
    p.add_argument("--reload-strata", action="store_true", help="POST /load and exit")
    return p.parse_args(argv)


def one_shot_conflicts(args):
    """Arguments that would turn a supervised one-shot into another mode."""
    names = ("service", "once", "json", "arm", "resume_check", "reload_strata")
    return [name for name in names if bool(getattr(args, name, False))]


def _iso_now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def main(argv=None):
    args = parse_args(argv)
    cfg = load_config(args.config)
    if args.interval is not None:
        cfg["poll_interval_s"] = args.interval
    if args.idle_interval is not None:
        cfg["idle_refresh_s"] = args.idle_interval
    if args.countdown is not None:
        cfg["countdown_s"] = args.countdown
    if args.log_dir:
        cfg["log_dir"] = args.log_dir
    idle_timeout = cfg.get("idle_timeout_s", 600)
    if args.idle_timeout is not None:
        idle_timeout = args.idle_timeout if args.idle_timeout > 0 else None
    elif idle_timeout in (0, False):
        idle_timeout = None

    one_shot = bool(getattr(args, "arm_once", False))
    if one_shot:
        conflicts = one_shot_conflicts(args)
        if conflicts:
            print("--arm-once cannot be combined with: " + ", ".join("--" + c.replace("_", "-")
                                                                      for c in conflicts),
                  file=sys.stderr)
            return 2
        if args.lock_file:
            print("--arm-once always uses the configured service lock; --lock-file is not allowed.",
                  file=sys.stderr)
            return 2
        if not sys.stdin.isatty():
            print("--arm-once requires an interactive terminal (no unattended mode).",
                  file=sys.stderr)
            return 2
        print("ONE-SHOT supervised mode: exactly one real gate-first suspend/resume cycle.")
        print("This does not enable unattended suspension; the process exits afterwards.")
        print("Another monitor must not be running (the shared service lock is required).")
        if input('Type SUSPEND (all caps) to run the one-shot cycle, anything else to abort: ') != "SUSPEND":
            print("one-shot not started.")
            return 0

    if args.resume_check:
        return resume_check(cfg)
    if args.reload_strata:
        return reload_strata(cfg)

    dry_run = not (args.arm or one_shot)
    if args.arm:
        allow_unattended = bool(cfg.get("service", {}).get("allow_unattended_suspend", False))
        if not sys.stdin.isatty():
            if not (args.service and allow_unattended):
                print("--arm requires an interactive terminal (refusing to arm unattended).",
                      file=sys.stderr)
                return 2
        else:
            print("ARMED mode: this monitor will run `systemctl suspend` after a clean")
            print(f"{cfg['countdown_s']:.0f}s countdown and its final safety check.")
            print("Strata will be asked to unload its model first (POST /unload).")
            if input('Type SUSPEND (all caps) to arm, anything else to abort: ') != "SUSPEND":
                print("not armed; use the default dry-run mode.")
                return 0
        if not allow_unattended:
            print("--arm refused: service.allow_unattended_suspend is false.", file=sys.stderr)
            return 2

    log_dir = cfg.get("log_dir") or "/tmp/opencode/sleepmgr"
    service_cfg = cfg.get("service", {}) or {}
    pause_cfg = cfg.get("pause", {}) or {}
    log_max = int(cfg.get("log_max_bytes", 10 * 1024 * 1024))
    log_backups = int(cfg.get("log_backups", 5))
    events = EventLog(None if args.no_log else os.path.join(log_dir, "monitor.log"),
                      max_bytes=log_max, backups=log_backups)
    control_log = EventLog(None if args.no_log else os.path.join(log_dir, "control.log"),
                           max_bytes=log_max, backups=log_backups)
    status_path = args.status_file or service_cfg.get("status_file") or os.path.join(log_dir, "status.json")
    state_path = args.state_file or pause_cfg.get("state_file") or os.path.join(log_dir, "state.json")
    socket_path = args.socket or pause_cfg.get("socket") or os.path.join(log_dir, "control.sock")
    lock_path = args.lock_file or service_cfg.get("lock_file") or os.path.join(log_dir, "monitor.lock")

    if one_shot:
        lock_ok, lock_detail = oneshot.runtime_lock_preflight(lock_path)
        if not lock_ok:
            print("one-shot preflight failed: " + lock_detail, file=sys.stderr)
            return 2

    # --once is read-only and must not take the service lock or hold an inhibitor.
    if args.once:
        mon = Monitor(cfg)
        mon.sweep()
        blockers = blocker_reasons(mon.results)
        pc = pause_mod.PauseController(state_path,
                                       inhibitor=pause_mod.PauseInhibitor(enabled=False),
                                       log=control_log.add)
        pc.load()
        st = {"state": "once", "remaining": None, "inactive_s": None, "suspend_in_s": None}
        extra = {"pause": pc.status(),
                 "service": {"armed": False, "service_mode": False},
                 "gate": netgate.build_gate(cfg.get("gate", {})).last_status()}
        doc = status_document(mon, st, Countdown(cfg.get("countdown_s", 30),
                                                 cfg.get("idle_grace_s", 5),
                                                 idle_timeout_s=idle_timeout),
                             0, True, extra)
        if args.json:
            print(json.dumps(doc, indent=1))
        else:
            print(f"idle: {mon.idle_ms} ms ({mon.idle_source})")
            for r in mon.results:
                print(f"[{r.tag()}] {r.name:<10} {r.reason}")
            for n in mon.notes:
                print(f"       ~ {n}")
            print(f"pause: {pc.status()['mode']}"
                  + (" (effective: paused)" if pc.status()["paused"] else ""))
            print("PREVENTING SLEEP: " + "; ".join(blockers) if blockers else "All clear - safe to sleep.")
        return 1 if blockers else 0

    # Single instance: only one monitor may control suspension.
    lock = InstanceLock(lock_path)
    ok, holder = lock.acquire()
    if not ok:
        print(f"another sleep monitor is already running: {holder or 'unknown holder'}", file=sys.stderr)
        return 3

    inhibitor = pause_mod.PauseInhibitor(
        enabled=(bool(pause_cfg.get("inhibitor", True)) and not args.no_pause_inhibitor),
        why="sleepmgr pause requested", log=control_log.add)
    pc = pause_mod.PauseController(state_path, inhibitor=inhibitor, log=control_log.add)
    pc.load()
    pc.reconcile_inhibitor()
    control_log.add(f"pause state loaded: {pc.status()['mode']}"
                    + (" (paused)" if pc.status()["paused"] else ""))

    mon = Monitor(cfg)
    countdown = Countdown(cfg.get("countdown_s", 30), cfg.get("idle_grace_s", 5),
                          idle_timeout_s=idle_timeout)
    interval = float(cfg.get("poll_interval_s", 5))
    idle_interval = float(cfg.get("idle_refresh_s", 1))
    max_seconds = args.max_seconds
    journal = JsonlLog(None if args.no_log else os.path.join(log_dir, "suspend.jsonl"))

    # The inference-arrival gate is disabled unless gate.enabled is true.  Even
    # when enabled, the monitor only talks to the privileged helper: it never
    # runs nft itself and keeps NoNewPrivileges=yes.
    gate_cfg = cfg.get("gate", {}) or {}
    gate = netgate.build_gate(gate_cfg, log=events.add)
    strata_port = suspendflow.StrataPort(cfg.get("strata", {}), log=events.add)
    # The guard is an independent service.  When it is not configured, the
    # client is a no-op and the monitor's behaviour is unchanged.
    guard_cfg = cfg.get("suspend_guard", {}) or {}
    guard = suspendguard.build_guard(guard_cfg, log=events.add)
    # Logind can keep its suspend operation active for several seconds after
    # resume, rejecting new sleep inhibitors with OperationInProgress.  Retry
    # rather than aborting on the first transient failure.
    guard_acquire_timeout_s = float(
        guard_cfg.get("post_resume_acquire_timeout_s", 90.0))
    guard_retry_interval_s = float(guard_cfg.get("acquire_retry_s", 1.0))
    guard_status = GuardStatusRefresher(
        guard,
        interval_s=float(guard_cfg.get("status_refresh_s", 10.0)),
        timeout_s=float(guard_cfg.get("status_timeout_s", 1.5)),
        log=events.add)
    # Populate the status document immediately.  A failed probe is logged and
    # leaves the cached state unknown; it cannot abort startup or suspend flow.
    guard_status.refresh(force=True)

    # Crash recovery: a previous monitor (or a crashed helper) may have left the
    # gate closed.  Do not blindly open it: a sealed gate can mean Strata is
    # unloaded after a failed recovery.  Open only after the guard is protected
    # and Strata reports loaded and inference-ready.  Retry for a bounded time
    # (Strata can take minutes to load after boot) while keeping the seal and
    # the inhibitor; a permanent failure leaves the gate sealed and records a
    # clear recovery-failed status.  The supervised one-shot skips startup
    # normalization entirely; its own flow reopens the gate only after recovery.
    startup_recovery = {"state": "not-run", "message": "", "at": None,
                        "gate_state": None}
    if gate.enabled and not one_shot:
        startup_recovery_timeout_s = float(
            gate_cfg.get("startup_recovery_timeout_s", 180.0))
        startup_recovery_interval_s = float(
            gate_cfg.get("startup_recovery_interval_s", 2.0))
        try:
            ok, st, msg = suspendflow.startup_gate_recovery_retry(
                gate, strata_port, guard=guard,
                timeout_s=startup_recovery_timeout_s,
                interval_s=startup_recovery_interval_s,
                log=events.add)
            gate_state = st.get("state") if isinstance(st, dict) else None
            if ok:
                startup_recovery.update({
                    "state": "recovered", "message": msg, "at": _iso_now(),
                    "gate_state": gate_state})
                events.add(f"gate: startup recovery - inference gate {gate_state}"
                           f" ({(st or {}).get('reason', '')})")
            else:
                startup_recovery.update({
                    "state": "recovery-failed", "message": msg, "at": _iso_now(),
                    "gate_state": gate_state})
                events.add("gate: startup recovery FAILED; the gate remains "
                           "sealed: " + msg, echo=True)
        except Exception as e:  # noqa: BLE001
            startup_recovery.update({
                "state": "recovery-failed", "at": _iso_now(),
                "message": f"{type(e).__name__}: {e}"})
            events.add(f"gate: startup recovery FAILED ({type(e).__name__}: {e}); "
                       "the gate remains closed", echo=True)

    snapshotter = suspendguard.SystemSnapshotter(cfg, log=events.add)

    def gate_idle_before_close():
        """Idle proof before the gate changes; the gate is still open."""
        return gate_recheck(mon, strata_port, gate_cfg, gate=None,
                            require_unloaded=False)

    def gate_idle_after_close():
        """Idle proof after the gate settles; still before unload."""
        return gate_recheck(mon, strata_port, gate_cfg, gate=gate,
                            require_unloaded=False)

    def post_unload_verify():
        """Verify release of GPU memory, CUDA clients, RAM and the closed gate."""
        # Keep the critical-detector sweep after unload too: an update or
        # transfer that started during the unload must not be missed.
        ok, msg = gate_recheck(mon, strata_port, gate_cfg, gate=gate,
                               require_unloaded=True)
        if not ok:
            return False, "post-unload recheck: " + msg
        try:
            report = suspendguard.evaluate_safety(snapshotter.snapshot(), guard_cfg)
        except Exception as e:  # noqa: BLE001
            return False, f"post-unload snapshot failed: {type(e).__name__}: {e}"
        if not report.get("safe"):
            return False, "; ".join((report.get("reasons") or ["unsafe"])[:4])
        return True, "GPU memory, CUDA clients, RAM and gate verified"

    def nvidia_verify():
        """Post-resume NVIDIA liveness check with a bounded nvidia-smi call."""
        rc, out, err = detectors.nvidia_snapshot()
        if rc != 0:
            return False, (err or out or f"nvidia-smi rc={rc}").strip()[:200]
        if not out.strip():
            return False, "nvidia-smi returned no GPU data"
        return True, "nvidia-smi healthy"

    def readiness_verify():
        return detectors.strata_readiness(cfg.get("strata", {}))

    settle_s = float(gate_cfg.get("settle_s", 0.0))

    manual_lock = threading.Lock()
    manual_request = {"flag": False, "by": ""}
    manual_state = {"state": "idle", "message": "", "blockers": [], "at": None, "by": ""}

    flow_lock = threading.Lock()
    last_flow = {"at": None, "ok": None, "aborted": "", "suspended": False,
                 "gate_closed": None, "gate_reopened": None,
                 "gate_lease_lost": None, "nvidia_verified": None,
                 "ready": None, "post_unload_verified": None}

    def record_flow(res):
        with flow_lock:
            last_flow.update({
                "at": _iso_now(), "ok": bool(res.ok), "aborted": res.aborted,
                "suspended": bool(res.suspended), "gate_closed": bool(res.gate_closed),
                "gate_reopened": bool(res.gate_reopened),
                "gate_lease_lost": bool(res.gate_lease_lost),
                "nvidia_verified": bool(res.nvidia_verified),
                "ready": bool(res.ready),
                "post_unload_verified": bool(res.post_unload_verified),
            })

    def manual_snapshot():
        with manual_lock:
            return dict(manual_state)

    def flow_snapshot():
        with flow_lock:
            return dict(last_flow)

    def request_manual(uid):
        with manual_lock:
            if manual_request["flag"] or manual_state["state"] in ("queued", "running"):
                return {"ok": False, "error": "a manual suspend is already queued or running"}
            manual_request.update({"flag": True, "by": str(uid)})
            manual_state.update({"state": "queued", "message": "queued; workloads will be re-checked",
                                 "blockers": [], "at": _iso_now(), "by": str(uid)})
        control_log.add(f"manual suspend requested by uid {uid}")
        return {"ok": True, "queued": True,
                "message": "queued; the monitor re-checks Strata, updates and agents before suspending"}

    def take_manual():
        with manual_lock:
            if not manual_request["flag"]:
                return None
            manual_request["flag"] = False
            by = manual_request["by"]
            manual_state.update({"state": "running", "message": "checking workloads",
                                 "blockers": [], "at": _iso_now(), "by": by})
        return by

    def read_status():
        try:
            with open(status_path) as f:
                return json.load(f)
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"status unavailable: {e}"}

    allowed_uids = pause_cfg.get("allow_uids") or [0, os.getuid()]
    server = control_mod.ControlServer(
        socket_path, pc, allowed_uids, status_fn=read_status,
        manual_fn=request_manual, group=pause_cfg.get("group"),
        log=control_log.add)

    started_iso = _iso_now()
    gnome_info = {"checked": False, "conflict": False, "reasons": [], "error": "not checked yet"}
    last_gnome_check = 0.0
    events.add(f"monitor started ({'dry-run' if dry_run else 'ARMED'}); "
               f"idle_timeout={idle_timeout if idle_timeout is not None else 'legacy'}s, "
               f"countdown {countdown.seconds:.0f}s, sweep {interval:.0f}s, idle poll {idle_interval:.0f}s")
    if args.service:
        events.add("service mode: non-interactive; status in " + status_path)
    if not dry_run:
        events.add("ARMED: a real suspend is possible after the countdown", echo=True)

    start = time.monotonic()
    next_sweep = 0.0
    prev_state = None
    would = 0
    sweep_ran = True
    stopping = {"flag": False}

    def on_signal(_sig, _frame):
        stopping["flag"] = True

    def on_hup(_sig, _frame):
        events.add("SIGHUP received: configuration changes require a service restart")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_hup)

    def run_manual(by):
        nonlocal would
        mon.sweep(session=mon.session)
        refusals = manual_refusal(mon.results)
        if not dry_run:
            auth_ok, auth_detail = detectors.logind_suspend_authorized()
            if not auth_ok:
                refusals = refusals + ["authorization: " + auth_detail]
        if refusals:
            with manual_lock:
                manual_state.update({"state": "refused",
                                     "message": "refused: " + "; ".join(refusals[:4]),
                                     "blockers": refusals, "at": _iso_now(), "by": by})
            events.add("MANUAL SUSPEND REFUSED: " + "; ".join(refusals[:4]), echo=True)
            return None
        if dry_run:
            would += 1
            with manual_lock:
                manual_state.update({"state": "would_suspend",
                                     "message": "DRY RUN: all critical workloads clear; would suspend (manual)",
                                     "blockers": [], "at": _iso_now(), "by": by})
            events.add("MANUAL: all critical workloads clear - WOULD SUSPEND (dry-run); "
                       "not suspending", echo=True)
            return None
        with manual_lock:
            manual_state.update({"state": "running", "message": "unloading Strata / preparing to suspend",
                                 "blockers": [], "at": _iso_now(), "by": by})
        with pc.manual_suspend_override(enabled=True):
            res = suspendflow.run_quiesce(
                pc, strata_port,
                lambda: _run_suspend(cfg, log=events.add),
                dry_run=False, log=events.add, journal=journal.add,
                gate=gate, settle_s=settle_s,
                pre_gate_verify=gate_idle_before_close,
                post_gate_verify=gate_idle_after_close,
                post_unload_verify=post_unload_verify,
                post_resume_verify=nvidia_verify,
                readiness_verify=readiness_verify,
                respect_pause=False, pause_override=True, guard=guard,
                guard_acquire_timeout_s=guard_acquire_timeout_s,
                guard_retry_interval_s=guard_retry_interval_s)
        record_flow(res)
        with manual_lock:
            if res.ok and res.suspended:
                manual_state.update({"state": "suspended", "message": "manual suspend completed and resumed",
                                     "blockers": [], "at": _iso_now(), "by": by})
            else:
                manual_state.update({"state": "error", "message": "manual suspend aborted: " + res.aborted,
                                     "blockers": [], "at": _iso_now(), "by": by})
        countdown.mark_activity(time.monotonic(), "manual suspend")
        return res

    def _status_extra():
        return {
            "pause": pc.status(),
            "service": {
                "armed": not dry_run,
                "one_shot": one_shot,
                "service_mode": bool(args.service),
                "allow_unattended_suspend": bool(service_cfg.get("allow_unattended_suspend", False)),
                "started": started_iso,
                "version": VERSION,
                "config": args.config,
                "lock_file": lock_path,
                "socket": socket_path,
                "state_file": state_path,
            },
            "manual": manual_snapshot(),
            "last_flow": flow_snapshot(),
            "gnome_suspend": dict(gnome_info),
            "gate": gate.last_status(),
            "gate_recovery": dict(startup_recovery),
            "guard": guard.last_status(),
            "stale_status_s": float(service_cfg.get("stale_status_s", 15)),
        }

    if one_shot:
        try:
            def one_shot_preflight():
                mon.session = detectors.active_graphical_session(refresh=0)
                ok, checks = mon.final_check(
                    countdown, paused_fn=lambda: pc.is_paused(),
                    inactive_s=None, require_idle=False)
                events.add("one-shot final safety check: " + ("PASSED" if ok else "FAILED") +
                           " | " + " | ".join(
                               f"{c[0]}={'pass' if c[1] else 'FAIL(' + c[2] + ')'}"
                               for c in checks))
                if not ok:
                    detail = "; ".join(f"{c[0]}: {c[2]}" for c in checks if not c[1])
                    return False, detail or "final safety check failed"
                p_ok, p_msg = suspendflow.preflight_protection(
                    gate, guard=guard, log=events.add)
                events.add("one-shot protection preflight: "
                           + ("PASSED" if p_ok else "FAILED") + " | " + p_msg)
                if not p_ok:
                    return False, p_msg
                return True, "all final safety checks passed"

            outcome = oneshot.run_supervised_cycle(
                one_shot_preflight, lambda: run_manual("one-shot"), log=events.add)
            if not outcome.ran:
                with manual_lock:
                    manual_state.update({"state": "refused",
                                         "message": outcome.reason or "one-shot preflight failed",
                                         "blockers": [], "at": _iso_now(), "by": "one-shot"})
            final_state = "one-shot-finished" if outcome.ok else "one-shot-aborted"
            events.add(f"one-shot {final_state}: {outcome.reason or 'ok'}", echo=True)
            write_status(status_path, status_document(
                mon, {"state": final_state, "remaining": None, "inactive_s": None,
                      "suspend_in_s": None},
                countdown, would, dry_run, _status_extra()))
            return 0 if outcome.ok else (1 if outcome.ran else 2)
        finally:
            try:
                pc.close()
            except Exception:  # noqa: BLE001
                pass
            lock.release()
            events.add("one-shot monitor stopped")

    try:
        server.start()
        # Initial GUI/service status before the first sweep is complete.
        write_status(status_path, status_document(
            mon, {"state": "starting", "remaining": None, "inactive_s": None, "suspend_in_s": None},
            countdown, would, dry_run, _status_extra()))
        while not stopping["flag"]:
            now = time.monotonic()
            wall = time.time()

            # Timed pause expiry is evaluated even while the loop is idle.
            exp = pc.expire_if_due(wall)
            if exp.get("changed"):
                countdown.mark_activity(now, "timed pause expired")
                events.add("timed pause expired - inactivity timer restarted", echo=True)
            # The main thread owns the logind block lock (a control thread would
            # die and take its child with it via PR_SET_PDEATHSIG).
            pc.reconcile_inhibitor()

            # Read-only and throttled; failures are contained inside refresh().
            guard_status.refresh()

            session = detectors.active_graphical_session(refresh=30)
            if mon.session and session and mon.session.get("id") != session.get("id"):
                events.add(f"graphical session changed: {mon.session.get('id')} -> {session.get('id')}")
            mon.session = session
            idle_ms, idle_source = detectors.probe_idle(session=session)

            sweep_ran = now >= next_sweep
            if sweep_ran:
                mon.sweep(idle_ms, idle_source, session=session)
                next_sweep = now + interval
                if args.verbose:
                    events.add("sweep: " + ", ".join(f"{r.name}={r.state}" for r in mon.results))

            blockers = blocker_reasons(mon.results)
            paused = pc.is_paused(wall)
            st = countdown.tick(now, (idle_ms / 1000.0) if idle_ms is not None else None,
                                blockers, paused=paused)
            state = st["state"]

            # A queued manual suspend takes priority over the automatic gate.
            manual_ran = False
            by = take_manual()
            if by is not None:
                run_manual(by)
                manual_ran = True
                # Re-read the gate so the automatic path sees fresh state and
                # cannot also fire in the same iteration.
                st = countdown.tick(now, (idle_ms / 1000.0) if idle_ms is not None else None,
                                    blockers, paused=pc.is_paused(wall))
                state = st["state"]

            if state != prev_state:
                if state == "countdown":
                    events.add(f"countdown started ({countdown.seconds:.0f}s) - all clear", echo=True)
                elif state == "waiting":
                    events.add(f"waiting: inactivity timer running; suspend in "
                               f"{_fmt_seconds(st.get('suspend_in_s'))}", echo=True)
                elif state == "active":
                    events.add("input detected - inactivity timer reset", echo=True)
                elif state == "blocked":
                    events.add("BLOCKED: " + "; ".join(blockers), echo=True)
                elif state == "unknown":
                    events.add("UNKNOWN: " + st.get("reason", ""), echo=True)
                elif state == "paused":
                    events.add("PAUSED: automatic unload/suspend disabled", echo=True)
                prev_state = state

            if state == "ready" and not manual_ran:
                ok, checks = mon.final_check(
                    countdown, paused_fn=lambda: pc.is_paused(),
                    inactive_s=st.get("inactive_s"))
                events.add("final safety check: " + ("PASSED" if ok else "FAILED") +
                           " | " + " | ".join(f"{c[0]}={'pass' if c[1] else 'FAIL(' + c[2] + ')'}"
                                              for c in checks))
                if not ok:
                    countdown.reset("final check failed")
                elif dry_run:
                    would += 1
                    events.add(f"final check passed - WOULD SUSPEND now (dry-run #{would}); not suspending",
                               echo=True)
                    countdown.consumed("dry-run simulated suspend")
                else:
                    res = suspendflow.run_quiesce(
                        pc, strata_port,
                        lambda: _run_suspend(cfg, log=events.add),
                        dry_run=False, log=events.add, journal=journal.add,
                        gate=gate, settle_s=settle_s,
                        pre_gate_verify=gate_idle_before_close,
                        post_gate_verify=gate_idle_after_close,
                        post_unload_verify=post_unload_verify,
                        post_resume_verify=nvidia_verify,
                        readiness_verify=readiness_verify,
                        respect_pause=True, guard=guard,
                        guard_acquire_timeout_s=guard_acquire_timeout_s,
                        guard_retry_interval_s=guard_retry_interval_s)
                    record_flow(res)
                    if not res.ok:
                        events.add("ABORT suspend: " + res.aborted, echo=True)
                        countdown.reset("suspend aborted: " + res.aborted)
                    else:
                        events.add("system was suspended and has resumed", echo=True)
                        countdown.mark_activity(time.monotonic(), "resume from suspend")

            # GNOME/logind competing-timer check, read-only and periodic.
            if wall - last_gnome_check >= float(service_cfg.get("gnome_check_s", 300)):
                last_gnome_check = wall
                gnome_info = detectors.gnome_suspend_conflict(session=session)
                if gnome_info.get("conflict"):
                    events.add("WARNING: competing automatic suspend setting: "
                               + "; ".join(gnome_info.get("reasons", [])), echo=True)
                elif gnome_info.get("checked"):
                    events.add("GNOME/logind automatic-suspend check: no conflict")

            render(cfg, args, mon, countdown, st, would, dry_run, sweep_ran,
                   pause_state=pc.status())
            write_status(status_path, status_document(mon, st, countdown, would, dry_run,
                                                      _status_extra()))

            loop_end = time.monotonic()
            if loop_end - start >= (max_seconds or float("inf")):
                break
            nap = min(idle_interval, max(0.05, next_sweep - time.monotonic()))
            time.sleep(max(0.05, nap))
    finally:
        try:
            server.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            pc.close()
        except Exception:  # noqa: BLE001
            pass
        final = status_document(
            mon, {"state": "stopped", "remaining": None, "inactive_s": None, "suspend_in_s": None},
            countdown, would, dry_run, _status_extra())
        final["stopped"] = True
        write_status(status_path, final)
        events.add("monitor stopped")
        lock.release()
        if sys.stdout.isatty() and not args.plain and not args.service:
            sys.stdout.write("\033[H\033[J")
            print("Sleep monitor stopped.")
            print(events.tail(10))
    return 0


def gate_recheck(mon, strata_port, gate_cfg, gate=None,
                 require_unloaded=True, clock=time.monotonic, sleep=time.sleep):
    """Sustained idle/gate re-check; returns (ok, message).

    This is the actual safety argument: the firewall only stops *new*
    connections, so before suspending we require ``verify_probes`` consecutive
    clean probes (critical detectors clear, Strata not busy/queued, and -- when
    a gate is configured -- the gate still actually closed) across
    ``verify_s`` seconds.  Any doubt fails safe.

    ``require_unloaded`` is true for the post-unload check.  The pre-close and
    post-close checks set it false: Strata is still loaded at those points, but
    must be idle.
    """
    gate_cfg = gate_cfg or {}
    verify_s = float(gate_cfg.get("verify_s", 5.0))
    probes_needed = max(1, int(gate_cfg.get("verify_probes", 3)))
    end = clock() + max(0.0, verify_s)
    clean, last = 0, "no probe"
    gated = bool(gate is not None and getattr(gate, "enabled", False))
    while True:
        mon.sweep(session=mon.session)
        refusals = manual_refusal(mon.results)
        try:
            loaded = strata_port.loaded()
            if require_unloaded and loaded:
                refusals = refusals + ["strata: model is loaded again after unload"]
        except Exception as e:  # noqa: BLE001 - a failed read must fail safe
            refusals = refusals + [f"strata: health unreadable after unload ({e})"]
        if gated:
            # A helper restart clears the table (fail-open) by design.  If that
            # happened mid-quiesce, the firewall is no longer protecting us.
            # "closed" alone is not protection: the helper must prove the live
            # rule (ports, verdict, SYN match, loopback exemption, chain order).
            try:
                gstatus = gate.status()
            except Exception as e:  # noqa: BLE001
                refusals = refusals + [f"gate: status unreadable ({type(e).__name__}: {e})"]
            else:
                state = gstatus.get("state") if isinstance(gstatus, dict) else None
                if state != "closed":
                    refusals = refusals + [f"gate: expected closed, found {state}"]
                else:
                    problem = suspendflow.gate_protection_problem(gstatus)
                    if problem:
                        refusals = refusals + ["gate: " + problem]
        if refusals:
            clean = 0
            last = "; ".join(refusals[:4])
        else:
            clean += 1
            last = "critical workloads clear"
        if clean >= probes_needed:
            return True, f"{clean} consecutive clean probes; {last}"
        if clock() >= end:
            break
        sleep(min(1.0, max(0.05, end - clock())))
    return False, f"{clean}/{probes_needed} clean probes; last: {last}"


def _sleep_gap():
    """Seconds of suspend time observed by the process.

    CLOCK_BOOTTIME advances during suspend; CLOCK_MONOTONIC does not.  Their
    difference therefore grows by the real sleep duration and stays constant
    while merely awake.  The wall-clock fallback is only for old platforms.
    """
    try:
        return (time.clock_gettime(time.CLOCK_BOOTTIME)
                - time.clock_gettime(time.CLOCK_MONOTONIC))
    except (AttributeError, OSError):
        return time.time() - time.monotonic()


def _run_suspend(cfg, log=None):
    """The only real suspend call; only reachable from an armed monitor or
    the explicit supervised one-shot cycle.

    ``systemctl suspend`` is asynchronous: it returns once logind enqueues the
    operation, not when the machine wakes.  Waiting for the real suspend/resume
    gap prevents resume recovery from racing logind's still-active operation.

    ``--check-inhibitors=yes`` is preserved.  There is deliberately no ``-i``,
    ``--force`` or other inhibitor bypass.
    """
    before_gap = _sleep_gap()
    p = subprocess.run(build_suspend_command(False), capture_output=True, text=True,
                       timeout=cfg.get("suspend_timeout_s", 600))
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip().replace("\n", " ")[:300]
        if log:
            log(f"suspend command failed rc={p.returncode}: "
                + (detail or "no error output (possibly authorization failure)"))
        return p.returncode or 1

    wait_s = float(cfg.get("suspend_resume_wait_s", 120.0))
    if log:
        log("suspend command accepted; waiting for the real resume")
    ok, detail = suspendflow.wait_for_resume(
        before_gap, _sleep_gap, timeout_s=wait_s)
    if not ok:
        if log:
            log("suspend command returned rc=0 but no suspend/resume cycle was "
                "observed: " + str(detail))
        return 1
    if log:
        log(f"suspend/resume observed after {float(detail):.1f}s of sleep")
    return 0


if __name__ == "__main__":
    sys.exit(main())
