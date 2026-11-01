"""Persistent Pause / Timed Pause control for the sleep monitor.

The pause state is intentionally fail-safe: a state file that exists but cannot
be parsed means "paused indefinitely", never "go ahead and suspend".  Writes are
atomic (temporary file + fsync + rename) and the previous good file is kept as
``state.json.bak``.

While paused the monitor also holds a logind ``sleep`` block inhibitor.  That
keeps GNOME, a manual Suspend from the menu, or any other suspender from
overriding the pause.  The explicit "Suspend now" action releases it for the
duration of that one intentional suspend.
"""
from __future__ import annotations

import contextlib
import ctypes
import datetime
import json
import os
import shutil
import signal
import subprocess
import threading
import time

SCHEMA = 1
DEFAULT_TIMED_S = 3600


def _pdeathsig():
    """Make the inhibitor child die with the monitor (Linux PR_SET_PDEATHSIG)."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001 - best effort
        pass


class PauseInhibitor:
    """A logind block lock held for as long as the pause lasts."""

    def __init__(self, enabled=True, why="sleepmgr pause requested", log=None,
                 who="sleepmgr", label="pause inhibitor",
                 fallback="pause still enforced by the monitor"):
        self.enabled = bool(enabled)
        self.why = why
        self.who = who
        self.label = label
        self.fallback = fallback
        self.log = log or (lambda _s: None)
        self.proc = None

    def start(self):
        if not self.enabled or self.alive():
            return False
        cmd = ["systemd-inhibit", "--what=sleep", "--mode=block",
               f"--who={self.who}", f"--why={self.why}", "sleep", "infinity"]
        # systemd-inhibit sends sd_notify READY/STOPPING messages when it
        # inherits NOTIFY_SOCKET.  The guard unit uses NotifyAccess=main, so
        # those child messages are rejected as noise.  The child does not need
        # the service notification socket.
        env = os.environ.copy()
        env.pop("NOTIFY_SOCKET", None)
        try:
            self.proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, preexec_fn=_pdeathsig, env=env,
            )
        except OSError as e:
            self.proc = None
            self.log(f"{self.label} unavailable ({e}); {self.fallback}")
            return False
        # Give systemd-inhibit a moment to register the lock, then report.
        time.sleep(0.15)
        if self.proc.poll() is not None:
            detail = ""
            try:
                detail = (self.proc.stderr.read() or "").strip()
            except (OSError, ValueError):
                pass
            self.log(f"{self.label} exited immediately"
                     + (f" ({detail[:300]})" if detail else "")
                     + f"; {self.fallback}")
            try:
                if self.proc.stderr is not None:
                    self.proc.stderr.close()
            except OSError:
                pass
            self.proc = None
            return False
        self.log(f"{self.label} acquired (pid {self.proc.pid})")
        return True

    def stop(self):
        p, self.proc = self.proc, None
        if p is None:
            return False
        try:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=2)
        except OSError:
            pass
        try:
            if p.stderr is not None:
                p.stderr.close()
        except OSError:
            pass
        self.log(f"{self.label} released")
        return True

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def status(self):
        return {"enabled": self.enabled, "held": self.alive(),
                "pid": self.proc.pid if self.alive() else None}


class PauseController:
    """Thread-safe, persisted pause state."""

    def __init__(self, path, inhibitor=None, clock=time.time, log=None):
        self.path = os.path.expanduser(path) if path else ""
        self.inhibitor = inhibitor or PauseInhibitor(enabled=False)
        self.clock = clock
        self.log = log or (lambda _s: None)
        self._lock = threading.RLock()
        self._state = self._auto_state()
        self.loaded = False
        self.load_error = ""
        self.corrupt = False

    # ------------------------------------------------------------------ state
    @staticmethod
    def _auto_state():
        return {"schema": SCHEMA, "mode": "auto", "paused_until": None,
                "paused_since": None, "reason": "", "requested_by": "",
                "updated_at": None, "last_resume_at": None,
                "last_resume_reason": ""}

    def _now(self):
        return float(self.clock())

    def _read(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("mode") not in ("auto", "paused"):
            raise ValueError("invalid pause state")
        until = data.get("paused_until")
        if until is not None:
            data["paused_until"] = float(until)
        return data

    def load(self):
        with self._lock:
            self.loaded = True
            data = None
            try:
                data = self._read(self.path) if self.path else None
            except FileNotFoundError:
                data = None
            except (OSError, ValueError, TypeError) as e:
                self.load_error = f"{type(e).__name__}: {e}"
                self.log(f"pause state unreadable ({self.load_error}); trying backup")
                bak = self.path + ".bak" if self.path else ""
                if bak:
                    try:
                        data = self._read(bak)
                        self.log("pause state recovered from backup")
                    except (OSError, ValueError, TypeError) as e2:
                        self.log(f"pause backup unreadable ({e2}); PAUSING for safety")
                        data = None
                        self.corrupt = True
                else:
                    self.corrupt = True
            if data is None:
                if self.corrupt:
                    now = self._now()
                    self._state = self._auto_state()
                    self._state.update({"mode": "paused", "paused_since": now,
                                        "reason": "corrupt state file - failing safe",
                                        "updated_at": now})
                    self._write_locked()
                # else: first start, normal auto mode
            else:
                if self.load_error:
                    # The main file was bad but the backup was good: heal it.
                    self._state = self._auto_state()
                    self._state.update({k: data.get(k) for k in self._state if k in data})
                    self._write_locked()
                    self.load_error += " (recovered from backup)"
                else:
                    self._state = self._auto_state()
                    self._state.update({k: data.get(k) for k in self._state if k in data})
                self.corrupt = False
                # A timed pause may have expired while the service was stopped.
                until = self._state.get("paused_until")
                if (self._state.get("mode") == "paused" and until is not None
                        and until <= self._now()):
                    self._state["mode"] = "auto"
                    self._state["last_resume_at"] = self._now()
                    self._state["last_resume_reason"] = "timed_expiry_while_stopped"
                    self._state["paused_until"] = None
                    self._state["updated_at"] = self._now()
                    self.log("timed pause expired while the monitor was stopped; back to auto")
                    self._write_locked()
            return self.status()
    # ----------------------------------------------------------------- write
    def _write_locked(self):
        if not self.path:
            return True
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
            data = dict(self._state)
            data["schema"] = SCHEMA
            data["updated_at"] = self._now()
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o640)
            if os.path.exists(self.path):
                try:
                    shutil.copy2(self.path, self.path + ".bak")
                except OSError:
                    pass
            os.replace(tmp, self.path)
            try:
                dfd = os.open(d or ".", os.O_DIRECTORY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
            self._state["updated_at"] = data["updated_at"]
            return True
        except OSError as e:
            self.log(f"cannot persist pause state to {self.path}: {e}")
            return False

    # ------------------------------------------------------------------ API
    def status(self, now=None):
        with self._lock:
            now = self._now() if now is None else float(now)
            st = dict(self._state)
            until = st.get("paused_until")
            paused = st.get("mode") == "paused" and (until is None or until > now)
            st["paused"] = bool(paused)
            st["remaining_s"] = (max(0.0, until - now) if (paused and until is not None) else None)
            st["inhibitor"] = self.inhibitor.status()
            st["corrupt"] = self.corrupt
            return st

    def is_paused(self, now=None):
        return bool(self.status(now=now)["paused"])

    def reconcile_inhibitor(self):
        """Hold/release the logind block lock to match the pause state.

        Called from the monitor's main thread (never from a short-lived control
        thread: PR_SET_PDEATHSIG follows the creating thread, so a child created
        there would die as soon as the command handler returns).
        """
        with self._lock:
            want = self.is_paused()
            if want and not self.inhibitor.alive():
                self.inhibitor.start()
            elif not want and self.inhibitor.alive():
                self.inhibitor.stop()
            return self.inhibitor.status()

    def pause(self, duration_s=None, by="", reason=""):
        """Pause indefinitely (duration None) or for duration_s seconds."""
        if duration_s is not None:
            duration_s = float(duration_s)
            if duration_s <= 0:
                return {"ok": False, "error": "duration must be positive",
                        "state": self.status()}
        with self._lock:
            now = self._now()
            was = self.is_paused(now)
            self._state["mode"] = "paused"
            self._state["paused_until"] = (now + duration_s) if duration_s else None
            if not was or not self._state.get("paused_since"):
                self._state["paused_since"] = now
            self._state["reason"] = reason or ("timed" if duration_s else "manual")
            self._state["requested_by"] = str(by or "")
            persisted = self._write_locked()
            st = self.status(now)
            st["persisted"] = persisted
            st["ok"] = True
            self.log(f"pause set ({self._state['reason']}"
                     + (f", until {self._fmt(self._state['paused_until'])}" if self._state["paused_until"] else "")
                     + f", by {by or 'unknown'})")
            return st

    def resume(self, by="", reason="manual"):
        with self._lock:
            was = self.is_paused()
            self._state["mode"] = "auto"
            self._state["paused_until"] = None
            self._state["paused_since"] = None
            self._state["last_resume_at"] = self._now()
            self._state["last_resume_reason"] = reason
            self._state["reason"] = ""
            self._state["requested_by"] = str(by or "")
            persisted = self._write_locked()
            st = self.status()
            st["persisted"] = persisted
            st["ok"] = True
            st["was_paused"] = was
            self.log(f"resume to auto ({reason}, by {by or 'unknown'})")
            return st

    def expire_if_due(self, now=None):
        with self._lock:
            now = self._now() if now is None else float(now)
            until = self._state.get("paused_until")
            if self._state.get("mode") == "paused" and until is not None and until <= now:
                self._state["mode"] = "auto"
                self._state["paused_until"] = None
                self._state["paused_since"] = None
                self._state["last_resume_at"] = now
                self._state["last_resume_reason"] = "timed_expiry"
                self._state["reason"] = ""
                self._state["requested_by"] = ""
                self._write_locked()
                self.log("timed pause expired; back to automatic monitoring")
                st = self.status(now)
                st["changed"] = True
                st["expired"] = True
                return st
            st = self.status(now)
            st["changed"] = False
            return st

    @contextlib.contextmanager
    def manual_suspend_override(self, enabled=True):
        """Release the pause inhibitor for one intentional manual suspend."""
        held = self.inhibitor.alive()
        if enabled and held:
            self.inhibitor.stop()
            self.log("manual suspend: pause inhibitor temporarily released")
        try:
            yield
        finally:
            if enabled and self.is_paused():
                self.inhibitor.start()
                self.log("manual suspend finished: pause inhibitor restored")

    def close(self):
        self.inhibitor.stop()

    @staticmethod
    def _fmt(epoch):
        try:
            return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            return "?"
