#!/usr/bin/env python3
"""Fail-closed logind sleep guard for the Strata/NVIDIA host.

The guard is deliberately independent of the sleep monitor.  It holds a logind
``sleep`` block inhibitor unless a local, authorised caller asks for a short,
one-shot release *and* every safety check passes.  If anything is unknown, the
inhibitor stays held.

Safety checks before a release:
  * Strata is not running, or its model is unloaded and neither busy nor queued;
  * ``nvidia-smi`` reports no compute clients, low VRAM use and low GPU util;
  * ``MemAvailable`` is above the configured headroom;
  * the inference gate exists, is reachable and is closed.

The guard never suspends, unloads Strata, or opens/closes the gate.  It only
takes read-only samples and controls its own inhibitor.

Protocol (one JSON object per line, one reply)::

    -> {"cmd": "status"}
    -> {"cmd": "release", "ttl_s": 30, "reason": "...", "token": "..."}
    -> {"cmd": "acquire", "reason": "...", "token": "..."}

``release`` requires an allowed peer uid and, when configured, a matching token.
It returns success only after a *fresh* sample passes every check.  The release
expires after ``ttl_s``; the next guard poll reacquires the inhibitor.  A guard
restart is intentionally not treated as a safe event: it records the gap but
cannot make it disappear.
"""
from __future__ import annotations

import argparse
import dataclasses
import hmac
import json
import os
import queue
import secrets
import shutil
import signal
import socket
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
from pause import PauseInhibitor  # noqa: E402

SCHEMA = 1
DEFAULT_SOCKET = "/run/sleepmgr-suspend-guard/guard.sock"
DEFAULT_STATUS = "/run/sleepmgr-suspend-guard/status.json"
DEFAULT_TOKEN = "/etc/sleepmgr/suspend-guard.token"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"

DEFAULTS = {
    "socket": DEFAULT_SOCKET,
    "status_file": DEFAULT_STATUS,
    "token_file": DEFAULT_TOKEN,
    "require_token": True,
    "allow_uids": [0, 1000],
    "group": "sleepuser",
    "poll_s": 3.0,
    "release_ttl_s": 30.0,
    "max_release_ttl_s": 120.0,
    "command_timeout_s": 15.0,
    "min_available_ram_mib": 4096,
    "max_gpu_memory_mib": 512,
    "max_gpu_util_pct": 5,
    "gpu_timeout_s": 3.0,
    "require_gate": True,
    "inhibitor_who": "sleepmgr-suspend-guard",
    "inhibitor_why": "Strata/CUDA state unsafe or unknown",
}


def boottime():
    """A monotonic clock that also advances while the machine is suspended.

    CLOCK_MONOTONIC pauses during suspend, so a release TTL would still have
    most of its budget left immediately after a long resume.  Boottime is the
    correct clock for a deadline that must not survive a suspend.
    """
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


def merged_config(cfg=None):
    """Return guard defaults overlaid by the supplied mapping."""
    out = dict(DEFAULTS)
    out.update(cfg or {})
    # A null/missing safety switch must not silently become "off".
    for key in ("require_token", "require_gate"):
        if out.get(key) is None:
            out[key] = DEFAULTS[key]
    out["allow_uids"] = [int(u) for u in (out.get("allow_uids") or [])]
    return out


# ---------------------------------------------------------------------------
# pure safety policy
# ---------------------------------------------------------------------------

def _check(checks, name, ok, detail, state=None):
    checks.append({
        "name": name,
        "ok": bool(ok),
        "state": state or ("ok" if ok else "unsafe"),
        "detail": str(detail),
    })


def _gate_evidence_problem(detail):
    """Return why a closed gate's live-rule/seal evidence is insufficient.

    ``snapshot["gate"]["detail"]`` is the helper's status reply.  A logical
    ``state="closed"`` without proof of the actual nftables table (and of the
    seal that survives a crash) must never authorise releasing the inhibitor.
    """
    if not isinstance(detail, dict):
        return "no live-rule evidence in the gate status"
    if detail.get("verified") is not True:
        problem = detail.get("problem")
        return ("the blocking rule is not verified"
                + (f" ({problem})" if problem else ""))
    if detail.get("consistent") is not True:
        return "the logical gate state is inconsistent with the live table"
    actual = detail.get("actual_state")
    if actual != "closed":
        return f"actual nftables state is {actual!r}, not 'closed'"
    rules = detail.get("rules")
    if (not isinstance(rules, int) or isinstance(rules, bool) or rules < 1):
        return f"the gate reports {rules!r} blocking rule(s)"
    if detail.get("sealed") is not True:
        return "the gate is closed but not sealed, so it could reopen"
    return ""


def evaluate_safety(snapshot, cfg=None):
    """Evaluate a plain snapshot without doing any I/O.

    A missing, ``None`` or contradictory value is *unknown* and therefore not
    safe.  The only way to get ``safe=True`` is for every check to be
    positively true.
    """
    cfg = merged_config(cfg)
    checks = []

    strata = snapshot.get("strata") or {}
    if not strata.get("configured", True):
        _check(checks, "strata", True, "Strata detection disabled")
    elif strata.get("server_running") is None:
        _check(checks, "strata", False,
               "Strata process state unreadable; cannot verify whether it is running",
               "unknown")
    elif not strata.get("server_running"):
        # No Strata server means no model can currently be loaded by it.  The
        # GPU check is still mandatory below; a different CUDA client must not
        # be missed.
        _check(checks, "strata", True, "Strata server not running")
    elif strata.get("health_ok") is not True or strata.get("loaded") is None:
        _check(checks, "strata", False,
               "Strata health unreadable; cannot verify loaded state: "
               + str(strata.get("health_error") or "missing loaded field"), "unknown")
    elif strata.get("loaded") is True:
        _check(checks, "strata", False, "Strata model is loaded", "unsafe")
    elif strata.get("status_ok") is not True:
        _check(checks, "strata", False,
               "Strata /status unreadable; cannot verify busy/queued: "
               + str(strata.get("status_error") or "unknown"), "unknown")
    elif strata.get("busy") is None or strata.get("queued") is None:
        _check(checks, "strata", False,
               "Strata /status lacks busy/queued fields", "unknown")
    elif bool(strata.get("busy")) or int(strata.get("queued") or 0) > 0:
        _check(checks, "strata", False,
               f"Strata inference active (busy={bool(strata.get('busy'))}, "
               f"queued={int(strata.get('queued') or 0)})", "unsafe")
    else:
        _check(checks, "strata", True, "model unloaded; idle and no queue")

    gpu = snapshot.get("gpu") or {}
    if gpu.get("ok") is not True:
        _check(checks, "gpu", False,
               "nvidia-smi unreadable; cannot verify GPU state: "
               + str(gpu.get("error") or "unknown"), "unknown")
    else:
        apps = gpu.get("compute_apps")
        if apps is None:
            _check(checks, "gpu-compute", False, "compute-app list missing", "unknown")
        elif apps:
            names = ", ".join(str(a.get("process_name") or a.get("pid") or "?")
                              for a in apps[:4])
            _check(checks, "gpu-compute", False,
                   f"CUDA compute client(s) present: {names}", "unsafe")
        else:
            _check(checks, "gpu-compute", True, "no CUDA compute clients")

        gpus = gpu.get("gpus")
        if not gpus:
            _check(checks, "gpu-memory", False, "no GPU memory data", "unknown")
            _check(checks, "gpu-util", False, "no GPU utilisation data", "unknown")
        else:
            try:
                peak_mem = max(float(g.get("memory_used_mib")) for g in gpus)
            except (TypeError, ValueError):
                peak_mem = None
            if peak_mem is None:
                _check(checks, "gpu-memory", False, "GPU memory value missing", "unknown")
            else:
                limit = float(cfg["max_gpu_memory_mib"])
                _check(checks, "gpu-memory", peak_mem <= limit,
                       f"peak VRAM {peak_mem:.0f} MiB (limit {limit:.0f})",
                       "ok" if peak_mem <= limit else "unsafe")
            try:
                peak_util = max(float(g.get("utilization_pct")) for g in gpus)
            except (TypeError, ValueError):
                peak_util = None
            if peak_util is None:
                _check(checks, "gpu-util", False, "GPU utilisation value missing", "unknown")
            else:
                limit = float(cfg["max_gpu_util_pct"])
                _check(checks, "gpu-util", peak_util <= limit,
                       f"peak GPU util {peak_util:.0f}% (limit {limit:.0f}%)",
                       "ok" if peak_util <= limit else "unsafe")

    ram = snapshot.get("ram") or {}
    if ram.get("ok") is not True:
        _check(checks, "ram", False,
               "MemAvailable unreadable: " + str(ram.get("error") or "unknown"), "unknown")
    else:
        avail = ram.get("available_mib")
        if avail is None:
            _check(checks, "ram", False, "MemAvailable value missing", "unknown")
        else:
            limit = float(cfg["min_available_ram_mib"])
            _check(checks, "ram", float(avail) >= limit,
                   f"MemAvailable {float(avail):.0f} MiB (minimum {limit:.0f})",
                   "ok" if float(avail) >= limit else "unsafe")

    gate = snapshot.get("gate") or {}
    gate_enabled = bool(gate.get("enabled"))
    if not gate_enabled:
        if cfg.get("require_gate", True):
            _check(checks, "gate", False,
                   "inference gate is disabled; cannot prove no new arrivals", "unknown")
        else:
            _check(checks, "gate", True,
                   "inference gate disabled and allow_ungated_release is set")
    elif gate.get("ok") is not True:
        _check(checks, "gate", False,
               "gate status unreadable: " + str(gate.get("error") or "unknown"), "unknown")
    elif gate.get("state") != "closed":
        _check(checks, "gate", False,
               f"inference gate state is {gate.get('state')!r}, not 'closed'", "unsafe")
    else:
        problem = _gate_evidence_problem(gate.get("detail"))
        if problem:
            _check(checks, "gate", False,
                   "inference gate is closed but protection is unproven: "
                   + problem, "unknown")
        else:
            _check(checks, "gate", True,
                   "inference gate is sealed with a verified blocking rule")

    reasons = [f"{c['name']}: {c['detail']}" for c in checks if not c["ok"]]
    return {
        "safe": not reasons,
        "checks": checks,
        "reasons": reasons,
        "at": float(snapshot.get("at") or time.time()),
    }


# ---------------------------------------------------------------------------
# read-only snapshotter
# ---------------------------------------------------------------------------

def parse_gpu_csv(text):
    gpus = []
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3 or not parts[0]:
            continue
        try:
            gpus.append({
                "index": int(float(parts[0])),
                "utilization_pct": float(parts[1]),
                "memory_used_mib": float(parts[2]),
            })
        except ValueError:
            continue
    return gpus


def parse_compute_csv(text):
    apps = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("no running processes"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        apps.append({
            "pid": parts[0],
            "process_name": parts[1] if len(parts) > 1 else "",
            "used_memory": parts[2] if len(parts) > 2 else "",
        })
    return apps


def parse_meminfo(text):
    """Return MemAvailable in MiB, or None if the field is absent/invalid."""
    for line in (text or "").splitlines():
        if line.startswith("MemAvailable:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return float(parts[1]) / 1024.0  # kB -> MiB
                except ValueError:
                    return None
    return None


class SystemSnapshotter:
    """Collect the read-only facts the pure evaluator needs."""

    def __init__(self, cfg, log=None):
        self.cfg = cfg or {}
        self.log = log or (lambda _s: None)
        self.guard_cfg = merged_config(self.cfg.get("suspend_guard", {}))
        self.strata_cfg = self.cfg.get("strata", {}) or {}
        self.gate_cfg = self.cfg.get("gate", {}) or {}
        self.count = 0

    def snapshot(self):
        self.count += 1
        return {
            "at": time.time(),
            "strata": self._strata(),
            "gpu": self._gpu(),
            "ram": self._ram(),
            "gate": self._gate(),
        }

    def _strata(self):
        if not self.strata_cfg.get("enabled", True):
            return {"configured": False, "server_running": False,
                    "health_ok": True, "loaded": False, "status_ok": True,
                    "busy": False, "queued": 0}
        try:
            probe = detectors.StrataProbe(self.strata_cfg)
            server, _engine = probe._processes()
        except Exception as e:  # noqa: BLE001 - a failed process scan is unknown
            return {"configured": True, "server_running": None,
                    "health_ok": False, "health_error": f"{type(e).__name__}: {e}",
                    "loaded": None, "status_ok": False,
                    "status_error": "process scan failed", "busy": None, "queued": None}
        if not server:
            return {"configured": True, "server_running": False,
                    "health_ok": True, "loaded": False, "status_ok": True,
                    "busy": False, "queued": 0}
        out = {"configured": True, "server_running": True}
        try:
            health = probe.health(timeout=float(
                self.guard_cfg.get("http_timeout_s", self.strata_cfg.get("http_timeout_s", 3))))
            loaded = health.get("loaded") if isinstance(health, dict) else None
            out["loaded"] = loaded if isinstance(loaded, bool) else None
            out["health_ok"] = out["loaded"] is not None
            if not out["health_ok"]:
                out["health_error"] = "missing boolean loaded field"
        except Exception as e:  # noqa: BLE001
            out.update({"health_ok": False, "loaded": None,
                        "health_error": f"{type(e).__name__}: {e}"})
        try:
            status = probe.get("/status", auth=True,
                               timeout=float(self.guard_cfg.get(
                                   "http_timeout_s", self.strata_cfg.get("http_timeout_s", 3))))
            out["status_ok"] = isinstance(status, dict)
            if out["status_ok"]:
                out["busy"] = status.get("busy") if isinstance(status.get("busy"), bool) else None
                try:
                    out["queued"] = int(status.get("queued")) if status.get("queued") is not None else None
                except (TypeError, ValueError):
                    out["queued"] = None
            else:
                out["status_error"] = "non-object reply"
        except Exception as e:  # noqa: BLE001
            out.update({"status_ok": False, "status_error": f"{type(e).__name__}: {e}",
                        "busy": None, "queued": None})
        return out

    def _gpu(self):
        if not shutil.which("nvidia-smi"):
            return {"ok": False, "error": "nvidia-smi not found"}
        timeout = float(self.guard_cfg.get("gpu_timeout_s", 3))
        rc, out, err = detectors._run(
            ["nvidia-smi", "--query-gpu=index,utilization.gpu,memory.used",
             "--format=csv,noheader,nounits"], timeout)
        if rc != 0:
            return {"ok": False, "error": (err or out or f"nvidia-smi rc={rc}").strip()[:200]}
        rc2, out2, err2 = detectors._run(
            ["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
             "--format=csv,noheader,nounits"], timeout)
        if rc2 != 0:
            return {"ok": False, "error": (err2 or out2 or f"compute query rc={rc2}").strip()[:200]}
        gpus = parse_gpu_csv(out)
        if not gpus:
            return {"ok": False, "error": "nvidia-smi returned no GPUs"}
        return {"ok": True, "gpus": gpus, "compute_apps": parse_compute_csv(out2)}

    @staticmethod
    def _ram():
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                avail = parse_meminfo(f.read())
        except OSError as e:
            return {"ok": False, "error": str(e)}
        if avail is None:
            return {"ok": False, "error": "MemAvailable missing"}
        return {"ok": True, "available_mib": avail}

    def _gate(self):
        enabled = bool(self.gate_cfg.get("enabled", False))
        if not enabled:
            return {"enabled": False, "ok": True, "state": "disabled"}
        try:
            gate = netgate.build_gate(self.gate_cfg, log=self.log)
            reply = gate.status()
            return {"enabled": True, "ok": bool(reply.get("ok", True)),
                    "state": reply.get("state") or "unknown",
                    "detail": reply}
        except Exception as e:  # noqa: BLE001
            return {"enabled": True, "ok": False, "state": "unknown",
                    "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# release authorisation
# ---------------------------------------------------------------------------

class Authorizer:
    """Allowed local uid plus optional rotating token."""

    def __init__(self, allow_uids, token_file=None, require_token=False,
                 token_reader=None, log=None):
        self.allow_uids = {int(u) for u in (allow_uids or [])}
        self.token_file = token_file or ""
        self.require_token = True if require_token is None else bool(require_token)
        self.token_reader = token_reader
        self.log = log or (lambda _s: None)

    def _expected_token(self):
        if self.token_reader is not None:
            try:
                return (self.token_reader() or "").strip()
            except Exception as e:  # noqa: BLE001
                self.log(f"suspend guard token read failed: {type(e).__name__}: {e}")
                return ""
        try:
            with open(os.path.expanduser(self.token_file), "r", encoding="utf-8") as f:
                return f.read(4096).strip()
        except OSError as e:
            self.log(f"suspend guard token unavailable: {e}")
            return ""

    def check(self, uid, supplied):
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            return False, "invalid peer uid"
        if uid not in self.allow_uids:
            return False, f"uid {uid} is not allowed"
        if self.require_token:
            expected = self._expected_token()
            if not expected:
                return False, "guard token is not configured/readable"
            if not hmac.compare_digest(str(supplied or ""), expected):
                return False, "bad token"
        return True, ""


# ---------------------------------------------------------------------------
# guard state machine
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class PendingCommand:
    cmd: dict
    uid: int
    event: threading.Event = dataclasses.field(default_factory=threading.Event)
    result: dict | None = None


class Guard:
    """Own the inhibitor and serialise all state changes on the main thread.

    ``start``/``stop`` of the inhibitor must happen on the thread that created
    it because the child uses PR_SET_PDEATHSIG.  Control requests are therefore
    queued to the main loop.  Tests call ``handle_command`` directly.
    """

    def __init__(self, cfg, inhibitor, snapshot_fn, authorizer,
                 clock=boottime, wallclock=time.time,
                 status_writer=None, boot_id_reader=None, log=None):
        self.cfg = merged_config(cfg)
        self.inhibitor = inhibitor
        self.snapshot_fn = snapshot_fn
        self.authorizer = authorizer
        self.clock = clock
        self.wallclock = wallclock
        self.status_writer = status_writer or (lambda _doc: None)
        self.boot_id_reader = boot_id_reader or read_boot_id
        self.log = log or (lambda _s: None)
        self.commands = queue.Queue()
        self._lock = threading.RLock()

        self.started_at = float(self.wallclock())
        self.boot_id = self.boot_id_reader()
        self.restart_gap_s = None
        self.last_failure = ""
        self.failure_count = 0
        self.authorization = None
        self.report = {"safe": False, "checks": [], "reasons": ["guard not polled yet"],
                       "at": None}
        self.last_heartbeat = None
        self.last_status_error = ""
        self._status = {}
        # Do not write the initial placeholder: startup() must be able to read
        # the previous process's heartbeat before it is overwritten.
        self._publish("initialising", write=False)

    # ------------------------------------------------------------------ state
    def _now(self):
        return float(self.clock())

    def _wall(self):
        return float(self.wallclock())

    def _start_inhibitor(self, why, count_failure=True):
        if self.inhibitor.alive():
            return True
        try:
            ok = bool(self.inhibitor.start())
        except Exception as e:  # noqa: BLE001
            ok = False
            self.log(f"suspend guard: inhibitor start raised {type(e).__name__}: {e}")
        if not ok:
            if count_failure:
                self.failure_count += 1
            self.last_failure = f"inhibitor acquire failed during {why}"
            self.log("suspend guard: " + self.last_failure)
        return ok

    def _recover_inhibitor(self, why):
        """Detect an unexpected loss and report it even if recovery works."""
        if self.inhibitor.alive():
            return True
        self.failure_count += 1
        self.last_failure = f"inhibitor was not held ({why})"
        self.log("suspend guard: " + self.last_failure + "; reacquiring")
        return self._start_inhibitor(why, count_failure=False)

    def _stop_inhibitor(self, why):
        try:
            self.inhibitor.stop()
        except Exception as e:  # noqa: BLE001
            self.log(f"suspend guard: inhibitor stop raised {type(e).__name__}: {e}")
        if self.inhibitor.alive():
            self.failure_count += 1
            self.last_failure = f"inhibitor still held after release request ({why})"
            self.log("suspend guard: " + self.last_failure)
            return False
        return True

    def _publish(self, reason="", write=True):
        with self._lock:
            self.last_heartbeat = self._wall()
            auth = dict(self.authorization) if self.authorization else None
            if auth:
                left = max(0.0, float(auth["until"]) - self._now())
                auth["remaining_s"] = round(left, 3)
            held = bool(self.inhibitor.alive())
            doc = {
                "schema": SCHEMA,
                "service": "sleepmgr-suspend-guard",
                "pid": os.getpid(),
                "boot_id": self.boot_id,
                "started_at": self.started_at,
                "heartbeat_wall": self.last_heartbeat,
                "state": ("released" if auth else ("protected" if held else "unprotected")),
                "protected": bool(held and not auth),
                "held": held,
                "authorized": bool(auth),
                "authorization": auth,
                "safe": bool(self.report.get("safe")),
                "checks": self.report.get("checks", []),
                "reasons": self.report.get("reasons", []),
                "last_failure": self.last_failure,
                "failure_count": self.failure_count,
                "restart_gap_s": self.restart_gap_s,
                "inhibitor": self.inhibitor.status(),
                "reason": reason,
                "updated_at": self._wall(),
            }
            self._status = doc
        if write:
            try:
                self.status_writer(doc)
                self.last_status_error = ""
            except Exception as e:  # noqa: BLE001 - a status file failure must not kill the guard
                msg = f"{type(e).__name__}: {e}"
                if msg != self.last_status_error:
                    self.log(f"suspend guard: cannot write status: {msg}")
                self.last_status_error = msg
        return doc

    def status(self):
        with self._lock:
            return json.loads(json.dumps(self._status))

    def startup(self):
        """Acquire before probing, then record the previous exit gap (if any)."""
        prev = self._read_previous_status()
        if prev and prev.get("boot_id") == self.boot_id:
            try:
                gap = max(0.0, self._wall() - float(prev.get("heartbeat_wall") or 0))
            except (TypeError, ValueError):
                gap = None
            if gap is not None and gap > 0.05:
                self.restart_gap_s = round(gap, 3)
                self.log(f"suspend guard: previous process heartbeat was {gap:.3f}s ago")
        self.log("suspend guard: acquiring inhibitor before first probe")
        self._start_inhibitor("startup")
        return self.poll("startup")

    def poll(self, reason="poll"):
        """Refresh the sample, enforce TTL/watchdog, and publish status."""
        with self._lock:
            now = self._now()
            auth = self.authorization
            expired = False
            if auth and now >= float(auth["until"]):
                self.log("suspend guard: release TTL expired; reacquiring inhibitor")
                self.authorization = None
                expired = True
                if not self._start_inhibitor("authorization expiry"):
                    self.log("suspend guard: CRITICAL: reacquire after expiry failed")
            if (self.authorization is None and not self.inhibitor.alive()
                    and not expired):
                self._recover_inhibitor("watchdog")

        try:
            report = evaluate_safety(self.snapshot_fn(), self.cfg)
        except Exception as e:  # noqa: BLE001 - any probe failure is unknown
            report = {"safe": False, "checks": [],
                      "reasons": [f"snapshot failed: {type(e).__name__}: {e}"],
                      "at": self._wall()}
        with self._lock:
            self.report = report
            if self.authorization is not None and not report["safe"]:
                self.log("suspend guard: safety changed during release; reacquiring")
                self.authorization = None
                self._start_inhibitor("safety changed")
            if self.authorization is None and not self.inhibitor.alive():
                self._recover_inhibitor("post-probe watchdog")
        return self._publish(reason)

    def _read_previous_status(self):
        path = self.cfg.get("status_file")
        if not path:
            return None
        try:
            with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    # -------------------------------------------------------------- commands
    def submit(self, cmd, uid, timeout=None):
        """Queue a mutating command and wait for the main loop to execute it.

        ``status``/``ping`` do not mutate the inhibitor and are answered from
        the cached status.  Authentication happens before queueing and again in
        ``handle_command`` so a token rotation cannot widen a queued request.
        """
        if not isinstance(cmd, dict) or not cmd.get("cmd"):
            return {"ok": False, "error": "missing cmd"}
        name = cmd["cmd"]
        allowed, why = self.authorizer.check(uid, cmd.get("token"))
        if not allowed:
            self.log(f"suspend guard command {name!r} refused: {why}")
            return {"ok": False, "error": why}
        if name in ("status", "ping"):
            reply = self.status()
            reply.update({"ok": True})
            return reply
        if name not in ("release", "acquire"):
            return {"ok": False, "error": f"unknown command {name!r}"}
        pending = PendingCommand(cmd=dict(cmd), uid=int(uid))
        self.commands.put(pending)
        if not pending.event.wait(float(timeout or self.cfg.get("command_timeout_s", 15))):
            return {"ok": False, "error": "guard main loop did not answer in time"}
        return pending.result or {"ok": False, "error": "guard returned no result"}

    def process_one(self, pending):
        try:
            pending.result = self.handle_command(pending.cmd, pending.uid)
        except Exception as e:  # noqa: BLE001
            pending.result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            pending.event.set()
        return pending.result

    def handle_command(self, cmd, uid):
        if not isinstance(cmd, dict) or not cmd.get("cmd"):
            return {"ok": False, "error": "missing cmd"}
        name = cmd["cmd"]
        allowed, why = self.authorizer.check(uid, cmd.get("token"))
        if not allowed:
            self.log(f"suspend guard command {name!r} refused: {why}")
            return {"ok": False, "error": why}
        if name in ("status", "ping"):
            reply = self.status()
            reply.update({"ok": True})
            return reply
        if name == "acquire":
            self.authorization = None
            ok = self._start_inhibitor("manual acquire")
            self._publish("manual acquire")
            if not ok:
                return {"ok": False, "error": self.last_failure,
                        "status": self.status()}
            return {"ok": True, "state": "protected", "status": self.status()}
        if name != "release":
            return {"ok": False, "error": f"unknown command {name!r}"}

        if not self.inhibitor.alive():
            return {"ok": False, "error": "guard is not currently protected; refusing release",
                    "status": self.status()}
        try:
            ttl = float(cmd.get("ttl_s", self.cfg["release_ttl_s"]))
        except (TypeError, ValueError):
            return {"ok": False, "error": "ttl_s must be a number"}
        if ttl <= 0 or ttl > float(self.cfg["max_release_ttl_s"]):
            return {"ok": False,
                    "error": f"ttl_s must be >0 and <={float(self.cfg['max_release_ttl_s']):.0f}"}
        try:
            report = evaluate_safety(self.snapshot_fn(), self.cfg)
        except Exception as e:  # noqa: BLE001
            report = {"safe": False, "checks": [],
                      "reasons": [f"snapshot failed: {type(e).__name__}: {e}"],
                      "at": self._wall()}
        with self._lock:
            self.report = report
            if not report["safe"]:
                self.log("suspend guard: release refused: " + "; ".join(report["reasons"][:4]))
                self._publish("release refused")
                return {"ok": False, "error": "safety checks failed",
                        "reasons": report["reasons"], "checks": report["checks"],
                        "status": self.status()}
            if not self._stop_inhibitor("authorized release"):
                self._publish("release failed")
                return {"ok": False, "error": self.last_failure, "status": self.status()}
            until = self._now() + ttl
            auth = {
                "id": secrets.token_hex(8),
                "by_uid": int(uid),
                "reason": str(cmd.get("reason") or "controlled suspend")[:200],
                "ttl_s": ttl,
                "at": self._wall(),
                "until": until,
                "until_wall": self._wall() + ttl,
                "created_mono": self._now(),
            }
            self.authorization = auth
            self.log(f"suspend guard: inhibitor released for {ttl:.0f}s by uid {uid} "
                     f"({auth['reason']})")
            self._publish("released")
            return {"ok": True, "state": "released",
                    "authorization": dict(auth), "status": self.status()}

    def close(self):
        with self._lock:
            self.authorization = None
            try:
                self.inhibitor.stop()
            except Exception:  # noqa: BLE001
                pass
            self._publish("stopped")


# ---------------------------------------------------------------------------
# local control socket
# ---------------------------------------------------------------------------

class GuardControlServer:
    """AF_UNIX server; peer credentials are the primary local authorisation."""

    def __init__(self, path, guard, group=None, log=None):
        self.path = path
        self.guard = guard
        self.group = group
        self.log = log or (lambda _s: None)
        self.sock = None
        self.thread = None
        self.bound = False
        self._stop = threading.Event()

    def start(self):
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, mode=0o750, exist_ok=True)
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
                raise RuntimeError(f"another suspend guard is listening on {self.path}")
            finally:
                try:
                    probe.close()
                except OSError:
                    pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self.path)
        self.bound = True
        os.chmod(self.path, 0o600)
        if os.geteuid() == 0 and self.group:
            import grp
            try:
                os.chown(self.path, 0, grp.getgrnam(self.group).gr_gid)
            except (KeyError, OSError):
                pass
        s.listen(8)
        s.settimeout(1.0)
        self.sock = s
        self.thread = threading.Thread(target=self._accept_loop, name="suspend-guard-control",
                                       daemon=True)
        self.thread.start()
        self.log(f"suspend guard control socket ready: {self.path}")
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
                             name="suspend-guard-client").start()

    def _handle(self, conn):
        with conn:
            conn.settimeout(10.0)
            try:
                _pid, uid, _gid = control_mod.peer_credentials(conn)
            except OSError as e:
                self._send(conn, {"ok": False, "error": f"peer credentials: {e}"})
                return
            data = b""
            while b"\n" not in data and len(data) < control_mod.MAX_LINE:
                try:
                    chunk = conn.recv(1024)
                except OSError:
                    return
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\n", 1)[0].strip()
            if not line:
                self._send(conn, {"ok": False, "error": "empty command"})
                return
            if len(data) >= control_mod.MAX_LINE and b"\n" not in data:
                self._send(conn, {"ok": False, "error": "command too long"})
                return
            try:
                cmd = json.loads(line.decode("utf-8"))
            except ValueError as e:
                self._send(conn, {"ok": False, "error": f"bad JSON: {e}"})
                return
            self._send(conn, self.guard.submit(cmd, uid))

    @staticmethod
    def _send(conn, obj):
        try:
            conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        except OSError:
            pass


# ---------------------------------------------------------------------------
# small client used by the sleep monitor
# ---------------------------------------------------------------------------

class GuardError(RuntimeError):
    pass


class NullGuard:
    enabled = False

    def release(self, ttl_s=None, reason=""):
        return {"ok": True, "state": "disabled"}

    def acquire(self, reason="", timeout=None):
        return {"ok": True, "state": "disabled"}

    def last_status(self):
        return {"enabled": False, "state": "disabled"}


class GuardClient:
    """Client for the local guard socket; never touches logind itself."""

    enabled = True

    def __init__(self, path, token=None, timeout=10.0):
        self.path = path
        self.token = token or None
        self.timeout = float(timeout)
        self._last = {"enabled": True, "state": "unknown"}

    def last_status(self):
        return dict(self._last)

    def _request(self, cmd, timeout=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout if timeout is None else max(0.1, float(timeout)))
        try:
            s.connect(self.path)
            s.sendall((json.dumps(cmd) + "\n").encode("utf-8"))
            data = b""
            while b"\n" not in data and len(data) < control_mod.MAX_LINE:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
        except OSError as e:
            raise GuardError(f"cannot reach suspend guard at {self.path}: {e}") from e
        finally:
            try:
                s.close()
            except OSError:
                pass
        line = data.split(b"\n", 1)[0].strip()
        if not line:
            raise GuardError("empty reply from suspend guard")
        try:
            reply = json.loads(line.decode("utf-8"))
        except ValueError as e:
            raise GuardError(f"bad reply from suspend guard: {e}") from e
        if not isinstance(reply, dict):
            raise GuardError("suspend guard reply is not an object")
        self._last = dict(reply)
        return reply

    def release(self, ttl_s=None, reason=""):
        cmd = {"cmd": "release", "reason": reason}
        if ttl_s is not None:
            cmd["ttl_s"] = ttl_s
        if self.token:
            cmd["token"] = self.token
        reply = self._request(cmd)
        if not reply.get("ok"):
            raise GuardError(str(reply.get("error") or "suspend guard refused release"))
        return reply

    def acquire(self, reason="", timeout=None):
        cmd = {"cmd": "acquire", "reason": reason}
        if self.token:
            cmd["token"] = self.token
        reply = self._request(cmd, timeout=timeout)
        if not reply.get("ok"):
            raise GuardError(str(reply.get("error") or "suspend guard refused acquire"))
        return reply

    def status(self, timeout=None):
        cmd = {"cmd": "status"}
        if self.token:
            cmd["token"] = self.token
        try:
            reply = self._request(cmd, timeout=timeout)
        except GuardError as e:
            self._last = {"enabled": True, "state": "unknown", "error": str(e)}
            raise
        if not reply.get("ok"):
            error = str(reply.get("error") or "suspend guard refused status")
            self._last = {"enabled": True, "state": "unknown", "error": error}
            raise GuardError(error)
        return reply


def _read_token(path):
    if not path:
        return None
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
            return f.read(4096).strip() or None
    except OSError:
        return None


def build_guard(cfg, log=None):
    """Return a client when the feature is enabled, else a no-op guard."""
    cfg = cfg or {}
    if not cfg.get("enabled", False):
        return NullGuard()
    token = _read_token(cfg.get("token_file"))
    if cfg.get("require_token", True) and not token and log:
        log('suspend guard: enabled, but the token file is unreadable; releases will be refused')
    return GuardClient(
        cfg.get("socket") or DEFAULT_SOCKET,
        token=token,
        timeout=float(cfg.get("command_timeout_s", 10.0)),
    )


# ---------------------------------------------------------------------------
# process / systemd glue
# ---------------------------------------------------------------------------

def read_boot_id():
    try:
        with open(BOOT_ID_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def write_status_file(path):
    def writer(doc):
        if not path:
            return
        d = os.path.dirname(os.path.expanduser(path))
        if d:
            os.makedirs(d, mode=0o750, exist_ok=True)
        tmp = os.path.expanduser(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.expanduser(path))
    return writer


def sd_notify(state):
    """Best-effort sd_notify without a third-party dependency."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(addr)
        s.sendall(state.encode("utf-8"))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def load_json_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("config is not an object")
    return data


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Fail-closed Strata/NVIDIA sleep guard")
    p.add_argument("--config", default=os.path.join(HERE, "config.json"))
    p.add_argument("--socket", default=None)
    p.add_argument("--status-file", default=None)
    p.add_argument("--token-file", default=None)
    p.add_argument("--poll-s", type=float, default=None)
    p.add_argument("--release-ttl-s", type=float, default=None)
    p.add_argument("--allow-uid", action="append", type=int, default=None)
    p.add_argument("--no-token", action="store_true",
                   help="test/manual only: rely on peer uid and socket mode")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        base = load_json_config(args.config)
    except (OSError, ValueError) as e:
        print(f"suspend guard: cannot read config {args.config}: {e}", file=sys.stderr)
        return 2
    cfg = dict(base.get("suspend_guard", {}) or {})
    if args.socket:
        cfg["socket"] = args.socket
    if args.status_file:
        cfg["status_file"] = args.status_file
    if args.token_file:
        cfg["token_file"] = args.token_file
    if args.poll_s is not None:
        cfg["poll_s"] = args.poll_s
    if args.release_ttl_s is not None:
        cfg["release_ttl_s"] = args.release_ttl_s
    if args.allow_uid:
        cfg["allow_uids"] = args.allow_uid
    if args.no_token:
        cfg["require_token"] = False
    cfg = merged_config(cfg)
    log = lambda s: print(s, file=sys.stderr, flush=True)
    if not cfg.get("enabled", False):
        log('suspend guard: service is running but suspend_guard.enabled is false; '
            'the monitor will not request releases')

    inhibitor = PauseInhibitor(
        enabled=True,
        who=cfg.get("inhibitor_who", "sleepmgr-suspend-guard"),
        label="suspend guard inhibitor",
        fallback="the guard will retry and report unprotected status",
        why=cfg.get("inhibitor_why", "Strata/CUDA state unsafe or unknown"),
        log=log)
    snapshotter = SystemSnapshotter(base, log=log)
    authorizer = Authorizer(cfg["allow_uids"], token_file=cfg["token_file"],
                            require_token=bool(cfg["require_token"]), log=log)
    guard = Guard(cfg, inhibitor, snapshotter.snapshot, authorizer,
                  status_writer=write_status_file(cfg["status_file"]), log=log)
    guard.startup()
    server = GuardControlServer(cfg["socket"], guard, group=cfg.get("group"), log=log)
    try:
        server.start()
    except Exception as e:  # noqa: BLE001 - keep protection even if control is unavailable
        log(f"suspend guard: control socket unavailable ({type(e).__name__}: {e}); "
            "inhibitor remains held")
    sd_notify("READY=1")

    stop = {"flag": False}

    def on_signal(_sig, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    next_poll = 0.0
    try:
        while not stop["flag"]:
            now = boottime()
            if now >= next_poll:
                guard.poll()
                sd_notify("WATCHDOG=1")
                next_poll = now + max(0.5, float(cfg["poll_s"]))
            timeout = min(0.5, max(0.0, next_poll - boottime()))
            try:
                pending = guard.commands.get(timeout=timeout)
            except queue.Empty:
                continue
            guard.process_one(pending)
            next_poll = 0.0  # re-sample immediately after a state change
    finally:
        sd_notify("STOPPING=1")
        try:
            server.stop()
        except Exception:  # noqa: BLE001
            pass
        guard.close()
        log("suspend guard: stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
