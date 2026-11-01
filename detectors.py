"""Read-only probes for the workload-aware sleep monitor.

Every probe reads OS state (procfs, sysfs, D-Bus, nvidia-smi, ss) or asks a
local service a question.  Nothing here suspends, unloads, installs or writes
outside the monitor's own log directory.  The one exception is
``strata_prepare_for_suspend``/``strata_load``, which are only called on the
explicitly armed path (and are never reached in dry-run mode).

Secrets: the Strata API key is read at runtime from Strata's own config and is
never printed or logged.
"""
from __future__ import annotations

import ipaddress
import json
import os
import os.path
import re
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request

from policy import ACTIVE, OK, UNKNOWN, DetectorResult, Sustained, match_any_process

HZ = os.sysconf("SC_CLK_TCK")

# Bounded default for the post-resume readiness check.  The preserved live
# config predates ``strata.readiness_deadline_s``; absence must not mean
# "unbounded", or a slow endpoint could hold the sealed gate forever.
DEFAULT_READINESS_DEADLINE_S = 300.0


def _run(cmd, timeout=5, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError as e:
        return 127, "", f"not found: {e}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as e:  # noqa: BLE001 - report, never crash the monitor
        return 126, "", str(e)


def _http_json(url, headers=None, timeout=3):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _http_error_text(exc):
    """Describe an HTTP/URL error without hiding the host-specific reason."""
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read(200).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001 - the status line is still useful
            body = ""
        return f"HTTP {exc.code}" + (f": {body[:160]}" if body else "")
    if isinstance(exc, urllib.error.URLError):
        return f"URLError: {exc.reason}"
    return f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------
# process table
# --------------------------------------------------------------------------

def iter_procs():
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
        except OSError:
            continue
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
        out.append((pid, comm, argv))
    return out


def proc_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
    except OSError:
        return None
    r = s.rfind(")")
    if r < 0:
        return None
    f = s[r + 2:].split()
    try:
        return int(f[11]) + int(f[12])  # utime + stime
    except (IndexError, ValueError):
        return None


def proc_ppids():
    d = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat") as f:
                s = f.read()
        except OSError:
            continue
        r = s.rfind(")")
        if r < 0:
            continue
        f = s[r + 2:].split()
        try:
            d[int(name)] = int(f[1])
        except (IndexError, ValueError):
            pass
    return d


# --------------------------------------------------------------------------
# idle detection: GNOME Mutter is the canonical X11/Wayland source
# --------------------------------------------------------------------------

MUTTER_DEST = "org.gnome.Mutter.IdleMonitor"
MUTTER_PATH = "/org/gnome/Mutter/IdleMonitor/Core"

_SESSION_CACHE = {"at": 0.0, "session": None}


def session_env(uid, display=None):
    """Environment for talking to a user's session bus from a system service."""
    env = dict(os.environ)
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{int(uid)}/bus"
    env["XDG_RUNTIME_DIR"] = f"/run/user/{int(uid)}"
    if display:
        env["DISPLAY"] = display
    return env


def _parse_loginctl_show(out):
    props = {}
    for line in (out or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props


def active_graphical_session(refresh=30.0):
    """Find the active graphical session (greeter included) on this seat.

    Returns a dict with id/uid/user/seat/type/class/display/active or None.
    Cached for ``refresh`` seconds; pass refresh=0 to force a fresh lookup.
    """
    now = time.monotonic()
    cached = _SESSION_CACHE.get("session")
    if cached and refresh and now - _SESSION_CACHE.get("at", 0.0) < refresh:
        return cached
    rc, out, _err = _run(["loginctl", "list-sessions", "--no-legend"], 4)
    candidates = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            sid = parts[0]
            rc2, show, _ = _run(["loginctl", "show-session", sid,
                                 "-p", "Type", "-p", "Active", "-p", "Class",
                                 "-p", "Display", "-p", "Remote"], 3)
            if rc2 != 0:
                continue
            p = _parse_loginctl_show(show)
            if p.get("Type") not in ("x11", "wayland"):
                continue
            if p.get("Active") != "yes":
                continue
            try:
                uid = int(parts[1])
            except (IndexError, ValueError):
                continue
            candidates.append({
                "id": sid, "uid": uid, "user": parts[2], "seat": parts[3],
                "tty": parts[4], "type": p.get("Type"),
                "class": p.get("Class"), "display": p.get("Display") or "",
                "remote": p.get("Remote") == "yes",
            })
    if not candidates:
        # Development fallback: the calling user's own bus, if it exists.
        uid = os.getuid()
        if os.path.exists(f"/run/user/{uid}/bus"):
            candidates.append({"id": "", "uid": uid, "user": "", "seat": "seat0",
                               "tty": "", "type": "x11", "class": "user",
                               "display": os.environ.get("DISPLAY", ""), "remote": False})
        else:
            _SESSION_CACHE.update({"at": now, "session": None})
            return None
    # Prefer a real user session over the greeter, and a remote-free one.
    candidates.sort(key=lambda c: (c.get("class") != "user", bool(c.get("remote"))))
    sess = candidates[0]
    _SESSION_CACHE.update({"at": now, "session": sess})
    return sess


def logind_idle_seconds(session_id, timeout=3):
    """Coarse fallback: logind's last idle hint (system bus, root-safe)."""
    if not session_id:
        return None
    rc, out, _ = _run(["loginctl", "show-session", str(session_id),
                       "-p", "IdleHint", "-p", "IdleSinceHintMonotonic"], timeout)
    if rc != 0:
        return None
    p = _parse_loginctl_show(out)
    if p.get("IdleHint") != "yes":
        # GNOME says the session is not idle; do not guess.
        return None
    try:
        since_us = int(p.get("IdleSinceHintMonotonic") or 0)
    except ValueError:
        return None
    if since_us <= 0:
        return None
    mono = time.clock_gettime(time.CLOCK_MONOTONIC)
    return max(0.0, mono - since_us / 1_000_000.0)


def probe_idle(timeout=3, session=None, allow_logind=True):
    """Return (idle_ms, source) or (None, None) when no source answers.

    Mutter is precise and seat-wide.  It is queried with an explicit session
    bus address so a root system service can use it; logind's idle hint is a
    conservative fallback when the session bus is unavailable.
    """
    sess = session if session is not None else active_graphical_session()
    if sess is not None:
        env = session_env(sess["uid"], sess.get("display") or os.environ.get("DISPLAY"))
        rc, out, _err = _run(["gdbus", "call", "--session", "--dest", MUTTER_DEST,
                              "--object-path", MUTTER_PATH,
                              "--method", f"{MUTTER_DEST}.GetIdletime"], timeout, env=env)
        m = re.search(r"uint64\s+(\d+)", out)
        if rc == 0 and m:
            return int(m.group(1)), "mutter"
        rc, out, _err = _run(["busctl", "--user", "call", MUTTER_DEST, MUTTER_PATH,
                              MUTTER_DEST, "GetIdletime"], timeout, env=env)
        m = re.search(r"\bu\s+(\d+)", out)
        if rc == 0 and m:
            return int(m.group(1)), "mutter"
    if allow_logind:
        sid = sess.get("id") if sess else None
        secs = logind_idle_seconds(sid, timeout)
        if secs is not None:
            return int(secs * 1000), "logind"
    return None, None


def _has_battery():
    base = "/sys/class/power_supply"
    try:
        for name in os.listdir(base):
            try:
                with open(f"{base}/{name}/type") as f:
                    if f.read().strip() == "Battery":
                        return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def gnome_suspend_conflict(session=None, timeout=4):
    """Read-only check for a competing GNOME/logind automatic suspend timer."""
    sess = session if session is not None else active_graphical_session()
    result = {"checked": False, "conflict": False, "reasons": [], "error": ""}
    battery = _has_battery()
    result["battery_present"] = battery
    if sess is None:
        result["error"] = "no active graphical session"
        return result
    env = session_env(sess["uid"], sess.get("display"))
    try:
        import pwd
        home = pwd.getpwuid(int(sess["uid"])).pw_dir
        env["HOME"] = home
        env["XDG_CONFIG_HOME"] = os.path.join(home, ".config")
    except (KeyError, ImportError):
        pass

    def get(key):
        rc, out, err = _run(["gsettings", "get",
                             "org.gnome.settings-daemon.plugins.power", key],
                            timeout, env=env)
        if rc != 0:
            return None, (err or out).strip()[:120]
        return out.strip().strip("'"), ""

    values = {}
    errors = []
    for key in ("sleep-inactive-ac-type", "sleep-inactive-ac-timeout",
                "sleep-inactive-battery-type", "sleep-inactive-battery-timeout"):
        val, err = get(key)
        values[key] = val
        if err:
            errors.append(f"{key}: {err}")
    rc, out, _ = _run(["busctl", "get-property", "org.freedesktop.login1",
                       "/org/freedesktop/login1",
                       "org.freedesktop.login1.Manager", "IdleAction"], timeout)
    idle_action = None
    if rc == 0:
        m = re.search(r'"([^"]+)"', out)
        idle_action = m.group(1) if m else out.strip()
    else:
        errors.append("IdleAction unreadable")
    result.update({"checked": bool(values.get("sleep-inactive-ac-type") is not None
                                   or idle_action is not None),
                   "ac_type": values.get("sleep-inactive-ac-type"),
                   "ac_timeout": values.get("sleep-inactive-ac-timeout"),
                   "battery_type": values.get("sleep-inactive-battery-type"),
                   "battery_timeout": values.get("sleep-inactive-battery-timeout"),
                   "idle_action": idle_action})
    try:
        ac_t = int(str(values.get("sleep-inactive-ac-timeout") or "0").split()[-1])
    except (ValueError, IndexError):
        ac_t = 0
    try:
        bat_t = int(str(values.get("sleep-inactive-battery-timeout") or "0").split()[-1])
    except (ValueError, IndexError):
        bat_t = 0
    if values.get("sleep-inactive-ac-type") in ("suspend", "hibernate", "shutdown") and ac_t > 0:
        result["reasons"].append(
            f"GNOME AC auto-{values['sleep-inactive-ac-type']} after {ac_t}s")
    if (battery and values.get("sleep-inactive-battery-type") in ("suspend", "hibernate", "shutdown")
            and bat_t > 0):
        result["reasons"].append(
            f"GNOME battery auto-{values['sleep-inactive-battery-type']} after {bat_t}s")
    if idle_action and idle_action not in ("ignore", "none"):
        result["reasons"].append(f"logind IdleAction={idle_action}")
    if not battery:
        result.setdefault("notes", []).append("no battery present; battery rule inert")
    result["conflict"] = bool(result["reasons"])
    if errors:
        result["error"] = "; ".join(errors)[:300]
    return result


# --------------------------------------------------------------------------
# inhibitors
# --------------------------------------------------------------------------

class InhibitorProbe:
    LOGIN1 = "org.freedesktop.login1"
    PATH1 = "/org/freedesktop/login1"
    GNOME = "org.gnome.SessionManager"
    GPATH = "/org/gnome/SessionManager"

    def entries(self, timeout=5):
        rc, out, err = _run(["busctl", "--json=short", "call", self.LOGIN1, self.PATH1,
                             f"{self.LOGIN1}.Manager", "ListInhibitors"], timeout)
        if rc != 0 or not out.strip():
            return None, (err.strip() or "busctl failed")[:140]
        try:
            data = json.loads(out)
        except json.JSONDecodeError as e:
            return None, f"bad JSON: {e}"
        rows = data.get("data") or []
        if rows and isinstance(rows[0], list) and rows[0] and isinstance(rows[0][0], list):
            rows = rows[0]
        entries = []
        for r in rows:
            if isinstance(r, list) and len(r) >= 6:
                entries.append({"what": r[0], "who": r[1], "why": r[2],
                                "mode": r[3], "uid": r[4], "pid": r[5]})
        return entries, None

    def gnome(self, timeout=3, session=None):
        """GNOME SessionManager inhibit state (``suspend``/``idle``).

        A root system service has no inherited ``DBUS_SESSION_BUS_ADDRESS``,
        so the caller must pass the discovered ``session``; without it the
        query cannot reach the user bus and each flag reports ``None``.
        """
        env = None
        if session is not None:
            env = session_env(session["uid"], session.get("display") or None)
        res = {}
        for flag, key in ((4, "suspend"), (8, "idle")):
            rc, out, _err = _run(["gdbus", "call", "--session", "--dest", self.GNOME,
                                  "--object-path", self.GPATH,
                                  "--method", f"{self.GNOME}.IsInhibited", str(flag)],
                                 timeout, env=env)
            m = re.search(r"\((true|false)", out)
            res[key] = (m.group(1) == "true") if (rc == 0 and m) else None
        return res


def logind_can_suspend(timeout=3):
    _rc, out, _err = _run(["gdbus", "call", "--system", "--dest", "org.freedesktop.login1",
                           "--object-path", "/org/freedesktop/login1",
                           "--method", "org.freedesktop.login1.Manager.CanSuspend"], timeout)
    m = re.search(r"\('([^']+)'", out)
    return m.group(1) if m else None


def preflight_suspend_dry_run(timeout=15):
    """Safe gate: rc==0 means systemd would proceed (no block locks)."""
    return _run(["systemctl", "--dry-run", "--check-inhibitors=yes", "suspend"], timeout)


def logind_suspend_authorized(timeout=5):
    """Read-only polkit check for this monitor process's suspend request.

    ``pkcheck --process`` asks polkit whether logind would require interactive
    authentication for the calling process.  It does not suspend anything and
    never prompts.  Running it in the final safety check catches a missing
    service authorization *before* the gate is closed or Strata is unloaded.
    """
    rc, out, err = _run(["pkcheck", "--action-id", "org.freedesktop.login1.suspend",
                         "--process", str(os.getpid())], timeout)
    if rc == 0:
        return True, "polkit authorized"
    detail = (out + err).strip().replace("\n", " ")
    if not detail:
        detail = "authentication required" if rc == 2 else f"pkcheck rc={rc}"
    return False, detail[:200]


# --------------------------------------------------------------------------
# Strata LLM
# --------------------------------------------------------------------------

class StrataProbe:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.gpu = Sustained(self.cfg.get("gpu_consecutive", 2))
        self.fail = 0
        self.info = self._load_config()

    def _load_config(self):
        path = self.cfg.get("config_path")
        if not path:
            return {"error": "no config_path"}
        try:
            with open(os.path.expanduser(path)) as f:
                c = json.load(f)
        except (OSError, ValueError) as e:
            return {"error": str(e)}
        return {"key": c.get("api_key") or "", "port": int(c.get("port") or 8080),
                "host": c.get("host") or "127.0.0.1",
                "model": c.get("model_name") or ""}

    def _hosts(self):
        hosts = []
        for h in (self.info.get("host"), "127.0.0.1", "localhost"):
            if h and h not in hosts:
                hosts.append(h)
        return hosts

    def _processes(self):
        server = engine = False
        s_subs = self.cfg.get("server_cmdline_substrings", [])
        e_subs = self.cfg.get("engine_cmdline_substrings", [])
        for _pid, _comm, argv in iter_procs():
            cmd = " ".join(argv)
            if s_subs and any(s in cmd for s in s_subs):
                server = True
            if e_subs and any(s in cmd for s in e_subs):
                engine = True
        return server, engine

    def _gpu(self):
        if not shutil.which("nvidia-smi"):
            self.gpu.reset()
            return False, "nvidia-smi not found"
        rc, out, _err = _run(["nvidia-smi", "--query-gpu=index,utilization.gpu",
                              "--format=csv,noheader,nounits"], 5)
        if rc != 0:
            self.gpu.reset()
            return False, "nvidia-smi failed"
        utils = []
        for line in out.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                try:
                    utils.append(int(float(parts[1])))
                except ValueError:
                    pass
        if not utils:
            self.gpu.reset()
            return False, "no GPU reported"
        peak = max(utils)
        hit = self.gpu.add(peak >= self.cfg.get("gpu_util_threshold", 5))
        return hit, f"gpu max {peak}%"

    def get(self, path, auth=True, timeout=None, deadline=None,
            clock=time.monotonic):
        """GET from the configured host, then loopback fallbacks.

        ``deadline`` is an absolute ``clock()`` value shared by *all* host
        attempts.  Each attempt gets at most the remaining budget, and no
        later host is tried once the budget is exhausted.  Without a deadline
        the older per-host ``timeout`` behaviour is preserved.
        """
        if self.info.get("error"):
            raise OSError(f"config: {self.info['error']}")
        headers = {}
        if auth:
            if not self.info.get("key"):
                raise OSError("no api_key in the Strata config")
            headers["Authorization"] = "Bearer " + self.info["key"]
        default_timeout = self.cfg.get("http_timeout_s", 3)
        errors = []
        for host in self._hosts():
            per_host = timeout if timeout is not None else default_timeout
            if deadline is not None:
                remaining = float(deadline) - float(clock())
                if remaining <= 0:
                    errors.append(f"{host}: deadline expired before request")
                    break
                per_host = min(per_host, remaining)
            try:
                return _http_json(f"http://{host}:{self.info['port']}{path}",
                                  headers, max(0.01, per_host))
            except Exception as e:  # noqa: BLE001
                errors.append(f"{host}: {_http_error_text(e)}")
        raise OSError("unreachable on all hosts (" + "; ".join(errors) + ")")

    def health(self, timeout=None):
        return self.get("/health", auth=False, timeout=timeout)

    def probe(self):
        server, engine = self._processes()
        detail = {"server": server, "engine": engine}
        if not server:
            self.fail = 0
            self.gpu.reset()
            return DetectorResult("strata", OK, "Strata server not running", detail)
        try:
            status = self.get("/status")
        except Exception as e:  # noqa: BLE001
            self.fail += 1
            if self.fail >= self.cfg.get("status_failures_before_unknown", 2):
                return DetectorResult("strata", UNKNOWN,
                                      f"server running but /status unreadable ({e}) - failing safe", detail)
            return DetectorResult("strata", OK, f"/status not readable yet ({e})", detail)
        self.fail = 0
        busy = bool(status.get("busy"))
        queued = int(status.get("queued") or 0)
        gpu_busy, gpu_note = self._gpu()
        detail.update({"busy": busy, "queued": queued, "phase": status.get("phase"), "gpu": gpu_note})
        if busy or queued > 0:
            return DetectorResult("strata", ACTIVE,
                                  f"inference active (busy={busy}, queued={queued})", detail)
        if gpu_busy:
            return DetectorResult("strata", ACTIVE, f"GPU compute active ({gpu_note})", detail)
        return DetectorResult("strata", OK, f"model loaded but idle (busy=false, {gpu_note})", detail)


def strata_prepare_for_suspend(cfg, log=print):
    """Arm path only: POST /unload and verify the model is really unloaded."""
    cfg = cfg or {}
    if not cfg.get("enabled", True):
        return True, "strata disabled"
    probe = StrataProbe(cfg)
    server, _engine = probe._processes()
    if not server:
        return True, "Strata server not running"
    if probe.info.get("error"):
        return False, f"cannot read the Strata config: {probe.info['error']}"
    if not probe.info.get("key"):
        return False, "no api_key for Strata /unload"
    try:
        health = probe.get("/health", auth=False)
    except Exception as e:  # noqa: BLE001
        return False, f"Strata /health unreadable: {e}"
    if not health.get("loaded"):
        return True, "model already unloaded"
    wait = int(cfg.get("unload_wait_s", 300))
    body_ok = False
    last = None
    for host in probe._hosts():
        url = f"http://{host}:{probe.info['port']}/unload?wait={wait}"
        req = urllib.request.Request(url, data=b"", method="POST",
                                     headers={"Authorization": "Bearer " + probe.info["key"],
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=wait + 30) as r:
                log(f"strata /unload: {r.read(200).decode('utf-8', 'replace').strip()}")
            body_ok = True
            break
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}: {e.read(200).decode('utf-8', 'replace')[:120]}"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
    if not body_ok:
        return False, f"/unload failed: {last}"
    deadline = time.time() + float(cfg.get("unload_verify_s", 90))
    while time.time() < deadline:
        try:
            h = probe.get("/health", auth=False)
        except Exception:  # noqa: BLE001
            h = None
        if h is not None and not h.get("loaded"):
            return True, "model unloaded (VRAM released)"
        time.sleep(2)
    return False, "model did not report loaded=false after /unload"


def _strata_request_each_host(probe, path, *, auth, timeout, log, label,
                              deadline=None, clock=time.monotonic):
    """GET ``path`` from each candidate host, logging every real error.

    Returns ``(host, data, errors)``.  Unlike ``StrataProbe.get`` this keeps the
    per-host failures instead of returning only the last one, which is what the
    post-resume recovery log needs to explain a failed fallback.

    When ``deadline`` (a ``clock`` value) is supplied, each host's request is
    capped by the *remaining* budget and no host is tried once it is exhausted,
    so a slow first host cannot silently extend an overall recovery bound.
    """
    headers = {}
    if auth:
        if not probe.info.get("key"):
            return None, None, ["no api_key in the Strata config"]
        headers["Authorization"] = "Bearer " + probe.info["key"]
    errors = []
    for host in probe._hosts():
        host_timeout = max(0.05, float(timeout))
        if deadline is not None:
            left = deadline - float(clock())
            if left <= 0:
                errors.append(f"{host}: recovery deadline reached before probing")
                log(f"strata load: {label}: deadline reached before {host}{path}")
                break
            host_timeout = min(host_timeout, max(0.05, left))
        try:
            data = _http_json(f"http://{host}:{probe.info['port']}{path}", headers,
                              timeout=host_timeout)
        except Exception as e:  # noqa: BLE001
            msg = _http_error_text(e)
            errors.append(f"{host}: {msg}")
            log(f"strata load: {label}: {host}{path} failed: {msg}")
            continue
        log(f"strata load: {label}: {host}{path} ok")
        return host, data, errors
    return None, None, errors


def _post_strata_load(probe, host, timeout, log, label):
    """POST /load and classify the outcome for safe retrying.

    ``ok`` means the server accepted the request.  ``refused`` means the
    connection was definitely not delivered, so another candidate address may
    be tried.  ``ambiguous`` means the request may have reached the server (a
    timeout, reset, or lost response), so health/status must be re-read before
    any retry.  ``fatal`` is an auth refusal and is never retried.
    """
    url = f"http://{host}:{probe.info['port']}/load"
    req = urllib.request.Request(
        url, data=b"", method="POST",
        headers={"Authorization": "Bearer " + probe.info["key"],
                 "Content-Type": "application/json"})
    log(f"strata load: {label}: POST {host}/load (timeout {float(timeout):.1f}s)")
    try:
        with urllib.request.urlopen(req, timeout=max(0.05, float(timeout))) as r:
            body = r.read(200).decode("utf-8", "replace").strip()
        log(f"strata load: {label}: {host}/load accepted: {body[:120]!r}")
        return "ok", body
    except urllib.error.HTTPError as e:
        msg = _http_error_text(e)
        log(f"strata load: {label}: {host}/load failed: {msg}")
        if e.code in (401, 403):
            return "fatal", msg
        return "delivered-error", msg
    except Exception as e:  # noqa: BLE001
        msg = _http_error_text(e)
        reason = getattr(e, "reason", None)
        refused = (isinstance(reason, ConnectionRefusedError)
                   or getattr(reason, "errno", None) == 111
                   or "connection refused" in str(reason).lower())
        if refused:
            log(f"strata load: {label}: {host}/load refused: {msg}")
            return "refused", msg
        log(f"strata load: {label}: {host}/load response lost/ambiguous: {msg}")
        return "ambiguous", msg


def strata_load(cfg, log=None, deadline_s=None, request_timeout_s=None,
                retry_interval_s=None, probe_timeout_s=None,
                clock=time.monotonic, sleep=time.sleep):
    """POST /load to warm Strata after resume, with bounded, safe retries.

    A timeout, reset or lost response does not prove that ``/load`` was not
    delivered, and Strata exposes no state that proves a load is *not* running:
    ``/load`` is serialized by the engine FIFO, but the loading request drops
    out of ``status["queued"]`` the moment it holds that FIFO and never sets
    ``busy``, so ``loaded == false`` with ``queued == 0`` is also the shape of a
    load that is still starting the engine.  (``StrataProbe``'s ``/status`` is
    the server's own status dict; ``queued`` counts requests *waiting* for the
    engine, not an in-progress engine start.)

    The rule is therefore conservative and does not depend on Strata being
    idempotent:

    * ``/load`` is POSTed at most once per recovery.  It is only sent when no
      earlier POST could have been delivered;
    * after an ``ambiguous`` (timeout/reset) or ``delivered-error`` (server
      HTTP error) POST, ``/health`` is polled until the model reports loaded or
      the deadline passes - ``/load`` is **never** re-POSTed;
    * only a proven non-delivery (``ECONNREFUSED``, which the kernel rejects
      before the application sees it) may be retried, including on a fallback
      host;
    * ``queued > 0`` with ``loaded == false`` means some request is waiting for
      the engine, so this path waits rather than adding a POST.

    Individual requests are bounded by ``request_timeout_s`` (default 120 s,
    or ``strata.load_request_timeout_s``) and the whole attempt is bounded by
    ``deadline_s`` (default 180 s, or ``strata.recovery_timeout_s``).  Every
    host attempt and its actual error is passed to ``log``.
    """
    cfg = cfg or {}
    log = log or (lambda _s: None)
    probe = StrataProbe(cfg)
    if probe.info.get("error"):
        return False, f"strata config: {probe.info['error']}"
    if not probe.info.get("key"):
        return False, "strata config/api_key unavailable"

    if deadline_s is None:
        deadline_s = cfg.get("recovery_timeout_s", 180.0)
    if request_timeout_s is None:
        request_timeout_s = cfg.get("load_request_timeout_s", 120.0)
    if retry_interval_s is None:
        retry_interval_s = cfg.get("load_retry_interval_s", 2.0)
    if probe_timeout_s is None:
        probe_timeout_s = cfg.get("http_timeout_s", 3.0)
    deadline_s = max(0.0, float(deadline_s))
    request_timeout_s = max(0.1, float(request_timeout_s))
    interval_s = max(0.05, float(retry_interval_s))
    probe_timeout_s = max(0.05, float(probe_timeout_s))
    deadline = clock() + deadline_s
    attempt = 0
    last_error = ""
    started = clock()
    # Once a POST may have reached the server, this recovery never POSTs again.
    # Only a proven non-delivery (ECONNREFUSED) leaves this false and may be
    # retried; the polled /health is the single source of truth afterwards.
    maybe_delivered = False

    while True:
        attempt += 1
        remaining = deadline - clock()
        if remaining <= 0:
            break

        # Read health first.  This is the confirmation step after a POST, so a
        # lost reply never triggers a duplicate load.
        host, health, errors = _strata_request_each_host(
            probe, "/health", auth=False,
            timeout=probe_timeout_s,
            deadline=deadline, clock=clock,
            log=log, label=f"attempt {attempt} health")
        if errors and health is None:
            last_error = errors[-1]
        if health is not None:
            if not isinstance(health, dict):
                last_error = f"{host}: /health returned a non-object"
                log(f"strata load: attempt {attempt}: {last_error}")
            elif health.get("loaded"):
                detail = f"model loaded ({host})"
                log(f"strata load: {detail}")
                return True, detail

        if maybe_delivered:
            # A load this recovery may have started is the only thing that can
            # flip /health; keep polling until the deadline, never POST again.
            last_error = last_error or "a /load POST may already be in flight"
            log(f"strata load: attempt {attempt}: {last_error}; "
                "not re-POSTing /load while a load may be in flight")
        else:
            # No POST could have been delivered yet.  `queued > 0` means a
            # request is waiting for the engine, so wait for it rather than
            # adding another.  `queued == 0` does NOT prove no load is running,
            # but it does mean this is the first POST of this recovery.
            status_host, status, status_errors = _strata_request_each_host(
                probe, "/status", auth=True,
                timeout=probe_timeout_s,
                deadline=deadline, clock=clock,
                log=log, label=f"attempt {attempt} status")
            queued = 0
            can_post = False
            auth_error = next((e for e in status_errors
                               if "HTTP 401" in e or "HTTP 403" in e), None)
            if auth_error:
                # A token mismatch must never be hidden by a fallback address
                # that happens to answer.
                return False, f"Strata /status authorization failed: {auth_error}"
            if status is None:
                # No host returned usable data; only then do the errors block us.
                last_error = (status_errors[-1] if status_errors
                              else "no host returned /status")
                log(f"strata load: attempt {attempt}: cannot inspect /status; "
                    "not POSTing /load until the server state is readable")
            elif not isinstance(status, dict):
                last_error = f"{status_host}: /status returned a non-object"
                log(f"strata load: attempt {attempt}: {last_error}")
            else:
                try:
                    queued = int(status.get("queued") or 0)
                except (TypeError, ValueError):
                    queued = 0
                    last_error = f"{status_host}: invalid queued={status.get('queued')!r}"
                if queued > 0:
                    last_error = (f"{status_host}: a request already holds the "
                                  f"engine queue (queued={queued})")
                    log(f"strata load: attempt {attempt}: {last_error}; "
                        "not POSTing /load")
                else:
                    can_post = True

            if can_post:
                for target in probe._hosts():
                    left = deadline - clock()
                    if left <= 0:
                        break
                    kind, detail = _post_strata_load(
                        probe, target, min(request_timeout_s, left),
                        log, f"attempt {attempt}")
                    if kind == "ok":
                        # The server has completed /load.  Readiness is still
                        # verified separately by the caller.
                        return True, detail or f"loaded ({target})"
                    last_error = detail
                    if kind == "fatal":
                        return False, f"Strata /load refused: {detail}"
                    if kind in ("ambiguous", "delivered-error"):
                        # The request may have started a load.  Poll /health
                        # from here on; never re-POST.
                        maybe_delivered = True
                        break
                    # "refused": definitely not delivered; try the next host.

        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleep(min(interval_s, remaining))

    elapsed = max(0.0, clock() - started)
    detail = last_error or "no reachable host"
    log(f"strata load: giving up after {elapsed:.1f}s and {attempt} attempt(s): {detail}")
    return False, (f"Strata /load did not succeed within {deadline_s:.0f}s "
                   f"({attempt} attempt(s)): {detail}")


def strata_readiness(cfg, log=None, deadline_s=None, probe_timeout_s=None,
                     clock=time.monotonic):
    """Prove Strata can serve a real inference before reopening the gate.

    The check is intentionally small (one token) but exercises the same HTTP
    path as a client.  It only runs after ``strata_load`` on the armed resume
    path; local traffic remains usable while the gate is closed.

    Each host and each sub-request is bounded by the *remaining* overall
    budget, so a slow first host cannot extend the check past
    ``readiness_deadline_s``.  When the key is absent (the preserved live
    config), the bounded :data:`DEFAULT_READINESS_DEADLINE_S` applies; an
    explicit ``0`` still opts out for pure callers.
    """
    cfg = cfg or {}
    log = log or (lambda _s: None)
    probe = StrataProbe(cfg)
    if probe.info.get("error"):
        return False, f"strata config: {probe.info['error']}"
    if not probe.info.get("key"):
        return False, "no api_key for Strata readiness check"

    if deadline_s is None:
        deadline_s = cfg.get("readiness_deadline_s",
                             DEFAULT_READINESS_DEADLINE_S)
    try:
        deadline_s = float(deadline_s)
    except (TypeError, ValueError):
        deadline_s = 0.0
    if probe_timeout_s is None:
        probe_timeout_s = cfg.get("http_timeout_s", 3.0)
    probe_timeout_s = max(0.05, float(probe_timeout_s))
    deadline = (float(clock()) + max(0.0, deadline_s)) if deadline_s > 0 else None

    def remaining():
        return None if deadline is None else deadline - float(clock())

    if deadline is not None and remaining() <= 0:
        return False, "Strata readiness deadline passed before probing"

    _host, health, health_errors = _strata_request_each_host(
        probe, "/health", auth=False, timeout=probe_timeout_s,
        deadline=deadline, clock=clock, log=log, label="readiness health")
    if health is None:
        detail = health_errors[-1] if health_errors else "no reachable host"
        return False, f"Strata /health unreadable: {detail}"
    if not isinstance(health, dict) or not health.get("loaded"):
        return False, "Strata /health reports loaded=false"

    left = remaining()
    if left is not None and left <= 0:
        return False, "Strata readiness deadline passed before /status"
    _host, status, status_errors = _strata_request_each_host(
        probe, "/status", auth=True, timeout=probe_timeout_s,
        deadline=deadline, clock=clock, log=log, label="readiness status")
    if status is None:
        detail = status_errors[-1] if status_errors else "no reachable host"
        if any("HTTP 401" in e or "HTTP 403" in e for e in status_errors):
            return False, f"Strata /status authorization failed: {detail}"
        return False, f"Strata /status unreadable: {detail}"
    if not isinstance(status, dict):
        return False, "Strata /status returned a non-object"
    try:
        queued = int(status.get("queued") or 0)
    except (TypeError, ValueError):
        return False, f"Strata /status queued value invalid: {status.get('queued')!r}"
    if bool(status.get("busy")) or queued > 0:
        return False, ("Strata busy after reload "
                       f"(busy={bool(status.get('busy'))}, queued={status.get('queued')})")

    model = probe.info.get("model") or ""
    if not model:
        return False, "no model_name in the Strata config"
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "Reply with OK."}],
        "max_tokens": 1,
        "temperature": 0,
        "stream": False,
    }).encode()
    timeout = float(cfg.get("readiness_timeout_s", 180))
    last = None
    for host in probe._hosts():
        host_timeout = timeout
        left = remaining()
        if left is not None:
            if left <= 0:
                last = last or f"{host}: readiness deadline reached"
                log("strata readiness: deadline reached before the smoke test")
                break
            host_timeout = min(timeout, max(0.05, left))
        url = f"http://{host}:{probe.info['port']}/v1/chat/completions"
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Authorization": "Bearer " + probe.info["key"],
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=host_timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            choices = data.get("choices") if isinstance(data, dict) else None
            if choices:
                return True, "inference smoke test returned a completion"
            last = "response contained no choices"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}: {e.read(200).decode('utf-8', 'replace')[:120]}"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        log(f"strata readiness: smoke test {host} failed: {last}")
    return False, f"readiness inference failed: {last}"


# --------------------------------------------------------------------------
# OpenCode / AI agents
# --------------------------------------------------------------------------

_SS_PID_RE = re.compile(r"pid=(\d+)")
_SS_BYTES_RE = re.compile(r"bytes_sent:(\d+)")
_SS_BYTES_RX_RE = re.compile(r"bytes_received:(\d+)")
_SS_LASTSND_RE = re.compile(r"lastsnd:(\d+)")
_SS_LASTRCV_RE = re.compile(r"lastrcv:(\d+)")


def _ss_sockets(pids):
    """Per-socket traffic for the given pids, from `ss -tinp` (cumulative bytes
    and the age of the last send/receive)."""
    rc, out, _err = _run(["ss", "-tinp"], 5)
    if rc != 0:
        return []
    socks, cur = [], None
    for line in out.splitlines():
        m = _SS_PID_RE.search(line)
        if m:
            if int(m.group(1)) in pids:
                parts = line.split()
                cur = {"pid": int(m.group(1)), "peer": parts[4] if len(parts) >= 5 else "",
                       "bytes": None, "last_ms": None}
            else:
                cur = None
            continue
        if cur is not None and line[:1] in ("\t", " "):
            sent = _SS_BYTES_RE.search(line)
            recv = _SS_BYTES_RX_RE.search(line)
            if sent or recv:
                lasts = [int(x.group(1)) for x in
                         (_SS_LASTSND_RE.search(line), _SS_LASTRCV_RE.search(line)) if x]
                cur["bytes"] = (int(sent.group(1)) if sent else 0) + (int(recv.group(1)) if recv else 0)
                cur["last_ms"] = min(lasts) if lasts else None
                socks.append(cur)
                cur = None
    return socks


def _is_loopback(peer):
    return peer.startswith("127.") or peer.startswith("[::1]") or peer.startswith("::1")


class OpenCodeProbe:
    """Informational detector for the local OpenCode maintenance tool.

    This host is a dedicated Strata inference server; OpenCode is not part of
    the sleep-blocking policy.  The probe still collects CPU, socket, tool-child
    and session evidence for the status document, but every result is marked
    informational so harmless background activity cannot reset the inactivity
    timer.
    """

    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.cpu = Sustained(self.cfg.get("cpu_consecutive", 2))
        self.net = Sustained(self.cfg.get("net_consecutive", 2))
        self._prev_ticks = {}
        self._prev_t = None
        self._prev_net_bytes = None
        self._prev_net_t = None

    def _hits(self):
        return match_any_process(iter_procs(), self.cfg.get("processes", []))

    def _cpu_pct(self, hits):
        now = time.monotonic()
        ticks = {}
        for h in hits:
            t = proc_ticks(h["pid"])
            if t is not None:
                ticks[h["pid"]] = t
        pct = 0.0
        if self._prev_t is not None and now > self._prev_t:
            dt = now - self._prev_t
            delta = sum(max(0, ticks[p] - self._prev_ticks[p]) for p in ticks if p in self._prev_ticks)
            pct = 100.0 * delta / (HZ * dt)
        self._prev_ticks = ticks
        self._prev_t = now
        return pct

    def _descendant_tools(self, hits):
        pids = {h["pid"] for h in hits}
        if not pids:
            return []
        ppids = proc_ppids()
        children = {}
        for pid, ppid in ppids.items():
            children.setdefault(ppid, []).append(pid)
        tools = set(self.cfg.get("tool_processes", []))
        found, stack, seen = [], list(pids), set(pids)
        while stack:
            pid = stack.pop()
            for c in children.get(pid, []):
                if c in seen:
                    continue
                seen.add(c)
                stack.append(c)
                try:
                    with open(f"/proc/{c}/comm") as f:
                        comm = f.read().strip()
                except OSError:
                    continue
                if comm in tools:
                    found.append(f"{comm}({c})")
        return found

    def _net(self, hits):
        pids = {h["pid"] for h in hits}
        external = [s for s in _ss_sockets(pids)
                    if s.get("bytes") is not None and not _is_loopback(s.get("peer", ""))]
        total = sum(s["bytes"] for s in external)
        lasts = [s["last_ms"] for s in external if s.get("last_ms") is not None]
        min_last = min(lasts) if lasts else None
        now = time.monotonic()
        rate = 0.0
        if self._prev_net_bytes is not None and self._prev_net_t is not None and now > self._prev_net_t:
            rate = max(0, total - self._prev_net_bytes) / (now - self._prev_net_t)
        self._prev_net_bytes, self._prev_net_t = total, now
        busy = self.net.add(rate >= self.cfg.get("net_threshold_bytes_s", 20000))
        if min_last is not None and min_last <= self.cfg.get("socket_activity_ms", 5000):
            busy = True
        return busy, rate, min_last

    def _sessions(self, limit=25):
        path = os.path.expanduser(self.cfg.get("db_path", ""))
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)
        try:
            con.execute("PRAGMA query_only=1")
            base = "select id, title, time_updated, time_idle from session_v2"
            try:
                rows = list(con.execute(base + " where time_archived is null or time_archived = 0"
                                               " order by time_updated desc limit ?", (limit,)))
            except sqlite3.Error:
                rows = list(con.execute(base + " order by time_updated desc limit ?", (limit,)))
            sessions = [{"id": r[0], "title": r[1] or "", "time_updated": int(r[2] or 0),
                         "idle": r[3] is None} for r in rows]
            pending = 0
            window = int(self.cfg.get("pending_window_s", 600)) * 1000
            now_ms = int(time.time() * 1000)
            for table in ("session_pending", "session_inbox"):
                try:
                    c = con.execute(f"select count(*) from {table} where time_created > ?",
                                    (now_ms - window,)).fetchone()
                    pending += int(c[0] or 0)
                except sqlite3.Error:
                    pass
            return sessions, pending
        finally:
            con.close()

    def probe(self):
        if not self.cfg.get("enabled", True):
            return DetectorResult("opencode", OK, "agent detection disabled", {},
                                  informational=True)
        hits = self._hits()
        cpu = self._cpu_pct(hits)
        cpu_busy = self.cpu.add(cpu >= self.cfg.get("cpu_threshold_pct", 2.0))
        tools = self._descendant_tools(hits)
        net_busy, net_rate, net_last = self._net(hits)
        detail = {"processes": len(hits), "cpu_pct": round(cpu, 2), "tool_children": tools[:6],
                  "net_bytes_s": round(net_rate), "net_last_activity_ms": net_last}
        db_err, sessions, pending = None, [], 0
        try:
            sessions, pending = self._sessions()
        except Exception as e:  # noqa: BLE001
            db_err = f"{type(e).__name__}: {e}"
        now_ms = int(time.time() * 1000)
        window_ms = int(self.cfg.get("active_window_s", 90)) * 1000
        fresh = [s for s in sessions if s["time_updated"] and now_ms - s["time_updated"] <= window_ms]
        null_idle = [s for s in sessions if s["idle"]]
        fresh_ids = {s["id"] for s in fresh}
        detail["sessions"] = [s["title"][:40] for s in (fresh[:3] or null_idle[:3])]
        detail["pending"] = pending
        reasons = []
        if tools:
            reasons.append(f"tool running ({', '.join(tools[:3])})")
        if cpu_busy:
            reasons.append(f"OpenCode cpu {cpu:.1f}%")
        if net_busy:
            reasons.append(f"model traffic {net_rate / 1000:.0f} kB/s")
        if fresh:
            freshest = min(now_ms - s["time_updated"] for s in fresh) / 1000.0
            reasons.append(f"session updated {freshest:.0f}s ago ({fresh[0]['title'][:32]})")
        if pending:
            reasons.append(f"{pending} queued prompt(s)")
        if reasons:
            return DetectorResult("opencode", ACTIVE,
                                  "agent active: " + "; ".join(reasons[:3]), detail,
                                  informational=True)
        stale = [s for s in null_idle if s["id"] not in fresh_ids]
        if stale:
            mins = (now_ms - stale[0]["time_updated"]) / 60000.0 if stale[0]["time_updated"] else 0
            return DetectorResult("opencode", UNKNOWN,
                                  f"stale open turn: {stale[0]['title'][:32]} "
                                  f"({mins:.0f} min without updates) - failing safe", detail,
                                  informational=True)
        if db_err and hits:
            return DetectorResult("opencode", UNKNOWN,
                                  f"session db unreadable ({db_err[:60]}) with OpenCode running - failing safe",
                                  detail, informational=True)
        return DetectorResult("opencode", OK, "no active agent session", detail,
                              informational=True)


# --------------------------------------------------------------------------
# software updates / installs
# --------------------------------------------------------------------------

class UpdateProbe:
    # PackageKit is D-Bus activated and can sit resident, idle, after a brief
    # apt-daily run.  An active daemon by itself is not an update operation:
    # real work still appears as apt-get/dpkg/... or a one-shot apt/fwupd unit.
    # Keep PackageKit visible in the status detail, but do not block on it.
    IDLE_DAEMON_UNITS = frozenset({"packagekit.service"})

    def __init__(self, cfg):
        self.cfg = cfg or {}

    def probe(self):
        hits = match_any_process(iter_procs(), self.cfg.get("processes", []))
        names = sorted({h["matched"] for h in hits})
        configured = list(dict.fromkeys(
            list(self.cfg.get("units", [])) + list(self.cfg.get("idle_units", []))))
        idle_configured = set(self.cfg.get("idle_units", []))
        active_units = []
        for u in configured:
            _rc, out, _err = _run(["systemctl", "is-active", u], 3)
            if out.strip() in ("active", "activating", "reloading"):
                active_units.append(u)
        units = [u for u in active_units
                 if u not in self.IDLE_DAEMON_UNITS and u not in idle_configured]
        idle_units = [u for u in active_units
                      if u in self.IDLE_DAEMON_UNITS or u in idle_configured]
        detail = {"processes": names, "units": units, "idle_units": idle_units}
        if names or units:
            what = ", ".join(names) if names else ", ".join(units)
            return DetectorResult("updates", ACTIVE, f"package operation in progress: {what}", detail)
        return DetectorResult("updates", OK, "no package operation", detail)


# --------------------------------------------------------------------------
# file transfers
# --------------------------------------------------------------------------

class TransferProbe:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.net = Sustained(self.cfg.get("net_consecutive", 3))
        self.disk = Sustained(self.cfg.get("disk_consecutive", 3))
        self._prev = None

    def _rates(self):
        now = time.monotonic()
        net = {}
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if ":" in line:
                        name, rest = line.split(":", 1)
                        fields = rest.split()
                        net[name.strip()] = int(fields[0]) + int(fields[8])  # rx + tx bytes
        except (OSError, IndexError):
            return None
        disk = {}
        try:
            with open("/proc/diskstats") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) > 9:
                        disk[fields[2]] = (int(fields[5]), int(fields[9]))  # sectors read, written
        except (OSError, IndexError):
            return None
        rates = {"net": 0.0, "disk_write": 0.0}
        if self._prev is not None:
            pnow, pnet, pdisk = self._prev
            dt = now - pnow
            if dt > 0:
                rx = sum(net.get(i, 0) - pnet.get(i, 0) for i in self.cfg.get("net_ifaces", []))
                rates["net"] = max(0, rx) / dt
                w = sum(disk.get(d, (0, 0))[1] - pdisk.get(d, (0, 0))[1]
                        for d in self.cfg.get("disk_devices", []))
                rates["disk_write"] = max(0, w) * 512 / dt
        self._prev = (now, net, disk)
        return rates

    def probe(self):
        hits = match_any_process(iter_procs(), self.cfg.get("processes", []))
        names = sorted({h["matched"] for h in hits})
        rates = self._rates() or {"net": 0.0, "disk_write": 0.0}
        net_hit = self.net.add(rates["net"] >= self.cfg.get("net_mbps_threshold", 2.0) * 1e6)
        disk_hit = self.disk.add(rates["disk_write"] >= self.cfg.get("disk_write_mbps_threshold", 8.0) * 1e6)
        detail = {"processes": names, "net_bytes_s": round(rates["net"]),
                  "disk_bytes_s": round(rates["disk_write"])}
        if names:
            return DetectorResult("transfers", ACTIVE, f"transfer running: {', '.join(names)}", detail)
        if net_hit:
            return DetectorResult("transfers", ACTIVE,
                                  f"sustained network traffic ({rates['net'] / 1e6:.1f} MB/s)", detail)
        if disk_hit:
            return DetectorResult("transfers", ACTIVE,
                                  f"sustained disk writes ({rates['disk_write'] / 1e6:.1f} MB/s)", detail)
        return DetectorResult("transfers", OK, "no transfer", detail)


# --------------------------------------------------------------------------
# remote streaming (Sunshine)
# --------------------------------------------------------------------------

def _endpoint_port(token):
    """Return the numeric port of a normal numeric IPv4/IPv6 ss endpoint."""
    host, sep, port_text = token.rpartition(":")
    if not sep or not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return None
    else:
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return None
    return port


def _parse_ss_row(line):
    """Return (recv_q, send_q, local_port, peer_port) for one ss row."""
    fields = line.split()
    if len(fields) != 4:
        return None
    try:
        recv_q = int(fields[0])
        send_q = int(fields[1])
    except ValueError:
        return None
    if recv_q < 0 or send_q < 0:
        return None
    local_port = _endpoint_port(fields[2])
    peer_port = _endpoint_port(fields[3])
    if local_port is None or peer_port is None:
        return None
    return recv_q, send_q, local_port, peer_port


def last_client_state(path, connect_re, disconnect_re, tail_bytes=200000):
    """True if the most recent Sunshine log line is a connect."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - tail_bytes))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    for line in reversed(data.splitlines()):
        if re.search(connect_re, line):
            return True
        if re.search(disconnect_re, line):
            return False
    return None


class StreamProbe:
    CONNECT_RE = r"CLIENT CONNECTED"
    DISCONNECT_RE = r"CLIENT DISCONNECTED"

    def __init__(self, cfg):
        self.cfg = cfg or {}

    def probe(self):
        if not self.cfg.get("enabled", True):
            return DetectorResult("streams", OK, "stream detection disabled", {})
        ports = set(self.cfg.get("ports", []))
        active = set()
        try:
            rc, out, err = _run(["ss", "-Htn", "state", "established"], 4)
        except UnicodeDecodeError as exc:
            rc, out, err = 126, "", f"ss output could not be decoded: {exc}"
        ss_ok = rc == 0
        rows_valid = False
        if ss_ok:
            rows_valid = True
            for raw_line in out.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                row = _parse_ss_row(line)
                if row is None:
                    rows_valid = False
                    continue
                _, _, local_port, peer_port = row
                if local_port in ports:
                    active.add(local_port)
                if peer_port in ports:
                    active.add(peer_port)
        client = None
        path = os.path.expanduser(self.cfg.get("log_path", "") or "")
        if path and os.path.exists(path):
            client = last_client_state(path, self.CONNECT_RE, self.DISCONNECT_RE)
        detail = {"ports": sorted(active), "client_from_log": client,
                  "ss_ok": ss_ok, "ss_rows_valid": rows_valid}
        if not ss_ok:
            detail["ss_error"] = (err.strip() or f"ss exited {rc}")[:200]
        elif not rows_valid:
            detail["ss_error"] = "ss output contained malformed row(s)"
        if active:
            return DetectorResult("streams", ACTIVE, f"remote stream active on ports {sorted(active)}", detail)
        if client:
            return DetectorResult("streams", ACTIVE, "remote stream active (Sunshine log)", detail)
        # A disconnect, missing log, truncated tail, or malformed ss row cannot
        # prove that no stream exists.  Fail closed unless there was positive
        # stream evidence above.
        if not ss_ok or not rows_valid:
            if not ss_ok:
                reason = f"connection evidence unavailable (ss rc={rc}); failing safe"
            else:
                reason = "connection evidence unreliable (malformed ss output); failing safe"
            return DetectorResult("streams", UNKNOWN, reason, detail)
        return DetectorResult("streams", OK, "no remote stream", detail)


# --------------------------------------------------------------------------
# post-resume helpers
# --------------------------------------------------------------------------

def nvidia_snapshot():
    return _run(["nvidia-smi", "--query-gpu=index,name,utilization.gpu,memory.used,temperature.gpu",
                 "--format=csv,noheader"], 10)


def kernel_nvidia_errors(limit=12):
    rc, out, _err = _run(["journalctl", "-b", "-k", "--no-pager"], 12)
    if rc != 0:
        return []
    hits = [l for l in out.splitlines()
            if re.search(r"Xid|NVRM|nvidia.*(error|fail|reset|not responding)", l, re.I)]
    return hits[-limit:]


def iface_state(iface):
    for base in ("/sys/class/net", "/sys/class/net"):
        try:
            with open(f"{base}/{iface}/operstate") as f:
                return f.read().strip()
        except OSError:
            continue
    return "unknown"


if __name__ == "__main__":
    import sys
    cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")))
    idle_ms, src = probe_idle()
    print(f"idle: {idle_ms} ms ({src})")
    print("strata :", StrataProbe(cfg["strata"]).probe())
    print("opencode:", OpenCodeProbe(cfg["opencode"]).probe())
    print("updates:", UpdateProbe(cfg["updates"]).probe())
    print("transfer:", TransferProbe(cfg["transfers"]).probe())
    print("streams:", StreamProbe(cfg["streams"]).probe())
    inh = InhibitorProbe()
    print("inhibitors:", inh.entries())
    print("gnome:", inh.gnome(), "can_suspend:", logind_can_suspend())
    sys.exit(0)
