"""Local Unix-socket control channel (Pause / Resume / Suspend now / status).

The sleep transition will eventually reject TCP connections to Strata's port,
so control must not depend on that port.  AF_UNIX also keeps the channel local.
"""
from __future__ import annotations

import errno
import grp
import json
import os
import socket
import struct
import threading

MAX_LINE = 4096
# Status documents include detector, gate, and guard details and can exceed
# 4 KiB.  Replies are newline framed and bounded independently of commands.
MAX_REPLY = 1024 * 1024


class ControlError(RuntimeError):
    pass


def peer_credentials(conn):
    """Return (pid, uid, gid) of the process on the other end (Linux)."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _recv_frame(sock, limit, what):
    """Read one newline-terminated frame, with an explicit byte limit.

    A missing newline is an error instead of a silently truncated JSON
    document.  The limit applies to the complete frame, not to individual
    recv() calls.
    """
    data = bytearray()
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            if newline > limit:
                raise ControlError(f"{what} too large (limit {limit} bytes)")
            return bytes(data[:newline])
        if len(data) > limit:
            raise ControlError(f"{what} too large (limit {limit} bytes)")
    if not data:
        raise ControlError(f"empty {what}")
    raise ControlError(f"incomplete {what} (missing newline)")


def request(path, obj, timeout=3.0):
    """Send one JSON command and return the decoded reply."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        line = _recv_frame(s, MAX_REPLY, "reply from sleep monitor").strip()
    finally:
        s.close()
    if not line:
        raise ControlError("empty reply from sleep monitor")
    try:
        return json.loads(line.decode("utf-8"))
    except ValueError as e:
        raise ControlError(f"bad reply: {e}") from e


class ControlServer:
    def __init__(self, path, controller, allow_uids, status_fn=None,
                 manual_fn=None, group=None, log=None):
        self.path = path
        self.controller = controller
        self.allow_uids = {int(u) for u in (allow_uids or [])}
        self.status_fn = status_fn or (lambda: {"ok": True})
        self.manual_fn = manual_fn
        self.group = group
        self.log = log or (lambda _s: None)
        self.sock = None
        self.thread = None
        self.bound = False
        self._stop = threading.Event()

    def _allowed(self, uid):
        return int(uid) in self.allow_uids

    def start(self):
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
                raise ControlError(f"another control server is listening on {self.path}")
            finally:
                probe.close()
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
                    self.log(f"control group {self.group!r} does not exist; socket stays root-only")
                    gid = 0
            try:
                os.chown(self.path, 0, gid if gid is not None else 0)
            except OSError as e:
                self.log(f"cannot chown control socket: {e}")
        elif self.group:
            try:
                gid = grp.getgrnam(self.group).gr_gid
                os.chown(self.path, os.getuid(), gid)
            except (KeyError, OSError):
                pass
        s.listen(8)
        s.settimeout(1.0)
        self.sock = s
        self.thread = threading.Thread(target=self._accept_loop, name="sleepmgr-control",
                                       daemon=True)
        self.thread.start()
        self.log(f"control socket ready: {self.path} (allowed uids: "
                 f"{', '.join(str(u) for u in sorted(self.allow_uids)) or 'none'})")
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
                             name="sleepmgr-control-client").start()

    @staticmethod
    def _send(conn, obj):
        try:
            conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        except OSError:
            pass

    def _handle(self, conn):
        with conn:
            conn.settimeout(5.0)
            try:
                pid, uid, _gid = peer_credentials(conn)
            except OSError as e:
                self._send(conn, {"ok": False, "error": f"peer credentials: {e}"})
                return
            try:
                line = _recv_frame(conn, MAX_LINE, "command").strip()
            except ControlError as e:
                self._send(conn, {"ok": False, "error": str(e)})
                return
            except OSError:
                return
            if not line:
                self._send(conn, {"ok": False, "error": "empty command"})
                return
            if not self._allowed(uid):
                self.log(f"control command refused from uid {uid} (pid {pid})")
                self._send(conn, {"ok": False, "error": f"uid {uid} is not allowed"})
                return
            try:
                cmd = json.loads(line.decode("utf-8"))
            except ValueError as e:
                self._send(conn, {"ok": False, "error": f"bad JSON: {e}"})
                return
            if not isinstance(cmd, dict) or not cmd.get("cmd"):
                self._send(conn, {"ok": False, "error": "missing cmd"})
                return
            name = cmd["cmd"]
            who = f"uid:{uid}"
            try:
                if name == "status":
                    reply = self.status_fn()
                    if isinstance(reply, dict):
                        reply.setdefault("ok", True)
                    self._send(conn, reply)
                elif name == "ping":
                    self._send(conn, {"ok": True, "pid": os.getpid()})
                elif name == "pause":
                    duration = cmd.get("duration_s")
                    if duration is not None:
                        duration = float(duration)
                    self._send(conn, self.controller.pause(duration, by=who))
                elif name == "resume":
                    self._send(conn, self.controller.resume(by=who))
                elif name == "suspend-now":
                    if self.manual_fn is None:
                        self._send(conn, {"ok": False, "error": "manual suspend unavailable"})
                    else:
                        self._send(conn, self.manual_fn(uid))
                else:
                    self._send(conn, {"ok": False, "error": f"unknown command {name!r}"})
            except Exception as e:  # noqa: BLE001 - never kill the server
                self.log(f"control command {name!r} failed: {type(e).__name__}: {e}")
                self._send(conn, {"ok": False, "error": f"{type(e).__name__}: {e}"})
