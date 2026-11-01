"""Unprivileged client half of the inference-arrival gate.

The privileged helper (``nftgate_helper.py``, root-owned, ``CAP_NET_ADMIN``)
owns exactly one nftables table and nothing else.  This module is the small
AF_UNIX client the sleep monitor uses to close/open that gate and to read its
state.  The monitor itself stays unprivileged and keeps
``NoNewPrivileges=yes``: it never runs ``nft`` and never touches the firewall.

Protocol (one JSON object per line, one reply per request)::

    -> {"cmd": "ping"}
    <- {"ok": true, "proto": 1, "state": "open"}
    -> {"cmd": "close", "ttl_s": 900, "token": "..."}
    <- {"ok": true, "state": "closed", "seconds_left": 900}
    -> {"cmd": "open", "token": "..."}
    <- {"ok": true, "state": "open"}
    -> {"cmd": "status"}
    <- {"ok": true, "state": "open"}

The connection is a *lease*: ``close()`` keeps one connection open for as long
as the gate must stay shut.  If the monitor dies, the helper notices the
disconnect and reopens the gate (crash recovery); ``ttl_s`` caps the lease so a
hung monitor cannot wedge the inference port closed forever.

``seal()`` is the controlled-suspend variant: it closes the gate with no lease
expiry and the helper deliberately does **not** reopen it if the monitor
disconnects.  Only an explicit ``open()`` clears the seal.  This keeps an
unloaded Strata protected when one-shot recovery fails and the monitor exits.

``open()`` is the recovery path and is deliberately tolerant; a gate that cannot
be reopened must never stop a resume (or a monitor start) from proceeding.
"""
from __future__ import annotations

import json
import os
import socket

PROTO = 1
DEFAULT_SOCKET = "/run/sleepmgr-gate/gate.sock"
MAX_LINE = 4096


class GateError(RuntimeError):
    pass


class NullGate:
    """Used when the gate is disabled; every call is a no-op success."""

    enabled = False

    def close(self):
        return {"ok": True, "state": "disabled"}

    def seal(self):
        return {"ok": True, "state": "disabled"}

    def open(self):
        return {"ok": True, "state": "disabled"}

    def status(self):
        return {"state": "disabled", "enabled": False}

    def last_status(self):
        return {"state": "disabled", "enabled": False}

    def close_connection(self):
        return None


class GateClient:
    """AF_UNIX client for the privileged nft gate helper."""

    enabled = True

    def __init__(self, path=DEFAULT_SOCKET, timeout=3.0, token=None,
                 ttl_s=900, log=None):
        self.path = path
        self.timeout = float(timeout)
        self.token = token or None
        self.ttl_s = float(ttl_s)
        self.log = log or (lambda _s: None)
        self._sock = None
        self.last_error = ""
        self._last = {"state": "unknown", "enabled": True}

    def last_status(self):
        """Last known state, without any socket I/O (safe for the status loop)."""
        return dict(self._last)

    def _remember(self, reply):
        if isinstance(reply, dict):
            # Keep the helper's live-verification fields (`rules`,
            # `consistent`, `actual_state`, `actual_error`) as well as the
            # logical lease state: the monitor refuses to arm when the helper
            # cannot prove the real nftables table matches its lease.
            self._last = {k: reply.get(k) for k in
                          ("ok", "state", "reason", "seconds_left", "sealed",
                           "error", "rules", "verified", "problem",
                           "consistent", "actual_state",
                           "actual_error")
                          if k in reply}
            self._last["enabled"] = True
        return reply

    # ------------------------------------------------------------------ plumbing
    def _connect(self):
        if self._sock is not None:
            return self._sock
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.path)
        except OSError as e:
            try:
                s.close()
            except OSError:
                pass
            raise GateError(f"cannot reach the gate helper at {self.path}: {e}") from e
        self._sock = s
        return s

    def _drop(self):
        s, self._sock = self._sock, None
        if s is not None:
            try:
                s.close()
            except OSError:
                pass

    def close_connection(self):
        """Drop the connection.

        The helper reopens an ordinary lease it owns, but intentionally keeps a
        sealed gate closed.
        """
        self._drop()

    def _request(self, obj, required=False):
        try:
            s = self._connect()
            s.sendall((json.dumps(obj) + "\n").encode("utf-8"))
            data = b""
            while b"\n" not in data and len(data) < MAX_LINE:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
        except GateError:
            raise
        except OSError as e:
            self._drop()
            raise GateError(f"gate helper I/O error: {e}") from e
        line = data.split(b"\n", 1)[0].strip()
        if not line:
            self._drop()
            raise GateError("empty reply from the gate helper")
        try:
            reply = json.loads(line.decode("utf-8"))
        except ValueError as e:
            raise GateError(f"bad reply from the gate helper: {e}") from e
        if not isinstance(reply, dict):
            raise GateError("bad reply from the gate helper (not an object)")
        if required and not reply.get("ok"):
            raise GateError(str(reply.get("error") or "gate helper refused the request"))
        return reply

    def _payload(self, cmd, **extra):
        obj = {"cmd": cmd, "proto": PROTO}
        obj.update(extra)
        if self.token:
            obj["token"] = self.token
        return obj

    # ------------------------------------------------------------------ API
    def ping(self):
        return self._remember(self._request(self._payload("ping"), required=True))

    def status(self):
        return self._remember(self._request(self._payload("status"), required=True))

    def close(self):
        """Close the gate and hold the lease.  Raises GateError on failure."""
        return self._remember(
            self._request(self._payload("close", ttl_s=self.ttl_s), required=True))

    def seal(self):
        """Close the gate with no lease expiry and no disconnect reopen.

        Used for the controlled suspend window.  Only :meth:`open` clears it.
        Raises GateError on failure.
        """
        return self._remember(
            self._request(self._payload("seal"), required=True))

    def open(self):
        """Reopen the gate (recovery/abort/resume).  Raises GateError on failure."""
        return self._remember(self._request(self._payload("open"), required=True))


def _read_token(path):
    if not path:
        return None
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
            tok = f.read().strip()
        return tok or None
    except OSError:
        return None


def build_gate(cfg, log=None):
    """Return a GateClient when ``gate.enabled`` is true, else a NullGate.

    Nothing here changes production networking by itself: the helper is a
    separate, privileged process, and ``enabled`` defaults to false in the
    shipped configuration.
    """
    cfg = cfg or {}
    if not cfg.get("enabled", False):
        return NullGate()
    token = _read_token(cfg.get("token_file"))
    return GateClient(
        path=cfg.get("socket") or DEFAULT_SOCKET,
        timeout=float(cfg.get("timeout_s", 3.0)),
        token=token,
        ttl_s=float(cfg.get("lease_ttl_s", 900)),
        log=log,
    )
