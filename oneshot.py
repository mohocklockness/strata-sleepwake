"""Small, testable policy for the supervised one-shot suspend mode.

The caller owns all I/O and locking.  This module only enforces the
order and refusal semantics: a failed preflight must never start the cycle, and
the cycle must be attempted at most once.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class OneShotOutcome:
    ok: bool
    reason: str = ""
    result: object = None
    ran: bool = False


def runtime_lock_preflight(lock_path):
    """Check that the shared monitor lock is usable by this user.

    The service's runtime directory is normally created by systemd.  If it was
    removed because the service stopped, sleepuser cannot recreate it under
    /run.  Fail with an actionable message instead of a raw PermissionError.
    """
    parent = os.path.dirname(os.path.abspath(lock_path)) or "."
    if not os.path.isdir(parent):
        return False, (f"shared lock directory {parent} is missing; deploy the updated "
                       "sleepmgr.service with RuntimeDirectoryPreserve=yes, or start "
                       "the service once so systemd recreates it")
    if os.path.exists(lock_path):
        if not os.access(lock_path, os.R_OK | os.W_OK):
            return False, f"shared monitor lock {lock_path} is not writable by uid {os.getuid()}"
    elif not os.access(parent, os.W_OK):
        return False, f"shared lock directory {parent} is not writable by uid {os.getuid()}"
    return True, f"shared lock directory {parent} is writable"


def run_supervised_cycle(preflight, cycle, log=None):
    """Run exactly one preflight + cycle pair.

    ``preflight`` returns ``(ok, detail)``.  ``cycle`` returns a flow-like
    object with ``ok`` and ``aborted`` attributes, or ``None`` when it refused
    to run.  The cycle is not called when the preflight fails.
    """
    ok, detail = preflight()
    detail = str(detail or "")
    if not ok:
        if log:
            log("one-shot preflight failed: " + (detail[:300] or "refused"))
        return OneShotOutcome(False, "preflight failed: " + (detail or "refused"))
    if log:
        log("one-shot preflight passed; starting the single cycle")
    result = cycle()
    if result is None:
        return OneShotOutcome(False, "cycle refused", ran=True)
    good = bool(getattr(result, "ok", False))
    reason = str(getattr(result, "aborted", "") or "")
    return OneShotOutcome(good, reason, result=result, ran=True)
