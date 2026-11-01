"""The pause-aware sequence between "safe to suspend" and the suspend syscall.

The verified order is:

  1. confirm inference is idle (``pre_gate_verify``),
  2. seal the inference gate closed (no lease expiry and no reopen on monitor
     disconnect),
  3. confirm inference is still idle after the gate closes
     (``post_gate_verify``),
  4. unload Strata,
  5. verify GPU memory, CUDA clients, RAM and gate state
     (``post_unload_verify``; the guard release also re-checks this),
  6. release the sleep guard,
  7. suspend with ``systemctl suspend --check-inhibitors=yes``.

On resume the monitor retries guard reacquisition for a bounded time, verifies
NVIDIA, reloads Strata, verifies inference readiness, and only then reopens the
gate.  Every abort after the gate has closed keeps it sealed until the guard is
protected *and* the model is verified ready; if that cannot be done, the gate
stays closed and the failure is reported.  Sealing is deliberately stronger
than the ordinary close lease: the helper will not reopen on monitor disconnect
or lease expiry, so a one-shot process cannot expose an unloaded Strata by
exiting after a recovery failure.

This module is deliberately free of policy about *when* to suspend; the caller
passes a ``strata`` adapter, a ``suspend`` callable, and optional gate/guard
clients plus verification callbacks.
"""
from __future__ import annotations

import dataclasses
import time


@dataclasses.dataclass
class FlowResult:
    ok: bool = False
    dry_run: bool = True
    suspended: bool = False
    was_loaded: bool = False
    unloaded: bool = False
    reloaded: bool = False
    aborted: str = ""
    guard_released: bool = False
    guard_reacquired: bool = False
    gate_closed: bool = False
    gate_reopened: bool = False
    gate_lease_lost: bool = False
    post_unload_verified: bool = False
    nvidia_verified: bool = False
    ready: bool = False
    phases: list = dataclasses.field(default_factory=list)

    def as_dict(self):
        d = dataclasses.asdict(self)
        d["phases"] = self.phases[-30:]
        return d


class StrataPort:
    """Thin adapter around the existing, already-tested Strata helpers."""

    def __init__(self, cfg, log=None, clock=time.monotonic):
        import detectors  # local import keeps the pure tests light
        self.cfg = cfg or {}
        self.probe = detectors.StrataProbe(self.cfg)
        self._detectors = detectors
        self.log = log or (lambda _s: None)
        self.clock = clock

    def loaded(self, timeout=None):
        if not self.cfg.get("enabled", True):
            return False
        server, _engine = self.probe._processes()
        if not server:
            return False
        deadline = None
        per_host = None
        if timeout is not None:
            budget = max(0.0, float(timeout))
            deadline = self.clock() + budget
            per_host = budget
        health = self.probe.get(
            "/health", auth=False, timeout=per_host,
            deadline=deadline, clock=self.clock)
        return bool(health.get("loaded"))

    def unload(self, log):
        return self._detectors.strata_prepare_for_suspend(self.cfg, log=log)

    def reload(self):
        return self._detectors.strata_load(self.cfg, log=self.log)

    def ready(self, timeout=None):
        if timeout is None:
            return self._detectors.strata_readiness(self.cfg)
        return self._detectors.strata_readiness(
            self.cfg, deadline_s=max(0.05, float(timeout)))


def wait_for_resume(before_gap, gap_fn, timeout_s=120.0, interval_s=0.25,
                    min_gap_s=1.0, clock=time.monotonic, sleep=time.sleep):
    """Wait until a real suspend/resume cycle is visible to this process.

    ``systemctl suspend`` is asynchronous: it returns after logind enqueues the
    operation, not after the kernel resumes.  ``gap_fn`` returns the difference
    between a clock that advances during suspend (CLOCK_BOOTTIME) and one that
    does not (CLOCK_MONOTONIC).  That difference grows by the sleep duration;
    it is unchanged while the process is merely awake and waiting.

    Returns ``(ok, detail)``.  ``detail`` is the observed sleeping gap in
    seconds on success, or a timeout explanation on failure.
    """
    if before_gap is None:
        return False, "sleep-time clock is unavailable"
    deadline = float(clock()) + max(0.0, float(timeout_s))
    interval = max(0.01, float(interval_s))
    while True:
        sleep(interval)
        now_gap = gap_fn()
        if now_gap is not None:
            slept = float(now_gap) - float(before_gap)
            if slept >= float(min_gap_s):
                return True, slept
        if float(clock()) >= deadline:
            return False, f"no suspend/resume gap observed within {float(timeout_s):.0f}s"


def _gate_rules_count(status):
    """Return the live rule count when the helper reports one, else None.

    Older helpers (and pure test doubles) only report ``state``.  A missing
    count must not be treated as "zero rules"; it means the helper cannot
    prove consistency itself, so the logical state is the best available
    evidence.  Callers that must not arm on unproven protection use
    :func:`_require_verified_gate` and :func:`_gate_evidence_problem` instead
    of accepting that.
    """
    if not isinstance(status, dict) or "rules" not in status:
        return None
    value = status.get("rules")
    if isinstance(value, bool):
        # ``True`` is not a rule count.
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _gate_verification_capable(status):
    """True when the helper *reports* the fields needed for verification.

    This is only a capability probe used to distinguish an older helper from a
    new one; the values themselves are checked by
    :func:`_gate_evidence_problem`.
    """
    return isinstance(status, dict) and "consistent" in status


def _gate_evidence_problem(status):
    """Return a reason string unless the status *proves* live protection.

    A helper must report ``consistent=true`` (its logical lease state matches
    the live nftables table) and, for a closed gate, at least one blocking rule.
    Merely naming the fields is not proof: ``consistent`` must be the boolean
    ``True`` and ``rules`` must be a positive integer.  ``actual_state``, when
    present, must agree with the logical state.  Returns ``""`` when the
    evidence is sufficient.
    """
    if not isinstance(status, dict):
        return "gate status is not an object"
    if status.get("consistent") is not True:
        return ("gate helper reports an inconsistent or unknown logical/actual "
                "state (consistent is not true)")
    if status.get("verified") is False:
        detail = status.get("problem")
        return ("gate helper could not verify the live blocking rule"
                + (f" ({detail})" if detail else ""))
    state = status.get("state")
    actual = status.get("actual_state")
    if state == "open":
        if status.get("sealed"):
            return "gate is open but still marked sealed"
        if actual not in (None, "open"):
            return f"gate is open but the live table reports {actual!r}"
        return ""
    if state == "closed":
        rules = _gate_rules_count(status)
        if rules is None or rules < 1:
            return "gate is closed but no blocking rule is verified (rules < 1)"
        if actual not in (None, "closed"):
            return f"gate is closed but the live table reports {actual!r}"
        return ""
    return f"gate state {state!r} is not verifiable"


# The monitor's sustained re-check uses exactly this proof, so a gate that is
# only *claimed* closed cannot pass the safety argument either.
gate_protection_problem = _gate_evidence_problem


def _require_verified_gate(status):
    """Raise unless the helper can prove its logical state against nftables.

    This is the armed-operation capability gate: a monitor must not seal a gate
    when the helper is too old to inspect the live table, because "the helper
    says closed" would then be unproven.  The live rule *values* themselves are
    checked (and repaired once) by :func:`reconcile_gate_status` and by the
    preflight via :func:`_gate_evidence_problem`.
    """
    if not _gate_verification_capable(status):
        raise RuntimeError(
            "gate helper does not report actual nftables rule state "
            "(older helper?); refusing to arm without live rule verification")


def verify_gate_protection(gate, log=None):
    """Reconcile and prove the gate is actually blocking.

    Returns ``(ok, message)``.  Used before reopening a gate after resume so a
    gate is only opened once its protection is verified, not merely because a
    previous ``seal`` reply claimed success.
    """
    log = log or (lambda _s: None)
    try:
        st = reconcile_gate_status(gate, log=log, require_verification=True)
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    if not _gate_verification_capable(st):
        return False, ("gate helper cannot prove the actual nftables rule state "
                       "(older helper?)")
    problem = _gate_evidence_problem(st)
    if problem:
        return False, problem
    return True, f"gate protection verified ({st.get('state')})"


def reconcile_gate_status(gate, log=None, require_verification=False):
    """Read the gate and repair a provably inconsistent closed/sealed state.

    The helper's status is derived from both its logical lease state and the
    actual nftables table.  A closed/sealed gate with zero rules, or an
    ``open`` gate still marked sealed, is not protection.  Re-issue ``seal``
    (the helper re-applies a missing table) and re-read.  Unknown states are
    returned unchanged for the caller to reject.

    With ``require_verification`` a status that cannot prove the live table
    (an older helper with no ``rules``/``consistent``) is refused outright.
    """
    log = log or (lambda _s: None)
    st = gate.status()
    if not isinstance(st, dict):
        raise RuntimeError("gate status is not an object")
    state = st.get("state")
    if state not in ("open", "closed"):
        return st
    if require_verification:
        _require_verified_gate(st)
    rules = _gate_rules_count(st)
    inconsistent = st.get("consistent") is False
    needs_repair = inconsistent
    if state == "closed" and rules is not None and rules < 1:
        needs_repair = True
    if state == "open" and st.get("sealed"):
        needs_repair = True
    if not needs_repair:
        return st

    log(f"gate reconciliation: state={state!r}, rules={rules!r}, "
        f"sealed={bool(st.get('sealed'))}, consistent={st.get('consistent')!r}; "
        "re-sealing before use")
    reply = gate.seal()
    if isinstance(reply, dict):
        if reply.get("ok") is False:
            raise RuntimeError(str(reply.get("error") or "gate refused seal"))
        if reply.get("state") not in (None, "closed"):
            raise RuntimeError(f"gate reported state {reply.get('state')!r} "
                               "after re-seal, not 'closed'")
    st = gate.status()
    if not isinstance(st, dict):
        raise RuntimeError("gate status is not an object after re-seal")
    rules = _gate_rules_count(st)
    if st.get("state") != "closed":
        raise RuntimeError("gate is not closed after reconciliation")
    if rules is not None and rules < 1:
        raise RuntimeError("gate reports closed but has no blocking rule")
    if st.get("consistent") is not True:
        raise RuntimeError(
            "gate helper does not confirm a consistent closed state after "
            f"reconciliation (consistent={st.get('consistent')!r})")
    log("gate reconciliation: closed gate re-sealed and verified")
    return st


def preflight_protection(gate, guard=None, log=None):
    """Prove the gate and guard are usable before any unload can begin.

    A socket path or a running process is not readiness.  This performs a live
    gate status query (which the helper derives from nftables), repairs a
    closed/sealed table that is missing its rule, and asks the guard for its
    current protected state.  It changes no gate state on a healthy host.
    """
    log = log or (lambda _s: None)
    if gate is not None and getattr(gate, "enabled", True):
        try:
            st = reconcile_gate_status(gate, log=log, require_verification=True)
        except Exception as e:  # noqa: BLE001
            return False, f"gate status/reconciliation failed: {type(e).__name__}: {e}"
        state = st.get("state") if isinstance(st, dict) else None
        if state not in ("open", "closed"):
            return False, f"gate state {state!r} is not verifiable"
        if not _gate_verification_capable(st):
            return False, ("gate helper cannot prove the actual nftables rule "
                           "state (older helper?); refusing to arm")
        problem = _gate_evidence_problem(st)
        if problem:
            return False, f"gate protection not proven: {problem}"
        rules = _gate_rules_count(st)
        log(f"preflight: gate verified ({state}"
            + (f", rules={rules}" if rules is not None else "") + ")")
    if guard is not None and getattr(guard, "enabled", False):
        try:
            guard_st = guard.status()
        except Exception as e:  # noqa: BLE001
            return False, f"suspend guard status unreadable: {type(e).__name__}: {e}"
        if not isinstance(guard_st, dict):
            return False, "suspend guard status is not an object"
        if not guard_st.get("protected"):
            return False, ("suspend guard is not protected "
                           f"(state={guard_st.get('state')!r})")
        log(f"preflight: sleep guard verified "
            f"({guard_st.get('state') or 'protected'})")
    return True, "gate/guard preflight passed"


def startup_gate_recovery(gate, strata, guard=None, log=None,
                          deadline=None, clock=time.monotonic):
    """Safely normalise the gate at monitor startup.

    An ordinary open gate is left alone.  A closed/sealed gate is opened only
    when the guard is protected and Strata is both loaded and inference-ready.
    This prevents a service start (often after a failed one-shot) from undoing
    the seal and exposing an unloaded model or an unprotected host.  Returns
    the gate status or open reply; exceptions are left to the caller, which
    logs them.

    ``deadline`` (from :func:`startup_gate_recovery_retry`) is threaded into
    every nested probe as its remaining budget, so a slow guard or readiness
    call cannot stretch the retry window.
    """
    log = log or (lambda _s: None)

    def remaining():
        if deadline is None:
            return None
        return max(0.0, float(deadline) - float(clock()))

    st = reconcile_gate_status(gate, log=log)
    if not isinstance(st, dict):
        raise RuntimeError("gate status is not an object")
    if st.get("state") == "open":
        return st
    if st.get("state") != "closed":
        log(f"gate startup: gate state {st.get('state')!r} is not provably "
            "closed/open; leaving it unchanged")
        return st
    if not _gate_verification_capable(st):
        # The helper cannot show us the live table.  Do not open on its word
        # alone; an operator (or the updated helper) must resolve this.
        log("gate startup: the helper does not report actual nftables rule "
            "state (older helper?); leaving the gate closed")
        return st
    problem = _gate_evidence_problem(st)
    if problem:
        # The helper names the fields but they do not prove blocking.
        log(f"gate startup: leaving the gate closed; protection not proven: "
            f"{problem}")
        return st
    if guard is not None and getattr(guard, "enabled", False):
        try:
            guard_st = guard.status(timeout=remaining())
        except Exception as e:  # noqa: BLE001
            log(f"gate startup: guard status failed: {type(e).__name__}: {e}")
            guard_st = {}
        if not isinstance(guard_st, dict) or not guard_st.get("protected"):
            log("gate startup: gate remains closed; the sleep guard is not "
                "confirmed protected")
            return st
    loaded = bool(strata.loaded(timeout=remaining()))
    ready = False
    if loaded:
        try:
            ready, _msg = strata.ready(timeout=remaining())
        except Exception as e:  # noqa: BLE001
            log(f"gate startup: readiness probe failed: {type(e).__name__}: {e}")
            ready = False
    if not (loaded and ready):
        log("gate startup: gate remains closed; Strata is not loaded and "
            "inference-ready")
        return st
    log("gate startup: Strata is loaded and inference-ready; opening gate")
    return gate.open()


def startup_gate_recovery_retry(gate, strata, guard=None, log=None,
                                timeout_s=0.0, interval_s=1.0,
                                clock=time.monotonic, sleep=time.sleep):
    """Bounded startup recovery that keeps the seal and inhibitor until ready.

    Runs :func:`startup_gate_recovery` repeatedly until the gate is open or the
    deadline passes.  It never clears the seal and never releases the guard:
    the gate is opened only once the guard is protected and Strata is loaded and
    inference-ready.  A timeout returns ``(False, status, reason)`` with the
    gate still sealed, so the caller can report a clear recovery-failed state.

    ``timeout_s=0`` makes exactly one attempt, preserving the single-attempt
    behaviour used by pure tests.
    """
    log = log or (lambda _s: None)
    deadline = float(clock()) + max(0.0, float(timeout_s))
    interval = max(0.05, float(interval_s))
    attempt = 0
    last_status = None
    last_reason = "no attempt made"
    while True:
        remaining = deadline - float(clock())
        if attempt > 0 and remaining <= 0:
            break
        attempt += 1
        try:
            st = startup_gate_recovery(gate, strata, guard=guard, log=log,
                                       deadline=deadline, clock=clock)
        except Exception as e:  # noqa: BLE001
            st = None
            last_reason = f"{type(e).__name__}: {e}"
        else:
            last_status = st
            if isinstance(st, dict) and st.get("state") == "open":
                return True, st, "inference gate open"
            if isinstance(st, dict):
                last_reason = str(st.get("reason") or st.get("state"))
            else:
                last_reason = str(st)
        remaining = deadline - float(clock())
        if remaining <= 0:
            break
        log(f"gate startup: recovery attempt {attempt} did not open the gate "
            f"({last_reason}); retrying in {min(interval, remaining):.0f}s")
        sleep(min(interval, remaining))
    reason = (f"gate recovery failed after {float(timeout_s):.0f}s and "
              f"{attempt} attempt(s): {last_reason}")
    log("gate startup: " + reason + "; the gate remains sealed")
    return False, last_status, reason


def run_quiesce(pause, strata, suspend, dry_run=True, log=None,
                journal=None, gate=None, respect_pause=True,
                pause_override=False, settle_s=0.0, pre_gate_verify=None,
                post_gate_verify=None, post_unload_verify=None,
                post_resume_verify=None, readiness_verify=None,
                guard=None, guard_acquire_timeout_s=0.0,
                guard_retry_interval_s=1.0, clock=time.monotonic,
                sleep=time.sleep):
    """Run the verified gate-first unload/verify/suspend/recovery sequence.

    Verification callbacks return ``(ok, message)``.  ``pre_gate_verify`` and
    ``post_gate_verify`` prove that inference is idle before and after the gate
    closes.  ``post_unload_verify`` proves GPU/RAM release.  On resume,
    ``post_resume_verify`` checks NVIDIA before ``strata.reload()``, and
    ``readiness_verify`` proves the model can answer before the gate reopens.
    If ``readiness_verify`` is omitted, the adapter's ``ready()`` method is
    used.

    ``pause_override`` is for the explicit manual "Suspend now" action: it
    intentionally ignores the pause *policy* (but never the critical-workload
    refusals, which are checked before this function is called).

    ``guard`` is an optional fail-closed sleep-guard client.  It is asked for a
    short release only after gate close, unload and verification, and is always
    asked to reacquire afterwards (including every abort and an uncertain
    release response).  ``guard_acquire_timeout_s`` controls how long resume
    recovery retries a transient logind/inhibitor failure; ``guard=`` plus a
    zero timeout preserves the single-attempt behaviour used by pure tests.
    Dry-run never closes the gate, unloads, releases the guard, or suspends.

    The gate is sealed, not merely leased.  If the helper itself is unavailable,
    remote inference cannot be guaranteed blocked; that condition is reported
    as ``gate_lease_lost`` and the gate is never opened by this flow.
    """
    log = log or (lambda _s: None)
    result = FlowResult(dry_run=dry_run)
    start = time.monotonic()
    guard_may_be_released = {"value": False}
    gate_active = bool(gate is not None and getattr(gate, "enabled", True))

    def phase(name, **kw):
        rec = {"ts": time.time(), "mono": time.monotonic(), "phase": name}
        rec.update(kw)
        result.phases.append(rec)
        if journal:
            journal(rec)
        log("quiesce: " + name + (":" if kw else "") +
            ((" " + ", ".join(f"{k}={v}" for k, v in kw.items())) if kw else ""))

    def paused(where):
        if not respect_pause and not pause_override:
            return False
        # manual_override means "ignore the pause policy for this one action"
        if pause_override:
            return False
        if pause.is_paused():
            phase("pause-detected", at=where)
            return True
        return False

    def run_verify(name, fn, **kw):
        """Run a (ok, message) callback and journal the outcome.

        A missing callback is skipped for compatibility with callers that use
        only the guard's own fresh safety sample.  The monitor always supplies
        all of these callbacks.
        """
        if fn is None:
            phase(name + "-skipped")
            return True, "verifier not configured"
        try:
            ok, msg = fn()
        except Exception as e:  # noqa: BLE001
            phase(name + "-failed", error=f"{type(e).__name__}: {e}")
            return False, f"{type(e).__name__}: {e}"
        phase(name, ok=bool(ok), message=str(msg)[:200], **kw)
        return bool(ok), str(msg)

    def shut_gate():
        """Seal the gate when the client supports it; otherwise use close()."""
        seal = getattr(gate, "seal", None)
        if seal is not None:
            return seal()
        return gate.close()

    def check_gate_closed(reply, action):
        if isinstance(reply, dict):
            if reply.get("ok") is False:
                raise RuntimeError(str(reply.get("error") or f"gate refused {action}"))
            state = reply.get("state")
            if state is not None and state != "closed":
                raise RuntimeError(f"gate reported state {state!r}, not 'closed'")
            # A "closed" claim is not protection: require the helper's proof
            # that the live nftables rule really blocks the configured ports.
            problem = _gate_evidence_problem(reply)
            if problem:
                raise RuntimeError(f"gate {action}: protection not verified: "
                                   f"{problem}")

    def close_gate():
        if not gate_active:
            return True
        try:
            check_gate_closed(shut_gate(), "seal")
            result.gate_closed = True
            phase("gate-close", mode="sealed")
            return True
        except Exception as e:  # noqa: BLE001
            phase("gate-close-failed", error=f"{type(e).__name__}: {e}")
            return False

    def ensure_gate_closed(why):
        """Re-seal the gate.  Returns False if blocking is unproven."""
        if not gate_active:
            return True
        if not result.gate_closed:
            return False
        try:
            check_gate_closed(shut_gate(), "re-seal")
            result.gate_closed = True
            phase("gate-renew", why=why, mode="sealed")
            return True
        except Exception as e:  # noqa: BLE001
            result.gate_lease_lost = True
            phase("gate-renew-failed", why=why,
                  error=f"{type(e).__name__}: {e}")
            return False

    def reopen_gate():
        if not gate_active:
            return True
        try:
            reply = gate.open()
            if isinstance(reply, dict):
                if reply.get("ok") is False:
                    raise RuntimeError(str(reply.get("error") or "gate refused open"))
                state = reply.get("state")
                if state is not None and state != "open":
                    raise RuntimeError(f"gate reported state {state!r}, not 'open'")
            result.gate_closed = False
            result.gate_reopened = True
            phase("gate-open")
            return True
        except Exception as e:  # noqa: BLE001
            phase("gate-open-failed", error=f"{type(e).__name__}: {e}")
            return False

    def reacquire_guard(why, timeout_s=None):
        """Try to reacquire the guard, retrying transient logind failures.

        A failed attempt leaves ``guard_may_be_released`` true so every later
        cleanup path tries again.  Only a confirmed ``acquire`` clears it.
        """
        if guard is None or not guard_may_be_released["value"]:
            return True
        timeout = float(guard_acquire_timeout_s if timeout_s is None else timeout_s)
        deadline = float(clock()) + max(0.0, timeout)
        interval = max(0.05, float(guard_retry_interval_s))
        attempts = 0
        last_error = ""
        while True:
            remaining = deadline - float(clock())
            if attempts > 0 and remaining <= 0:
                break
            attempts += 1
            try:
                reply = guard.acquire(reason=why,
                                      timeout=max(0.1, remaining))
                ok = bool(reply.get("ok", True)) if isinstance(reply, dict) else bool(reply)
                if ok:
                    result.guard_reacquired = True
                    guard_may_be_released["value"] = False
                    phase("guard-acquire", ok=True, why=why, attempts=attempts)
                    return True
                last_error = str(reply.get("error") or "guard refused acquire") \
                    if isinstance(reply, dict) else "guard refused acquire"
            except Exception as e:  # noqa: BLE001
                last_error = f"{type(e).__name__}: {e}"
            phase("guard-acquire-retry", why=why, attempts=attempts,
                  error=last_error[:200])
            remaining = deadline - float(clock())
            if remaining <= 0:
                break
            sleep(min(interval, remaining))
        result.guard_reacquired = False
        phase("guard-acquire-failed", why=why, attempts=attempts,
              error=last_error[:200])
        log("quiesce: could not reacquire the sleep guard after "
            f"{attempts} attempt(s); it may remain released")
        return False

    def reload_if_needed(why):
        if not (result.unloaded and result.was_loaded):
            return True
        try:
            ok, msg = strata.reload()
        except Exception as e:  # noqa: BLE001
            phase("reload-failed", why=why, error=f"{type(e).__name__}: {e}")
            return False
        result.reloaded = bool(ok)
        phase("reload", ok=bool(ok), why=why, message=str(msg)[:200])
        return bool(ok)

    def verify_readiness(why):
        if not result.was_loaded:
            # The model was already unloaded before this flow started; there is
            # no reload/readiness transition to protect.
            result.ready = True
            return True
        fn = readiness_verify
        if fn is None:
            fn = getattr(strata, "ready", None)
        ok, msg = run_verify("readiness-verify", fn, why=why)
        result.ready = bool(ok)
        if not ok:
            log("quiesce: Strata is not ready; keeping the inference gate closed")
        return bool(ok)

    def recover_model(why, reload_model=True):
        if reload_model and not reload_if_needed(why):
            return False
        return verify_readiness(why)

    def abort(reason, reload_model=True):
        result.ok = False
        result.aborted = reason
        guard_ok = reacquire_guard("abort")
        gate_ok = True
        if gate_active and result.gate_closed:
            gate_ok = ensure_gate_closed("abort")
        recovery_ok = False
        if reload_model:
            recovery_ok = recover_model("abort")
        else:
            phase("recovery-skipped", reason="unsafe to reload after this failure")
        if (gate_active and result.gate_closed and guard_ok and gate_ok
                and recovery_ok and not result.gate_lease_lost):
            reopen_gate()
        elif gate_active:
            phase("gate-kept-closed", reason=reason,
                  guard_ok=guard_ok, gate_ok=gate_ok, ready=recovery_ok)
        phase("abort", reason=reason, elapsed_s=round(time.monotonic() - start, 3))
        return result

    phase("start", dry_run=dry_run, pause=bool(pause.is_paused()))
    if paused("before-pre-gate-verify"):
        return abort("pause requested before closing the gate")

    # Read health before changing anything.  An unreadable state is not safe.
    try:
        result.was_loaded = bool(strata.loaded())
        phase("health", loaded=result.was_loaded)
    except Exception as e:  # noqa: BLE001
        return abort(f"cannot read Strata health: {type(e).__name__}: {e}")

    if dry_run:
        phase("would-close-gate")
        phase("would-unload", loaded=result.was_loaded)
        phase("would-suspend", elapsed_s=round(time.monotonic() - start, 3))
        result.ok = True
        return result

    # A configured gate or guard must be provably usable before unload.  A
    # socket file or a running process alone is not readiness; ask both
    # services for their live state and fail closed if either is unverifiable.
    if gate_active or (guard is not None and getattr(guard, "enabled", False)):
        preflight_ok, preflight_msg = preflight_protection(
            gate, guard=guard, log=log)
        phase("protection-preflight", ok=bool(preflight_ok),
              message=str(preflight_msg)[:200])
        if not preflight_ok:
            return abort("protective preflight failed: " + preflight_msg,
                         reload_model=False)

    if gate_active:
        ok, msg = run_verify("pre-gate-verify", pre_gate_verify)
        if not ok:
            return abort(f"pre-gate verification failed: {msg}")
        if paused("before-gate-close"):
            return abort("pause requested before closing the network gate")
        if not close_gate():
            return abort("cannot close the network gate")
        if paused("after-gate-close"):
            return abort("pause requested after the network gate closed")
        if settle_s and settle_s > 0:
            deadline = time.monotonic() + float(settle_s)
            while time.monotonic() < deadline:
                if paused("during-gate-settle"):
                    return abort("pause requested while the network gate settled")
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
            phase("gate-settle", seconds=round(float(settle_s), 3))
        ok, msg = run_verify("gate-verify", post_gate_verify)
        if not ok:
            return abort(f"post-gate verification failed: {msg}")
        if paused("after-gate-verify"):
            return abort("pause requested after post-gate verification")

    if paused("before-unload"):
        return abort("pause requested before Strata unloading")

    try:
        ok, msg = strata.unload(log)
    except Exception as e:  # noqa: BLE001
        return abort(f"Strata unload raised {type(e).__name__}: {e}")
    phase("unload", ok=bool(ok), message=str(msg)[:200])
    if not ok:
        return abort(f"Strata unload failed: {msg}")
    result.unloaded = True
    if paused("after-unload"):
        return abort("pause requested during Strata unloading")

    ok, msg = run_verify("post-unload-verify", post_unload_verify)
    result.post_unload_verified = bool(ok)
    if not ok:
        return abort(f"post-unload verification failed: {msg}")

    # Re-lease immediately before the release/suspend window.  This renews the
    # 900 s lease and detects a helper that disappeared during the checks.
    if gate_active and not ensure_gate_closed("before-suspend"):
        return abort("cannot renew the gate lease before suspension")

    if paused("before-suspend"):
        return abort("pause requested immediately before suspension")

    if guard is not None and getattr(guard, "enabled", True):
        # Mark this before the request: a timeout can mean the guard released
        # but the reply was lost, so every failure path must try to reacquire.
        guard_may_be_released["value"] = True
        try:
            reply = guard.release(reason="controlled suspend after gate close/unload/verify")
        except Exception as e:  # noqa: BLE001
            return abort(f"sleep guard release raised {type(e).__name__}: {e}")
        result.guard_released = bool(reply.get("ok"))
        phase("guard-release", ok=result.guard_released,
              state=str(reply.get("state") or ""))
        if not result.guard_released:
            return abort("sleep guard refused release: "
                         + str(reply.get("error") or "safety checks failed"))
        if paused("after-guard-release"):
            return abort("pause requested after the sleep guard released")

    phase("suspend", command="systemctl suspend --check-inhibitors=yes")
    try:
        rc = suspend()
    except Exception as e:  # noqa: BLE001
        return abort(f"suspend raised {type(e).__name__}: {e}")
    phase("resumed", rc=rc, elapsed_s=round(time.monotonic() - start, 3))
    if rc != 0:
        return abort(f"suspend returned rc={rc}")

    # Resume recovery, deliberately ordered: protection, gate re-seal, NVIDIA,
    # reload, readiness, and only then reopen the gate.  The guard acquisition
    # is retried because logind can reject inhibitors while its own suspend
    # operation is still finishing after the kernel wakes.
    if not reacquire_guard("resume"):
        # The guard is still unreleased.  Recover the model and verify
        # readiness so an operator does not have to reload it later, but the
        # abort path keeps the gate sealed because guard_ok is false.
        return abort("could not reacquire the sleep guard after resume",
                     reload_model=True)
    if gate_active and not ensure_gate_closed("resume"):
        return abort("gate lease could not be re-established after resume",
                     reload_model=False)
    ok, msg = run_verify("nvidia-verify", post_resume_verify)
    result.nvidia_verified = bool(ok)
    if not ok:
        return abort(f"NVIDIA verification failed after resume: {msg}",
                     reload_model=False)
    if not reload_if_needed("resume"):
        return abort("Strata reload failed after resume", reload_model=False)
    if not verify_readiness("resume"):
        return abort("Strata is not inference-ready after resume", reload_model=False)
    if gate_active:
        # Re-prove protection before reopening: readiness alone is not enough,
        # and a completed suspend must not open a gate that is not actually
        # blocking (for example a table that lost its rule while we slept).
        prot_ok, prot_msg = run_verify("protection-verify-before-open",
                                       lambda: verify_gate_protection(gate, log=log))
        if not prot_ok:
            return abort("gate protection not verified before reopening: "
                         + prot_msg, reload_model=False)
    if gate_active and not reopen_gate():
        result.ok = False
        result.aborted = "Strata is ready but the inference gate could not be reopened"
        phase("abort", reason=result.aborted,
              elapsed_s=round(time.monotonic() - start, 3))
        return result

    result.suspended = True
    result.ok = True
    return result
