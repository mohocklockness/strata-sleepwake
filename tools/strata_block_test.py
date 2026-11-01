#!/usr/bin/env python3
"""Dry-run test: does *active Strata inference specifically* block the sleep
monitor's 30-second countdown?

Strict attribution
------------------
A PASS requires that, while the monitor's countdown stops/resets, Strata's
detector is ACTIVE **and every other detector is ok** (OpenCode, updates,
transfers, streams, inhibitors, input).  A block caused by OpenCode, by input,
or by anything else can therefore never produce a PASS.

Unique sweeps
-------------
The monitor writes ``status.json`` about once a second but only refreshes the
detectors every ``poll_interval_s`` (5 s).  Every detector sweep carries a
monotonic cycle ID (``sweep``) plus its wall-clock ``sweep_time``.  This test
counts **only unique cycle IDs**, so repeatedly reading the same snapshot is
never counted as several sweeps.  (If an older status file has no cycle ID it
falls back to a content fingerprint, which can only under-count.)

Timeline
--------
    A  countdown running, all detectors ok            (negative control)
    B  inference burst: strata ACTIVE, all others ok  (the actual test)
    C  countdown resumes, all detectors ok            (transience)

Usage (detached, so it is not seen as an OpenCode tool child):

    setsid nohup python3 tools/strata_block_test.py \
        > /tmp/opencode/sleepmgr/strata_block_test.out 2>&1 &
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

DEFAULT_STATUS = "/tmp/opencode/sleepmgr/status.json"
DEFAULT_LOG = "/tmp/opencode/sleepmgr/strata_block_test.log"
DEFAULT_STRATA_CONFIG = "/srv/strata/Strata/strata-iq2_xs.json"

DETECTORS = ("strata", "opencode", "updates", "transfers", "streams", "inhibitors", "input")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def log(msg, path):
    line = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    if path:
        try:
            with open(path, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


def read_status(path, tries=4):
    for _ in range(tries):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            time.sleep(0.1)
    return None


def detectors_of(doc):
    return {d.get("name"): d for d in (doc.get("detectors") or [])}


def _auth_headers(cfg):
    """Build the auth headers from the Strata config read at runtime.

    The key is never printed or logged; the caller only learns whether it was
    present.  Returns None when the config carries no api_key.
    """
    key = cfg.get("api_key") or ""
    if not key:
        return None
    return {"Content-Type": "application/json", "Authorization": "Bearer " + key}


def strata_preflight(cfg_path, log_path):
    """Verify the key is present and accepted before any inference is sent.

    Uses only GET /status (no model work) and reports the HTTP status, so a 401
    is caught up front instead of surfacing as a mysterious failed burst.
    """
    try:
        with open(cfg_path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log(f"ABORT: cannot read the Strata config {cfg_path}: {e}", log_path)
        return False
    if _auth_headers(cfg) is None:
        log("ABORT: no api_key in the Strata config; refusing to send unauthenticated "
            "requests (fix the key in Strata, not here).", log_path)
        return False
    log("auth: api_key read at runtime from the Strata config (value not logged)", log_path)
    url = f"http://{cfg.get('host', '127.0.0.1')}:{cfg.get('port', 8080)}/status"
    req = urllib.request.Request(url, headers=_auth_headers(cfg))
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            log(f"auth: authenticated GET /status -> HTTP {r.status} (key accepted)", log_path)
            return True
    except urllib.error.HTTPError as e:
        what = "401 Unauthorized - key missing or wrong" if e.code == 401 else f"HTTP {e.code}"
        log(f"ABORT: authenticated GET /status -> {what}", log_path)
        return False
    except Exception as e:  # noqa: BLE001
        log(f"ABORT: GET /status failed: {type(e).__name__}: {e}", log_path)
        return False


def row_of(doc):
    dm = detectors_of(doc)
    return {
        "sweep": doc.get("sweep"),
        "sweep_time": doc.get("sweep_time"),
        "time": doc.get("time"),
        "state": doc.get("state"),
        "remaining": doc.get("remaining_s"),
        "resets": doc.get("resets"),
        "idle": doc.get("idle_s"),
        "blockers": doc.get("blockers") or [],
        "det": {n: dm.get(n, {}).get("state", "-") for n in DETECTORS},
        "strata_reason": dm.get("strata", {}).get("reason", ""),
        "strata_detail": dm.get("strata", {}).get("detail", {}) or {},
        "opencode_reason": dm.get("opencode", {}).get("reason", ""),
    }


def fmt_row(r):
    det = " ".join(f"{n}={r['det'][n]}" for n in DETECTORS)
    return (f"cycle={r['sweep']} {r['time']} state={r['state']} rem={r['remaining']} "
            f"resets={r['resets']} idle={r['idle']} | {det} | blockers={r['blockers']}")


def non_strata_active(row):
    """Detectors (other than strata) that are not ok in this sweep."""
    return [f"{n}={row['det'][n]}" for n in DETECTORS
            if n != "strata" and row["det"][n] != "ok"]


class SweepTracker:
    """Counts each detector sweep exactly once (cycle ID, or a fallback key)."""

    def __init__(self):
        self.seen = set()
        self.rows = []
        self.duplicate_reads = 0

    def key(self, doc, r):
        if doc.get("sweep") is not None:
            return ("sweep", doc.get("sweep"))
        if doc.get("sweep_time"):
            return ("time", doc.get("sweep_time"))
        # Conservative fallback: identical content is treated as one sweep.
        blob = json.dumps([r["det"], r["state"], r["resets"], r["remaining"]], sort_keys=True)
        return ("hash", hashlib.sha1(blob.encode()).hexdigest())

    def unique(self, doc):
        r = row_of(doc)
        k = self.key(doc, r)
        if k in self.seen:
            self.duplicate_reads += 1
            return None
        self.seen.add(k)
        self.rows.append(r)
        return r


# --------------------------------------------------------------------------
# the inference burst
# --------------------------------------------------------------------------

def run_burst(cfg_path, count, max_tokens, gap, results):
    cfg = json.load(open(cfg_path))
    headers = _auth_headers(cfg)
    if headers is None:
        results.append({"n": 0, "ok": False, "error": "no api_key in the Strata config"})
        return
    url = f"http://{cfg.get('host', '127.0.0.1')}:{cfg.get('port', 8080)}/v1/chat/completions"
    prompt = "Count from 1 to 400, comma separated, nothing else."
    for i in range(1, count + 1):
        body = {"model": cfg.get("model_name"),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens, "temperature": 0}
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=900) as r:
                status, raw = r.status, r.read()
            usage = (json.loads(raw.decode()).get("usage") or {})
            results.append({"n": i, "ok": True, "status": status,
                            "seconds": round(time.time() - t0, 1),
                            "completion_tokens": usage.get("completion_tokens")})
        except urllib.error.HTTPError as e:
            try:
                detail = e.read(200).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                detail = ""
            results.append({"n": i, "ok": False, "status": e.code,
                            "seconds": round(time.time() - t0, 1),
                            "error": f"HTTP {e.code}" + (" AUTH (401 Unauthorized)" if e.code == 401 else ""),
                            "body": detail})
        except Exception as e:  # noqa: BLE001
            results.append({"n": i, "ok": False, "seconds": round(time.time() - t0, 1),
                            "error": f"{type(e).__name__}: {e}"})
        if i < count and gap:
            time.sleep(gap)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Strata-blocks-sleep attribution test (dry run).")
    ap.add_argument("--status-file", default=DEFAULT_STATUS)
    ap.add_argument("--log", default=DEFAULT_LOG)
    ap.add_argument("--strata-config", default=DEFAULT_STRATA_CONFIG)
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--max-tokens", type=int, default=800)
    ap.add_argument("--gap", type=float, default=0.0)
    ap.add_argument("--pre-sweeps", type=int, default=3, help="unique sweeps required for the negative control")
    ap.add_argument("--min-block-sweeps", type=int, default=2, help="unique sweeps required to attribute the block")
    ap.add_argument("--wait-timeout", type=float, default=1200.0)
    ap.add_argument("--post-timeout", type=float, default=180.0)
    args = ap.parse_args(argv)

    # fresh log for this run
    try:
        with open(args.log, "w") as f:
            f.write(f"=== strata_block_test {datetime.now().isoformat(timespec='seconds')} ===\n")
    except OSError:
        pass
    log(f"mode guard: status file {args.status_file}", args.log)

    # ---- mode guard: refuse unless the monitor is in dry-run -------------
    deadline = time.time() + 30
    while time.time() < deadline:
        doc = read_status(args.status_file)
        if doc is not None:
            if doc.get("mode") != "dry-run":
                log(f"ABORT: monitor mode is {doc.get('mode')!r}, not 'dry-run'", args.log)
                return 3
            log(f"monitor pid={doc.get('pid')} mode=dry-run cycle={doc.get('sweep')}", args.log)
            break
        time.sleep(0.5)
    else:
        log("ABORT: could not read status.json (is the monitor running?)", args.log)
        return 3

    tracker = SweepTracker()

    # ---- authentication preflight (before any inference) -----------------
    if not strata_preflight(args.strata_config, args.log):
        return 3

    # ---- phase A: a clean countdown (negative control) -------------------
    log(f"phase A: waiting for {args.pre_sweeps} consecutive clean countdown cycles "
        f"(all detectors ok, remaining 10-25s) ...", args.log)
    pre, deadline = [], time.time() + args.wait_timeout
    while time.time() < deadline:
        doc = read_status(args.status_file)
        if doc is not None:
            r = tracker.unique(doc)
            if r is not None:
                bad = non_strata_active(r)
                good = (r["state"] == "countdown" and not r["blockers"] and not bad
                        and r["remaining"] is not None and 10.0 <= r["remaining"] <= 25.0
                        and r["det"]["strata"] == "ok")
                if good:
                    pre.append(r)
                    log("  A ok   " + fmt_row(r), args.log)
                    if len(pre) >= args.pre_sweeps:
                        break
                else:
                    if pre:
                        why = r["blockers"] or bad or r["state"]
                        log(f"  A break ({why})", args.log)
                    pre = []
        time.sleep(0.4)
    if len(pre) < args.pre_sweeps:
        log("FAIL: no clean countdown window before the timeout "
            "(OpenCode still busy, or input kept resetting) - no test performed.", args.log)
        return 2
    log(f"phase A ok: {len(pre)} clean cycles; resets={pre[-1]['resets']}", args.log)

    # ---- phase B: inference burst ---------------------------------------
    log(f"phase B: firing {args.count} x {args.max_tokens} tokens (gap {args.gap}s) ...", args.log)
    burst_results = []
    burst_thread = threading.Thread(
        target=run_burst,
        args=(args.strata_config, args.count, args.max_tokens, args.gap, burst_results),
        daemon=True)
    burst_thread.start()

    block_streak, contaminated, during = [], [], []
    burst_deadline = time.time() + 900
    while burst_thread.is_alive() and time.time() < burst_deadline:
        doc = read_status(args.status_file)
        if doc is not None:
            r = tracker.unique(doc)
            if r is not None:
                during.append(r)
                bad = non_strata_active(r)
                strata_active = r["det"]["strata"] == "active"
                left_countdown = r["state"] == "blocked"
                strata_only_block = (strata_active and left_countdown and not bad
                                     and r["blockers"] and all(b.startswith("strata") for b in r["blockers"]))
                if strata_only_block:
                    if r["idle"] is not None and r["idle"] < 5.0:
                        contaminated.append(r)
                        log("  B cont " + fmt_row(r), args.log)
                    else:
                        block_streak.append(r)
                        log("  B BLOCK " + fmt_row(r), args.log)
                else:
                    tag = "B ok   " if not bad else "B other"
                    log(f"  {tag} " + fmt_row(r), args.log)
        time.sleep(0.4)
    burst_thread.join(timeout=10)
    log(f"burst finished: {json.dumps(burst_results)}", args.log)

    # ---- phase C: does the countdown come back? -------------------------
    log("phase C: waiting for the countdown to resume (all detectors ok) ...", args.log)
    resumes, deadline = [], time.time() + args.post_timeout
    while time.time() < deadline:
        doc = read_status(args.status_file)
        if doc is not None:
            r = tracker.unique(doc)
            if r is not None:
                bad = non_strata_active(r)
                if r["state"] == "countdown" and not bad and r["det"]["strata"] == "ok" and not r["blockers"]:
                    resumes.append(r)
                    log("  C ok   " + fmt_row(r), args.log)
                    if len(resumes) >= 2:
                        break
                elif resumes:
                    log(f"  C ({r['blockers'] or bad or r['state']})", args.log)
        time.sleep(0.4)

    # ---- verdict ---------------------------------------------------------
    resets_before = pre[-1]["resets"] if pre[-1]["resets"] is not None else None
    resets_during = max((r["resets"] for r in during if r["resets"] is not None), default=resets_before)
    opencode_confound = [r for r in during if r["det"]["opencode"] != "ok"]
    other_confound = [r for r in during
                      if any(r["det"][n] != "ok" for n in DETECTORS if n not in ("strata", "opencode"))]

    checks = [
        ("A negative control: clean countdown before the burst", len(pre) >= args.pre_sweeps,
         f"{len(pre)}/{args.pre_sweeps} cycles"),
        ("B strata ACTIVE while the countdown stopped", len(block_streak) >= args.min_block_sweeps,
         f"{len(block_streak)}/{args.min_block_sweeps} unique cycles, "
         f"reason={block_streak[0]['strata_reason'][:60] if block_streak else '-'}"),
        ("B attribution: every other detector ok", not opencode_confound and not other_confound,
         f"opencode confounds={len(opencode_confound)}, other={len(other_confound)}"),
        ("B countdown actually reset/stopped", (resets_during is not None and resets_before is not None
                                                and resets_during > resets_before),
         f"resets {resets_before} -> {resets_during}"),
        ("C countdown resumed, all detectors ok", len(resumes) >= 2, f"{len(resumes)} cycles"),
    ]
    passed = all(ok for _n, ok, _d in checks)

    log("", args.log)
    log("=== VERDICT ===", args.log)
    for name, ok, detail in checks:
        log(f"  [{'PASS' if ok else 'FAIL'}] {name} ({detail})", args.log)
    if contaminated:
        log(f"  note: {len(contaminated)} contaminated cycle(s) with recent input were excluded", args.log)
    log(f"  unique detector sweeps: A={len(pre)} B={len(during)} C={len(resumes)}; "
        f"duplicate reads ignored={tracker.duplicate_reads}", args.log)
    log(f"RESULT: {'PASS' if passed else 'FAIL'}"
        + (" - active Strata inference specifically blocks the sleep countdown"
           if passed else " - attribution not established"), args.log)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
