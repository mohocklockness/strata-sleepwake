#!/usr/bin/env python3
"""Detect deployment config changes that remove gate/guard protection.

This is deliberately a pure JSON comparison: it never reads a service, writes a
file, or contacts the gate.  ``install.sh`` uses it before replacing an existing
``/etc/sleepmgr/config.json``; an operator can also run it directly.

Exit status: 0 = no protective downgrade, 3 = at least one protective
downgrade, 2 = unreadable/invalid JSON or usage error.
"""
from __future__ import annotations

import json
import sys


def _get(doc, path, default=None):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _truthy(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def compare_protection(old, new):
    """Return a list of protection problems introduced by ``new``.

    Each item is ``{"key", "message", "severity"}``.  ``severity="block"``
    means an enabled protection is being disabled/removed; ``severity="warn"``
    means the change is suspicious but not a proven downgrade (for example a
    socket or token path change).
    """
    old = old if isinstance(old, dict) else {}
    new = new if isinstance(new, dict) else {}
    problems = []

    def disabled(key, label):
        before = _get(old, key)
        after = _get(new, key)
        if _truthy(before) and not _truthy(after):
            problems.append({
                "key": key,
                "severity": "block",
                "message": f"{label} changes {before!r} -> {after!r}",
            })

    def removed_true(key, label):
        before = _get(old, key)
        after = _get(new, key)
        if before is True and after is not True:
            problems.append({
                "key": key,
                "severity": "block",
                "message": f"{label} is no longer explicitly true ({after!r})",
            })

    def changed_when_enabled(section, key, label):
        if not _truthy(_get(old, f"{section}.enabled")):
            return
        before = _get(old, f"{section}.{key}")
        after = _get(new, f"{section}.{key}")
        if before is not None and before != after:
            problems.append({
                "key": f"{section}.{key}",
                "severity": "warn",
                "message": f"{label} changes {before!r} -> {after!r}",
            })

    disabled("gate.enabled", "inference gate")
    disabled("suspend_guard.enabled", "suspend guard")
    removed_true("suspend_guard.require_gate", "guard requirement for a closed gate")
    removed_true("gate.require_token", "gate control-token requirement")
    removed_true("suspend_guard.require_token", "guard control-token requirement")

    changed_when_enabled("gate", "socket", "gate socket")
    changed_when_enabled("gate", "token_file", "gate token file")
    changed_when_enabled("gate", "port", "gated inference port")
    changed_when_enabled("suspend_guard", "socket", "guard socket")
    changed_when_enabled("suspend_guard", "token_file", "guard token file")

    # Changing the Strata config can silently point the monitor at a different
    # bind address/model.  The installer must not edit Strata's own config; a
    # changed pointer is worth surfacing even though it is not a gate bypass.
    before_path = _get(old, "strata.config_path")
    after_path = _get(new, "strata.config_path")
    if before_path and after_path and before_path != after_path:
        problems.append({
            "key": "strata.config_path",
            "severity": "warn",
            "message": ("Strata config pointer changes "
                        f"{before_path!r} -> {after_path!r}; Strata's bind "
                        "address must be preserved"),
        })
    return problems


def has_blocking_downgrade(problems):
    return any(p.get("severity") == "block" for p in problems)


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 2:
        print("usage: config_guard.py OLD.json NEW.json [--json]", file=sys.stderr)
        return 2
    try:
        old = _load(argv[0])
        new = _load(argv[1])
    except (OSError, ValueError) as e:
        print(f"config_guard: cannot read config: {e}", file=sys.stderr)
        return 2
    problems = compare_protection(old, new)
    if as_json:
        print(json.dumps({"problems": problems,
                          "blocking": has_blocking_downgrade(problems)}, indent=2))
    elif not problems:
        print("config_guard: no gate/guard protection downgrade detected")
    else:
        for p in problems:
            print(f"config_guard: {p['severity'].upper()}: "
                  f"{p['key']}: {p['message']}")
    return 3 if has_blocking_downgrade(problems) else 0


if __name__ == "__main__":
    sys.exit(main())
