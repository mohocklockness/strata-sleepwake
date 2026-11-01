#!/usr/bin/env python3
"""sleepmgr-ctl: control the workload-aware sleep monitor from a terminal.

    sleepmgr-ctl status
    sleepmgr-ctl pause                 # pause indefinitely
    sleepmgr-ctl pause --for 1h        # timed pause (1h default for the GUI)
    sleepmgr-ctl resume
    sleepmgr-ctl suspend-now           # intentional manual suspend (dry-run aware)

Talks to the monitor over its local Unix socket; works while the future
inference gate has TCP/8080 closed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import control as control_mod  # noqa: E402

DEFAULT_CONFIG = os.path.join(HERE, "config.json")


def parse_duration(text):
    if text is None:
        return None
    text = str(text).strip().lower()
    if text in ("", "0"):
        return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd]?)", text)
    if not m:
        raise argparse.ArgumentTypeError(f"bad duration {text!r} (use e.g. 30m, 1h, 3600)")
    value = float(m.group(1))
    unit = m.group(2) or "s"
    return int(value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit])


def resolve_socket(args):
    if args.socket:
        return args.socket
    cfg = {}
    try:
        with open(args.config) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    sock = (cfg.get("pause") or {}).get("socket")
    if sock:
        return sock
    log_dir = cfg.get("log_dir") or "/tmp/opencode/sleepmgr"
    return os.path.join(log_dir, "control.sock")


def print_status(doc):
    if not isinstance(doc, dict) or doc.get("error"):
        print(json.dumps(doc, indent=1))
        return
    pause = doc.get("pause") or {}
    svc = doc.get("service") or {}
    manual = doc.get("manual") or {}
    print(f"mode      : {doc.get('mode')}"
          + (f"  (service={svc.get('service_mode')}, armed={svc.get('armed')})"))
    print(f"state     : {doc.get('state')}")
    print(f"input idle: {doc.get('idle_s')}s ({doc.get('idle_source')})"
          if doc.get("idle_s") is not None else "input idle: unknown")
    if doc.get("suspend_in_s") is not None:
        print(f"suspend in: {doc.get('suspend_in_s'):.0f}s"
              + (f"   (inactive {doc.get('inactive_s'):.0f}s / "
                 f"timeout {doc.get('idle_timeout_s')}s)"
                 if doc.get("inactive_s") is not None else ""))
    if pause.get("mode") == "paused":
        if pause.get("paused_until"):
            print(f"pause     : timed, {pause.get('remaining_s'):.0f}s left "
                  f"(until {pause.get('paused_until'):.0f})")
        else:
            print("pause     : indefinite")
        print(f"inhibitor : {'held' if (pause.get('inhibitor') or {}).get('held') else 'not held'}")
    else:
        print("pause     : none (automatic monitoring active)")
    if manual.get("state") and manual.get("state") != "idle":
        print(f"manual    : {manual.get('state')} - {manual.get('message')}")
    gnome = doc.get("gnome_suspend") or {}
    if gnome.get("conflict"):
        print("WARNING   : competing automatic suspend setting: "
              + "; ".join(gnome.get("reasons", [])))
    gate = doc.get("gate") or {}
    if gate:
        state = gate.get("state") or "unknown"
        extra = "" if gate.get("enabled", True) else " (disabled)"
        print(f"gate      : {state}{extra}")
    guard = doc.get("guard") or {}
    if guard:
        state = guard.get("state") or "unknown"
        extra = "" if guard.get("enabled", True) else " (disabled)"
        print(f"guard     : {state}{extra}")
        if guard.get("enabled", True) and state not in ("protected", "disabled"):
            print(f"            {guard.get('last_failure') or guard.get('reason') or guard.get('error') or ''}")
    blockers = doc.get("blockers") or []
    print("blockers  : " + ("; ".join(blockers) if blockers else "none"))
    print(f"sweep     : #{doc.get('sweep')} at {doc.get('sweep_time')} "
          f"(pid {doc.get('pid')})")
    print(f"stale if older than {doc.get('stale_status_s')}s")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["status", "pause", "resume", "suspend-now", "ping"])
    p.add_argument("--for", dest="duration", default=None,
                   help="pause duration, e.g. 1h, 30m, 3600 (default: indefinite)")
    p.add_argument("--seconds", type=float, default=None, help="pause duration in seconds")
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("--socket", default=None)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    sock = resolve_socket(args)

    if args.command == "suspend-now":
        cmd = {"cmd": "suspend-now"}
    elif args.command == "pause":
        try:
            duration = args.seconds if args.seconds is not None else parse_duration(args.duration)
        except argparse.ArgumentTypeError as e:
            print(str(e), file=sys.stderr)
            return 2
        cmd = {"cmd": "pause", "duration_s": duration}
    else:
        cmd = {"cmd": args.command}

    try:
        reply = control_mod.request(sock, cmd)
    except control_mod.ControlError as e:
        print(f"cannot reach the sleep monitor on {sock}: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"cannot reach the sleep monitor on {sock}: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(reply, indent=1))
    elif args.command == "status":
        print_status(reply)
    elif args.command in ("pause", "resume"):
        if not reply.get("ok"):
            print("failed: " + str(reply.get("error")))
        elif reply.get("paused"):
            if reply.get("paused_until"):
                print(f"paused (timed, {reply.get('remaining_s', 0):.0f}s left)")
            else:
                print("paused (indefinite) - automatic unload/suspend disabled")
        else:
            print("resumed: automatic monitoring active (inactivity timer restarts)")
    else:
        print(reply.get("error") or reply.get("message") or json.dumps(reply))
        if reply.get("blockers"):
            for b in reply["blockers"]:
                print(f"  blocker: {b}")
    return 0 if reply.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
