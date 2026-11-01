#!/usr/bin/env python3
"""Lightweight control panel for the workload-aware sleep monitor.

GTK4 + libadwaita, launched on demand from the desktop (also visible through a
Moonlight/Sunshine stream).  It does not autostart and it holds no privileges:
every action goes over the monitor's local Unix socket, and the monitor is the
only component that can suspend the machine.

Buttons:
  Pause            stop automatic unload/suspend indefinitely
  Pause 1 hour     timed pause; returns to automatic monitoring by itself
  Resume           return to automatic monitoring (restarts the 10-minute clock)
  Suspend now      an *intentional* suspend.  It is refused outright while a
                   critical workload is active (Strata inference, updates,
                   active agent jobs, transfers, streams) - confirmation alone
                   never bypasses that.

Use --self-test to exercise the buttons against a running monitor and exit.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

try:
    gi.require_version("Adw", "1")
    from gi.repository import Adw  # noqa: E402
    HAS_ADW = True
except (ValueError, ImportError):
    Adw = None
    HAS_ADW = False

import control as control_mod  # noqa: E402

DEFAULT_CONFIG = os.path.join(HERE, "config.json")
APP_ID = "org.sleepmgr.Control"

STATE_STYLE = {
    "active": ("Input active", "dim-label"),
    "waiting": ("Waiting for inactivity", "dim-label"),
    "countdown": ("Countdown - about to suspend", "warning"),
    "ready": ("Ready to suspend", "warning"),
    "blocked": ("Blocked by workload", "accent"),
    "paused": ("Paused", "accent"),
    "unknown": ("Idle source unavailable", "error"),
    "starting": ("Starting", "dim-label"),
    "stopped": ("Stopped", "error"),
}


# --------------------------------------------------------------------------
# pure helpers (unit-tested without a display)
# --------------------------------------------------------------------------

def status_is_fresh(doc, now, pid_alive, stale_s=15.0):
    """A status document is usable only if it is recent and its pid is alive."""
    if not isinstance(doc, dict) or not doc or doc.get("stopped"):
        return False
    if not pid_alive:
        return False
    ts = doc.get("time")
    if not ts:
        return False
    try:
        when = datetime.datetime.fromisoformat(ts).timestamp()
    except (TypeError, ValueError):
        return False
    return (now - when) <= float(stale_s)


def format_pause(pause, now=None):
    pause = pause or {}
    if pause.get("mode") != "paused" or not pause.get("paused"):
        return "Automatic monitoring active"
    until = pause.get("paused_until")
    if until:
        left = max(0, int(until - (now if now is not None else datetime.datetime.now().timestamp())))
        return f"Paused (timed) - resumes in {left // 60}m{left % 60:02d}s"
    return "Paused indefinitely"


def format_countdown(doc):
    if doc.get("suspend_in_s") is None:
        return "-"
    sec = int(max(0, doc["suspend_in_s"]))
    timeout = doc.get("idle_timeout_s")
    if timeout:
        return f"suspend in {sec // 60}m{sec % 60:02d}s (of {int(timeout)}s inactivity)"
    return f"suspend in {sec}s"


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------

def load_config(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def resolve_paths(args):
    cfg = load_config(args.config) if args.config else {}
    pause = cfg.get("pause") or {}
    service = cfg.get("service") or {}
    log_dir = cfg.get("log_dir") or "/tmp/opencode/sleepmgr"
    socket_path = args.socket or pause.get("socket") or os.path.join(log_dir, "control.sock")
    status_path = args.status_file or service.get("status_file") or os.path.join(log_dir, "status.json")
    stale = float(service.get("stale_status_s", 15))
    return socket_path, status_path, stale


# --------------------------------------------------------------------------
# application
# --------------------------------------------------------------------------

_Base = Adw.Application if HAS_ADW else Gtk.Application


class ControlApp(_Base):
    def __init__(self, socket_path, status_path, stale_s, self_test=False):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.socket_path = socket_path
        self.status_path = status_path
        self.stale_s = stale_s
        self.self_test = self_test
        self.doc = {}
        self.online = False
        self._test_log = []
        self.window = None
        self.labels = {}
        self.buttons = {}

    # ------------------------------------------------------------- UI
    def do_activate(self):
        self._build_window()
        self.window.present()
        self._tick()
        GLib.timeout_add(500, self._tick)
        if self.self_test:
            GLib.timeout_add(1500, self._run_self_test)

    def _build_window(self):
        if HAS_ADW:
            self.window = Adw.ApplicationWindow(application=self, title="Sleep Control")
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            box.set_margin_top(18)
            box.set_margin_bottom(18)
            box.set_margin_start(18)
            box.set_margin_end(18)
            header = Adw.HeaderBar()
            toolbar = Adw.ToolbarView()
            toolbar.add_top_bar(header)
            toolbar.set_content(box)
            self.window.set_content(toolbar)
        else:
            self.window = Gtk.ApplicationWindow(application=self, title="Sleep Control")
            header = Gtk.HeaderBar()
            self.window.set_titlebar(header)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            box.set_margin_top(18)
            box.set_margin_bottom(18)
            box.set_margin_start(18)
            box.set_margin_end(18)
            self.window.set_child(box)
        self.window.set_default_size(460, 420)

        self.labels["headline"] = Gtk.Label()
        self.labels["headline"].add_css_class("title-1")
        self.labels["headline"].set_xalign(0)
        box.append(self.labels["headline"])

        self.labels["detail"] = Gtk.Label()
        self.labels["detail"].set_xalign(0)
        self.labels["detail"].set_wrap(True)
        box.append(self.labels["detail"])

        self.labels["pause"] = Gtk.Label()
        self.labels["pause"].add_css_class("title-3")
        self.labels["pause"].set_xalign(0)
        box.append(self.labels["pause"])

        grid = Gtk.Grid(column_spacing=10, row_spacing=6)
        for row, key in enumerate(("idle", "timeout", "mode", "sweep", "gnome")):
            k = Gtk.Label(label=key.capitalize())
            k.add_css_class("dim-label")
            k.set_xalign(0)
            v = Gtk.Label(label="-")
            v.set_xalign(0)
            v.set_selectable(True)
            grid.attach(k, 0, row, 1, 1)
            grid.attach(v, 1, row, 1, 1)
            self.labels[key] = v
        box.append(grid)

        self.labels["blockers"] = Gtk.Label()
        self.labels["blockers"].set_xalign(0)
        self.labels["blockers"].set_wrap(True)
        self.labels["blockers"].set_margin_top(6)
        box.append(self.labels["blockers"])

        self.labels["manual"] = Gtk.Label()
        self.labels["manual"].set_xalign(0)
        self.labels["manual"].set_wrap(True)
        box.append(self.labels["manual"])

        box.append(Gtk.Separator())

        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row1.set_homogeneous(True)
        self.buttons["pause"] = Gtk.Button(label="Pause")
        self.buttons["pause"].set_tooltip_text("Disable automatic unload/suspend until Resume")
        self.buttons["pause1h"] = Gtk.Button(label="Pause 1 hour")
        self.buttons["resume"] = Gtk.Button(label="Resume")
        for name in ("pause", "pause1h", "resume"):
            self.buttons[name].connect("clicked", self._on_button, name)
            row1.append(self.buttons[name])
        box.append(row1)

        self.buttons["suspend"] = Gtk.Button(label="Suspend now")
        self.buttons["suspend"].add_css_class("destructive-action")
        self.buttons["suspend"].set_tooltip_text(
            "Intentional suspend. Refused while Strata inference, updates or agent jobs are active.")
        self.buttons["suspend"].connect("clicked", self._on_button, "suspend")
        box.append(self.buttons["suspend"])

        self.labels["footer"] = Gtk.Label()
        self.labels["footer"].set_xalign(0)
        self.labels["footer"].add_css_class("dim-label")
        self.labels["footer"].set_wrap(True)
        box.append(self.labels["footer"])

    # --------------------------------------------------------- status
    def _tick(self):
        try:
            with open(self.status_path) as f:
                doc = json.load(f)
        except (OSError, ValueError):
            doc = {}
        self.doc = doc
        pid = doc.get("pid")
        alive = False
        if isinstance(pid, int):
            try:
                os.kill(pid, 0)
                alive = True
            except OSError:
                alive = False
        self.online = status_is_fresh(doc, datetime.datetime.now().timestamp(), alive, self.stale_s)
        self._render()
        return True

    def _render(self):
        if not self.online:
            self.labels["headline"].set_text("Sleep monitor offline")
            self.labels["headline"].remove_css_class("error")
            self.labels["headline"].add_css_class("error")
            self.labels["detail"].set_text(
                f"No fresh status from {self.status_path} "
                f"(older than {self.stale_s:.0f}s or the process is gone).")
            self.labels["pause"].set_text("-")
            for key in ("idle", "timeout", "mode", "sweep", "gnome"):
                self.labels[key].set_text("-")
            self.labels["blockers"].set_text("")
            self.labels["manual"].set_text("")
            self._set_buttons(False)
            return

        state = self.doc.get("state", "?")
        text, css = STATE_STYLE.get(state, (state, "dim-label"))
        self.labels["headline"].set_text(f"State: {text}")
        for c in ("dim-label", "warning", "error", "accent"):
            self.labels["headline"].remove_css_class(c)
        self.labels["headline"].add_css_class(css)
        self.labels["detail"].set_text(
            f"Inactivity timeout {self.doc.get('idle_timeout_s')}s, "
            f"final countdown {self.doc.get('countdown_s')}s. "
            f"Dry-run: {'yes' if self.doc.get('mode') == 'dry-run' else 'NO - ARMED'}.")
        self.labels["pause"].set_text(format_pause(self.doc.get("pause")))
        self.labels["idle"].set_text(
            f"{self.doc.get('idle_s')}s ({self.doc.get('idle_source')})"
            if self.doc.get("idle_s") is not None else "unknown")
        self.labels["timeout"].set_text(format_countdown(self.doc))
        self.labels["mode"].set_text(str(self.doc.get("mode")) + (
            " / service" if (self.doc.get("service") or {}).get("service_mode") else ""))
        self.labels["sweep"].set_text(f"#{self.doc.get('sweep')} at {self.doc.get('sweep_time')}")
        gnome = self.doc.get("gnome_suspend") or {}
        if gnome.get("conflict"):
            self.labels["gnome"].set_text("competition: " + "; ".join(gnome.get("reasons", [])))
            self.labels["gnome"].add_css_class("warning")
        else:
            self.labels["gnome"].set_text("no competing auto-suspend"
                                          if gnome.get("checked") else "unknown")
            self.labels["gnome"].remove_css_class("warning")
        blockers = self.doc.get("blockers") or []
        self.labels["blockers"].set_text(
            "Preventing sleep: " + "; ".join(blockers) if blockers else "All clear - safe to sleep.")
        manual = self.doc.get("manual") or {}
        if manual.get("state") and manual.get("state") != "idle":
            self.labels["manual"].set_text(f"Manual suspend: {manual.get('state')} - {manual.get('message')}")
        else:
            self.labels["manual"].set_text("")
        paused = bool((self.doc.get("pause") or {}).get("paused"))
        self._set_buttons(True, paused=paused)

    def _set_buttons(self, online, paused=False):
        for name, btn in self.buttons.items():
            if not online:
                btn.set_sensitive(False)
                continue
            if name == "resume":
                btn.set_sensitive(paused)
            elif name in ("pause", "pause1h"):
                btn.set_sensitive(not paused)
            else:
                btn.set_sensitive(True)

    # --------------------------------------------------------- actions
    def _on_button(self, _btn, name):
        if name == "suspend":
            self._confirm_suspend()
            return
        if name == "pause":
            self._send({"cmd": "pause", "duration_s": None})
        elif name == "pause1h":
            self._send({"cmd": "pause", "duration_s": 3600})
        elif name == "resume":
            self._send({"cmd": "resume"})

    def _confirm_suspend(self):
        if not self.online:
            return
        msg = ("This is an intentional suspend. It will be refused if Strata inference, "
               "updates, an active agent job, a transfer or a stream is running.")
        if self.doc.get("mode") == "dry-run":
            msg += "\n\nThe monitor is in dry-run: it will report what it would do and not suspend."
        if HAS_ADW:
            dialog = Adw.MessageDialog(transient_for=self.window, heading="Suspend now?",
                                       body=msg)
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("ok", "Suspend now")
            dialog.set_response_appearance("ok", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.connect("response", lambda _d, r: self._send({"cmd": "suspend-now"}) if r == "ok" else None)
            dialog.present()
        else:
            dialog = Gtk.AlertDialog(message="Suspend now?", detail=msg,
                                     buttons=["Cancel", "Suspend now"], cancel_button=0,
                                     default_button=0)

            def on_choose(d, result, _data):
                try:
                    choice = d.choose_finish(result)
                except GLib.Error:
                    return
                if choice == 1:
                    self._send({"cmd": "suspend-now"})

            dialog.choose(self.window, None, on_choose, None)

    def _send(self, cmd):
        def worker():
            try:
                reply = control_mod.request(self.socket_path, cmd)
            except (control_mod.ControlError, OSError) as e:
                reply = {"ok": False, "error": str(e)}
            GLib.idle_add(self._after_send, reply)
        threading.Thread(target=worker, daemon=True).start()

    def _after_send(self, reply):
        self._test_log.append(reply)
        if not reply.get("ok"):
            self.labels["manual"].set_text("Command failed: " + str(reply.get("error")))
        GLib.timeout_add(250, self._tick)
        return False

    # --------------------------------------------------------- self test
    def _run_self_test(self):
        self._test_log = []
        self._send({"cmd": "status"})
        GLib.timeout_add(1200, self._st_pause)

    def _st_pause(self):
        if not self.online:
            return self._st_done("monitor offline before self-test")
        self._send({"cmd": "pause", "duration_s": None})
        GLib.timeout_add(1800, self._st_check_paused)

    def _st_check_paused(self):
        paused = bool((self.doc.get("pause") or {}).get("paused"))
        if not paused:
            return self._st_done("pause was not reflected in status")
        self._send({"cmd": "resume"})
        GLib.timeout_add(1800, self._st_check_resumed)

    def _st_check_resumed(self):
        paused = bool((self.doc.get("pause") or {}).get("paused"))
        if paused:
            return self._st_done("resume was not reflected in status")
        self._send({"cmd": "suspend-now"})
        GLib.timeout_add(2500, self._st_check_manual)

    def _st_check_manual(self):
        manual = self.doc.get("manual") or {}
        state = manual.get("state")
        if state in ("would_suspend", "refused", "suspended", "error"):
            return self._st_done(f"manual suspend outcome: {state} - {manual.get('message')}")
        return self._st_done(f"manual suspend did not resolve (state={state})")

    def _st_done(self, summary):
        ok = "not reflected" not in summary and "did not resolve" not in summary \
            and "offline" not in summary
        print(("GUI SELF-TEST PASS: " if ok else "GUI SELF-TEST FAIL: ") + summary)
        print("replies: " + json.dumps(self._test_log)[:800])
        self.quit()
        return False


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="Sleep control panel")
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("--socket", default=None)
    p.add_argument("--status-file", default=None)
    p.add_argument("--self-test", action="store_true",
                   help="click Pause/Resume/Suspend now against a running monitor and exit")
    args = p.parse_args(argv)
    socket_path, status_path, stale = resolve_paths(args)
    if HAS_ADW:
        Adw.init()
    app = ControlApp(socket_path, status_path, stale, self_test=args.self_test)
    return app.run([])


if __name__ == "__main__":
    sys.exit(main())
