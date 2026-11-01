#!/usr/bin/env bash
# Install the sleep monitor.  DRY-RUN by default: it prints the actions and
# changes nothing unless you pass --apply (and you are root).
#
# It never arms the monitor and never enables unattended suspension: the
# installed service runs with --service (dry-run).  Arming is a separate,
# deliberate act that requires both --arm and service.allow_unattended_suspend
# = true in the config, plus an explicitly enabled inference-arrival gate.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="/opt/sleepmgr"
CONF_DIR="/etc/sleepmgr"
APPLY=0
ENABLE=0
WITH_GATE=0
REPLACE_CONFIG=0
ALLOW_DOWNGRADE=0
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --enable) ENABLE=1 ;;
    --with-gate) WITH_GATE=1 ;;
    --replace-config) REPLACE_CONFIG=1 ;;
    --allow-protection-downgrade) ALLOW_DOWNGRADE=1 ;;
    -h|--help)
      echo "usage: sudo $0 [--apply] [--enable] [--with-gate] [--replace-config] [--allow-protection-downgrade]" >&2
      exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }

say "source        : $SRC"
say "code          : $PREFIX"
say "config        : $CONF_DIR/config.json (existing file is preserved by default)"
say "unit          : /etc/systemd/system/sleepmgr.service"
say "polkit rule   : /etc/polkit-1/rules.d/00-sleepmgr-inhibit.rules"
say "desktop entry : /usr/share/applications/sleepmgr-control.desktop (+ ~/.local/share/applications)"
say "gate helper   : $([ "$WITH_GATE" -eq 1 ] && echo 'install helper + units + boot fail-closed unit' || echo 'not installed (use --with-gate)')"
say "mode          : DRY-RUN (no --arm, allow_unattended_suspend=false)"

if [ "$APPLY" -ne 1 ]; then
  say ""
  say "DRY-RUN only. Re-run with --apply (as root) to install."
  say "This installer never enables unattended suspension."
  if [ "$WITH_GATE" -eq 1 ]; then
    say "Gate plan: install nftgate_helper.py, the gate units and the"
    say "           sleepmgr-gate-boot fail-closed unit plus the strata.service"
    say "           drop-in that requires it; with --enable, enable"
    say "           sleepmgr-gate.socket and sleepmgr-gate-boot.service at boot,"
    say "           and sleepmgr.service."
  else
    say "Gate helper/units are NOT installed by default (see docs/inference-gate.md)."
  fi
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "--apply requires root." >&2
  exit 1
fi

install -d "$PREFIX" "$CONF_DIR" /usr/lib/systemd/system
# netgate.py is the unprivileged client and ships with the monitor.  The
# privileged nftgate_helper.py is installed only with --with-gate: it is a
# separate, deliberate privilege decision (see docs/inference-gate.md).
for f in "$SRC"/*.py; do
  if [ "$(basename "$f")" = "nftgate_helper.py" ] && [ "$WITH_GATE" -ne 1 ]; then
    continue
  fi
  install -m 0644 "$f" "$PREFIX"/
done

# Never silently replace a live /etc/sleepmgr/config.json.  A fresh install
# gets the production default; an existing install gets a .new file and the
# operator decides.  --replace-config is explicit, and a protective
# downgrade (gate/guard disabled or token requirement removed) is refused
# unless --allow-protection-downgrade is also supplied.
if [ -f "$CONF_DIR/config.json" ]; then
  install -m 0644 "$SRC/config.production.json" "$CONF_DIR/config.json.new"
  set +e
  python3 "$SRC/deploy/config_guard.py" \
    "$CONF_DIR/config.json" "$CONF_DIR/config.json.new"
  guard_rc=$?
  set -e
  if [ "$guard_rc" -eq 2 ]; then
    say "REFUSING to replace $CONF_DIR/config.json: the proposed config is not"
    say "valid JSON. Review $CONF_DIR/config.json.new."
    REPLACE_CONFIG=0
  elif [ "$guard_rc" -eq 3 ] && [ "$ALLOW_DOWNGRADE" -ne 1 ]; then
    say "REFUSING to replace $CONF_DIR/config.json: proposed config removes"
    say "gate/guard protection. Review $CONF_DIR/config.json.new; re-run with"
    say "--replace-config --allow-protection-downgrade only if that is intended."
    REPLACE_CONFIG=0
  fi
  if [ "$REPLACE_CONFIG" -eq 1 ]; then
    install -m 0644 "$CONF_DIR/config.json.new" "$CONF_DIR/config.json"
    say "replaced $CONF_DIR/config.json (previous file was not kept automatically)"
  else
    say "preserved existing $CONF_DIR/config.json; proposal is $CONF_DIR/config.json.new"
  fi
else
  install -m 0644 "$SRC/config.production.json" "$CONF_DIR/config.json"
fi
install -m 0644 "$SRC/README.md" "$PREFIX/README.md" 2>/dev/null || true
install -m 0644 "$SRC/deploy/sleepmgr.service" /etc/systemd/system/sleepmgr.service
install -m 0755 "$SRC/deploy/sleepmgr-gui" /usr/local/bin/sleepmgr-gui
install -m 0755 "$SRC/deploy/sleepmgr-ctl" /usr/local/bin/sleepmgr-ctl
install -m 0644 "$SRC/deploy/sleepmgr-control.desktop" /usr/share/applications/sleepmgr-control.desktop
# Remove the old filename if an earlier install used it.
rm -f /etc/polkit-1/rules.d/50-sleepmgr-inhibit.rules
install -m 0644 "$SRC/deploy/00-sleepmgr-inhibit.rules" \
  /etc/polkit-1/rules.d/00-sleepmgr-inhibit.rules
# The service suspend-authorization rule (deploy/49-sleepmgr-suspend.rules) is
# deliberately NOT installed here: it is a separate policy decision requiring
# explicit approval.  See docs/suspend-authorization.md.
install -d -o 1000 -g 1000 /home/sleepuser/.local/share/applications
install -m 0644 -o 1000 -g 1000 "$SRC/deploy/sleepmgr-control.desktop" \
  /home/sleepuser/.local/share/applications/sleepmgr-control.desktop

if [ "$WITH_GATE" -eq 1 ]; then
  install -m 0755 "$SRC/nftgate_helper.py" "$PREFIX/nftgate_helper.py"
  install -d "$PREFIX/docs"
  install -m 0644 "$SRC/docs/inference-gate.md" "$SRC/docs/gate-live-test.md" \
    "$SRC/docs/deploy-selective.md" "$PREFIX/docs/"
  install -m 0644 "$SRC/deploy/sleepmgr-gate.service" \
    "$SRC/deploy/sleepmgr-gate.socket" \
    "$SRC/deploy/sleepmgr-gate-boot.service" /etc/systemd/system/
  install -m 0755 "$SRC/deploy/sleepmgr-gate-emergency-open.sh" \
    /usr/local/sbin/sleepmgr-gate-emergency-open
  install -m 0755 "$SRC/deploy/sleepmgr-gate-boot.sh" \
    /usr/local/sbin/sleepmgr-gate-boot
  # Make a successful fail-closed boot seal a prerequisite for Strata, so a
  # boot that cannot establish the required seal also cannot serve remote
  # inference.  Host networking is untouched.
  install -d /etc/systemd/system/strata.service.d
  install -m 0644 "$SRC/deploy/strata.service.d/10-sleepmgr-gate-boot.conf" \
    /etc/systemd/system/strata.service.d/10-sleepmgr-gate-boot.conf
  say "installed gate helper, units, boot fail-closed unit, emergency opener"
  say "and the strata.service drop-in that requires the boot seal"
fi

systemctl daemon-reload
# polkitd auto-reloads rules.d, but force it when the unit supports it.
systemctl try-reload-or-restart polkit.service 2>/dev/null || true
if [ "$ENABLE" -eq 1 ]; then
  if [ "$WITH_GATE" -eq 1 ]; then
    # Socket activation creates the listener at boot.  The helper itself is
    # started on first connection (and pulls in the socket via Requires=).
    # The boot unit re-seals before network-pre when a seal marker survived an
    # interrupted sealed recovery, closing the gap before the helper starts.
    systemctl enable --now sleepmgr-gate.socket
    systemctl enable sleepmgr-gate-boot.service
    say "enabled sleepmgr-gate.socket and sleepmgr-gate-boot.service at boot"
  fi
  systemctl enable --now sleepmgr.service
  say "enabled sleepmgr.service (DRY-RUN; it will not suspend)"
else
  say "installed but not enabled. Start with: systemctl start sleepmgr.service"
  if [ "$WITH_GATE" -eq 1 ]; then
    say "gate units installed but not enabled. Enable with:"
    say "  systemctl enable --now sleepmgr-gate.socket"
    say "  systemctl enable sleepmgr-gate-boot.service   # fail closed after an interrupted seal"
  fi
fi
say ""
say "The service is dry-run. To arm unattended suspension later you must set"
say "service.allow_unattended_suspend=true and run sleepmon.py --arm (interactive)."
say ""
if [ "$WITH_GATE" -ne 1 ]; then
  say "The privileged inference gate was NOT installed. To add it later:"
  say "  sudo $0 --apply --with-gate [--enable]"
  say "Then create /etc/sleepmgr/gate.token (root:sleepuser 0640, random),"
  say "run the supervised live test in $PREFIX/docs/gate-live-test.md, and set"
  say "gate.enabled=true in $CONF_DIR/config.json."
fi
say "Gate deployment is selective: --with-gate installs the helper/units plus"
say "the sleepmgr-gate-boot fail-closed unit and the strata.service drop-in"
say "that makes the boot seal a prerequisite for Strata; --enable enables"
say "sleepmgr-gate.socket and sleepmgr-gate-boot.service at boot.  The .socket"
say "unit creates /run/sleepmgr-gate/gate.sock as root:sleepuser 0660; the"
say "helper stays CAP_NET_ADMIN-only.  Existing config is preserved unless"
say "--replace-config is given, and protective removals are refused by"
say "deploy/config_guard.py.  See docs/inference-gate.md and"
say "docs/deploy-selective.md, including the HTTP-level race limitations,"
say "backups of installed code/units/config/enablement (and the drop-in), and"
say "rollback steps."
