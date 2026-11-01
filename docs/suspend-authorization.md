# Suspend authorization for the background service

Status: **prepared, not deployed.** No polkit rule, unit, or service was changed
during this work.

## The failure

The monitor is an unprivileged systemd service (`User=sleepuser`) and has no
logind session.  Ubuntu 24.04 / systemd 255 / polkit 124 therefore applies the
`auth_admin_keep` default for `org.freedesktop.login1.suspend` instead of the
interactive `allow_active=yes` default.

Read-only evidence from the running dry-run service (PID 722747):

```
$ pkcheck --action-id org.freedesktop.login1.suspend --process 722747
polkit\56retains_authorization_after_challenge=1
Authorization requires authentication and -u wasn't passed.
rc=2
```

A child of the active tty2 session returns `rc=0`, which is why the manual
suspend/resume test succeeded.  The automatic service path has no session and
cannot answer an authentication challenge.

## Options considered

1. **Unit-scoped polkit rule** (`subject.system_unit == "sleepmgr.service"`).
   This would be the narrowest rule.  It was rejected because polkit 124
   reports `subject.system_unit=null` for this service; the existing
   `inhibit-block-sleep` rule work already measured this.  A rule that never
   matches is not reliable.
2. **User-wide rule** (`subject.user == "sleepuser"`).  Rejected as broader
   than necessary: every interactive process of the desktop user would gain
   non-interactive suspend authorization.
3. **Root suspend helper** (small AF_UNIX service that only accepts
   `suspend`).  This would avoid polkit entirely and can be tightly sandboxed,
   but adds a new privileged daemon and a new deployment surface.  It remains
   the fallback if even sessionless-user scope is too broad.
4. **Selected: sessionless-user polkit rule plus a preflight `pkcheck`.**
   The rule grants only `org.freedesktop.login1.suspend` to
   `sleepuser` processes with no logind session.  This is the narrowest
   stable subject available on this polkit version.  Interactive sessions keep
   the normal `allow_active` policy; other users are unaffected.

The rule is in `deploy/49-sleepmgr-suspend.rules`.  It does not grant
power-off, reboot, hibernate or other actions, and it does not disable polkit
globally.  It deliberately does not grant
`org.freedesktop.login1.suspend-multiple-sessions`; if a second user session is
present, the automatic path will still abort rather than broaden the policy.

## Code-side protections (already implemented)

- The final safety check runs `pkcheck` for the monitor's own PID **before**
  the gate closes or Strata unloads.  A missing authorization now aborts early
  instead of after the model has been unloaded.
- The actual suspend command remains `systemctl suspend
  --check-inhibitors=yes`.  There is no `-i`, `--force`, or inhibitor bypass.
- The monitor's own guard's block inhibitor is excluded from the dry-run
  result only when every reported inhibitor is `sleepmgr-suspend-guard`.
  Unrelated block inhibitors still fail the check.
- The guard is released only inside the gate-first flow, after the gate is
  closed, inference is idle, Strata is unloaded, and GPU/CUDA/RAM checks pass.

## Separate deployment approval procedure

Do not run this during code-only work.  After review and explicit approval:

1. Install the rule as root, owned by root and not writable by the user:

   ```bash
   sudo install -o root -g root -m 0644 \
       deploy/49-sleepmgr-suspend.rules \
       /etc/polkit-1/rules.d/49-sleepmgr-suspend.rules
   sudo systemctl try-reload-or-restart polkit.service
   ```

2. Verify authorization as the service process, without suspending:

   ```bash
   pid=$(systemctl show -p MainPID --value sleepmgr.service)
   pkcheck --action-id org.freedesktop.login1.suspend --process "$pid"
   # expected: rc=0 and no "Authorization requires authentication" text
   ```

3. Only then consider a supervised one-shot run.  Keep
   `allow_unattended_suspend=false`; do not enable the installed service to
   arm unattended suspension.

If verification still returns `rc=2`, stop.  Do not add `-i`, `--force`, a
global polkit default change, or a user-wide rule as a workaround.  Fall back
to the root-helper design under separate approval.

## Verification of the prepared files

The automated tests cover the pure final-check filtering, the `pkcheck`
failure path, the preserved suspend command, and the static shape of the rule
(only the suspend action, sessionless user scope, no force/global bypass).
