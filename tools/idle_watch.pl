#!/usr/bin/perl
# Lightweight detached watcher for the sleepmgr 10-minute inactivity test.
#
# Run as:  setsid -f /usr/bin/perl idle_watch.pl OUTDIR [MAX_S] [POST_S]
#
# It uses perl (not bash/python3, which are in the monitor's tool_processes
# list) and a new session, so it is not an active OpenCode workload.  It tails
# the monitor/control logs from their current EOF, samples status.json, and
# writes a PASS/FAIL summary into OUTDIR.
use strict;
use warnings;
use POSIX qw(strftime);
use Time::HiRes qw(time sleep clock_gettime CLOCK_MONOTONIC);
use JSON::PP qw(decode_json encode_json);
use File::Copy qw(copy);

my $outdir = shift @ARGV or die "usage: $0 OUTDIR [MAX_S] [POST_S]\n";
my $max    = shift @ARGV // 1500;
my $post   = shift @ARGV // 90;
mkdir $outdir unless -d $outdir;
my $logpath = "$outdir/watcher.log";
open(my $LOG, '>>', $logpath) or die "open $logpath: $!";
$LOG->autoflush(1);
open(my $PID, '>', "$outdir/watcher.pid") or die "pid: $!";
print $PID "$$\n";
close $PID;

sub ts { strftime('%Y-%m-%dT%H:%M:%S%z', localtime()) }
sub logmsg { print $LOG ts() . " " . join(' ', @_) . "\n"; }

sub cmdout {
    my @cmd = @_;
    open(my $fh, '-|', @cmd) or return '';
    local $/;
    my $out = <$fh>;
    close $fh;
    $out //= '';
    $out =~ s/\s+$//;
    return $out;
}

sub read_status {
    my $p = '/run/sleepmgr/status.json';
    open(my $fh, '<', $p) or return {};
    local $/;
    my $j = <$fh>;
    close $fh;
    my $d = eval { decode_json($j) };
    return ref($d) eq 'HASH' ? $d : {};
}

sub parse_dur {
    my $s = shift // return undef;
    return $1 * 60 + $2 if $s =~ /^(\d+)m(\d+)s$/;
    return $1 if $s =~ /^(\d+)s$/;
    return undef;
}

my $start_wall = time();
my $start_mono = clock_gettime(CLOCK_MONOTONIC);
my $st_start   = read_status();
my $strata_start_state = '?';
for my $d (@{ $st_start->{detectors} // [] }) {
    $strata_start_state = $d->{state} if ($d->{name} // '') eq 'strata';
}
logmsg("START", "pid=$$", "outdir=$outdir", "max=${max}s", "post=${post}s");

my $strata_active   = cmdout('systemctl', 'is-active', 'strata.service');
my $strata_pid      = cmdout('systemctl', 'show', 'strata.service', '-p', 'MainPID', '--value');
my $sleepmgr_active = cmdout('systemctl', 'is-active', 'sleepmgr.service');
logmsg("SERVICE", "sleepmgr=$sleepmgr_active", "strata=$strata_active", "strata_pid=$strata_pid");

# Tail from current EOF so old test lines cannot produce false events.
my %tail;
for my $spec (['monitor', '/var/log/sleepmgr/monitor.log'],
              ['control', '/var/log/sleepmgr/control.log']) {
    my ($name, $path) = @$spec;
    my ($off, $ino) = (0, 0);
    if (open(my $fh, '<', $path)) {
        my @st = stat($fh);
        $ino = $st[1];
        $off = $st[7];
        close $fh;
    }
    $tail{$name} = { path => $path, off => $off, ino => $ino };
}

sub tail_lines {
    my ($name) = @_;
    my $t = $tail{$name};
    my @lines;
    open(my $fh, '<', $t->{path}) or return @lines;
    my @st = stat($fh);
    if (($t->{ino} && $st[1] != $t->{ino}) || $st[7] < $t->{off}) {
        $t->{ino} = $st[1];
        $t->{off} = 0;
    }
    seek($fh, $t->{off}, 0);
    while (my $l = <$fh>) {
        chomp $l;
        push @lines, $l;
    }
    $t->{off} = tell($fh);
    close $fh;
    return @lines;
}

my ($waiting_at, $waiting_in, $countdown_at, $would_at, $would_n);
my ($input_resets, $blocked_after_wait, $final_failed, $suspend_detected) = (0, 0, 0, 0);
my ($last_state, $last_blockers, $last_status_log, $last_strata_check) = ('', '', -999, -999);
my $success_at;
my $end_reason = 'timeout';
my ($prev_wall, $prev_mono) = ($start_wall, $start_mono);
my ($strata_ever_bad, $strata_last_state) = (0, '');
my $status_samples = 0;

while (1) {
    my $now  = time();
    my $mono = clock_gettime(CLOCK_MONOTONIC);
    my $elapsed = $now - $start_wall;

    my $drift = ($now - $prev_wall) - ($mono - $prev_mono);
    if ($drift > 5) {
        $suspend_detected++;
        logmsg("SUSPEND_GAP", sprintf("wall-monotonic gap %.1fs", $drift));
    }
    $prev_wall = $now;
    $prev_mono = $mono;

    for my $name ('monitor', 'control') {
        for my $l (tail_lines($name)) {
            logmsg(uc($name) . "_LOG", $l);
            next unless $name eq 'monitor';
            if ($l =~ /waiting: inactivity timer running; suspend in (\S+)/) {
                $waiting_at = $now;
                $waiting_in = $1;
                $countdown_at = undef;
                $blocked_after_wait = 0;
                $input_resets = 0;
            } elsif ($l =~ /countdown started \((\d+)s\) - all clear/) {
                $countdown_at = $now unless defined $countdown_at;
            } elsif ($l =~ /final check passed - WOULD SUSPEND now \(dry-run #(\d+)\)/) {
                unless (defined $would_at) {
                    $would_at = $now;
                    $would_n = $1;
                }
            } elsif ($l =~ /final check failed/) {
                $final_failed++;
            } elsif ($l =~ /input detected - inactivity timer reset/) {
                $input_resets++ if defined $waiting_at;
            } elsif ($l =~ /BLOCKED:/) {
                $blocked_after_wait++ if defined $waiting_at;
            } elsif ($l =~ /system was suspended and has resumed/) {
                $suspend_detected++;
                logmsg("SUSPEND_LOG", $l);
            }
        }
    }

    my $st = read_status();
    $status_samples++;
    my $state = $st->{state} // '?';
    my $blockers = join('; ', @{ $st->{blockers} // [] });
    my $strata = '';
    for my $d (@{ $st->{detectors} // [] }) {
        next unless ($d->{name} // '') eq 'strata';
        $strata = $d->{state} // '?';
        $strata_ever_bad++ if $strata ne 'ok';
    }
    if ($strata ne '' && $strata ne $strata_last_state) {
        $strata_last_state = $strata;
        logmsg("STRATA_STATE", "state=$strata");
    }
    if ($state ne $last_state || $blockers ne $last_blockers || $elapsed - $last_status_log >= 30) {
        logmsg("STATUS",
            "state=$state",
            "idle=" . ($st->{idle_s} // '?'),
            "inactive=" . ($st->{inactive_s} // '?'),
            "suspend_in=" . ($st->{suspend_in_s} // '?'),
            "would=" . ($st->{dry_run_suspend_events} // '?'),
            "pause=" . ($st->{pause}{mode} // '?'),
            "strata=$strata",
            "blockers=[$blockers]");
        $last_state = $state;
        $last_blockers = $blockers;
        $last_status_log = $elapsed;
    }

    if ($elapsed - $last_strata_check >= 60) {
        my $alive = ($strata_pid && $strata_pid =~ /^\d+$/ && kill(0, $strata_pid)) ? 1 : 0;
        logmsg("STRATA_CHECK", "pid=$strata_pid", "alive=$alive", "detector=$strata");
        $last_strata_check = $elapsed;
    }

    if (defined $would_at && !defined $success_at) {
        $success_at = $now;
        logmsg("WOULD_SUSPEND", "dry_run_#$would_n", "post_window=${post}s");
    }
    if (defined $success_at && $now - $success_at >= $post) {
        $end_reason = 'would_suspend';
        last;
    }
    if ($elapsed >= $max) {
        $end_reason = 'timeout';
        last;
    }
    sleep(5);
}

my $end_wall = ts();
my $strata_end = cmdout('systemctl', 'is-active', 'strata.service');
my $sleepmgr_end = cmdout('systemctl', 'is-active', 'sleepmgr.service');
my $strata_pid_end = cmdout('systemctl', 'show', 'strata.service', '-p', 'MainPID', '--value');
my $st_end = read_status();

my $strata_end_state = '?';
for my $d (@{ $st_end->{detectors} // [] }) {
    $strata_end_state = $d->{state} if ($d->{name} // '') eq 'strata';
}

my $elapsed_wait = (defined $waiting_at && defined $would_at) ? ($would_at - $waiting_at) : undef;
my $target_wait  = defined $waiting_in ? parse_dur($waiting_in) : undef;
my $timing_ok    = 0;
if (defined $elapsed_wait) {
    my $target = defined $target_wait ? $target_wait : 600;
    $timing_ok = (abs($elapsed_wait - $target) <= 15) ? 1 : 0;
}

my $mode       = $st_end->{mode} // '?';
my $armed      = $st_end->{service}{armed} ? 1 : 0;
my $allow      = $st_end->{service}{allow_unattended_suspend} ? 1 : 0;
my $pause_mode = $st_end->{pause}{mode} // '?';
my $paused     = $st_end->{pause}{paused} ? 1 : 0;
my $would_total = $st_end->{dry_run_suspend_events} // 0;

my $strata_ok = ($strata_end eq 'active' && $strata_end_state eq 'ok' && !$strata_ever_bad) ? 1 : 0;
my $no_suspend = ($suspend_detected == 0 && $sleepmgr_end eq 'active') ? 1 : 0;

my $pass = (defined $waiting_at && defined $countdown_at && defined $would_at
            && $input_resets == 0 && $blocked_after_wait == 0 && $final_failed == 0
            && $timing_ok && $strata_ok && $no_suspend
            && $mode eq 'dry-run' && !$armed && !$allow
            && $pause_mode eq 'auto' && !$paused && $would_total >= 1) ? 1 : 0;

my $verdict = $pass ? 'PASS' : 'FAIL';
logmsg("END", "reason=$end_reason", "verdict=$verdict",
       "elapsed_wait=" . (defined $elapsed_wait ? sprintf('%.1fs', $elapsed_wait) : 'n/a'),
       "target=" . (defined $target_wait ? "${target_wait}s" : 'n/a'));

open(my $S, '>', "$outdir/summary.txt") or die "summary: $!";
print $S "sleepmgr 10-minute inactivity test\n";
print $S "==================================\n\n";
print $S "Result: $verdict\n";
print $S "Watcher start: " . strftime('%Y-%m-%dT%H:%M:%S%z', localtime($start_wall)) . "\n";
print $S "Watcher end:   $end_wall\n";
print $S "End reason:    $end_reason\n\n";

print $S "Timing\n";
print $S "------\n";
print $S "Timer start (waiting line): " . (defined $waiting_at ? strftime('%Y-%m-%dT%H:%M:%S%z', localtime($waiting_at)) : 'not seen') . "\n";
print $S "  monitor said: suspend in " . ($waiting_in // 'n/a') . "\n";
print $S "Final countdown (30s):     " . (defined $countdown_at ? strftime('%Y-%m-%dT%H:%M:%S%z', localtime($countdown_at)) : 'not seen') . "\n";
print $S "WOULD SUSPEND:             " . (defined $would_at ? strftime('%Y-%m-%dT%H:%M:%S%z', localtime($would_at)) : 'not seen') . "\n";
print $S "Measured wait start->would: " . (defined $elapsed_wait ? sprintf('%.1f s', $elapsed_wait) : 'n/a') . "\n";
print $S "Expected (monitor):        " . (defined $target_wait ? "${target_wait} s" : 'n/a') . "\n";
print $S "Timing within +/-15s:      " . ($timing_ok ? 'yes' : 'no') . "\n";
print $S "Input resets after start:  $input_resets\n";
print $S "Blocks after start:        $blocked_after_wait\n";
print $S "Final-check failures:      $final_failed\n\n";

print $S "Safety / dry-run\n";
print $S "----------------\n";
print $S "Mode:                      $mode\n";
print $S "Armed:                     $armed\n";
print $S "allow_unattended_suspend:  $allow\n";
print $S "Pause mode:                $pause_mode (paused=$paused)\n";
print $S "dry-run suspend events:    $would_total\n";
print $S "Actual suspend detected:   " . ($suspend_detected ? "YES ($suspend_detected)" : 'no') . "\n";
print $S "sleepmgr after:            $sleepmgr_end\n\n";

print $S "Strata\n";
print $S "------\n";
print $S "strata.service before:     $strata_active (pid $strata_pid)\n";
print $S "strata.service after:      $strata_end (pid $strata_pid_end)\n";
print $S "strata detector start:     $strata_start_state\n";
print $S "strata detector end:       $strata_end_state\n";
print $S "strata ever non-ok:        " . ($strata_ever_bad ? "yes ($strata_ever_bad samples)" : 'no') . "\n\n";

print $S "Checks\n";
print $S "------\n";
for my $c (
    ["timer start observed", defined $waiting_at],
    ["final 30s countdown observed", defined $countdown_at],
    ["WOULD SUSPEND observed", defined $would_at],
    ["timing ~= 600s", $timing_ok],
    ["no input reset", $input_resets == 0],
    ["no blocker after start", $blocked_after_wait == 0],
    ["no final-check failure", $final_failed == 0],
    ["strata running/healthy", $strata_ok],
    ["no actual suspend", $no_suspend],
    ["dry-run", $mode eq 'dry-run'],
    ["not armed", !$armed],
    ["unattended suspend disabled", !$allow],
    ["auto (not paused)", $pause_mode eq 'auto' && !$paused],
) {
    printf $S "  %-32s %s\n", $c->[0], ($c->[1] ? 'PASS' : 'FAIL');
}
close $S;

# Snapshots for review.
copy('/var/log/sleepmgr/monitor.log', "$outdir/monitor.log.snapshot");
copy('/var/log/sleepmgr/control.log', "$outdir/control.log.snapshot");
copy('/etc/sleepmgr/config.json', "$outdir/config.json.snapshot");
open(my $SS, '>', "$outdir/status-start.json");
print $SS JSON::PP->new->pretty->encode($st_start);
close $SS;
open(my $SE, '>', "$outdir/status-end.json");
print $SE JSON::PP->new->pretty->encode($st_end);
close $SE;
open(my $SY, '>', "$outdir/system.txt");
print $SY "date: " . cmdout('date', '-Is') . "\n";
print $SY "uptime: " . cmdout('uptime') . "\n";
print $SY "sleepmgr.service: " . cmdout('systemctl', 'show', 'sleepmgr.service', '-p', 'ActiveState,SubState,MainPID,User') . "\n";
print $SY "strata.service: " . cmdout('systemctl', 'show', 'strata.service', '-p', 'ActiveState,SubState,MainPID') . "\n";
print $SY "inhibitors:\n" . cmdout('systemd-inhibit', '--list', '--no-pager') . "\n";
close $SY;
open(my $ST, '>', "$outdir/strata.txt");
print $ST cmdout('systemctl', 'status', 'strata.service', '--no-pager', '-n', '5') . "\n";
close $ST;

close $LOG;
exit($pass ? 0 : 1);
