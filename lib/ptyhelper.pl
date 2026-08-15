#!/usr/bin/perl
# Real pty allocation for bridge.mjs, in pure core Perl (5.8+): POSIX, IO::Select,
# Errno, Fcntl. No CPAN, no native build, nothing added to package.json.
#
# Why a helper process at all: node-pty is a native dependency and package.json
# must stay dependency-free, and BSD script(1) — the obvious zero-dep alternative —
# cannot resize. Measured: with a program owning the tty, `stty size` under
# script(1) reports "0 0" and an injected `stty rows/cols` is consumed as the
# program's stdin and merely echoed, so pty_resize would report success it had not
# achieved. This helper owns /dev/ptmx directly and every resize is a real
# TIOCSWINSZ verified by a TIOCGWINSZ read-back.
#
# fd 0 : raw bytes -> pty master   (keystrokes, including 0x03 for ^C)
# fd 1 : raw bytes <- pty master   (screen output, verbatim, never escaped)
# fd 2 : JSON status lines, one per line
# fd 3 : control channel, line-delimited JSON. Every op may carry "id":N and the
#        acknowledgement echoes it back, so a caller matches its OWN answer:
#          {"op":"resize","cols":N,"rows":N,"id":N}
#          {"op":"signal","sig":"INT","id":N}   -> kill(-leaderpid)
#          {"op":"termios","id":N}              -> report ICANON on the slave
#          {"op":"eof","id":N}                  -> inject 0x04 through the line discipline
#
# argv: COLS ROWS -- command args...
use strict;
use warnings;
no warnings 'exec';
use POSIX qw(setsid dup2 _exit WNOHANG);
use IO::Select;
use Errno qw(EINTR EIO EAGAIN);
use Fcntl qw(O_RDWR O_NOCTTY);

# Darwin ioctl request codes, from <sys/ttycom.h> on this machine. They are
# hardcoded numbers, which is why bridge.mjs runs a startup self-test that
# resizes and reads the size back: a renumbering must surface as an absent
# feature, not as a pty that silently ignores its geometry.
use constant TIOCPTYGRANT => 0x20007454;
use constant TIOCPTYUNLK  => 0x20007452;
use constant TIOCPTYGNAME => 0x40807453;
use constant TIOCSCTTY    => 0x20007461;
use constant TIOCSWINSZ   => 0x80087467;   # slave fd only on Darwin; ENOTTY on the master
use constant TIOCGWINSZ   => 0x40087468;

use constant CTL_BUF_MAX  => 65536;        # a control line longer than this is a bug or an attack

my ($cols, $rows, $sep) = (shift @ARGV, shift @ARGV, shift @ARGV);
die "usage: ptyhelper.pl COLS ROWS -- cmd args...\n"
  unless defined $sep && $sep eq '--' && @ARGV;
my @cmd = @ARGV;
$cols = 80 unless defined $cols && $cols =~ /^\d+$/ && $cols > 0;
$rows = 24 unless defined $rows && $rows =~ /^\d+$/ && $rows > 0;

$| = 1;

# Status lines are JSON, and $! can contain quotes or backslashes on some errno
# strings. An unescaped one would make the line unparseable, and bridge.mjs would
# read "helper never reported readiness" instead of the real reason it failed.
sub jesc {
    my $s = defined $_[0] ? "$_[0]" : '';
    $s =~ s/\\/\\\\/g;
    $s =~ s/"/\\"/g;
    $s =~ s/[\x00-\x1f]/ /g;
    return $s;
}
sub status { print STDERR '{' . $_[0] . "}\n"; }
sub fatal  { status(qq("event":"fatal","error":") . jesc($_[0]) . qq(")); _exit(70); }

# ---- allocate the pty -------------------------------------------------------
sysopen(my $M, '/dev/ptmx', O_RDWR | O_NOCTTY) or fatal("ptmx: $!");
my $zero = 0;
ioctl($M, TIOCPTYGRANT, $zero) or fatal("grantpt: $!");
ioctl($M, TIOCPTYUNLK,  $zero) or fatal("unlockpt: $!");
my $nbuf = "\0" x 128;
ioctl($M, TIOCPTYGNAME, $nbuf) or fatal("ptsname: $!");
my $pts = unpack('Z128', $nbuf);

# Hold a slave fd open for the whole session. TIOCSWINSZ is rejected with ENOTTY
# on the master on Darwin, so without this fd every resize after start would fail
# and pty_resize could only ever lie.
sysopen(my $S, $pts, O_RDWR | O_NOCTTY) or fatal("slave open: $!");
ioctl($S, TIOCSWINSZ, pack('S4', $rows, $cols, 0, 0)) or fatal("initial winsize: $!");

my $pid = fork();
fatal("fork: $!") unless defined $pid;
if ($pid == 0) {
    # setsid() then TIOCSCTTY makes this child a session and process-group leader,
    # so its pid IS its pgid. Every reclaim path in bridge.mjs signals -leaderPid;
    # without setsid there is no group to signal and the kill silently no-ops.
    setsid() or _exit(126);
    ioctl($S, TIOCSCTTY, $zero) or _exit(126);
    dup2(fileno($S), 0); dup2(fileno($S), 1); dup2(fileno($S), 2);
    close($S) if fileno($S) > 2;
    close($M);
    # Every descriptor above stderr must die with the exec, and fd 3 is the one
    # that matters: it is bridge.mjs's control pipe. Left open here, the session
    # program holds the write end forever, so when the HELPER is killed the pipe
    # never reaches EOF, node's stdio[3] never closes, `child.once("close")` never
    # fires, and the reclaim it performs — the one that exists precisely because
    # `trap '' HUP TERM INT` survives the master-close SIGHUP — never runs.
    # Measured on the shipped code: after `pkill -f ptyhelper.pl` the leader was
    # still alive at t=20s, reparented to pid 1, while bridge_status reported
    # exited:false. The same child with fd 3 closed is detected in under 2.5s.
    POSIX::close($_) for 3 .. 63;
    exec { $cmd[0] } @cmd;
    # stdout/stderr are the tty here, so a failed exec is visible in the session
    # transcript rather than vanishing behind a bare exit 127.
    print STDERR "ptyhelper: cannot execute $cmd[0]: $!\r\n";
    _exit(127);
}

status(qq("event":"started","pid":$pid,"pts":") . jesc($pts) . qq(","cols":$cols,"rows":$rows));

open(my $CTL, '+<&=3') or fatal("ctl fd3: $!");
$SIG{PIPE} = 'IGNORE';

# Never signal a group we cannot own. In Perl as in JS, -0 is 0, and kill(SIG, 0)
# means "my own process group" — which here contains bridge.mjs and, on the tunnel
# transport, tunnel-client. A reclaim path that takes out its own supervisor is
# the containment bug this project has already shipped three times.
sub kill_group {
    my ($sig, $target) = @_;
    return 0 unless defined $target && $target =~ /^\d+$/ && $target > 1;
    return kill($sig, -$target) ? 1 : 0;
}

# ---- controlling-terminal sweep ---------------------------------------------
#
# A process-GROUP kill does not contain a pty session. Interactive job control
# puts every `cmd &` in its OWN pgid, so kill(-leader) reaches the leader and its
# foreground children and nothing else. bridge.mjs documents the same measurement
# and sweeps the controlling terminal for exactly this reason — but on THIS path
# the bridge is already dead, so nothing in bridge.mjs can run. Measured on the
# shipped helper: `nohup sleep 940 &` in an interactive shell survived a SIGKILLed
# bridge, reparented to pid 1, with teardown('parent_gone') reporting success.
#
# What every descendant keeps is the controlling terminal, and this process holds
# the master fd, so /dev/ttysNNN is unambiguously this session's device and cannot
# have been recycled to somebody else's session.
#
# ORDER MATTERS, and not the obvious way: the scan must happen while the LEADER is
# still alive. Measured on this machine, the instant the session leader exits
# Darwin revoke()s the terminal — `ps -t /dev/ttys001` then fails with "No such
# file or directory" and the survivor's tty reads as "??", and that is already
# true at the moment this helper reaps the leader, master fd still in hand. A
# sweep performed only after the group kill would therefore find nothing at all.
# So membership is RECORDED first and SIGNALLED after the group kill, and each pid
# is re-verified against its recorded start time before anything is sent to it: a
# pid whose start time changed is somebody else now, and killing it would be the
# recycled-pid mistake in a new costume.
use constant TTY_SCAN_MAX  => 64;    # same cap bridge.mjs uses; a session with more is pathological
use constant PS_WAIT_TICKS => 10;    # x 0.2s: ps is a fork on the path between the bridge's death and _exit

my @tty_targets;                     # [pid, lstart] recorded while the leader lives

# Bounded, and never left running. A wedged ps must not hold an unrestricted
# session open, so it is given PS_WAIT_TICKS and then killed — it is a child of
# this process, so the pid is unambiguously ours to signal.
sub ps_rows {
    my (@args) = @_;
    my $ps_pid = open(my $ph, '-|', '/bin/ps', @args);
    return () unless defined $ps_pid && $ps_pid > 1;
    my $out = '';
    my $sel_ps = IO::Select->new($ph);
    for (1 .. PS_WAIT_TICKS) {
        next unless $sel_ps->can_read(0.2);
        my $chunk;
        my $n = sysread($ph, $chunk, 65536);
        if (!defined $n) { next if $! == EINTR || $! == EAGAIN; last; }
        last if $n == 0;
        $out .= $chunk;
        last if length($out) > 1_000_000;
    }
    kill('KILL', $ps_pid) if kill(0, $ps_pid);
    waitpid($ps_pid, 0);
    close($ph);
    return grep { /\S/ } split(/\n/, $out);
}

sub snapshot_tty_members {
    return unless defined $pts && $pts =~ m{^/dev/tty[a-z0-9]{1,12}$};
    for my $row (ps_rows('-t', $pts, '-o', 'pid=,lstart=')) {
        my ($p, $lstart) = $row =~ /^\s*(\d+)\s+(\S.*?)\s*$/ or next;
        next if $p <= 1 || $p == $$ || $p == $pid;
        last if @tty_targets >= TTY_SCAN_MAX;
        push @tty_targets, [$p, $lstart];
    }
}

sub kill_tty_stragglers {
    my (@killed, @skipped);
    return (\@killed, \@skipped) unless @tty_targets;
    my @alive = grep { kill(0, $_->[0]) } @tty_targets;
    return (\@killed, \@skipped) unless @alive;
    # `ps -p` still works after the terminal is revoked; `ps -t` does not.
    my %now;
    for my $row (ps_rows('-o', 'pid=,lstart=', '-p', join(',', map { $_->[0] } @alive))) {
        my ($p, $l) = $row =~ /^\s*(\d+)\s+(\S.*?)\s*$/ or next;
        $now{$p} = $l;
    }
    for my $target (@alive) {
        my ($p, $lstart) = @$target;
        my $current = $now{$p};
        next unless defined $current;              # exited between the two calls
        if ($current ne $lstart) { push @skipped, $p; next; }
        next unless $p > 1 && $p != $$ && $p != $pid;
        push @killed, $p if kill('KILL', $p);
    }
    return (\@killed, \@skipped);
}

my $sel = IO::Select->new($M, \*STDIN, $CTL);
my ($stdin_open, $reported, $ctlbuf) = (1, 0, '');

sub pump_master {
    my $buf;
    my $n = sysread($M, $buf, 65536);
    if (!defined $n) { return 1 if $! == EINTR || $! == EAGAIN; return 0; }  # EIO => tty gone
    return 0 if $n == 0;
    syswrite(STDOUT, $buf);
    return 1;
}

sub teardown {
    my ($why) = @_;
    status(qq("event":"teardown","reason":") . jesc($why) . qq(","pid":$pid));
    # Recorded BEFORE anything is signalled: the leader must still be alive for
    # the terminal to be scannable at all. See the sweep comment above.
    snapshot_tty_members();
    kill_group('TERM', $pid);
    for (1 .. 100) {                       # up to ~2s for a graceful exit
        last if waitpid($pid, WNOHANG) == $pid;
        select(undef, undef, undef, 0.02);
    }
    if (kill_group(0, $pid)) { kill_group('KILL', $pid); waitpid($pid, 0); }
    # Then everything else that shared this session's controlling terminal: the
    # background jobs job control put in their own process groups, which the group
    # kill above cannot reach.
    my ($killed, $skipped) = kill_tty_stragglers();
    status(qq("event":"tty_sweep","reason":") . jesc($why)
        . qq(,"killed":[) . join(',', @$killed)
        . qq(],"recycled_skipped":[) . join(',', @$skipped) . qq(]));
    status(qq("event":"torndown","reason":") . jesc($why));
    _exit(0);
}

sub reap {
    my $r = waitpid($pid, WNOHANG);
    return 0 unless $r == $pid;
    my $st = $?;
    status(qq("event":"exited","code":) . ($st >> 8) . qq(,"signal":) . ($st & 127));
    $reported = 1;
    # Drain what the line discipline still holds, or the last lines of a command's
    # output are lost exactly when they matter most.
    my $d = IO::Select->new($M);
    while ($d->can_read(0.15)) { last unless pump_master(); }
    return 1;
}

LOOP: while (1) {
    for my $fh ($sel->can_read(0.2)) {
        if ($fh == $M) {
            last LOOP unless pump_master();
        } elsif ($stdin_open && $fh == \*STDIN) {
            my $buf;
            my $n = sysread(STDIN, $buf, 65536);
            if (!defined $n) { next if $! == EINTR; teardown('stdin_error'); }
            # EOF on stdin means the bridge that owns this session is gone —
            # including the case where it was SIGKILLed, which no in-process
            # revocation path can cover. It can NEVER mean "the model wants to
            # send ^D": that is the explicit {"op":"eof"} control op, precisely so
            # this signal stays unambiguous. An orphaned pty is an unrestricted
            # shell that outlives revocation.
            if ($n == 0) { teardown('parent_gone'); }
            syswrite($M, $buf);
        } elsif ($fh == $CTL) {
            my $buf;
            my $n = sysread($CTL, $buf, 65536);
            if (!defined $n || $n == 0) { $sel->remove($CTL); next; }
            $ctlbuf .= $buf;
            # Bounded: an unterminated control line must not grow this process
            # without limit.
            if (length($ctlbuf) > CTL_BUF_MAX) {
                status(qq("event":"control_overflow","bytes":) . length($ctlbuf));
                $ctlbuf = '';
                next;
            }
            while ($ctlbuf =~ s/^([^\n]*)\n//) {
                my $line = $1;
                next unless $line =~ /\S/;
                # Every acknowledgement carries back the request id it answers.
                # Matching acks to callers by event KIND alone made four concurrent
                # resizes each report their own geometry as confirmed when only one
                # of them was the kernel's actual winsize.
                my ($rid) = $line =~ /"id"\s*:\s*(\d+)/;
                $rid = 0 unless defined $rid;
                if ($line =~ /"op"\s*:\s*"resize"/) {
                    my ($c) = $line =~ /"cols"\s*:\s*(\d+)/;
                    my ($r) = $line =~ /"rows"\s*:\s*(\d+)/;
                    next unless $c && $r;
                    my $ok = ioctl($S, TIOCSWINSZ, pack('S4', $r, $c, 0, 0)) ? 1 : 0;
                    # Report the kernel's own read-back, never the request. A
                    # resize that reports the numbers it was asked for cannot be
                    # distinguished from one that did nothing.
                    my $g = "\0" x 8;
                    my $got = ioctl($S, TIOCGWINSZ, $g) ? 1 : 0;
                    my ($gr, $gc) = $got ? unpack('S2', $g) : (0, 0);
                    status(qq("event":"resize","id":$rid,"ok":$ok,"confirmed":$got,"rows":$gr,"cols":$gc));
                } elsif ($line =~ /"op"\s*:\s*"signal"/) {
                    my ($s) = $line =~ /"sig"\s*:\s*"([A-Z0-9]+)"/;
                    $s = 'TERM' unless defined $s && length $s;
                    my $sent = kill_group($s, $pid);
                    status(qq("event":"signal","id":$rid,"sig":") . jesc($s) . qq(","delivered":$sent));
                } elsif ($line =~ /"op"\s*:\s*"termios"/) {
                    # Reports the line discipline's real state, read from the
                    # kernel. In canonical mode the tty DISCARDS an entire line at
                    # or over MAX_CANON (1024 on Darwin) rather than truncating it,
                    # so a write of that size reaches the program as zero bytes.
                    # bridge.mjs cannot know which mode the program has selected —
                    # `stty raw` is invisible from outside — so it asks.
                    my $tio = POSIX::Termios->new;
                    my $got_tio = $tio->getattr(fileno($S)) ? 1 : 0;
                    my $icanon = ($got_tio && ($tio->getlflag & POSIX::ICANON())) ? 1 : 0;
                    status(qq("event":"termios","id":$rid,"ok":$got_tio,"icanon":$icanon));
                } elsif ($line =~ /"op"\s*:\s*"eof"/) {
                    syswrite($M, "\x04");
                    status(qq("event":"eof","id":$rid));
                }
            }
        }
    }
    last LOOP if reap();
}

# Darwin revoke()s the controlling terminal when the session leader exits, which
# invalidates even this process's slave fd. So master-EOF routinely arrives BEFORE
# waitpid() can reap, and a single WNOHANG here reported "detached" for processes
# that had in fact exited cleanly. Wait, bounded, for the real status.
unless ($reported) {
    my $deadline = time() + 5;
    while (time() < $deadline) {
        last if reap();
        select(undef, undef, undef, 0.02);
    }
}
status(qq("event":"detached","pid":$pid)) unless $reported;
exit 0;
