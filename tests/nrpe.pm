package nrpe;
use strict;
use warnings;
use Exporter;
use Socket;
use Test::More;

our @ISA= qw( Exporter );

# these CAN be exported.
our @EXPORT_OK = qw( check_if_port_available launch_daemon kill_daemon
        STATE_OK STATE_WARNING STATE_CRITICAL STATE_UNKNOWN
        $nrpe $checknrpe );

# these are exported by default.
our @EXPORT = qw( check_if_port_available launch_daemon kill_daemon
        STATE_OK STATE_WARNING STATE_CRITICAL STATE_UNKNOWN
        $nrpe $checknrpe );

defined($ARGV[0]) or die "Usage: $0 <top build dir>";

my $top_builddir = $ARGV[0]; # shift @ARGV;
our $nrpe = "$top_builddir/src/nrpe";
our $checknrpe = "$top_builddir/src/check_nrpe";
my $nrpe_pid = 0;

use constant {
    STATE_UNKNOWN => 3 << 8,
    STATE_CRITICAL => 2 << 8,
    STATE_WARNING => 1 << 8,
    STATE_OK => 0 << 8,
};

$SIG{INT}  = \&signal_handler;
$SIG{TERM} = \&signal_handler;

sub read_pid {
    open my $fh, '<', "run/nrpe.pid" or return 0;
    chomp( my $pid = <$fh> );
    return $pid
}

sub check_if_port_available {
    socket(my $s, PF_INET, SOCK_STREAM, Socket::IPPROTO_TCP) || die 'failed to create socket';
    my $a = connect($s, pack_sockaddr_in(40321, inet_aton("127.0.0.1")));
    close $s;
    BAIL_OUT('Something is already listening on our port 40321') if defined $a;
}

sub launch_daemon {
    my @args = @_;
    my @output = `$nrpe --daemon --dont-chdir @args`;
    my $pid = read_pid();
    if ($pid == 0) {
        # wait for startup
        sleep(3);
        $pid = read_pid();
    }
    diag(@output);
    BAIL_OUT('Unable to get nrpe daemon pid') if $pid == 0;
    note("started daemon on $pid");
    $nrpe_pid = $pid;
    return $pid
}

END {
    kill_daemon();
}

sub signal_handler {
    kill_daemon();
}

sub kill_daemon {
    if ($nrpe_pid > 0) {
        note("killing daemon on $nrpe_pid");
        kill 'TERM', $nrpe_pid;
        $nrpe_pid = 0;
    }
    return 0;
}

1;
