package nrpe;
use strict;
use warnings;

require Exporter;

use Digest::CRC qw( crc32 );
use IO::Socket;
use IO::Socket::SSL;
use Socket;
use Test::More;

our @ISA= qw( Exporter );

# these CAN be exported.
our @EXPORT_OK = qw( check_if_port_available check_if_ipv6_available supports_ssl
        switch_config_file launch_daemon restart_daemon kill_daemon ensure_daemon_running
        send_request send_and_wait_for_timeout is_response isnt_response
        STATE_OK STATE_WARNING STATE_CRITICAL STATE_UNKNOWN
        $nrpe $checknrpe );

# these are exported by default.
our @EXPORT = qw( check_if_port_available check_if_ipv6_available supports_ssl
        switch_config_file launch_daemon restart_daemon kill_daemon ensure_daemon_running
        send_request send_and_wait_for_timeout is_response isnt_response
        STATE_OK STATE_WARNING STATE_CRITICAL STATE_UNKNOWN
        $nrpe $checknrpe );

defined($ARGV[0]) or die "Usage: $0 <top build dir>";

my $top_builddir = $ARGV[0]; # shift @ARGV;
our $nrpe = "$top_builddir/src/nrpe";
our $checknrpe = "$top_builddir/src/check_nrpe --disable-syslog";
#our $checknrpe = "valgrind --leak-check=full --log-file=logs/valgrind-check-%p.log $top_builddir/src/check_nrpe --disable-syslog";
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

sub check_connection {
    if (socket(my $s, AF_INET, SOCK_STREAM, Socket::IPPROTO_TCP)) {
        my $a = connect($s, pack_sockaddr_in(40321, inet_aton("127.0.0.1")));
        close $s;
        return 1 if defined $a;
    }
    if (socket(my $s, AF_INET6, SOCK_STREAM, Socket::IPPROTO_TCP)) {
        my $a = connect($s, pack_sockaddr_in6(40321, Socket::inet_pton(AF_INET6, "::1")));
        close $s;
        return 1 if defined $a;
    }
    return 0;
}

sub check_if_ipv6_available {
    socket(my $s, AF_INET6, SOCK_STREAM, Socket::IPPROTO_TCP) || return 0;
    return 1;
}

sub check_if_port_available {
    BAIL_OUT('Something is already listening on our port 40321') if check_connection();
}

sub switch_config_file {
    my $filename = shift @_;
    unlink 'nrpe.cfg';
    symlink($filename, 'nrpe.cfg') || BAIL_OUT('Unable to update config symlink');
}

sub wait_for_daemon {
    my $counter = 0;
    while (!check_connection() && $counter < 15) {
        sleep(1);
        $counter++;
    }
    diag("Waiting $counter seconds for daemon") if $counter > 7;
}

sub launch_daemon {
    my @output = `$nrpe --daemon --dont-chdir --config nrpe.cfg`;
#    my @output = `valgrind --leak-check=full --show-leak-kinds=all --log-file=logs/valgrind-%p.log $nrpe --daemon --dont-chdir --config nrpe.cfg`;
    my $pid = 0;

    my $counter = 0;
    while ( ($pid = read_pid()) == 0 && $counter < 10) {
        sleep(1);
        $counter++;
    }
    diag(@output);
    BAIL_OUT('Unable to get nrpe daemon pid') if $pid == 0;
    note("started daemon on $pid");
    $nrpe_pid = $pid;

    wait_for_daemon();
    return $pid
}

sub ensure_daemon_running {
    my $pid = read_pid() || BAIL_OUT('daemon is not running');
    kill 0, $pid || BAIL_OUT('daemon is not running');
    $nrpe_pid = $pid;
}

sub restart_daemon {
    if ($nrpe_pid > 0) {
        note("restarting daemon on $nrpe_pid");
        kill 'HUP', $nrpe_pid;
        sleep(1);
        wait_for_daemon();
    } else {
        diag('pid for nrpe daemon unknown');
    }
    return 0;
}

sub kill_daemon {
    if ($nrpe_pid > 0) {
        note("killing daemon on $nrpe_pid");
        kill 'TERM', $nrpe_pid;
        $nrpe_pid = 0;
        sleep(1);
    }
    return 0;
}

sub supports_ssl {
    my @output = `$nrpe --help`;
    return grep(m'^SSL/TLS Available', @output);
}

################################################################################

sub send_request {
    my (%arg) = (
        'host' => 'localhost',
        'port' => 5666,
        'version' => 4,
        'type' => 1,
        'crc' => 1,
        'command' => '_NRPE_CHECK',
        'length' => 0,
        'ssl' => 1,
        @_
    );

    my $client;
    my $buffer;

    if ($arg{'ssl'}) {
        $client = IO::Socket::SSL->new(
            PeerHost => $arg{'host'},
            PeerPort => $arg{'port'},
            SSL_verify_mode => SSL_VERIFY_NONE,
        ) or diag("error=$!, ssl_error=$SSL_ERROR") and return ();
    } else {
        $client = IO::Socket->new(
            Domain => AF_INET,
            Type => SOCK_STREAM,
            proto => 'tcp',
            PeerHost => $arg{'host'},
            PeerPort => $arg{'port'},
        ) or diag("error=$!") and return ();
    }

    if ($arg{'version'} == 2) {
        $buffer = pack('n!n!N!n! Z[1024] x![N]', $arg{'version'}, $arg{'type'}, 0, 0, $arg{'command'} );
    } else {
        $buffer = pack('n!n!N!n! n!N!/Z', $arg{'version'}, $arg{'type'}, 0, 0, 0, $arg{'command'} );
    }

    if ($arg{'crc'} == 1) {
        my $d = pack('N!', crc32($buffer));
        substr($buffer, 4, 4, $d);
    }

    if ($arg{'length'} > 0) {
        $buffer = $buffer . "\0" x $arg{'length'};
    } elsif ($arg{'length'} < 0) {
        $buffer = substr($buffer, 0, $arg{'length'});
    }

#    diag(length($buffer), " - ", unpack("H*", $buffer), "\n");

    print $client $buffer;
    my $response = <$client>;

    if ($arg{'version'} == 2 && defined $response) {
        if (length($response) != 1036) {
            $response .= <$client>;
        }
    }

    $client->close();

    return () if ! defined $response;

    if ($arg{'version'} == 2) {
        return unpack('n!n!N!n! Z[1024]', $response);
    }
    return unpack('n!n!N!n! x[n] N!/Z', $response);
}

sub send_and_wait_for_timeout {
    my ($buffer, $name) = @_;
    my (%arg) = (
        'timeout' => 10,
        @_
    );

    SKIP: {
        my $client = IO::Socket::SSL->new(
                PeerHost => 'localhost',
                PeerPort => 40321,
                SSL_verify_mode => SSL_VERIFY_NONE,
            ) || skip 'failed create socket', 2;

        my $sel = IO::Select->new( $client );
        print $client $buffer;
        my $start = time();

        # SSL/TLS can have readable frames even though the server hasn't sent any data
        # We need to look for read letting us know the server closed the socket.
        $client->blocking(0);
        my $n;
        for (0..20) {
            $sel->can_read(15);
            $n = sysread($client, my $buf, 1);
            if (defined $n and $n <= 0) {
                last;
            }
        }
        my $end = time();
        $client->close();

        is($n, 0, "$name - disconnected");
        if ($arg{'timeout'} == 0) {
            # We're actually looking for an immediate abort
            cmp_ok($end - $start, '<=', 1, "$name - abort");
        } else {
            cmp_ok($end - $start, '>=', $arg{'timeout'}, "$name - timeout");
        }
    }
}


sub is_response {
    my $response = shift;
    my $name = shift;
    my (%arg) = (
        'version' => 4,
        'like' => qr/NRPE v.*/,
        @_
    );

    subtest "$name" => sub {
        plan tests => 5;
        is(@$response, 5, "$name count");

        my ($ver, $type, $crc, $result, $text) = @$response;
        is($ver, $arg{'version'}, "$name - is v$arg{'version'}");
        is($type, 2, "$name - is response");
        is($result, STATE_OK, "$name - result");
        like($text, $arg{'like'}, "$name - text");
    };
}

sub isnt_response {
    my $response = shift;
    my $name = shift;

    is(@$response, 0, "$name");
}

################################################################################

#END {
#    kill_daemon();
#}

sub signal_handler {
    kill_daemon();
}

1;
