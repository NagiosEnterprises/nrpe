#!/usr/bin/perl

use warnings;
use strict;
BEGIN {
    use File::Basename;
    use lib (dirname(__FILE__));
}

use IO::Select;
use IO::Socket;
use IO::Socket::SSL;
use Test::More;
use nrpe;

my @response;

if (!supports_ssl()) {
    plan skip_all => 'SSL/TLS support unavailable.';
}

plan tests => 16;


ensure_daemon_running();
switch_config_file("configs/ssl.cfg");
restart_daemon();


# v4
@response = send_request('port' => 40321);
is_response(\@response, 'v4 version check');

@response = send_request('port' => 40321, 'length' => +10);
is_response(\@response, 'v4 version check - large');

@response = send_request('port' => 40321, 'length' => -10);
isnt_response(\@response, "v4 version check - short");   # Expected failure - server read timeout

@response = send_request('port' => 40321, 'crc' => 0);
isnt_response(\@response, "v4 version check - invalid crc");   # Expected failure - crc

@response = send_request('port' => 40321, 'type' => 20);
isnt_response(\@response, "v4 version check - invalid type");   # Expected failure - invalid type

# v3
@response = send_request('port' => 40321, 'version' => 3);
isnt_response(\@response, 'v3 version check');  # Expected failure

# v2
@response = send_request('port' => 40321, 'version' => 2);
is_response(\@response, 'v2 version check', 'version' => 2);



# SSL/TLS Connection/Handshake Timeout
SKIP: {
    my $client = IO::Socket->new(
            Domain => AF_INET,
            Type => SOCK_STREAM,
            proto => 'tcp',
            PeerHost => 'localhost',
            PeerPort => 40321,
        ) || skip 'failed create socket', 1;

    my $sel = IO::Select->new( $client );
    my @c = $sel->can_read(15);
    is(@c, 1, 'SSL/TLS Handshake timeout');
    $client->close();
}

# SSL/TLS short header - result (less than common)
send_and_wait_for_timeout(pack('n!n!N! ', 4, 1, 0), 'v4 missing result');

# SSL/TLS short header - alignment
send_and_wait_for_timeout(pack('n!n!N!n! ', 4, 1, 0, 0), 'v4 missing alignmnet');

# SSL/TLS short header - buffer size
send_and_wait_for_timeout(pack('n!n!N!n! n!', 4, 1, 0, 0, 0), 'v4 buffer size');

# SSL/TLS large buffer size
send_and_wait_for_timeout(pack('n!n!N!n! n! N!', 4, 1, 0, 0, 0, 75*1024), 'v4 large buffer size', 'timeout' => 0);


done_testing();
