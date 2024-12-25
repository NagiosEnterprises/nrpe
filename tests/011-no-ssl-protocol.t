#!/usr/bin/perl

use warnings;
use strict;
BEGIN {
    use File::Basename;
    use lib (dirname(__FILE__));
}

use Test::More;
use nrpe;

my @response;

#if (!supports_ssl()) {
#    plan skip_all => 'SSL/TLS support unavailable.';
#}

plan tests => 9;


ensure_daemon_running();
switch_config_file("configs/nossl.cfg");
restart_daemon();


# v4
@response = send_request('port' => 40321, 'ssl' => 0);
is_response(\@response, 'v4 version check');

@response = send_request('port' => 40321, 'ssl' => 0, 'length' => +10);
is_response(\@response, 'v4 version check - large');

@response = send_request('port' => 40321, 'ssl' => 0, 'length' => -10);
isnt_response(\@response, "v4 version check - short");   # Expected failure - server read timeout

@response = send_request('port' => 40321, 'ssl' => 0, 'crc' => 0);
isnt_response(\@response, "v4 version check - invalid crc");   # Expected failure - crc

@response = send_request('port' => 40321, 'ssl' => 0, 'type' => 20);
isnt_response(\@response, "v4 version check - invalid type");   # Expected failure - invalid type

# v3
@response = send_request('port' => 40321, 'version' => 3, 'ssl' => 0);
isnt_response(\@response, "v3 version check");   # Expected failure

# v2
@response = send_request('port' => 40321, 'version' => 2, 'ssl' => 0);
is_response(\@response, 'v2 version check', 'version' => 2);

@response = send_request('port' => 40321, 'version' => 2, 'ssl' => 0, 'length' => +10);
is_response(\@response, 'v2 version check - large', 'version' => 2);

@response = send_request('port' => 40321, 'version' => 2, 'ssl' => 0, 'length' => -10);
isnt_response(\@response, "v2 version check - short");   # Expected failure

done_testing();
