#!/usr/bin/perl

use warnings;
use strict;
BEGIN {
    use File::Basename;
    use lib (dirname(__FILE__));
}

use Test::More;
use nrpe;

my @output;

if (!supports_ssl()) {
    plan skip_all => 'SSL/TLS support unavailable.';
}

plan tests => 8;


ensure_daemon_running();
switch_config_file("configs/nossl.cfg");
restart_daemon();


@output = `$checknrpe -H 127.0.0.1 -p 40321`;
is($?, STATE_UNKNOWN, 'connect ssl') || diag @output;
like($output[0], qr/CHECK_NRPE:.* Error - Could not .*: /, 'connect ssl response') || diag @output;


@output = `$checknrpe -H 127.0.0.1 -p 40321 --no-ssl`;
is($?, STATE_OK, 'connect without ssl') || diag @output;
like($output[0], qr/NRPE v.*/, 'connect without ssl response') || diag @output;


@output = `$checknrpe -H 127.0.0.1 -p 40321 --no-ssl -2`;
is($?, 0, 'version check - v2 packet') || diag @output;
like($output[0], qr/NRPE v.*/, 'version check response - v2 packet') || diag @output;

# Note: Server may fail v3 packet and we'll retry with a v2 packet. Could check log for difference if we care.
@output = `$checknrpe -H 127.0.0.1 -p 40321 --no-ssl -3`;
is($?, 0, 'version check - v3 packet') || diag @output;
like($output[0], qr/NRPE v.*/, 'version check response - v3 packet') || diag @output;


done_testing();
