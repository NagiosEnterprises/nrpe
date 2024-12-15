#!/usr/bin/perl

use warnings;
use strict;

use File::Basename;
use Test::More tests => 10;

use lib (dirname($0));
use nrpe;

my @output;

check_if_port_available();
launch_daemon("--config configs/ipv6.cfg");


@output = `$checknrpe -H ::1 -p 40321`;
is($?, STATE_OK, 'connection ipv6') || diag @output;
like($output[0], qr/NRPE v.*/, 'connection ipv6 response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321`;
is($?, STATE_OK, 'connection ipv4 on ipv6') || diag @output;
like($output[0], qr/NRPE v.*/, 'connection ipv4 on ipv6 response') || diag @output;

kill_daemon();

#####################################################################################

launch_daemon("--config configs/ipv6.cfg --ipv6");


@output = `$checknrpe -H ::1 -p 40321`;
is($?, STATE_OK, 'connection ipv6 only') || diag @output;
like($output[0], qr/NRPE v.*/, 'connection ipv6 only response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321 2>&1`;
is($?, STATE_CRITICAL, 'connection ipv4 on ipv6 only') || diag @output;
like($output[0], qr/connect to .*: Connection refused/, 'connection ipv6 only response') || diag @output;

kill_daemon();

#####################################################################################

launch_daemon("--config configs/ipv6-disallowed.cfg --ipv6");

@output = `$checknrpe -H ::1 -p 40321`;
is($?, STATE_CRITICAL, 'connection ipv6 disallowed') || diag @output;
like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: Connection reset by peer/, 'connection ipv6 only response') || diag @output;

kill_daemon();

#####################################################################################

done_testing();
