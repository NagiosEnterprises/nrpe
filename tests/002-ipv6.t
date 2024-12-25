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

if (!check_if_ipv6_available()) {
    plan skip_all => 'IPv6 unavailable.';
}

plan tests => 12;


ensure_daemon_running();
switch_config_file("configs/ipv6.cfg");
restart_daemon();


@output = `$checknrpe -H ::1 -p 40321`;
is($?, STATE_OK, 'connection ipv6') || diag @output;
like($output[0], qr/NRPE v.*/, 'connection ipv6 response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321`;
is($?, STATE_OK, 'connection ipv4 on ipv6') || diag @output;
like($output[0], qr/NRPE v.*/, 'connection ipv4 on ipv6 response') || diag @output;

# ipv6.conf has a command_prefix of /bin/echo
@output = `$checknrpe -H ::1 -p 40321 -c timeout`;
is($?, STATE_OK, 'timeout (echo)') || diag @output;
like($output[0], qr'checks/timeout', 'timeout (echo) response') || diag @output;

#####################################################################################

switch_config_file("configs/ipv6-only.cfg");
restart_daemon();


@output = `$checknrpe -H ::1 -p 40321`;
is($?, STATE_OK, 'connection ipv6 only') || diag @output;
like($output[0], qr/NRPE v.*/, 'connection ipv6 only response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321 --stderr-to-stdout`;
is($?, STATE_CRITICAL, 'connection ipv4 on ipv6 only') || diag @output;
like($output[0], qr/connect to .*: Connection refused/, 'connection ipv6 only response') || diag @output;

#####################################################################################

switch_config_file("configs/ipv6-disallowed.cfg");
restart_daemon();


@output = `$checknrpe -H ::1 -p 40321`;
is($?, STATE_UNKNOWN, 'connection ipv6 disallowed') || diag @output;
like($output[0], qr/CHECK_NRPE:.* Error - Could not .*: /, 'connection ipv6 disallowed response') || diag @output;

#####################################################################################

done_testing();
