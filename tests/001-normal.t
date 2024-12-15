#!/usr/bin/perl

use warnings;
use strict;

use File::Basename;
use Test::More tests => 24;
use Digest::SHA qw(sha1_hex);

use lib (dirname($0));
use nrpe;

my @output;

@output = `$nrpe -V`;
is($?, 3 << 8, 'nrpe executes');
like($output[0], qr/NRPE - Nagios Remote Plugin Executor/, 'nrpe banner');

@output = `$checknrpe -V`;
is($?, 3 << 8, 'check_nrpe executes');
like($output[0], qr/NRPE Plugin for Nagios/, 'check_nrpe banner');


check_if_port_available();
launch_daemon("--config configs/normal.cfg");


@output = `$checknrpe -H 127.0.0.1 -p 40321`;
is($?, STATE_OK, 'version check') || diag @output;
like($output[0], qr/NRPE v.*/, 'version check response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321 -2`;
is($?, STATE_OK, 'version check - v2 packet') || diag @output;
like($output[0], qr/NRPE v.*/, 'version check response - v2 packet') || diag @output;

# Note: Server may fail v3 packet and we'll retry with a v2 packet. Could check log for difference if we care.
@output = `$checknrpe -H 127.0.0.1 -p 40321 -3`;
is($?, STATE_OK, 'version check - v3 packet') || diag @output;
like($output[0], qr/NRPE v.*/, 'version check response - v3 packet') || diag @output;

# Source address not allowed
# CHECK_NRPE: Error - Could not connect to 127.0.0.1: Connection reset by peer
@output = `$checknrpe -H 127.0.0.1 -p 40321 -b 127.0.0.2`;
is($?, STATE_CRITICAL, 'invalid source ip') || diag @output;
like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: Connection reset by peer/, 'invalid source ip response') || diag @output;

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c lorem_10000`;
    is($?, STATE_OK, "10,000 byte test exec") || diag @output && skip 'failed exec', 1;

    is(sha1_hex(@output), '2ed4d81e96262f2b08441c1f819166209a2f5337', '10,000 byte test result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c lorem_60000`;
    is($?, STATE_OK, "60,000 byte test exec") || diag @output && skip 'failed exec', 1;

    is(sha1_hex(@output), '2ad3e654c043773c309321d8fb62232833510b8f', '60,000 byte test result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c lorem_70000`;
    is($?, STATE_OK, "70,000 byte test exec") || diag @output && skip 'failed exec', 1;

    # Note: We're expecting the output to be trimmed to 64k.
    is(sha1_hex(@output), 'af05e7c515f21dd9b6944e9b092bf1691ae47050', '70,000 byte test result');
}

@output = `$checknrpe -H 127.0.0.1 -p 40321 -c invalid_command`;
is($?, STATE_UNKNOWN, 'invalid command');
like($output[0], qr/NRPE: Command 'invalid_command' not defined/, 'invalid command response');

@output = `$checknrpe -H 127.0.0.1 -p 40321 -c nonexistent`;
is($?, STATE_UNKNOWN, 'nonexistent command');
like($output[0], qr/NRPE: Unable to read output/, 'nonexistent command response');

@output = `$checknrpe -H 127.0.0.1 -p 40321 -c timeout`;
is($?, STATE_UNKNOWN, 'timeout command');
like($output[0], qr/NRPE: Command timed out after 5 seconds/, 'timeout command response');

done_testing();
