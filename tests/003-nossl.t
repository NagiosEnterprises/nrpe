#!/usr/bin/perl

use warnings;
use strict;

use Digest::SHA qw(sha1_hex);
use File::Basename;
use Test::More tests => 8;

use lib (dirname($0));
use nrpe;

my @output;


check_if_port_available();
launch_daemon("--config configs/normal.cfg --no-ssl");


@output = `$checknrpe -H 127.0.0.1 -p 40321 2>&1`;
is($?, STATE_CRITICAL, 'connect ssl') || diag @output;
like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: Connection reset by peer/, 'connect ssl response') || diag @output;


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
exit 0;

# Source address not allowed
# CHECK_NRPE: Error - Could not connect to 127.0.0.1: Connection reset by peer
@output = `$checknrpe -H 127.0.0.1 -p 40321 -b 127.0.0.2`;
is($?, 512, 'invalid source ip - @output');

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c lorem_10000`;
    is($?, 0, "10,000 byte test exec - @output") || skip 'failed exec', 1;

    is(sha1_hex(@output), '2ed4d81e96262f2b08441c1f819166209a2f5337', '10,000 byte test result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c lorem_60000`;
    is($?, 0, "60,000 byte test exec - @output") || skip 'failed exec', 1;

    is(sha1_hex(@output), '2ad3e654c043773c309321d8fb62232833510b8f', '60,000 byte test result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c lorem_70000`;
    is($?, 0, "70,000 byte test exec - @output") || skip 'failed exec', 1;

    # Note: We're expecting the output to be trimmed to 64k.
    is(sha1_hex(@output), 'af05e7c515f21dd9b6944e9b092bf1691ae47050', '70,000 byte test result');
}

@output = `$checknrpe -H 127.0.0.1 -p 40321 -c invalid_command`;
is($?, 3 << 8, 'invalid command');
like($output[0], qr/NRPE: Command 'invalid_command' not defined/, 'invalid command');

@output = `$checknrpe -H 127.0.0.1 -p 40321 -c nonexistent`;
is($?, 3 << 8, 'nonexistent command');
like($output[0], qr/NRPE: Unable to read output/, 'invalid command');

@output = `$checknrpe -H 127.0.0.1 -p 40321 -c timeout`;
is($?, STATE_UNKNOWN, 'failed test exec');
like($output[0], qr/NRPE: Command timed out after 5 seconds/, 'invalid command');

done_testing();

