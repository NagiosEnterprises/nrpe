#!/usr/bin/perl

use warnings;
use strict;
BEGIN {
    use File::Basename;
    use lib (dirname(__FILE__));
}

use Test::More tests => 44;
use Digest::SHA qw(sha1_hex);
use nrpe;

my @output;


ensure_daemon_running();
switch_config_file("configs/normal.cfg");
restart_daemon();


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
SKIP: {
    skip 'not linux', 2 if $^O ne 'linux';

    @output = `$checknrpe -H 127.0.0.1 -p 40321 -b 127.0.0.2`;
    is($?, STATE_UNKNOWN, 'invalid source ip') || diag @output;
    like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: /, 'invalid source ip response') || diag @output;
}


SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c state_ok`;
    is($?, STATE_OK, "state_ok exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'state_ok result lines');
    is($output[0], "OK: Everything is normal\n", 'state_ok result');
}
SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c state_warning`;
    is($?, STATE_WARNING, "state_warning exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'state_warning result lines');
    is($output[0], "WARNING: That\'s strange.\n", 'state_warning result');
}
SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c state_critical`;
    is($?, STATE_CRITICAL, "state_critical exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'state_critical result lines');
    is($output[0], "CRITICAL: Danger!\n", 'state_critical result');
}
SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c state_unknown`;
    is($?, STATE_UNKNOWN, "state_unknown exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'state_unknown result lines');
    is($output[0], "UNKNOWN: Huh?\n", 'state_unknown result');
}


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
    if ($? != 0) {
        diag(scalar @output);
        diag($output[0]);
        diag($output[-1]);
    }
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


SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -2 -c state_ok`;
    is($?, STATE_OK, "v2 state_ok exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'v2 state_ok result lines');
    is($output[0], "OK: Everything is normal\n", 'v2 state_ok result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -2 -c ""`;
    is($?, STATE_UNKNOWN, "v2 null exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'v2 null result lines');
    like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: /, 'v2 null result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c "state_ok" -a 1 2 3`;
    is($?, STATE_UNKNOWN, "args exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'args - result lines');
    like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: /, 'args - result');
}

SKIP: {
    @output = `$checknrpe -H 127.0.0.1 -p 40321 -c "< >"`;
    is($?, STATE_UNKNOWN, "metachars - exec") || diag @output && skip 'failed exec', 2;

    is(@output, 1, 'metachars - result lines');
    like($output[0], qr/CHECK_NRPE: Error - Could not connect to .*: /, 'metachars - result');
}

done_testing();
