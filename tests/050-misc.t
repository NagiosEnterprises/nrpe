#!/usr/bin/perl

use warnings;
use strict;

use Digest::SHA qw(sha1_hex);
use File::Basename;
use Test::More tests => 6;

use lib (dirname($0));
use nrpe;

my @output;


# Various misc tests. Some just for code coverage

@output = `$checknrpe`;
is($?, STATE_UNKNOWN, 'usage') || diag @output;
@output = `$checknrpe --license`;
is($?, STATE_UNKNOWN, 'license') || diag @output;
@output = `$checknrpe --config-file=configs/check_nrpe.cfg`;
is($?, STATE_UNKNOWN, 'config') || diag @output;
@output = `$checknrpe --config-file=configs/nonexistant.cfg`;
is($?, STATE_UNKNOWN, 'config nonexistant') || diag @output;
@output = `$checknrpe --config-file=configs/check_nrpe.cfg -H 127.0.0.1 -p 40000`;
is($?, STATE_CRITICAL, 'invalid port') || diag @output;

# We're trying to invoke alarm_handler() due to a timeout. Use an IP address that shouldn't be in use
@output = `$checknrpe --config-file=configs/check_nrpe.cfg --timeout=1:WARNING -H 0.0.0.111 -p 40000`;
is($?, STATE_WARNING, 'invalid ip') || diag @output;
