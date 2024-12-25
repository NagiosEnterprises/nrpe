#!/usr/bin/perl

use warnings;
use strict;
BEGIN {
    use File::Basename;
    use lib (dirname(__FILE__));
}

use Test::More tests => 11;
use nrpe;


my @output;

@output = `$nrpe -V`;
is($?, STATE_UNKNOWN, 'nrpe executes');
like($output[0], qr/NRPE - Nagios Remote Plugin Executor/, 'nrpe banner');

@output = `$nrpe --license`;
is($?, STATE_UNKNOWN, 'license') || diag @output;

@output = `$checknrpe -V`;
is($?, STATE_UNKNOWN, 'check_nrpe executes');
like($output[0], qr/NRPE Plugin for Nagios/, 'check_nrpe banner');


@output = `$nrpe --daemon --dont-chdir --config configs/missing.cfg`;
is($?, STATE_CRITICAL, 'missing config') || diag @output;

SKIP: {
    skip 'no SSL', 5 if ! supports_ssl();

    @output = `$nrpe --daemon --dont-chdir --config configs/ssl-invalid.cfg`;
    is($?, STATE_CRITICAL, 'invalid ssl config 1') || diag @output;
    @output = `$nrpe --daemon --dont-chdir --config configs/ssl-invalid2.cfg`;
    is($?, STATE_CRITICAL, 'invalid ssl config 2') || diag @output;
    @output = `$nrpe --daemon --dont-chdir --config configs/ssl-invalid3.cfg`;
    is($?, STATE_CRITICAL, 'invalid ssl config 3') || diag @output;
    @output = `$nrpe --daemon --dont-chdir --config configs/ssl-invalid4.cfg`;
    is($?, STATE_CRITICAL, 'invalid ssl config 4') || diag @output;
    @output = `$nrpe --daemon --dont-chdir --config configs/ssl-invalid5.cfg`;
    is($?, STATE_CRITICAL, 'invalid ssl config 5') || diag @output;
}


check_if_port_available();
switch_config_file("configs/normal.cfg");
launch_daemon();


done_testing();
