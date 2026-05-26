#!/usr/bin/perl

use warnings;
use strict;
BEGIN {
    use File::Basename;
    use lib (dirname(__FILE__));
}

use Test::More tests => 1;
use nrpe;


ensure_daemon_running();
kill_daemon();

pass("shutdown");
done_testing();
