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

# SSLv3 may or may not be supported so we don't explicitly test it.
my @SSL_Versions_Bad = ( 'TLSv1', 'TLSv1.1' );
my @SSL_Versions_Good = ( 'SSLv3+', 'TLSv1+', 'TLSv1.1+', 'TLSv1.2', 'TLSv1.2+', 'TLSv1.3', 'TLSv1.3+' );

plan tests => 10 + ((scalar @SSL_Versions_Bad + scalar @SSL_Versions_Good) * 2);


ensure_daemon_running();
switch_config_file("configs/ssl.cfg");
restart_daemon();


@output = `$checknrpe -H 127.0.0.1 -p 40321`;
is($?, STATE_OK, 'connect ssl') || diag @output;
like($output[0], qr/NRPE v.*/, 'connect ssl response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321 --ca-cert-file=configs/certs/nrpe.crt`;
is($?, STATE_OK, 'connect ssl ca') || diag @output;
like($output[0], qr/NRPE v.*/, 'connect ssl ca response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321 --ca-cert-file=configs/certs/nrpe.crt --client-cert=configs/certs/nrpe.crt --key-file=configs/certs/nrpe.key`;
is($?, STATE_OK, 'connect ssl cert') || diag @output;
like($output[0], qr/NRPE v.*/, 'connect ssl cert response') || diag @output;

@output = `$checknrpe -H 127.0.0.1 -p 40321 --ca-cert-file=configs/certs/other.crt`;
is($?, STATE_UNKNOWN, 'connect ssl other ca') || diag @output;
like($output[0], qr/CHECK_NRPE: \(ssl_err != 5\) Error - Could not complete SSL handshake with/, 'connect ssl other ca response') || diag @output;

# --log-file=logs/check_nrpe_ssl.log --ssl-logging=255 
#  openssl: CHECK_NRPE: Error - Could not connect to .*
# libressl: CHECK_NRPE: Error sending query to host.
@output = `$checknrpe -H 127.0.0.1 -p 40321 --ca-cert-file=configs/certs/nrpe.crt --client-cert=configs/certs/other.crt --key-file=configs/certs/other.key`;
is($?, STATE_UNKNOWN, 'connect ssl other cert') || diag @output;
like($output[0], qr/CHECK_NRPE: Error /, 'connect ssl other cert response') || diag @output;


foreach ( @SSL_Versions_Bad ) {
    my $ver = $_;
    @output = `$checknrpe -H 127.0.0.1 -p 40321 --ca-cert-file=configs/certs/nrpe.crt --ssl-version=$ver`;
    is($?, STATE_UNKNOWN, "connect ssl $ver") || diag @output;
    like($output[0], qr/CHECK_NRPE: \(ssl_err != 5\) Error - Could not complete SSL handshake with/, "connect ssl $ver response") || diag @output;
}

foreach ( @SSL_Versions_Good ) {
    my $ver = $_;
    @output = `$checknrpe -H 127.0.0.1 -p 40321 --ca-cert-file=configs/certs/nrpe.crt --ssl-version=$ver`;
    is($?, STATE_OK, "connect ssl $ver") || diag @output;
    like($output[0], qr/NRPE v.*/, "connect ssl $ver response") || diag @output;
}


done_testing();
