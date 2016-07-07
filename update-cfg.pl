#! /usr/bin/perl -w

use strict;

my ($fname_in, $fname_out);

if ($#ARGV != 0) {
	&usage;
}

$fname_in = $ARGV[0];
$fname_out = $fname_in . ".new";

if (&check_ssl) {
	print "\n'$fname_in' already has some or all of the\n";
	print "new SSL parameters. No processing will be done.\n\n";
	exit 0;
}

open IN, $fname_in or die "Could not open '$fname_in' for reading: $!\n";
open OUT, ">$fname_out" or die "Could not open '$fname_out' for writing: $!\n";

while (<IN>) {
	print OUT;
	&add_ssl if $_ =~ /allow_weak_random_seed/;
}

print "\nConfig file '$fname_in' was read.\n";
print "The new SSL comments and parameters were added and the output written to\n";
print "'$fname_out'\n";
print "Please check this file for accuracy and rename it when you are satisfied.\n\n";

close IN;
close OUT;

# ==========================================================================

sub usage
{
	print "\nUsage: update-cfg.pl <path-to-nrpe.cfg-file>\n\n";
	print "This perl script will read the nrpe configuration file\n";
	print "specified on the command line, and write out a new file\n";
	print "with the new SSL comments and parameters added.\n\n";
	exit 1;
}

# --------------------------------------------------------------------------
#  check_ssl checks if the config file already has the ssl parameters
# --------------------------------------------------------------------------
sub check_ssl
{
	my $has_ssl = 0;

	open IN, $fname_in or die "Could not open '$fname_in' for reading: $!\n";

	while (<IN>) {
		if ($_ =~ /ssl_version=/ or
			$_ =~ /ssl_use_adh=/ or
			$_ =~ /ssl_cipher_list=/ or
			$_ =~ /ssl_cacert_file=/ or
			$_ =~ /ssl_cert_file=/ or
			$_ =~ /ssl_privatekey_file=/ or
			$_ =~ /ssl_client_certs=/ or
			$_ =~ /ssl_logging=/)
		{
			$has_ssl = 1;
			last;
		}
	}

	close IN;

	return $has_ssl;
}

# --------------------------------------------------------------------------
#  add_ssl inserts the new SSL comments and parameters into the config file
# --------------------------------------------------------------------------
sub add_ssl
{
my $txt = <<"END_SSL";



# SSL/TLS OPTIONS
# These directives allow you to specify how to use SSL/TLS.

# SSL VERSION
# This can be any of: SSLv2 (only use SSLv2), SSLv2+ (use any version),
#        SSLv3 (only use SSLv3), SSLv3+ (use SSLv3 or above), TLSv1 (only use
#        TLSv1), TLSv1+ (use TLSv1 or above), TLSv1.1 (only use TLSv1.1),
#        TLSv1.1+ (use TLSv1.1 or above), TLSv1.2 (only use TLSv1.2),
#        TLSv1.2+ (use TLSv1.2 or above)
# If an "or above" version is used, the best will be negotiated. So if both
# ends are able to do TLSv1.2 and use specify SSLv2, you will get TLSv1.2.

#ssl_version=SSLv2+

# SSL USE ADH
# This is for backward compatibility and is DEPRECATED. Set to 1 to enable
# ADH or 2 to require ADH. 1 is currently the default but will be changed
# in a later version.

#ssl_use_adh=1

# SSL CIPHER LIST
# This lists which ciphers can be used. For backward compatibility, this
# defaults to 'ssl_cipher_list=ALL:!MD5:\@STRENGTH' in this version but
# will be changed to something like the example below in a later version of NRPE.

#ssl_cipher_list=ALL:!MD5:\@STRENGTH
#ssl_cipher_list=ALL:!aNULL:!eNULL:!SSLv2:!LOW:!EXP:!RC4:!MD5:\@STRENGTH

# SSL Certificate and Private Key Files

#ssl_cacert_file=/etc/ssl/servercerts/ca-cert.pem
#ssl_cert_file=/etc/ssl/servercerts/nagios-cert.pem
#ssl_privatekey_file=/etc/ssl/servercerts/nagios-key.pem

# SSL USE CLIENT CERTS
# This options determines client certificate usage.
# Values: 0 = Don't ask for or require client certificates (default)
#         1 = Ask for client certificates
#         2 = Require client certificates

#ssl_client_certs=0

# SSL LOGGING
# This option determines which SSL messages are send to syslog. OR values
# together to specify multiple options.

# Values: 0x00 (0)  = No additional logging (default)
#         0x01 (1)  = Log startup SSL/TLS parameters
#         0x02 (2)  = Log remote IP address
#         0x04 (4)  = Log SSL/TLS version of connections
#         0x08 (8)  = Log which cipher is being used for the connection
#         0x10 (26) = Log if client has a certificate
#         0x20 (32) = Log details of client's certificate if it has one
#         -1 or 0xff or 0x2f = All of the above

#ssl_logging=0x00
END_SSL
	print OUT $txt;
}
