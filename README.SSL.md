NRPE With SSL/TLS
=================

This document covers the different methods of SSL transport
that NRPE allows for. 

If there was a TL;DR here, it is these:

### Don't use NRPE without encryption

and

### Use Public Key Encryption

Contents
--------

1. [Introduction](#introduction)
2. [NRPE Changes](#nrpe-changes)
3. [check_nrpe Changes](#check_nrpe-changes)
4. [Certificate Generation Example](#certificate-generation-example)


Introduction
------------

NRPE has had basic support for SSL/TLS for some time now, but it was
severely lacking. It only allowed anonymous Diffie Hellman (ADH) key
exchange, it used a fixed 512-bit key (generated at `./configure`
time and extremely insecure) and originally allowed SSLv2. In 2004,
SSLv2 and SSLv3 support was disabled.

`nrpe` and `check_nrpe` have been updated to offer much more secure
encryption and more options. And the updates are done in a backward-
compatible way, allowing you to migrate to the newer versions
without having to do it all at once, and possibly miss updating some
machines, causing lost reporting.



NRPE Changes
------------

Running `./configure` will now create a 2048-bit DH key instead
of the old 512-bit key. The most current versions of openSSL will
still not allow it. In my testing, openSSL 1.0.1e allowed DH keys
of 512 bits, and 1.0.1k would not allow 2048 bit keys. In addition
we now call `SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE)` so a
new key is generated on each connection, based on the 2048-bit
key generated.

The NRPE configuration file has added new SSL/TLS options. The
defaults currently will allow old check_nrpe plugins to continue to
connect to the nrpe daemon, but can report on "old style"
connections, or enforce more secure communication as your migration
progresses. The new options are in the "SSL/TLS OPTIONS" section of
nrpe.cfg, about two-thirds of the way down.

If you are upgrading NRPE from a prior version, you can run the
`update-cfg.pl` script to add the new parameters to your nrpe.cfg.

The `ssl_version` directive lets you set which versions of SSL/TLS
you want to allow. SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2 are
allowed, or those litereals with a `+` after them (as in TLSv1.1+).
Without the `+`, *that version only* will be used. With the `+`,
that *version or above* will be used. openSSL will always negotiate
the highest available allowed version available on both ends. This
directive currently defaults to `TLSv1+`.

The `ssl_use_adh` directive is **DEPRECATED**, even though it is new.
Possible values are `0` to not allow ADH at all, `1` to allow ADH,
and `2` to require ADH. The `2` should never be required, but it's
there just in case it's needed, for whatever reason. `1` is currently
the default, which allows older `check_nrpe` plugins to connect using
ADH. When all the plugins are migrated to the newer version, it
should be set to `0`. In an upcoming version of NRPE, ADH will no
longer be allowed at all. Note that if you use a `2` here, NRPE will
override any `ssl_cipher_list` entries (below) to *only* allow ADH.

The `ssl_cipher_list` directive lets you specify which ciphers you
want to allow. It currently defaults to `ALL:!MD5:@STRENGTH` but can
take any value allowed by openSSL. In an upcoming version of NRPE, it
will be changed to something more secure, something like
`ALL:!aNULL:!eNULL:!SSLv2:!LOW:!EXP:!RC4:!MD5:@STRENGTH`. Note that
if you have `ssl_use_adh=2`, this string will be overridden with
`ADH` which only only allow ADH.

The `ssl_cacert_file`, `ssl_cert_file` and `ssl_privatekey_file`
directives are used to specify which *.pem files are to be used for
Public-Key Encryption (PKE). Setting these will allow clients to use
PKE to communicate with the server, similar to how the HTTPS
protocol works.

The `ssl_client_certs` directive specifies whether or not a client
certificate will be requested when a client tries to connect. A value
of `0` means the nrpe daemon will not ask for or require a client
certificate. A `1` will cause it to ask for a client certificate, but
not require one. A `2` will require the client to present a valid
certificate. This currently defaults to `0`. If you want to use
client certificates and are upgrading the clients over time, you can
set this to `1` once many have been upgraded, then set to `2` to
force the use of client certs. Note that the client certs _must_ be
signed by the CA cert specified in the `ssl_cacert_file` directive.

The `ssl_logging` directive allows you to log some additional data
to syslog. OR (or add) values together to have more than one option
enabled. Values are `0` for no additional logging (the default),
`1` to log startup SSL/TLS parameters from the nrpe.cfg file, `2` to
log the SSL/TLS version of connections, `4` to log which cipher is
being used for the connection, `8` to log if the plugin has a cert, and
`16` to log details of plugin's certificate. `-1` will enable all.
This can be especially helpful during plugin migration, so you can
tell which plugins have certificates, what SSL/TLS version is being
used, and which ciphers are being used.


check_nrpe Changes
------------------

The `check_nrpe` plugin has also been updated to provide more secure
encryption and allow the use of client certificates. The command line
has several new options, which are outlined below. Both the long and
short arguments are presented.

`--no-adh` or `-d` will disable the use of ADH. This option is
**DEPRECATED**, even though it's new. It will be removed in a
future version.

`--ssl-version=<ver>` or `-S <ver>` specifies minimum SSL/TLS version
to use. See the `ssl_version` directive above for possible values.

`--cipher-list=<value.` or `-L <value>` determines which ciphers will
and won't be allowed. See the `ssl_cipher_list` directive above.

`--client-cert=<path>` or `-C <path>` specifies an optional client
certificate to use. If this value is entered, the next one below is
required.

`--key-file=<path>` or `-K <path>` specifies the client certificate
key file to use. This goes along with `--client-cert` above.

`--ca-cert-file=<path>` or `-A <path>` specifies the CA certificate
to use in order to validate the nrpe daemon's public key.

`--no-adh` or `-d` is **DEPRECATED**

`--use-adh` or `-d [num]` is **DEPRECATED**, even though it is new.
If you use `-d` or `-d 0` it acts the same way as as the old `-d`.
Otherwise, use `1` to allow ADH, and `2` to require ADH.

`--ssl-logging=<num>` or `-s <num>` allows you to log some additional
data to syslog. OR (or add) values together to have more than one
option enabled. See the description of the `ssl_logging` directive
from NRPE above.



Certificate Generation Example
------------------------------

**Note** _The following example does not follow best practice for
creating and running a CA or creating certificates. It is for testing
or possibly for use in a small environment. Sloppy security is as bad
as no security._

In this example, we are going to put everything in the
`/usr/local/nagios/etc/ssl` directory. You may want to use the more
common `/etc/ssl` directory, or somewhere else entirely.

We are going to assume your company name is Foo Widgets, LLC; the
server running the nagios process (and thus the check_nrpe program)
is called `nag_serv`; and there are two Linux machines that will
run the nrpe daemon: `db_server` and `bobs_workstation`.


#### Set up the directories

As root, do the following:

        mkdir -p -m 750 /usr/local/nagios/etc/ssl
        chown root:nagios /usr/local/nagios/etc/ssl
        cd /usr/local/nagios/etc/ssl
        mkdir -m 750 ca
        chown root:root ca
        mkdir -m 750 server_certs
        chown root:nagios server_certs
        mkdir -m 750 client_certs
        chown root:nagios client_certs


#### Create Certificate Authority

If you want to validate client or server certificates, you will need
to create a Certificate Authority (CA) that will sign all client and
server certificates. If your organization already has a CA, you can
use that.

As root, do the following:

        cd /usr/local/nagios/etc/ssl/ca
        openssl req -x509 -newkey rsa:4096 -keyout ca_key.pem \
           -out ca_cert.pem -utf8 -days 3650

When asked, enter a passphrase. Then follow the prompts. You will
probably want to include `CA` or `Certificate Authority` in for
`Organizational Unit Name` and `Common Name`. For example:

        Organization Name (eg, company) []:Foo Widgets LLC
        Organizational Unit Name (eg, section) []:Foo Certificate Authority
        Common Name (e.g. server FQDN or YOUR name) []:Foo Nagios CA


#### Create NRPE Server Certificate Requests

For each of the hosts that will be running the nrpe daemon, you will
need a server certificate. You can create a key, and the CSR
(Certificate Signing Request) separately, but the following commands
will do both with one command. As root, do the following:

        cd /usr/local/nagios/etc/ssl/server_certs
        openssl req -new -newkey rsa:2048 -keyout db_server.key \
           -out db_server.csr -nodes
        openssl req -new -newkey rsa:2048 -keyout bobs_workstation.key \
           -out bobs_workstation.csr -nodes

Follow the prompts. The `-nodes` at the end of the lines tells
openssl to generate the key without a passphrase. Leave it off if you
want someone to enter a passphrase whenever the machine boots.

Now you need to sign the CSRs with your CA key.

If you have the default `/etc/openssl.cnf`, either change it, or as root, do:

        cd /usr/local/nagios/etc/ssl
        mkdir demoCA
        mkdir demoCA/newcerts
        touch demoCA/index.txt
        echo "01" > demoCA/serial
        chown -R root:root demoCA
        chmod 700 demoCA
        chmod 700 demoCA/newcerts
        chmod 600 demoCA/serial
        chmod 600 demoCA/index.txt

Now, sign the CSRs. As root, do the following:

        cd /usr/local/nagios/etc/ssl
        openssl ca -days 365 -notext -md sha256 \
           -keyfile ca/ca_key.pem -cert ca/ca_cert.pem \
           -in server_certs/db_server.csr \
           -out server_certs/db_server.pem
        chown root:nagios server_certs/db_server.pem
        chmod 440 server_certs/db_server.pem
        openssl ca -days 365 -notext -md sha256 \
           -keyfile ca/ca_key.pem -cert ca/ca_cert.pem \
           -in server_certs/bobs_workstation.csr \
           -out server_certs/bobs_workstation.pem
        chown root:nagios server_certs/bobs_workstation.pem
        chmod 440 server_certs/bobs_workstation.pem

Now, copy the `db_server.pem` and `db_server.key` files to the
db_server machine, and the `bobs_workstation.pem` and
`bobs_workstation.key` files to bobs_workstation. Copy the
`ca/ca_cert.pem` file to both machines.


#### Create NRPE Client Certificate Requests

Now you need to do the same thing for the machine that will be
running the check_nrpe program.

        cd /usr/local/nagios/etc/ssl/client_certs
        openssl req -new -newkey rsa:2048 -keyout nag_serv.key \
           -out nag_serv.csr -nodes

        cd /usr/local/nagios/etc/ssl
        openssl ca -extensions usr_cert -days 365 -notext -md sha256 \
           -keyfile ca/ca_key.pem -cert ca/ca_cert.pem \
           -in client_certs/nag_serv.csr \
           -out client_certs/nag_serv.pem
        chown root:nagios client_certs/nag_serv.pem
        chmod 440 client_certs/nag_serv.pem

Now, copy the `nag_serv.pem`, `nag_serv.key` and `ca/ca_cert.pem`
files to the nag_serv machine, if you did the above on a different
computer.

Put the location of each computers' three files in the `nrpe.cfg`
file or in the check_nrpe command line. You should now have
encryption and, if desired, key validation.
