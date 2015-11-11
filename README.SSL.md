NRPE With SSL/TLS
=================

NRPE has had basic support for SSL/TLS for some time now, but it was
severely lacking. It only allowed anonymous Diffie Hellman (ADH) key
exchange, it used a fixed 512-bit key (generated at `./configure`
time and extremely insecure) and originally allowed SSLv2. In 2004,
SSLv2 and SSLv3 support was disabled.

nrpe and check_nrpe have been updated to offer much more secure
encryption and more options. And the updates are done in a backward-
compatible way, allowing you to migrate to the newer versions
without having to do it all at once, and possibly miss updating some
machines, causing lost reporting.

The changes to the NRPE daemon are outlined below first, followed by
the changes to the check_nrpe client.


------------------------------------------
####CHANGES IN THE CURRENT VERSION OF NRPE
------------------------------------------

Running `./configure` will now create a 2048-bit DH key instead
of the old 512-bit key. The most current versions of openSSL will
still not allow it. In my testing, openSSL 1.0.1e allowed DH keys
of 512 bits, and 1.0.1k would not allow 2048 bit keys. In addition
we now call `SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE)` so a
new key is generated on each connection, based on the 2048-bit
key generated.

The NRPE configuration file has added new SSL/TLS options. The
defaults currently will allow old check_nrpe clients to continue to
connect to the nrpe daemon, but can report on "old style" 
connections, or enforce more secure communication as your migration
progresses. The new options are in the "SSL/TLS OPTIONS" section of
nrpe.cfg, about two-thirds of the way down.

The `ssl_version` directive lets you set which versions of SSL/TLS
you want to allow. SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2 are
allowed, or those litereals with a `+` after them (as in TLSv1.1+).
Without the `+`, that version _only_ will be used. With the `+`,
that version _or above_ will be used. openSSL will always negotiate
the highest available allowed version available on both ends. This
directive currently defaults to `TLSv1+`.

The `ssl_use_adh` directive is **DEPRECATED**, even though it is new.
Possible values are `0` to not allow ADH at all, `1` to allow ADH,
and `2` to require ADH. The `2` should never be required, but it's
there just in case it's needed, for whatever reason. `1` is currently
the default, which allows older check_nrpe clients to connect using
ADH. When all the clients are migrated to the newer version, it
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
being used for the connection, `8` to log if client has a cert, and
`16` to log details of client's certificate. `-1` will enable all.
This can be especially helpful during client migration, so you can
tell which clients have certificates, what SSL/TLS version is being
used, and which ciphers are being used.


------------------------------------------------
####CHANGES IN THE CURRENT VERSION OF CHECK_NRPE
------------------------------------------------

The check_nrpe client has also been updated to provide more secure
encryption and allow the use of client certificates. The command line
has several new options, which are outlined below. Both the long and
short arguments are presented.

`--no-adh` or `-d` will disable the use of ADH. This option is **DEPRECATED**,
even though it's new. It will be removed in a future version.

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
data to syslog. OR (or add) values together to have more than one option
enabled. See the description of the `ssl_logging` directive from NRPE
above.
