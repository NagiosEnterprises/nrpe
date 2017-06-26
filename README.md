![Nagios!](https://www.nagios.com/wp-content/uploads/2015/05/Nagios-Black-500x124.png)

[![Build Status](https://travis-ci.org/NagiosEnterprises/nrpe.svg?branch=master)](https://travis-ci.org/NagiosEnterprises/nrpe)

NRPE
====

## Nagios Remote Plugin Executor


For installation instructions and information on the design overview
of the NRPE addon, please read the PDF documentation that is found in
this directory: `docs/NRPE.pdf`.

If you are upgrading from a previous version, you'll want to
check the [Changelog](CHANGELOG.md) and then run `./update-cfg.pl` to
add the new SSL parameters to your config file.

TL;DR: You can jump straight to [Compiling](#compiling) and
[Installing](#installing)

You'll want to read up on the [Security](SECURITY.md) document
regarding NRPE, no doubt.

And make sure to check out the [SSL Readme](README.SSL.md) as well,
if you plan on using encryption methods to transmit `nrpe` data.


Purpose
-------
The purpose of this addon is to allow you to execute Nagios
plugins on a remote host in as transparent a manner as possible.


Contents
--------

There are two pieces to this addon:

1. `nrpe`

   This program runs as a background process on the
   remote host and processes command execution requests
   from the check_nrpe plugin on the Nagios host.
   Upon receiving a plugin request from an authorized
   host, it will execute the command line associated
   with the command name it received and send the
   program output and return code back to the
   check_nrpe plugin

2. `check_nrpe` 

   This is a plugin that is run on the Nagios host
   and is used to contact the NRPE process on remote
   hosts.  The plugin requests that a plugin be
   executed on the remote host and wait for the NRPE
   process to execute the plugin and return the result.
   The plugin then uses the output and return code
   from the plugin execution on the remote host for
   its own output and return code.


Compiling
---------

If you are having any problems compiling on your system, 
please let us know (preferrably with fixes). Most users 
should be able to compile `nrpe` and the `check_nrpe` 
plugin with the following commands...

    ./configure
    make all

***HINT:*** `./configure --help`

**NOTE:** If you're cloning from GitHub, you'll need to run
`autoconf` first.

**NOTE:** Since the check_nrpe plugin and nrpe daemon run 
on different machines (the plugin runs on the Nagios host and 
the daemon runs on the remote host), you will have to compile 
the nrpe daemon on the target machine.


Installing
----------

You have a few options here. The binaries created from `make all` 
were placed in your `src/` directory. You can either copy these 
where they need to be, or you can run any of the following 
`make install` options:

* `make install-groups-users`

   Add the users and groups sepcified during `./configure`. Defaults
   to nagios and nagios, respectively. You can override these with the
   `./configure --with-nrpe-user=USER --with-nrpe-group=GROUP`.

* `make install`

   This will run both `install-plugin` and `install-daemon`.

* `make install-plugin`

   This will install the plugin by default in 
   `/usr/local/nagios/libexec`. You can override this 
   behavior by using the `--with-pluginsdir=DIR` flag during
   `./configure`.

* `make install-daemon`

   This will install the plugin by default in 
   `/usr/local/nagios/bin`. You can override this 
   behavior by using the `--prefix=DIR` or 
   `--bindir=DIR` flags during `./configure`.

* `make install-config`

   This will install the sample config by default in 
   `/usr/local/nagios/etc`. You can override this 
   behavior by using the `--with-pkgsysconfdir=DIR` 
   flag during `./configure`.

* `make install-inetd`

   `./configure` attempts to determine your inetd type.
   If it finds it, it will install the appropriate inetd 
   script in the proper location. You can help it out with
   `./configure --with-inetd-type=TYPE` where `TYPE` can be
   one of: `inetd`, `xinetd`, `systemd`, `launchd`, 
   `smf10`, `smf11`.

* `make install-init`

   `./configure` attempts to determine the appropriate
   init type. If it figures it out, will install the
   required startup script. You can help it out with
   `./configure --with-init-type=TYPE` where TYPE can be
   one of: `bsd`, `sysv`, `systemd`, `launchd`, `smf10`, 
   `smf11`, `upstart`, `openrc`.

If you used all the necessary `./configure` flags, you shouldn't
need to tweak your config file any at this point, and a simple
`service nrpe start` or `systemctl start nrpe.service` should
work just fine.

Configuring
-----------

A sample config file for the NRPE daemon are located in the
`sample-config/` subdirectory.

If you used the proper flags during `./configure`, this file
should contain all of the appropriate information as a starting
point.


Running Under `inetd` or `xinetd`
---------------------------------

If you plan on running nrpe under inetd or xinetd and making use
of TCP wrappers, you need to add a line to your `/etc/services`
file as follows (modify the port number as you see fit)

     nrpe            5666/tcp    # NRPE

The run `make install-inetd` to copy the appropriate file, or
add the appropriate line to your `/etc/inetd.conf`.

**NOTE:** If you run nrpe under inetd or xinetd, the server_port
and allowed_hosts variables in the nrpe configuration file are
ignored.


* `inetd`

   After running `make install-inetd`, your `/etc/inetd.conf` file will
   contain lines similar to the following:

       # Enable the following entry to enable the nrpe daemon
       #nrpe stream tcp nowait nagios /usr/local/nagios/bin/nrpe nrpe -c /usr/local/nagios/etc/nr
       # Enable the following entry if the nrpe daemon didn't link with libwrap
       #nrpe stream tcp nowait nagios /usr/sbin/tcpd /usr/local/nagios/bin/nrpe -c /usr/local/nag

   Un-comment the appropriate line, then Restart inetd:

       /etc/rc.d/init.d/inet restart

   OpenBSD users can use the following command to restart inetd:

       kill -HUP `cat /var/run/inet.pid`

   Then add entries to your `/etc/hosts.allow` and `/etc/hosts.deny`
   file to enable TCP wrapper protection for the nrpe service.
   This is optional, although highly recommended.


* `xinetd`

   If your system uses xinetd instead of inetd, `make install-inetd`
   will create a file called `nrpe` in your `/etc/xinetd.d`
   directory that contains a file similar to this:

       # default: off
       # description: NRPE (Nagios Remote Plugin Executor)
       service nrpe
       {
           disable         = yes
           socket_type     = stream
           port            = @NRPE_PORT@
           wait            = no
           user            = nagios
           group           = nagios
           server          = /usr/local/nagios/bin/nrpe
           server_args     = -c /usr/local/nagios/etc/nrpe.cfg --inetd
           only_from       = 127.0.0.1
           log_on_failure  += USERID
       }

   * Replace `disable = yes` with `disable = no`
   * Replace the `127.0.0.1` field with the IP addresses of hosts which
     are allowed to connect to the NRPE daemon.  This only works if xinetd was
     compiled with support for tcpwrappers.
   * Add entries to your `/etc/hosts.allow` and `/etc/hosts.deny`
     file to enable TCP wrapper protection for the nrpe service.
     This is optional, although highly recommended.

   * Restart xinetd:

          /etc/rc.d/init.d/xinetd restart


Configuring Things On The Nagios Host
---------------------------------------

Examples for configuring the nrpe daemon are found in the sample
`nrpe.cfg` file included in this distribution.  That config file
resides on the remote host(s) along with the nrpe daemon.  The
check_nrpe plugin gets installed on the Nagios host.  In order
to use the check_nrpe plugin from within Nagios, you will have
to define a few things in the host config file.  An example
command definition for the check_nrpe plugin would look like this:

    define command{
        command_name           check_nrpe
        command_line           /usr/local/nagios/libexec/check_nrpe -H $HOSTADDRESS$ -c $ARG1$
        }

In any service definitions that use the nrpe plugin/daemon to
get their results, you would set the service check command portion
of the definition to something like this (sample service definition
is simplified for this example):

    define service{
        host_name              someremotehost
        service_description    someremoteservice
        check_command          check_nrpe!yourcommand
        ... etc ...
        }

where `yourcommand` is a name of a command that you define in
your `nrpe.cfg` file on the remote host (see the docs in the
sample nrpe.cfg file for more information).


License Notice
--------------

NRPE - Nagios Remote Plugin Executor

Copyright (c) 2017 Nagios Enterprises

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


Questions?
----------

If you have questions about this addon, or encounter problems getting things
working along the way, your best bet for an answer or quick resolution is to check the
[Nagios Support Forums](https://support.nagios.com/forum/viewforum.php?f=5).
