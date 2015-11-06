********************
NRPE SECURITY README
********************


TCP WRAPPER SUPPORT
===================

NRPE 2.x includes native support for TCP wrappers.  The older
host access list directive was removed from the config file.
Make sure your system supports TCP wrappers before running NRPE.
Once you compile NRPE you can check to see if it has wrapper
support built in by running the daemon from the command line
without any arguments like this:

	./nrpe --help




COMMAND ARGUMENTS
=================

NRPE 2.0 includes the ability for clients to supply arguments to
commands which should be run.  Please note that this feature
should be considered a security risk, and you should only use
it if you know what you're doing!


BASH COMMAND SUBSTITUTION
-------------------------

Even with the metacharacter restrictions below, if command arguments 
are enabled, it is still possible to send bash command substitions 
in the form $(...) as an agrument. This is explicity disabled by 
default, but can be enabled by a configure-time option and a
configuration file option. Enabling this option is VERY RISKY and 
its use is HIGHLY DISCOURAGED.


ENABLING ARGUMENTS
------------------

To enable support for command argument in the daemon, you must
do two things:

   1.  Run the configure script with the --enable-command-args 
       option

   2.  Set the 'dont_blame_nrpe' directive in the NRPE config
       file to 1.


ENABLING BASH COMMAND SUBSTITUTION
----------------------------------

To enable support for arguments containing bash command substitions, 
you must do two things:

   1.  Enable arguments as described above

   2.  Include the --enable-bash-command-substitution configure
       option when running the configure script

   3.  Set the 'allow_bash_command_substitutions' directive in the 
       NRPE config file to 1.


ILLEGAL METACHARS
-----------------

To help prevent some nasty things from being done by evil 
clients, the following metacharacters are not allowed
in client command arguments:

   | ` & > < ' " \ [ ] { } ; !

Any client request which contains the abovementioned metachars
is discarded.


USER/GROUP RESTRICTIONS
-----------------------

The NRPE daemon cannot be run with (effective) root user/group
privileges.  You must run the daemon with an account that does
not have superuser rights.  Use the nrpe_user and nrpe_group
directives in the config file to specify which user/group the
daemon should run as.


ENCRYPTION
----------

If you do enable support for command arguments in the NRPE daemon,
make sure that you encrypt communications either by using:

   1.  Stunnel (see http://www.stunnel.org for more info)
   2.  Native SSL support

Do NOT assume that just because the daemon is behind a firewall
that you are safe!  Always encrypt NRPE traffic!


USING ARGUMENTS
---------------

How do you use command arguments?  Well, lets say you define a
command in the NRPE config file that looks like this:

	command[check_users]=/usr/local/nagios/libexec/check_users -w $ARG1$ -c $ARG2$

You could then call the check_nrpe plugin like this:

	./check_nrpe -H <host> -c check_users -a 5 10

The arguments '5' and '10' get substituted into the appropriate
$ARGx$ macros in the command ($ARG1$ and $ARG2$, respectively).
The command that would be executed by the NRPE daemon would look
like this:

	/usr/local/nagios/libexec/check_users -w 5 -c 10

You can supply up to 16 arguments to be passed to the command
for substitution in $ARG$ macros ($ARG1$ - $ARG16$).




    -- Ethan Galstad (nagios@nagios.org)

