NRPE Changelog
==============

[3.2.1](https://github.com/NagiosEnterprises/nrpe/releases/tag/nrpe-3.2.1) - 2017-08-31
---------------------------------------------------------------------------------------
**FIXES**
* Change seteuid error messages to warning/debug (Bryan Heden)
* Fix segfault when no nrpe_user is specified (Stephen Smoogen, Bryan Heden)
* Added additional strings to error messages to remove duplicates (Bryan Heden)
* Fix nrpe.spec for rpmbuild (Bryan Heden)
* Fix error for drop_privileges when using inetd (xalasys-luc, Bryan Heden)


[3.2.0](https://github.com/NagiosEnterprises/nrpe/releases/tag/nrpe-3.2.0) - 2017-06-26
---------------------------------------------------------------------------------------
**ENHANCEMENTS**
* Added max_commands definition to nrpe.cfg to rate limit simultaneous fork()ed children (Bryan Heden)
* Added -E, --stderr-to-stdout options for check_nrpe to redirect output (Bryan Heden)
* Added support for Gentoo init (Troy Lea @box293)
* Cleaned up code a bit, updated readmes and comments across the board (Bryan Heden)
* Added -V, --version to nrpe and fixed the output (Bryan Heden)
* Added different SSL error messages to be able to pinpoint where some SSL errors occured (Bryan Heden)
* Updated logic in al parse_allowed_hosts (Bryan Heden)
* Added builtin OpenSSL Engine support where available (Bryan Heden + @skrueger8)
* Clean up compilation warnings (Bryan Heden)
* Added more commented commands in nrpe.cfg (Bryan Heden)

**FIXES**
* Undefined check returns UNKNOWN (Bryan Heden)
* Fix incompatibility with OpenSSL 1.1.0 via SECLEVEL distinction (Bryan Heden)
* Fix ipv4 error in logfile even if address is ipv6 (Bryan Heden)
* Fix improper valid/invalid certificate warnings (Bryan Heden)

[3.1.1](https://github.com/NagiosEnterprises/nrpe/releases/tag/nrpe-3.1.1) - 2017-05-24
---------------------------------------------------------------------------------------
**FIXES**
* The '--log-file=' or '-g' option is missing from the help (John Frickson)
* check_nrpe = segfault when specifying a config file (John Frickson)
* Alternate log file not being used soon enough (John Frickson)
* Unable to compile v3.1.0rc1 with new SSL checks on rh5 (John Frickson)
* Unable to compile nrpe-3.1.0 - undefined references to va_start, va_end (John Frickson)
* Can't build on Debian Stretch, openssl 1.1.0c (John Frickson)
* Fix build failure with -Werror=format-security (Bas Couwenberg)
* Fixed a typo in `nrpe.spec.in` (John Frickson)
* More detailed error logging for SSL (John Frickson)
* Fix infinite loop when unresolvable host is in allowed_hosts (Nick / John Frickson)

[3.1.0](https://github.com/NagiosEnterprises/nrpe/releases/tag/nrpe-3.1.0) - 2017-04-17
---------------------------------------------------------------------------------------
**ENHANCEMENTS**
* Added option to nrpe.cfg.in that can override hard-coded NASTY_METACHARS (John Frickson)
* While processing 'include_dir' statement, sort the files (Philippe Kueck / John Frickson)
* nrpe can now write to a log file using 'log_file=' in nrpe.cfg (John Frickson)
* check_nrpe can now write to a log file using '--log-file=' or '-g' options (John Frickson)

**FIXES**
* Added missing debugging syslog entries, and changed printf()'s to syslog()'s. (Jobst Schmalenbach)
* Fix help output for ssl option (configure) (Ruben Kerkhof)
* Fixes to README.SSL.md and SECURITY.md (Elan Ruusamäe)
* Changed the 'check_load' command in nrpe.cfg.in (minusdavid)
* Cleanup of config.h.in suggested by Ruben Kerkhof
* Minor change to logging in check_nrpe (John Frickson)
* Solaris 11 detection is broken in configure (John Frickson)
* Removed function `b64_decode` which wasn't being used (John Frickson)
* check_nrpe ignores -a option when -f option is specified (John Frickson)
* Added missing LICENSE file (John Frickson)
* Off-by-one BO in my_system() (John Frickson)
* Got rid of some compiler warnings (Stefan Krüger / John Frickson)
* Add SOURCE_DATE_EPOCH specification support for reproducible builds. (Bas Couwenberg)
* nrpe 3.0.1 allows TLSv1 and TLSv1.1 when I configure for TLSv1.2+ (John Frickson)
* "Remote %s accepted a Version %s Packet", please add to debug (John Frickson)
* nrpe 3.0.1 segfaults when key and/or cert are broken symlinks (John Frickson)
* Fixed a couple of typos in docs/NRPE.* files (Ludmil Meltchev)
* Changed release date to ISO format (yyyy-mm-dd) (John Frickson)
* Fix systemd unit description (Bas Couwenberg)
* Add reload command to systemd service file (Bas Couwenberg)
* fix file not found error when updating version (Sven Nierlein)
* Spelling fixes (Josh Soref)
* Return UNKNOWN when check_nrpe cannot communicate with nrpe and -u set (John Frickson)
* xinetd.d parameter causes many messages in log file (John Frickson)
* Fixes for openssl 1.1.x (Stephen Smoogen / John Frickson)
* PATH and other environment variables not set with numeric nrpe_user (John Frickson)
* rpmbuild -ta nrpe-3.0.1.tar.gz failed File not found: /etc/init.d/nrpe (bvandi / John Frickson)

[3.0.1](https://github.com/NagiosEnterprises/nrpe/releases/tag/nrpe-3.0.1) - 2016-09-08
---------------------------------------------------------------------------------------
**FIXES**
* _set_rc: command not found reported by init script (John Frickson)
* Version string contains name (John Frickson)
* Changes to get 'rpmbuild' to work - nrpe.spec file outdated (John Frickson)
* typo in startup/default-xinetd.in (Philippe Kueck)
* debug output missing command name (Philippe Kueck)
* /usr/lib/tmpfiles.d/ndo2db.conf should have 'd' type, not 'D' (John Frickson)
* Fixes in parse_allowed_hosts() and called functions (Jobst Schmalenbach / John Frickson)
* nrpe.cfg: 'debug' statement needs to be first in file (Jobst Schmalenbach / John Frickson)

[3.0.0](https://github.com/NagiosEnterprises/nrpe/releases/tag/nrpe-3.0.0) - 2016-08-01
---------------------------------------------------------------------------------------
**SECURITY**
* Fix for CVE-2014-2913
* Added function to clean the environment before forking. (John Frickson)

**ENHANCEMENTS**
* Added support for optional config file to check_nrpe. With the new SSL
  parameters, the line was getting long. The config file is specified with
  --config-file=<path> or -f <path> parameters. The config file must look
  like command line options, but the options can be on separate lines. It
  MUST NOT include --config-file (-f), --command (-c) or --args (-a). If any
  options are in both the config file and on the command line, the command line
  options are used.
* make can now add users and groups using "make install-groups-users" (John Frickson)
* Added "nrpe-uninstall" script to the same directory nrpe get installed to (John Frickson)
* Updated code so configure && make will work on AIX, HP-UX, Solaris, OS X.
  There should be no errors or warnings. Let me know if any errors or
  warning appear (John Frickson)
* Added command-line option to prevent forking, since some of the init
  replacements (such as systemd, etc.) don't want daemons to fork (John Frickson)
* Added autoconf macros and additional files to better support multi-platform
  config and compile. The default will still set up to install to
  /usr/local/nagios but I added a new configure option:
  '--enable-install-method=<method>'. If <method> is 'opt', everything will
  install to '/opt/nagios'. If <method> is 'os', installation will be to O/S-
  and distribution-specific locations, such as /usr/sbin, /usr/lib/nagios,
  /etc/nagios, and so on.
* Added additional init and inetd config files to support more systems,
  including SuSE, Debian, Slackware, Gentoo, *BSD, AIX, HP-UX, Solaris, OS X.
* Added listen_queue_size as configuration option (Vadim Antipov, Kaspersky Lab)
* Reworked SSL/TLS. See the README.SSL.md file for full info. (John Frickson)
* Added support for version 3 variable sized packets up to 64KB. nrpe will
  accept either version from check_nrpe. check_nrpe will try to send a
  version 3 packet first, and fall back to version 2. check_nrpe can be forced
  to only send version 2 packets if the switch `-2` is used. (John Frickson)
* Added extended timeout syntax in the -t <secs>:<status> format. (ABrist)

**FIXES**
* Fixed configure to check more places for SSL headers/libs. (John Frickson)
* Added ifdefs for complete_SSL_shutdown to compile without SSL. (Matthew L. Daniel)
* Renamed configure.in to configure.ac and added check for sigaction (John Frickson)
* Replaced all instances of signal() with sigaction() + blocking (John Frickson)
* check_nrpe does not parse passed arguments correctly (John Frickson)
* NRPE should not start if cannot write pid file (John Frickson)
* Fixed out-of-bounds error (return code 255) for some failures (John Frickson)
* Connection Timeout and Connection Refused messages need a new line (Andrew Widdersheim)
* allowed_hosts doesn't work, if one of the hostnames can't be resolved by dns (John Frickson)
* allowed_hosts doesn't work with a hostname resolving to an IPv6 address (John Frickson)
* Return UNKNOWN when issues occur (Andrew Widdersheim)
* NRPE returns OK if check can't be executed (Andrew Widdersheim)
* nrpe 2.15 [regression in Added SRC support on AIX - 2.14] (frphoebus)
* compile nrpe - Solaris 9 doesn't have isblank() (lilo, John Frickson)
* sample configuration for check_load has crazy sample load avg (ernestoongaro)


2.15 - 09/06/2013
-----------------
* Now compiles on HP-UX (Grant Byers)
* Added support for IPv6 (Leo Baltus, Eric Stanley)



2.14 - 12/21/2012
-----------------
* Added configure option to allow bash command substitutions, disabled by default [bug #400] (Eric Stanley)
* Patched to shutdown SSL connection completely (Jari Takkala)
* Added SRC support on AIX (Thierry Bertaud)
* Updated RPM SPEC file to support creating RPMs on AIX (Eric Stanley)
* Updated logging to support compiling on AIX (Eric Stanley)



2.13 - 11/11/2011
-----------------
* Applied Kaspersky Labs supplied patch for extending allowed_hosts (Konstantin Malov)
* Fixed bug in allowed_hosts parsing (Eric Stanley)
* Updated to support compiling on Solaris 10 (thanks to Kevin Pendleton)



2.12 - 03/10/2008
-----------------
* Fix for unterminated multiline plugin (garbage) output (Krzysztof Oledzki)



2.11 - 12/26/2007
-----------------
* Added lib64 library paths to configure script for 64-bit systems (John Maag)
* Added --with-ssl-lib configure script option
* Added --with-log-facility option to control syslog logging (Ryan Ordway and Brian Seklecki)



2.10 - 10/19/2007
-----------------
* Moved PDF docs to docs/ subdirectory, added OpenOffice source document
* A critical result is now returned for child processed that die due to a signal (Klas Lindfors) 



2.9 - 08/13/2007
----------------
* Fixed bug with --with-nrpe-group configure script option (Graham Collinson)
* Fixed bug with check_disk thresholds in sample config file (Patric Wust)
* Added NRPE_PROGRAMVERSION and NRPE_MULTILINESUPPORT environment variables
  for scripts that need to detect NRPE version and capabilities (Gerhard Lausser)
* Added asprintf() support for systems that are missing it (Samba team)



2.8.1 - 05/10/2007
-----------------
* Fixed configure script error with user-specified NRPE group



2.8 - 05/08/2007
---------------
* Added support for multiline plugin output (limited to 1KB at the moment) (Matthias Flacke)



2.8b1 - 03/14/2007
-----------------
* Changes to sample config files
* Added ';' as an additional prohibited metachar for command arguments
* Updated documentation and added easier installation commands



2.7.1 - 03/08/2007
------------------
* Changed C++ style comment to C style to fix compilation errors on AIX (Ryan McGarry)



2.7 - 02/18/2007
----------------
* Patches for detection SSL header and library locations (Andrew Boyce-Lewis)
* NRPE daemon will now partially ignore non-fatal configuration file errors and attempt to startup (Andrew Boyce-Lewis)



2.6 - 12/11/2006
----------------
* Added -u option to check_nrpe to return UNKNOWN states on socket timeouts (Bjoern Beutel)
* Added connection_timeout variable to NRPE daemon to catch dead client connections (Ton Voon)
* Added graceful timeout to check_nrpe to ensure connection to NRPE daemon is properly closed (Mark Plaksin)



2.5.2 - 06/30/2006
------------------
* Fixed incorrect service name in sample xinetd config file
* Added note on how to restart inetd for OpenBSD users (Robert Peaslee)
* Fix for nonblocking accept()s on systems that define EAGAIN differently than EWOULDBLOCK (Gerhard Lausser)
* Fix to (re)allow week random seed (Gerhard Lausser)



2.5.1 - 04/09/2006
------------------
* Patch to fix segfault if --no-ssl option is used (Sean Finney/Peter Palfrader)



2.5 - 04/06/2006
----------------
* (Re)added allowed_hosts option for systems that don't support TCP wrappers
* Fix for SSL errors under Solaris 8 (Niels Endres)
* Fix for config file directory inclusion on ReiserFS (Gerhard Lausser)



2.4 - 02/22/2006
----------------
* Added option to allow week random seed (Gerhard Lausser)
* Added optional command line prefix (Sean Finney)
* Added ability to reload config file with SIGHUP
* Fixed bug with location of dh.h include file
* Fixed bug with disconnect message in debug mode



2.3 - 01/23/2006
----------------
* Spec file fixes
* Removed errant PID file debugging code
* Fixed problem with trimming command definitions



2.2 - 01/22/2006
----------------
* Spec file fix
* Patch to add Tru64 and IRIX support (Ton Voon)
* Updated config.sub and config.guess
* Fixed bug with config file lines with only whitespace
* Fixed bug with missing getopt() command line option for -V
* Removed sample FreeBSD init script (now maintained by FreeBSD port)
* Added config file option for writing a PID file



2.1 - 01/19/2004
----------------
* Replaced host access list with TCP wrapper support
* Removed length restrictions for command names and command lines
* Configure script patch for getopt_long on Solaris
* Bug fixes for accept() on HP-UX 11.0
* Init script for SUSE Linux (Subhendu Ghosh)
* SSL protocol used is now limited to TLSv1
* Any output from plugins after first line is now ignored before
  plugin process is closed



2.0 - 09/08/2003
----------------
* Added support for passing arguments to command
* NRPE daemon can no longer be run as root user/group
* Added getopt support
* Added 'include' variable to config file to allow inclusion
  of external config files
* Added 'include_dir' variable to allow inclusion of external
  config files in directories (with recursion)
* Added native SSL support (Derrick Bennett)
* Added my_strsep(), as Solaris doesn't have strsep()
* Added license exemption for use with OpenSSL



1.8 - 01/16/2003
----------------
* Daemon now closes stdio/out/err properly (James Peterson)
* Makefile changes (James Peterson)
* Mode command line option bug fix in daemon
* Fixed incorrect command line options in check_nrpe plugin



1.7 - 01/08/2003
----------------
* Spec file updates and minor bug fixes (James Peterson)
* Bug fix with default nrpe port definition
* Added sample xinetd config file (nrpe.xinetd)
* Bug fix for command_timeout variable (James Peterson)



1.6 - 12/30/2002
----------------
* Updated sample commands to match new plugin argument format
* Added sample init scripts for FreeBSD and Debian (Andrew Ryder)
* Syntax changes (-H option specifies host name in check_nrpe, 
  -c option specifies config file in nrpe)
* Added command_timeout directive to config file to allow user
  to specify timeout for executing plugins
* Added spec file and misc patches for building RPMs (James Peterson)
* Added --with-nrpe-port config directive (James Peterson)



1.5 - 06/03/2002
----------------
* Added setuid/setgid option to config file (suggested by Marek Cervenka) 



1.4 - 06/01/2002
----------------
* Changed STATE_UNKNOWN to value of 3 instead of -1 (old style)
* Minor doc and sample config file changes



1.3 - 02/21/2002
----------------
* Name and version change
* Ignore SIGHUP, minor cleanup (Jon Andrews)



1.2.5 - 12/22/2001
------------------
* Implemented Beej's sendall() to handle partial send()s
* Added instructions on running under xinetd to README
* Removed some old crud



1.2.4 - 02/22/2001
------------------
* I forgot what changes I made.  Go figure...



1.2.3 - 12/21/2000
------------------
* A bit more documentation on configuring command definitions for the plugin



1.2.2 - 06/05/2000
------------------
* Fixed error in docs for running under inetd using TCP wrappers
* Replaced old email address in src/netutils.h with new one



1.2.1 - 05/07/2000
------------------
* Removed trapping of SIGCHLD
* Changed wait4() to waitpid() to allow compilation on HP-UX and AIX



1.2.0 - 04/18/2000
------------------
* Server forks twice after accepting a client connection, so as to prevent the
  creation of zombies



1.1.5 - 04/07/2000
------------------
* Fixed a small bug where one debug message was not getting logged properly



1.1.4 - 03/30/2000
------------------
* Added option to disable/enable debug messages using the debug option in the
  config file



1.1.3 - 03/11/2000
------------------
* Changed config file to use an absolute path
* Changed all debug output to use syslog (Rene Klootwijk)
* No convert all data to network order before sending it and convert it back to
  host order when receiving it. This makes it possible to mix Solaris and Linux,  
  e.g. running check_nrpe on Linux and nrpe on Solaris. (Rene Klootwijk)



1.1.2 - 03/07/2000
------------------
* Removed unnecessary code in signal handler routine
* Unused signals are no longer trapper



1.1.1 - 02/28/2000 - RKL
---------------------------
* Modified syslog code to include string describing the error code.
* Changed hardcoded number in signal handler to its name. This prevented nrpe
  to run on Solaris.
* Fixed race condition in accept loop. The result of accept should also be
  checked for EINTR.
* Modified recv and send function calls to compile without warnings on Solaris.
* Modified configure.in,configure and Makefile.in to include nsl and socket libs
  for Solaris.
* Modified the signal handler to reestablish itself after being called.



1.1 - 02/24/2000 - Rene Klootwijk <rene@klootwijk.org>
-----------------
* Added ability to bind nrpe to a specific interface by specifying the address
  of this interface in the nrpe.cfg file (e.g. server_address=192.168.2.3)



1.0   - 02/16/2000
------------------
* Added ability to run as a service under inetd



1.0b6 - 02/01/2000
------------------
* Added configure script
* Netutils functions from the NetSaint plugins is now used
* Reset SIGCHLD to default behavior before calling popen() to
  prevent race condition with pclose() (Reported by Rene Klootwijk)
* Cleaned up code



1.0b5 - 01/10/2000
------------------
* Added init script contributed by Jacob L
* Incorporated syslog code and other patches contributed by Jacob L



1.0b4 - 11/04/1999
------------------
* Changed 'allowed_ip' option in configuration file to
  'allowed_hosts' and added support for multiple hosts
* Minor buffer overflow protection fixes
* main() returned STATE_UNKNOWN on successful launch, changed to STATE_OK (jaclu@grm.se)
* Added syslog support (jaclu@grm.se)
