dnl Process this -*-m4-*- file with autoconf to produce a configure script.

dnl Disable caching
define([AC_CACHE_LOAD],)
define([AC_CACHE_SAVE],)

m4_include([build-aux/custom_help.m4])
AC_INIT([nrpe],[newdate],[nagios-users@lists.sourceforge.net],[nrpe],[https://www.nagios.org/downloads/nagios-core-addons/])
AC_CONFIG_SRCDIR([src/nrpe.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_PREFIX_DEFAULT(/usr/local/nagios)

PKG_NAME=nrpe
PKG_VERSION="3.2.1"
PKG_HOME_URL="http://www.nagios.org/"
PKG_REL_DATE="2017-09-01"
RPM_RELEASE=1

LANG=C
LC_ALL=C
LC_COLLATE=C
LC_CTYPE=C
LC_MESSAGES=C
LC_MONETARY=C
LC_NUMERIC=C
LC_TIME=C

AC_SUBST(PKG_NAME)
AC_SUBST(PKG_VERSION)
AC_SUBST(PKG_HOME_URL)
AC_SUBST(PKG_REL_DATE)
AC_SUBST(RPM_RELEASE)
AC_SUBST(INSTALL)
AC_SUBST(SNPRINTF_O)
AC_SUBST(LDFLAGS)
AC_SUBST(OTHERLIBS)
AC_SUBST(SOCKETLIBS)
AC_SUBST(LIBWRAPLIBS)
AC_SUBST(NRPE_INSTALL_OPTS)
AC_SUBST(log_facility)
AC_SUBST(nrpe_user)
AC_SUBST(nrpe_group)
AC_SUBST(nrpe_port)
AC_SUBST(nagios_user)
AC_SUBST(nagios_group)
AC_SUBST(NAGIOS_INSTALL_OPTS)
AC_SUBST(TARGET_VER)
AC_SUBST(TARGET_OS)
AC_SUBST(TARGET_ARCH)
AC_SUBST(TARGET_PLATFORM)

dnl Figure out how to invoke "install" and what install options to use.
AC_PROG_INSTALL

dnl Get O/S, Distribution, init, inetd, system-specific directories
AC_NAGIOS_GET_OS
AC_NAGIOS_GET_DISTRIB_TYPE
AC_NAGIOS_GET_INIT
AC_NAGIOS_GET_INETD
AC_NAGIOS_GET_PATHS
AC_NAGIOS_GET_FILES

if test "$dist_type" = solaris -a "$dist_ver" = 10; then
	AC_DEFINE(SOLARIS_10,yes)
fi

dnl Do they just want to see where things will go?
if test x${showdirs_only} = xyes; then
	AC_CONFIG_FILES([paths])
	AC_OUTPUT()
	chmod 755 paths
	./paths
	exit 0
fi

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_FILES([Makefile
	src/Makefile
	nrpe.spec
	uninstall
	sample-config/nrpe.cfg
	startup/bsd-init
	startup/debian-init
	startup/default-init
	startup/default-inetd
	startup/default-service
	startup/default-socket
	startup/default-socket-svc
	startup/default-xinetd
	startup/mac-init.plist
	startup/mac-inetd.plist
	startup/newbsd-init
	startup/openbsd-init
	startup/openrc-conf
	startup/openrc-init
	startup/solaris-init.xml
	startup/solaris-inetd.xml
	startup/tmpfile.conf
	startup/upstart-init
	startup/rh-upstart-init
	include/common.h
])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(ctype.h dirent.h errno.h fcntl.h getopt.h grp.h inttypes.h)
AC_CHECK_HEADERS(netdb.h pwd.h signal.h stdint.h strings.h string.h syslog.h)
AC_CHECK_HEADERS(tcpd.h unistd.h arpa/inet.h netinet/in.h socket.h sys/types.h)
AC_CHECK_HEADERS(sys/time.h sys/resource.h sys/wait.h sys/socket.h sys/stat.h)
AC_CHECK_HEADERS(paths.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_TYPE_GETGROUPS

dnl Check lengths for later tests of u_int32_t and int32_t
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(long)

dnl Define u_int32_t if we don't have it already (Solaris, etc.)
AC_CHECK_TYPE(uint32_t,unsigned int)
AC_CHECK_TYPE(u_int32_t,unsigned int)
if test "$ac_cv_type_u_int32_t" = no ; then
	if test "$ac_cv_type_u_int32_t" = yes ; then
		AC_DEFINE(U_INT32_T_IS_UINT32_T,[1],[u_int32_t is uint32_t])
	else
		if test "$ac_cv_sizeof_int" = 4 ; then
			AC_DEFINE(U_INT32_T_IS_UINT,[1],[u_int32_t is uint])
		else
			if test "$ac_cv_sizeof_long" = 4 ; then
				AC_DEFINE(U_INT32_T_IS_ULONG,[1],[u_int32_t is ulong])
			else
				if test "$ac_cv_sizeof_short" = 4 ; then
					AC_DEFINE(U_INT32_T_IS_USHORT,[1],[u_int32_t is ushort])
				fi
			fi
		fi
	fi
fi

dnl Define int32_t if we don't have it already
AC_CHECK_TYPE(int32_t,int)
if test "$ac_cv_type_int32_t" = no ; then
	if test "$ac_cv_sizeof_int" = 4 ; then
		AC_DEFINE(INT32_T_IS_UINT,[1],[int32_t is uint])
	else
		if test "$ac_cv_sizeof_long" = 4 ; then
			AC_DEFINE(INT32_T_IS_ULONG,[1],[int32_t is ulong])
		else
			if test "$ac_cv_sizeof_short" = 4 ; then
				AC_DEFINE(INT32_T_IS_USHORT,[1],[int32_t is ushort])
			fi
		fi
	fi
fi

dnl Check for struct sockaddr_storate
AC_CHECK_TYPES([struct sockaddr_storage],[],[],[#include <sys/socket.h>])

dnl Should we use seteuid() or setresuid()?
AC_CHECK_FUNC(seteuid,
	AC_DEFINE(SETEUID(id),[seteuid(id)]),
	AC_DEFINE(SETEUID(id),[setresuid((uid_t) -1, id, (uid_t) -1)])
)

dnl Check for asprintf() and friends...
AC_CACHE_CHECK([for va_copy],ac_cv_HAVE_VA_COPY,[
AC_TRY_LINK([#include <stdarg.h>
va_list ap1,ap2;], [va_copy(ap1,ap2);],
ac_cv_HAVE_VA_COPY=yes,
ac_cv_HAVE_VA_COPY=no)])
if test x"$ac_cv_HAVE_VA_COPY" = x"yes"; then
	AC_DEFINE(HAVE_VA_COPY,1,[Whether va_copy() is available])
else
	AC_CACHE_CHECK([for __va_copy],ac_cv_HAVE___VA_COPY,[
	AC_TRY_LINK([#include <stdarg.h>
	va_list ap1,ap2;], [__va_copy(ap1,ap2);],
	ac_cv_HAVE___VA_COPY=yes,
	ac_cv_HAVE___VA_COPY=no)])
	if test x"$ac_cv_HAVE___VA_COPY" = x"yes"; then
		AC_DEFINE(HAVE___VA_COPY,1,[Whether __va_copy() is available])
	fi
fi

AC_CHECK_FUNC(vsnprintf,,SNPRINTF_O=./snprintf.o)
AC_CHECK_FUNC(snprintf,,SNPRINTF_O=./snprintf.o)
AC_CHECK_FUNC(asprintf,,SNPRINTF_O=./snprintf.o)
AC_CHECK_FUNC(vasprintf,,SNPRINTF_O=./snprintf.o)

AC_CACHE_CHECK([for C99 vsnprintf],ac_cv_HAVE_C99_VSNPRINTF,[
AC_TRY_RUN([
#include <sys/types.h>
#include <stdarg.h>
void foo(const char *format, ...) {
	va_list ap;
	int len;
	char buf[5];

	va_start(ap, format);
	len = vsnprintf(buf, 0, format, ap);
	va_end(ap);
	if (len != 5) exit(1);

	va_start(ap, format);
	len = vsnprintf(0, 0, format, ap);
	va_end(ap);
	if (len != 5) exit(1);

	if (snprintf(buf, 3, "hello") != 5 || strcmp(buf, "he") != 0) exit(1);

	exit(0);
}
main() { foo("hello"); }
],
ac_cv_HAVE_C99_VSNPRINTF=yes,ac_cv_HAVE_C99_VSNPRINTF=no,ac_cv_HAVE_C99_VSNPRINTF=cross)])
if test x"$ac_cv_HAVE_C99_VSNPRINTF" = x"yes"; then
	AC_DEFINE(HAVE_C99_VSNPRINTF,1,[Define if system has C99 compatible vsnprintf])
fi

dnl AC_CHECK_FUNC(snprintf,AC_DEFINE(HAVE_SNPRINTF),SNPRINTF_O=./snprintf.o)

dnl Check for getopt_long (Solaris)
AC_CHECK_FUNCS([getopt_long],,AC_CHECK_LIB([iberty],[getopt_long],OTHERLIBS="$OTHERLIBS -liberty"))

dnl Checks for library functions.
AC_CHECK_LIB(nsl,main,SOCKETLIBS="$SOCKETLIBS -lnsl")
AC_CHECK_LIB(socket,socket,SOCKETLIBS="$SOCKETLIBS -lsocket")
AC_CHECK_LIB(wrap,main,[
	LIBWRAPLIBS="$LIBWRAPLIBS -lwrap"
	AC_DEFINE(HAVE_LIBWRAP,[1],[Have the TCP wrappers library])
	AC_TRY_LINK([#include <tcpd.h>
		],[int a = rfc931_timeout;],AC_DEFINE(HAVE_RFC931_TIMEOUT))
	])
AC_CHECK_FUNCS(strdup strstr strtoul strtok_r initgroups closesocket sigaction scandir)

dnl socklen_t check - from curl
AC_CHECK_TYPE([socklen_t], ,[
	AC_MSG_CHECKING([for socklen_t equivalent])
	AC_CACHE_VAL([curl_cv_socklen_t_equiv],
	[
		# Systems have either "struct sockaddr *" or
		# "void *" as the second argument to getpeername
		curl_cv_socklen_t_equiv=
		for arg2 in "struct sockaddr" void; do
			for t in int size_t unsigned long "unsigned long"; do
				AC_TRY_COMPILE([
					#ifdef HAVE_SYS_TYPES_H
					#include <sys/types.h>
					#endif
					#ifdef HAVE_SYS_SOCKET_H
					#include <sys/socket.h>
					#endif

					int getpeername (int, $arg2 *, $t *);
				],[
					$t len;
					getpeername(0,0,&len);
				],[
					curl_cv_socklen_t_equiv="$t"
					break
				])
			done
		done

		if test "x$curl_cv_socklen_t_equiv" = x; then
			AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
		fi
	])
	AC_MSG_RESULT($curl_cv_socklen_t_equiv)
	AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
						[type to use in place of socklen_t if not defined])],
		[#include <sys/types.h>
#include <sys/socket.h>])


AC_MSG_CHECKING(for type of socket size)
AC_TRY_COMPILE([#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
],
[int a = send(1, (const void *)0, (size_t *) 0, (int *) 0);],
[AC_DEFINE(SOCKET_SIZE_TYPE, size_t, [Socket Size Type]) AC_MSG_RESULT(size_t)],
[AC_DEFINE(SOCKET_SIZE_TYPE, int, [Socket Size Type]) AC_MSG_RESULT(int)])

dnl Does user want to check for SSL?
AC_ARG_ENABLE([ssl],
	AS_HELP_STRING([--disable-ssl],[disables native SSL support @<:@default=check@:>@]),[
	if test x$enableval = xyes; then
		check_for_ssl=yes
	else
		check_for_ssl=no
	fi
	],check_for_ssl=yes)

need_dh=yes
AC_ARG_WITH([need_dh],
	AS_HELP_STRING([--with-need-dh],[set to 'no' to not include Diffie-Hellman SSL logic]),
	[need_dh=$withval],
	[nrpe_group=need_dh])

dnl Optional SSL library and include paths
if test x$check_for_ssl = xyes; then
	# need_dh should only be set for NRPE
	#need_dh=yes
	AC_NAGIOS_GET_SSL
fi

AC_ARG_WITH([log_facility],
	AS_HELP_STRING([--with-log-facility=<facility>],
		[sets NRPE syslog facility]),
	[log_facility=$withval],
	[log_facility=daemon])
AC_DEFINE_UNQUOTED(NRPE_LOG_FACILITY,["$log_facility"],[NRPE syslog facility])

AC_ARG_WITH([nrpe_user],
	AS_HELP_STRING([--with-nrpe-user=<user>],[sets user name to run NRPE]),
	[nrpe_user=$withval],
	[nrpe_user=nagios])

AC_ARG_WITH([nrpe_group],
	AS_HELP_STRING([--with-nrpe-group=<group>],[sets group name to run NRPE]),
	[nrpe_group=$withval],
	[nrpe_group=nagios])

AC_ARG_WITH([nrpe_port],
	AS_HELP_STRING([--with-nrpe-port=<port>],
		[sets port number for NRPE to listen on]),
	[nrpe_port=$withval],
	[nrpe_port=5666])
NRPE_INSTALL_OPTS="-o $nrpe_user -g $nrpe_group"
AC_DEFINE_UNQUOTED(DEFAULT_SERVER_PORT,$nrpe_port,[Default port for NRPE daemon])

AC_ARG_WITH([nagios_user],
	AS_HELP_STRING([--with-nagios-user=<user>],
		[sets user name for file permissions]),
	[nagios_user=$withval],
	[nagios_user=nagios])
AC_ARG_WITH([nagios_group],
	AS_HELP_STRING([--with-nagios-group=<grp>],
		[sets group name file permissions]),
	[nagios_group=$withval],
	[nagios_group=nagios])
NAGIOS_INSTALL_OPTS="-o $nagios_user -g $nagios_group"

	dnl On HP-UX the compile will fail with a 'Duplicate symbol "setenv"' error
	dnl in '/usr/local/lib/libwrap.a(setenv.o)' and '/usr/local/lib/libiberty.a(setenv.o)'
	dnl so allow duplicate symbols, and use the first one
	if test "`uname -s`" = "HP-UX" ; then
		LDFLAGS="$LDFLAGS -Wl,+allowdups";
	fi

AC_ARG_ENABLE([command-args],
	AS_HELP_STRING([--enable-command-args],[allows clients to specify command arguments.  *** THIS IS A SECURITY RISK! *** Read the SECURITY file before using this option!]),
	AC_DEFINE_UNQUOTED(ENABLE_COMMAND_ARGUMENTS,[1],[Enable command-line arguments]))

AC_ARG_ENABLE([bash-command-substitution],
	AS_HELP_STRING([--enable-bash-command-substitution],[allows clients to pass bash command substitutions of the form $(command).  *** THIS IS A HIGH SECURITY RISK! *** Read the SECURITY file before using this option!]),
	AC_DEFINE_UNQUOTED(ENABLE_BASH_COMMAND_SUBSTITUTION,[1],[Enable bash command substitution]))


AC_PATH_PROG(PERL,perl)
AC_OUTPUT()

dnl Review options
echo ""
echo ""
AC_MSG_RESULT([*** Configuration summary for $PKG_NAME $PKG_VERSION $PKG_REL_DATE ***:])

echo "";\
echo " General Options:";\
echo " -------------------------"

AC_MSG_RESULT([ NRPE port:    $nrpe_port])
AC_MSG_RESULT([ NRPE user:    $nrpe_user])
AC_MSG_RESULT([ NRPE group:   $nrpe_group])
AC_MSG_RESULT([ Nagios user:  $nagios_user])
AC_MSG_RESULT([ Nagios group: $nagios_group])


echo "";\
echo "";\
echo "Review the options above for accuracy.  If they look okay,";\
echo "type 'make all' to compile the NRPE daemon and client";\
echo "or type 'make' to get a list of make options.";\
echo ""
