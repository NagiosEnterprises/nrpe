dnl Process this -*-m4-*- file with autoconf to produce a configure script.

dnl Disable caching
define([AC_CACHE_LOAD],)
define([AC_CACHE_SAVE],)

m4_include([build-aux/custom_help.m4])
AC_INIT([nrpe],[3.0-beta1],[nagios-users@lists.sourceforge.net],[nrpe],[https://www.nagios.org/downloads/nagios-core-addons/])
AC_CONFIG_SRCDIR([src/nrpe.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_PREFIX_DEFAULT(/usr/local/nagios)

PKG_NAME=nrpe
PKG_VERSION="3.0-beta1"
PKG_HOME_URL="http://www.nagios.org/"
PKG_REL_DATE="04-21-2016"
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
AC_SUBST(HAVE_SSL)
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
AC_SUBST(opsys)
AC_SUBST(arch)
AC_SUBST(dist_type)
AC_SUBST(dist_ver)
AC_SUBST(init_type)
AC_SUBST(inetd_type)
AC_SUBST(pkgsysconfdir)
AC_SUBST(objsysconfdir)
AC_SUBST(sbindir)
AC_SUBST(initname)
AC_SUBST(inetdname)
AC_SUBST(pluginsdir)
AC_SUBST(brokersdir)
AC_SUBST(cgibindir)
AC_SUBST(webdir)
AC_SUBST(privatesysconfdir)
AC_SUBST(pkglocalstatedir)
AC_SUBST(logdir)
AC_SUBST(piddir)
AC_SUBST(pipedir)
AC_SUBST(spooldir)
AC_SUBST(initdir)
AC_SUBST(inetddir)
AC_SUBST(tmpfilesd)
AC_SUBST(subsyslockdir)
AC_SUBST(subsyslockfile)
AC_SUBST(src_tmpfile)
AC_SUBST(src_init)
AC_SUBST(src_inetd)

dnl Figure out how to invoke "install" and what install options to use.
AC_PROG_INSTALL

dnl Get O/S, Distribution, init, inetd, system-specific directories
AC_NAGIOS_GET_OS
AC_NAGIOS_GET_DISTRIB_TYPE
AC_NAGIOS_GET_INIT
AC_NAGIOS_GET_INETD
AC_NAGIOS_GET_PATHS
AC_NAGIOS_GET_FILES

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
	package/solaris/Makefile
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
	startup/mac-org.nagios.PKG_NAME.plist
	startup/newbsd-init
	startup/openrc-conf
	startup/openrc-init
	startup/solaris-init.xml
	startup/solaris-inetd.xml
	startup/tmpfile.conf
	startup/upstart-init
	startup/rh-upstart-init
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
AC_CHECK_FUNCS(strdup strstr strtoul strtok_r initgroups closesocket sigaction)

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
	AS_HELP_STRING([--enable-ssl],[enables native SSL support]),[
	if test x$enableval = xyes; then
		check_for_ssl=yes
	else
		check_for_ssl=no
	fi
	],check_for_ssl=yes)

dnl Optional SSL library and include paths
ssl_dir=
ssl_inc_dir=
ssl_lib_dir=
ssl_usedh=
AC_ARG_WITH([dh],
	AS_HELP_STRING([--with-dh],[use --without-dh to turn of DH keys]),
	[ssl_usedh=$withval])
AC_ARG_WITH([ssl],
	AS_HELP_STRING([--with-ssl=DIR],[sets location of the SSL installation]),
	[ssl_dir=$withval])
AC_ARG_WITH([ssl-inc],
	AS_HELP_STRING([--with-ssl-inc=DIR],
		[sets location of the SSL include files]),
	[ ssl_inc_dir=$withval])
AC_ARG_WITH([ssl-lib],
	AS_HELP_STRING([--with-ssl-lib=DIR],[sets location of the SSL libraries]),
	[ssl_lib_dir=$withval])
AC_ARG_WITH([kerberos-inc],
	AS_HELP_STRING([--with-kerberos-inc=DIR],
		[sets location of the Kerberos include files]),
	[kerberos_inc_dir=$withval])

dnl Check for SSL support
dnl Modified version of Mark Ethan Trostler's macro <trostler@juniper.net>
if test x$check_for_ssl = xyes; then
	AC_MSG_CHECKING(for SSL headers)
	found_ssl=no
	for dir in $ssl_inc_dir $ssl_dir /usr/local/openssl /usr/local/opt/openssl \
				/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr \
				/usr/freeware/lib/openssl /usr/sfw /usr/sfw/include \
				/opt/openssl; do
		ssldir="$dir"
		if test -f "$dir/include/openssl/ssl.h"; then
			found_ssl=yes
			CFLAGS="$CFLAGS -I$dir/include/openssl -I$ssldir/include"
			sslincdir="$dir/include/openssl"
			break
		fi
		if test -f "$dir/include/ssl.h"; then
			found_ssl=yes
			CFLAGS="$CFLAGS -I$dir/include"
			sslincdir="$dir/include"
			break
		fi
		if test -f "$dir/ssl.h"; then
			found_ssl=yes
			CFLAGS="$CFLAGS -I$dir"
			sslincdir="$dir"
			ssldir="$dir/.."
			break
		fi
		if test -f "$dir/openssl/ssl.h"; then
			found_ssl=yes
			CFLAGS="$CFLAGS -I$dir/openssl"
			sslincdir="$dir/openssl"
			ssldir="$dir/.."
			break
		fi
	done

	if test x_$found_ssl != x_yes; then
		AC_MSG_ERROR(Cannot find ssl headers)
	else
		AC_MSG_RESULT(found in $ssldir)

		dnl Now try and find SSL libraries
		AC_MSG_CHECKING(for SSL libraries)
		found_ssl=no
		if test "`uname -s`" = "Darwin" ; then
			soext="dylib"
		elif test "`uname -s`" = "HP-UX" ; then
			if test x$arch = "xia64"; then
				soext="so"
			else
				soext="sl"
			fi
		elif test "`uname -s`" = "AIX" ; then
			soext="a"
		else
			soext="so"
		fi
		for dir in $ssl_lib_dir $ssldir $ssldir/lib $ssldir/lib64 /usr/lib64 \
					/usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu \
					/usr/local/lib /usr/lib/ssl /usr/ssl/lib /usr/openssl/lib \
					/usr/pkg/lib /usr/freeware/lib/openssl /usr/sfw/lib \
					/opt/freeware/lib /opt/openssl/lib/hpux64 \
					/opt/openssl/lib/pa20_64 /opt/openssl/lib/hpux32 \
					/opt/openssl/lib /opt/openssl; do
			ssllibdir="$dir"
			if test -f "$dir/libssl.$soext"; then
				found_ssl=yes
				break
			fi
		done

		if test x_$found_ssl != x_yes; then
			AC_MSG_ERROR(Cannot find ssl libraries)
		else
			AC_MSG_RESULT(found in $ssllibdir)

			LDFLAGS="$LDFLAGS -L$ssllibdir";
			LIBS="$LIBS -lssl -lcrypto";

			AC_DEFINE_UNQUOTED(HAVE_SSL,[1],[Have SSL support])

			AC_PATH_PROG(sslbin,openssl,value-if-not-found,$ssldir/sbin$PATH_SEPARATOR$ssldir/bin$PATH_SEPARATOR$PATH)

			if test x$ssl_usedh = xno; then
				echo "skipping DH Parameter generation"
			else
				AC_DEFINE(USE_SSL_DH)
				dnl Generate DH parameters
				if test -f "$sslbin"; then
					echo ""
					echo "*** Generating DH Parameters for SSL/TLS ***"
					# awk to strip off meta data at bottom of dhparam output
					$sslbin dhparam -C 2048 | awk '/^-----/ {exit} {print}' > include/dh.h
				fi
			fi
		fi
	fi

	dnl RedHat 8.0 and 9.0 include openssl compiled with kerberos, so we must include header file
	AC_MSG_CHECKING(for Kerberos include files)
	found_kerberos=no
	for dir in $kerberos_inc_dir /usr/kerberos/include; do
		kerbdir="$dir"
		if test -f "$dir/krb5.h"; then
			found_kerberos=yes
			CFLAGS="$CFLAGS -I$kerbdir"
			AC_DEFINE_UNQUOTED(HAVE_KRB5_H,[1],[Have the krb5.h header file])
			dnl AC_CHECK_HEADERS(krb5.h)
			break
		fi
	done

	if test x_$found_kerberos != x_yes; then
		AC_MSG_WARN(could not find include files)
	else
		AC_MSG_RESULT(found Kerberos include files in $kerbdir)
	fi


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

# Determine target OS, version and architecture for package build macros
if test "x$target_ver" = "x" ; then
	TARGET_VER=`uname -r`
else
	TARGET_VER=$target_ver
fi
if test "x$target_os" = "x" ; then
	TARGET_OS=`uname -s`
else
	TARGET_OS=$target_os
fi
if test "x$target_cpu" = "x" ; then
	TARGET_ARCH=`uname -p`
else
	TARGET_ARCH=$target_cpu
fi
TARGET_PLATFORM=""
if test "x$TARGET_OS" = "xSunOS" ; then
	if test "x$TARGET_VER" = "x5.10" ; then
		TARGET_PLATFORM="sol10"
	fi
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
