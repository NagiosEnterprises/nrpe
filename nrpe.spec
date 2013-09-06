%define isaix %(test "`uname -s`" = "AIX" && echo "1" || echo "0")
%define islinux %(test "`uname -s`" = "Linux" && echo "1" || echo "0")

%if %{isaix}
	%define _prefix	/opt/nagios
	%define _docdir %{_prefix}/doc/nrpe-2.15
	%define nshome /opt/nagios
	%define _make gmake
%endif
%if %{islinux}
	%define _init_dir /etc/init.d
	%define _exec_prefix %{_prefix}/sbin
	%define _bindir %{_prefix}/sbin
	%define _sbindir %{_prefix}/lib/nagios/cgi
	%define _libexecdir %{_prefix}/lib/nagios/plugins
	%define _datadir %{_prefix}/share/nagios
	%define _localstatedir /var/log/nagios
	%define nshome /var/log/nagios
	%define _make make
%endif
%define _sysconfdir /etc/nagios

%define name nrpe
%define version 2.15
%define release 1
%define nsusr nagios
%define nsgrp nagios
%define nsport 5666

# Reserve option to override port setting with:
# rpm -ba|--rebuild --define 'nsport 5666'
%{?port:%define nsport %{port}}

# Macro that print mesages to syslog at package (un)install time
%define nnmmsg logger -t %{name}/rpm

Summary: Host/service/network monitoring agent for Nagios
URL: http://www.nagios.org
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group: Application/System
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-buildroot
Prefix: %{_prefix}
Prefix: /etc/init.d
Prefix: /etc/nagios
%if %{isaix}
Requires: nagios-plugins
%endif
%if %{islinux}
Requires: bash, grep, nagios-plugins, util-linux, chkconfig, shadow-utils, sed, initscripts, mktemp
%endif

%description
NPRE (Nagios Remote Plugin Executor) is a system daemon that 
will execute various Nagios plugins locally on behalf of a 
remote (monitoring) host that uses the check_nrpe plugin.  
Various plugins that can be executed by the daemon are available 
at: http://sourceforge.net/projects/nagiosplug

This package provides the client-side NRPE agent (daemon).

%package plugin
Group: Application/System
Summary: Provides nrpe plugin for Nagios.
Requires: nagios-plugins

%description plugin
NPRE (Nagios Remote Plugin Executor) is a system daemon that 
will execute various Nagios plugins locally on behalf of a 
remote (monitoring) host that uses the check_nrpe plugin.  
Various plugins that can be executed by the daemon are available 
at: http://sourceforge.net/projects/nagiosplug

This package provides the server-side NRPE plugin for 
Nagios-related applications.

%prep
%setup -q


%pre
# Create `nagios' group on the system if necessary
%if %{isaix}
lsgroup %{nsgrp} > /dev/null 2> /dev/null
if [ $? -eq 2 ] ; then
	mkgroup %{nsgrp} || %nnmmsg Unexpected error adding group "%{nsgrp}". Aborting install process.
fi
%endif
%if %{islinux}
getent group %{nsgrp} > /dev/null 2> /dev/null
if [ $? -ne 0 ] ; then
	groupadd %{nsgrp} || %nnmmsg Unexpected error adding group "%{nsgrp}". Aborting install process.
fi
%endif

# Create `nagios' user on the system if necessary
%if %{isaix}
lsuser %{nsusr} > /dev/null 2> /dev/null
if [ $? -eq 2 ] ; then
	useradd -d %{nshome} -c "%{nsusr}" -g %{nsgrp} %{nsusr} || \
		%nnmmsg Unexpected error adding user "%{nsusr}". Aborting install process.
fi
%endif
%if %{islinux}
getent passwd %{nsusr} > /dev/null 2> /dev/null
if [ $? -ne 0 ] ; then
	useradd -r -d %{nshome} -c "%{nsusr}" -g %{nsgrp} %{nsusr} || \
		%nnmmsg Unexpected error adding user "%{nsusr}". Aborting install process.
fi
%endif

%if %{isaix}
# Check to see if the nrpe service is running and, if so, stop it.
/usr/bin/lssrc -s nrpe > /dev/null 2> /dev/null
if [ $? -eq 0 ] ; then
	status=`/usr/bin/lssrc -s nrpe | /usr/bin/gawk '$1=="nrpe" {print $NF}'`
	if [ "$status" = "active" ] ; then
		/usr/bin/stopsrc -s nrpe
	fi
fi
%endif

%if %{islinux}
# if LSB standard /etc/init.d does not exist,
# create it as a symlink to the first match we find
if [ -d /etc/init.d -o -L /etc/init.d ]; then
  : # we're done
elif [ -d /etc/rc.d/init.d ]; then
  ln -s /etc/rc.d/init.d /etc/init.d
elif [ -d /usr/local/etc/rc.d ]; then
  ln -s  /usr/local/etc/rc.d /etc/init.d
elif [ -d /sbin/init.d ]; then
  ln -s /sbin/init.d /etc/init.d
fi
%endif

%if %{isaix}
%post
/usr/bin/lssrc -s nrpe > /dev/null 2> /dev/null
if [ $? -eq 1 ] ; then
	/usr/bin/mkssys -p %{_bindir}/nrpe -s nrpe -u 0 -a "-c %{_sysconfdir}/nrpe.cfg -d -s" -Q -R -S -n 15 -f 9
fi
/usr/bin/startsrc -s nrpe
%endif

%preun
%if %{isaix}
status=`/usr/bin/lssrc -s nrpe | /usr/bin/gawk '$1=="nrpe" {print $NF}'`
if [ "$status" = "active" ] ; then
	/usr/bin/stopsrc -s nrpe
fi
/usr/bin/rmssys -s nrpe
%endif
%if %{islinux}
if [ "$1" = 0 ]; then
	/sbin/service nrpe stop > /dev/null 2>&1
	/sbin/chkconfig --del nrpe
fi
%endif

%if %{islinux}
%postun
if [ "$1" -ge "1" ]; then
	/sbin/service nrpe condrestart >/dev/null 2>&1 || :
fi
%endif

%build
export PATH=$PATH:/usr/sbin
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" \
MAKE=%{_make} ./configure \
	--with-init-dir=/etc/init.d \
	--with-nrpe-port=%{nsport} \
	--with-nrpe-user=%{nsusr} \
	--with-nrpe-group=%{nsgrp} \
	--prefix=%{_prefix} \
	--exec-prefix=%{_exec_prefix} \
	--bindir=%{_bindir} \
	--sbindir=%{_sbindir} \
	--libexecdir=%{_libexecdir} \
	--datadir=%{_datadir} \
	--sysconfdir=%{_sysconfdir} \
	--localstatedir=%{_localstatedir} \
	--enable-command-args
%{_make} all

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%if %{islinux}
install -d -m 0755 ${RPM_BUILD_ROOT}%{_init_dir}
%endif
DESTDIR=${RPM_BUILD_ROOT} %{_make} install install-daemon-config
#install -d -m 0755 ${RPM_BUILD_ROOT}%{_sysconfdir}
#install -d -m 0755 ${RPM_BUILD_ROOT}%{_bindir}
#install -d -m 0755 ${RPM_BUILD_ROOT}%{_libexecdir}

# install templated configuration files
#cp sample-config/nrpe.cfg ${RPM_BUILD_ROOT}%{_sysconfdir}/nrpe.cfg
#%if %{isaix}
#cp init-script ${RPM_BUILD_ROOT}%{_init_dir}/nrpe
#%endif
#cp src/nrpe ${RPM_BUILD_ROOT}%{_bindir}
#cp src/check_nrpe ${RPM_BUILD_ROOT}%{_libexecdir}

%clean
rm -rf $RPM_BUILD_ROOT


%files
%if %{islinux}
%defattr(755,root,root)
/etc/init.d/nrpe
%endif
%{_bindir}/nrpe
%dir %{_sysconfdir}
%defattr(600,%{nsusr},%{nsgrp})
%config(noreplace) %{_sysconfdir}/*.cfg
%defattr(755,%{nsusr},%{nsgrp})
%doc Changelog LEGAL README 

%files plugin
%defattr(755,%{nsusr},%{nsgrp})
%{_libexecdir}
%defattr(644,%{nsusr},%{nsgrp})
%doc Changelog LEGAL README 

%changelog
* Mon Mar 12 2012 Eric Stanley estanley<@>nagios.com
- Created autoconf input file 
- Updated to support building on AIX
- Updated install to use make install*
* Mon Jan 23 2006 Andreas Kasenides ank<@>cs.ucy.ac.cy
- fixed nrpe.cfg relocation to sample-config
- replaced Copyright label with License
- added --enable-command-args to enable remote arg passing (if desired can be disabled by commenting out)

* Wed Nov 12 2003 Ingimar Robertsson <iar@skyrr.is>
- Added adding of nagios group if it does not exist.

* Tue Jan 07 2003 James 'Showkilr' Peterson <showkilr@showkilr.com>
- Removed the lines which removed the nagios user and group from the system
- changed the patch release version from 3 to 1

* Mon Jan 06 2003 James 'Showkilr' Peterson <showkilr@showkilr.com>
- Removed patch files required for nrpe 1.5
- Update spec file for version 1.6 (1.6-1)

* Sat Dec 28 2002 James 'Showkilr' Peterson <showkilr@showkilr.com>
- First RPM build (1.5-1)
