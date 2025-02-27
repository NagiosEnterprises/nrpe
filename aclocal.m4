# generated automatically by aclocal 1.17 -*- Autoconf -*-

# Copyright (C) 1996-2024 Free Software Foundation, Inc.

# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
# ===========================================================================
#    https://www.gnu.org/software/autoconf-archive/ax_check_link_flag.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_LINK_FLAG(FLAG, [ACTION-SUCCESS], [ACTION-FAILURE], [EXTRA-FLAGS], [INPUT])
#
# DESCRIPTION
#
#   Check whether the given FLAG works with the linker or gives an error.
#   (Warnings, however, are ignored)
#
#   ACTION-SUCCESS/ACTION-FAILURE are shell commands to execute on
#   success/failure.
#
#   If EXTRA-FLAGS is defined, it is added to the linker's default flags
#   when the check is done.  The check is thus made with the flags: "LDFLAGS
#   EXTRA-FLAGS FLAG".  This can for example be used to force the linker to
#   issue an error when a bad flag is given.
#
#   INPUT gives an alternative input source to AC_LINK_IFELSE.
#
#   NOTE: Implementation based on AX_CFLAGS_GCC_OPTION. Please keep this
#   macro in sync with AX_CHECK_{PREPROC,COMPILE}_FLAG.
#
# LICENSE
#
#   Copyright (c) 2008 Guido U. Draheim <guidod@gmx.de>
#   Copyright (c) 2011 Maarten Bosmans <mkbosmans@gmail.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.  This file is offered as-is, without any
#   warranty.

#serial 6

AC_DEFUN([AX_CHECK_LINK_FLAG],
[AC_PREREQ(2.64)dnl for _AC_LANG_PREFIX and AS_VAR_IF
AS_VAR_PUSHDEF([CACHEVAR],[ax_cv_check_ldflags_$4_$1])dnl
AC_CACHE_CHECK([whether the linker accepts $1], CACHEVAR, [
  ax_check_save_flags=$LDFLAGS
  LDFLAGS="$LDFLAGS $4 $1"
  AC_LINK_IFELSE([m4_default([$5],[AC_LANG_PROGRAM()])],
    [AS_VAR_SET(CACHEVAR,[yes])],
    [AS_VAR_SET(CACHEVAR,[no])])
  LDFLAGS=$ax_check_save_flags])
AS_VAR_IF(CACHEVAR,yes,
  [m4_default([$2], :)],
  [m4_default([$3], :)])
AS_VAR_POPDEF([CACHEVAR])dnl
])dnl AX_CHECK_LINK_FLAGS

# ===========================================================================
#    https://www.gnu.org/software/autoconf-archive/ax_normalize_path.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_NORMALIZE_PATH(VARNAME, [REFERENCE_STRING])
#
# DESCRIPTION
#
#   Perform some cleanups on the value of $VARNAME (interpreted as a path):
#
#     - empty paths are changed to '.'
#     - trailing slashes are removed
#     - repeated slashes are squeezed except a leading doubled slash '//'
#       (which might indicate a networked disk on some OS).
#
#   REFERENCE_STRING is used to turn '/' into '\' and vice-versa: if
#   REFERENCE_STRING contains some backslashes, all slashes and backslashes
#   are turned into backslashes, otherwise they are all turned into slashes.
#
#   This makes processing of DOS filenames quite easier, because you can
#   turn a filename to the Unix notation, make your processing, and turn it
#   back to original notation.
#
#     filename='A:\FOO\\BAR\'
#     old_filename="$filename"
#     # Switch to the unix notation
#     AX_NORMALIZE_PATH([filename], ["/"])
#     # now we have $filename = 'A:/FOO/BAR' and we can process it as if
#     # it was a Unix path.  For instance let's say that you want
#     # to append '/subpath':
#     filename="$filename/subpath"
#     # finally switch back to the original notation
#     AX_NORMALIZE_PATH([filename], ["$old_filename"])
#     # now $filename equals to 'A:\FOO\BAR\subpath'
#
#   One good reason to make all path processing with the unix convention is
#   that backslashes have a special meaning in many cases. For instance
#
#     expr 'A:\FOO' : 'A:\Foo'
#
#   will return 0 because the second argument is a regex in which
#   backslashes have to be backslashed. In other words, to have the two
#   strings to match you should write this instead:
#
#     expr 'A:\Foo' : 'A:\\Foo'
#
#   Such behavior makes DOS filenames extremely unpleasant to work with. So
#   temporary turn your paths to the Unix notation, and revert them to the
#   original notation after the processing. See the macro
#   AX_COMPUTE_RELATIVE_PATHS for a concrete example of this.
#
#   REFERENCE_STRING defaults to $VARIABLE, this means that slashes will be
#   converted to backslashes if $VARIABLE already contains some backslashes
#   (see $thirddir below).
#
#     firstdir='/usr/local//share'
#     seconddir='C:\Program Files\\'
#     thirddir='C:\home/usr/'
#     AX_NORMALIZE_PATH([firstdir])
#     AX_NORMALIZE_PATH([seconddir])
#     AX_NORMALIZE_PATH([thirddir])
#     # $firstdir = '/usr/local/share'
#     # $seconddir = 'C:\Program Files'
#     # $thirddir = 'C:\home\usr'
#
# LICENSE
#
#   Copyright (c) 2008 Alexandre Duret-Lutz <adl@gnu.org>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 8

AU_ALIAS([ADL_NORMALIZE_PATH], [AX_NORMALIZE_PATH])
AC_DEFUN([AX_NORMALIZE_PATH],
[case ":[$]$1:" in
# change empty paths to '.'
  ::) $1='.' ;;
# strip trailing slashes
  :*[[\\/]]:) $1=`echo "[$]$1" | sed 's,[[\\/]]*[$],,'` ;;
  :*:) ;;
esac
# squeeze repeated slashes
case ifelse($2,,"[$]$1",$2) in
# if the path contains any backslashes, turn slashes into backslashes
 *\\*) $1=`echo "[$]$1" | sed 's,\(.\)[[\\/]][[\\/]]*,\1\\\\,g'` ;;
# if the path contains slashes, also turn backslashes into slashes
 *) $1=`echo "[$]$1" | sed 's,\(.\)[[\\/]][[\\/]]*,\1/,g'` ;;
esac])

m4_include([macros/ax_nagios_get_distrib.m4])
m4_include([macros/ax_nagios_get_files.m4])
m4_include([macros/ax_nagios_get_inetd.m4])
m4_include([macros/ax_nagios_get_init.m4])
m4_include([macros/ax_nagios_get_os.m4])
m4_include([macros/ax_nagios_get_paths.m4])
m4_include([macros/ax_nagios_get_ssl.m4])
