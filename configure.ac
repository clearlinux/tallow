#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([tallow], [0], [auke-jan.h.kok@intel.com])
AM_INIT_AUTOMAKE([])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

PKG_CHECK_MODULES([SYSTEMD], [systemd])
PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd])
AC_SUBST(LIBSYSTEMD_CFLAGS)
AC_SUBST(LIBSYSTEMD_LIBS)

AC_ARG_WITH([systemdsystemunitdir], AC_HELP_STRING([--with-systemdsystemunitdir=DIR],
	[path to systemd system service directory]), [path_systemdsystemunit=${withval}],
	[path_systemdsystemunit="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"])
if (test -n "${path_systemdsystemunit}"); then
SYSTEMD_SYSTEMUNITDIR="${path_systemdsystemunit}"
AC_SUBST(SYSTEMD_SYSTEMUNITDIR)
AM_CONDITIONAL(SYSTEMD, test -n "${path_systemdsystemunit}")
fi

AC_CHECK_HEADERS([stdlib.h stdio.h string.h stdarg.h limits.h sys/time.h])

AC_OUTPUT([
tallow.service
])
