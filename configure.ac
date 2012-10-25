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
PKG_CHECK_MODULES([LIBSYSTEMD_JOURNAL], [libsystemd-journal])
AC_SUBST(LIBSYSTEMD_JOURNAL_CFLAGS)
AC_SUBST(LIBSYSTEMD_JOURNAL_LIBS)

AC_OUTPUT([
])
