#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([tallow], [0], [auke-jan.h.kok@intel.com])
AM_INIT_AUTOMAKE([])
AC_CONFIG_FILES([Makefile])

# Systemd is required, obviously
PKG_CHECK_MODULES([SYSTEMD], [systemd])
PKG_CHECK_MODULES([SD_JOURNAL], [libsystemd-journal])

SYSTEMDSYSTEMUNITDIR="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
AC_SUBST(SYSTEMDSYSTEMUNITDIR)

AC_OUTPUT([
])
