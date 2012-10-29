
EXTRA_DIST = AUTHORS COPYING INSTALL

AM_CFLAGS = -g $(LIBSYSTEMD_JOURNAL_CFLAGS) -Wall -Wno-uninitialized

systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = tallow.service

sbin_PROGRAMS = tallow
tallow_SOURCES = tallow.c
tallow_LDADD = $(LIBSYSTEMD_JOURNAL_LIBS)





