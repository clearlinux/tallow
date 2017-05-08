
AM_CFLAGS = -g $(LIBSYSTEMD_CFLAGS) $(LIBSYSTEMD_JOURNAL_CFLAGS) -Wall -Wno-uninitialized -W -D_FORTIFY_SOURCE=2

systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = tallow.service

sbin_PROGRAMS = tallow
tallow_SOURCES = tallow.c
tallow_LDADD = $(LIBSYSTEMD_LIBS) $(LIBSYSTEMD_JOURNAL_LIBS)

EXTRA_DIST = AUTHORS COPYING INSTALL tallow.service.in tallow.1.md

dist_man_MANS = tallow.1 tallow.conf.5

dist_doc_DATA = tallow.conf

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)

docs: tallow.1 tallow.conf.5
tallow.conf.5:
	ronn -r tallow.conf.5.md --pipe > tallow.conf.5

tallow.1:
	ronn -r tallow.1.md --pipe > tallow.1

