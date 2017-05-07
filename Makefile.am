
AM_CFLAGS = -g $(LIBSYSTEMD_CFLAGS) -Wall -Wno-uninitialized -W -D_FORTIFY_SOURCE=2

systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = tallow.service

sbin_PROGRAMS = tallow
tallow_SOURCES = tallow.c
tallow_LDADD = $(LIBSYSTEMD_LIBS)

EXTRA_DIST = AUTHORS COPYING INSTALL tallow.service.in tallow.1.md

dist_doc_DATA = tallow.conf
dist_man_MANS = tallow.1 tallow.conf.5

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)

docs: tallow.1.md
	ronn -r tallow.1.md
