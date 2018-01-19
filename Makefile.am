
AM_CFLAGS = -g $(PCRE_CFLAGS) $(LIBSYSTEMD_CFLAGS) -Wall -Wno-uninitialized -W -D_FORTIFY_SOURCE=2

systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = tallow.service

sbin_PROGRAMS = tallow
tallow_SOURCES = tallow.c
tallow_LDADD = $(PCRE_LIBS) $(LIBSYSTEMD_LIBS)

EXTRA_DIST = AUTHORS COPYING INSTALL README.md tallow.service.in tallow.conf.5.md tallow.1.md

dist_man_MANS = tallow.1 tallow.conf.5

dist_doc_DATA = tallow.conf

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)

docs: tallow.1 tallow.conf.5
tallow.conf.5: tallow.conf.5.md
	ronn -r tallow.conf.5.md --pipe > tallow.conf.5

tallow.1: tallow.1.md
	ronn -r tallow.1.md --pipe > tallow.1

