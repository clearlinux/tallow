
AM_CFLAGS = -g \
	$(JSON_C_CFLAGS) $(PCRE_CFLAGS) $(LIBSYSTEMD_CFLAGS) \
	-Wall -Wno-uninitialized -W -D_FORTIFY_SOURCE=2

AM_CPPFLAGS = \
	-DDATADIR='"$(datadir)"' -DSYSCONFDIR='"$(sysconfdir)"'

systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = data/tallow.service

sbin_PROGRAMS = tallow
tallow_SOURCES = tallow.c json.c json.h data.c data.h
tallow_LDADD = $(JSON_C_LIBS) $(PCRE_LIBS) $(LIBSYSTEMD_LIBS)

pkgdata_DATA = data/sshd.json

EXTRA_DIST = \
	AUTHORS COPYING INSTALL README.md \
	data/tallow.service.in \
	data/sshd.json \
	tallow.conf.5.md \
	tallow.1.md

dist_man_MANS = tallow.1 tallow.conf.5

dist_doc_DATA = tallow.conf

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)

docs: tallow.1 tallow.conf.5
tallow.conf.5: tallow.conf.5.md
	ronn -r tallow.conf.5.md --pipe > tallow.conf.5

tallow.1: tallow.1.md
	ronn -r tallow.1.md --pipe > tallow.1
