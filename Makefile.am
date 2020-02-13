
AM_CFLAGS = -g \
	$(JSON_C_CFLAGS) $(PCRE_CFLAGS) $(LIBSYSTEMD_CFLAGS) \
	-Wall -Wno-uninitialized -W -D_FORTIFY_SOURCE=2

AM_CPPFLAGS = \
	-DDATADIR='"$(datadir)"' -DSYSCONFDIR='"$(sysconfdir)"'

systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = data/tallow.service

sbin_PROGRAMS = tallow
tallow_SOURCES = \
	src/tallow.c \
	src/json.c \
	src/json.h \
	src/data.c \
	src/data.h
tallow_LDADD = $(JSON_C_LIBS) $(PCRE_LIBS) $(LIBSYSTEMD_LIBS)

pkgdata_DATA = data/sshd.json

EXTRA_DIST = \
	AUTHORS COPYING INSTALL README.md \
	data/tallow.service.in \
	data/sshd.json \
	man/tallow.conf.5.md \
	man/tallow.patterns.5.md \
	man/tallow.1.md

dist_man_MANS = man/tallow.1 man/tallow.conf.5 man/tallow.patterns.5

dist_doc_DATA = tallow.conf

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)

docs: $(dist_man_MANS)
man/%.5: man/%.5.md
	ronn -r $< --pipe > $@

man/%.1: man/%.1.md
	ronn -r $< --pipe > $@

