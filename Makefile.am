SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	COPYING \
	README.md \
	version

version:
	$(AM_V_GEN)$(top_srcdir)/build-aux/git-version-gen > $@
