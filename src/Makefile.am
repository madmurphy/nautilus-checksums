# Process this file with automake to produce Makefile.in


AM_CPPFLAGS = \
	"-DPACKAGE_LOCALE_DIR=\"$(localedir)\"" \
	"-DPACKAGE_SRC_DIR=\"$(srcdir)\"" \
	"-DPACKAGE_DATA_DIR=\"$(pkgdatadir)\"" \
	"-DG_LOG_DOMAIN=\"NautilusChecksums\""


AM_CFLAGS = \
	-Wall \
	-Wextra \
	-g \
	$(WARN_CFLAGS) \
	$(NAUTILUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(NAUTILUS_CHECKSUMS_CFLAGS)


nautilus_extensiondir = $(NAUTILUS_EXTENSION_DIR)


nautilus_extension_LTLIBRARIES = \
	libnautilus-checksums.la


libnautilus_checksums_la_SOURCES = \
	nautilus-checksums.c


libnautilus_checksums_la_LDFLAGS = \
	-module \
	-avoid-version


libnautilus_checksums_la_LIBADD = \
	$(NAUTILUS_CHECKSUMS_LIBS)


# EOF

