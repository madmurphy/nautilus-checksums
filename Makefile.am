# Process this file with automake to produce Makefile.in


ACLOCAL_AMFLAGS = -I m4

AM_DISTCHECK_CONFIGURE_FLAGS = --without-nautilus-libdir

SUBDIRS = \
	src

dist_doc_DATA = \
	AUTHORS \
	COPYING \
	ChangeLog \
	NEWS \
	README

EXTRA_DIST = \
	ChangeLog.md \
	INSTALL \
	NEWS \
	README.md \
	bootstrap \
	package.json \
	.editorconfig

nodist_pkgdata_DATA =

BUILT_SOURCES =


if NLS_ENABLED

SUBDIRS += \
	po

else !NLS_ENABLED

EXTRA_DIST += \
	po

endif !NLS_ENABLED


_clean_dirs_ = \
	no-dist

# Shell expansion is supported here
_distclean_dirs_ = \
	'po/backups'

# Shell expansion is supported here
_bootstrapclean_dirs_ = \
	'autom4te.cache' \
	'build-aux' \
	'm4'

# Shell expansion is supported here
_bootstrapclean_files_ = \
	*'~' \
	'ABOUT-NLS' \
	'aclocal.m4' \
	'compile' \
	'config'.* \
	'configure' \
	'depcomp' \
	'install-sh' \
	'libtool' \
	'ltmain.sh' \
	'missing' \
	'po/@PACKAGE_TARNAME@.pot' \
	'po/boldquot.sed' \
	'po/en@boldquot.header' \
	'po/en@quot.header' \
	'po/insert-header.sin' \
	'po'/*'~' \
	'po/Makefile.in.in' \
	'po/Makevars.template' \
	'po/quot.sed' \
	'po/remove-potcdate.sin' \
	'po/Rules-quot'


if HAVE_FIND

_bootstrapclean_dirs_ += \
	`$(FIND) -L . -type d -name .deps`


_bootstrapclean_files_ += \
	`$(FIND) -L . -type f -name 'Makefile.in'`

endif HAVE_FIND


# Remove `$(docdir)` and `$(pkgdatadir)` on uninstall
uninstall-local:
	-rm -rf '$(DESTDIR)$(docdir)' '$(DESTDIR)$(pkgdatadir)';


clean-local:
	-rm -rf $(_clean_dirs_);


distclean-local:
	-rm -rf $(_distclean_dirs_);


# Update translations
.PHONY: i18n-update
i18n-update:
	$(MKDIR_P) 'po/backups' && $(GREP) -o '^\s*\w\S\+' 'po/LINGUAS' | \
	while read _i_; do cp "po/$${_i_}.po" "po/backups/$${_i_}.po.bak" && \
	rm -f 'po/@PACKAGE_TARNAME@.pot' && $(MAKE) -C 'po' "$${_i_}.po" && \
	sed -i \
	's/"Project-Id-Version:.*$$/"Project-Id-Version: @PACKAGE_TARNAME@ @PACKAGE_VERSION@\\n"/' \
	"po/$${_i_}.po"; done;


# Make the source directory depend on Autotools and a `bootstrap` script
.PHONY: bootstrap-clean
bootstrap-clean: maintainer-clean
	-rm -rf $(_bootstrapclean_dirs_); rm -f $(_bootstrapclean_files_); \
	(cd '$(srcdir)' && rm -rf $(_bootstrapclean_dirs_); \
	rm -f $(_bootstrapclean_files_));


# EOF
