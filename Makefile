# Installs LibreWard into a private application directory, as distribution
# packages expect for arch-independent Python applications. Module names such
# as `core` and `ui` stay out of the system's site-packages.
#
#   make install DESTDIR=/tmp/root PREFIX=/usr
#
# Packages: packaging/arch (AUR), packaging/rpm (Fedora/openSUSE), packaging/debian.

PREFIX ?= /usr/local
DESTDIR ?=
PYTHON ?= /usr/bin/python3
BINDIR = $(PREFIX)/bin
APPDIR = $(PREFIX)/share/libreward
DATADIR = $(PREFIX)/share

MODULES = main.py config.py scanner.py excludes.py
PACKAGES = backends core ui

.PHONY: all install uninstall test

all:

install:
	install -d $(DESTDIR)$(APPDIR)
	install -m 644 $(MODULES) $(DESTDIR)$(APPDIR)/
	for package in $(PACKAGES); do \
		install -d $(DESTDIR)$(APPDIR)/$$package; \
		install -m 644 $$package/*.py $(DESTDIR)$(APPDIR)/$$package/; \
	done
	install -d $(DESTDIR)$(APPDIR)/updates $(DESTDIR)$(APPDIR)/assets/icons
	install -m 644 updates/*.json $(DESTDIR)$(APPDIR)/updates/
	install -m 644 assets/icons/libreward.svg assets/icons/libreward-256.png $(DESTDIR)$(APPDIR)/assets/icons/
	install -d $(DESTDIR)$(BINDIR)
	sed -e 's|@PYTHON@|$(PYTHON)|g' -e 's|@APPDIR@|$(APPDIR)|g' -e 's|@BINDIR@|$(BINDIR)|g' \
		packaging/libreward.in > $(DESTDIR)$(BINDIR)/libreward
	chmod 755 $(DESTDIR)$(BINDIR)/libreward
	install -Dm 644 packaging/libreward.desktop $(DESTDIR)$(DATADIR)/applications/libreward.desktop
	install -Dm 644 assets/icons/libreward.svg $(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/libreward.svg
	install -Dm 644 assets/icons/libreward-256.png $(DESTDIR)$(DATADIR)/icons/hicolor/256x256/apps/libreward.png
	$(PYTHON) -m compileall -q -d $(APPDIR) $(DESTDIR)$(APPDIR)

uninstall:
	rm -rf $(DESTDIR)$(APPDIR)
	rm -f $(DESTDIR)$(BINDIR)/libreward $(DESTDIR)$(DATADIR)/applications/libreward.desktop \
		$(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/libreward.svg \
		$(DESTDIR)$(DATADIR)/icons/hicolor/256x256/apps/libreward.png

test:
	QT_QPA_PLATFORM=offscreen $(PYTHON) -m unittest discover -s tests
