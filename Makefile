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
USERUNITDIR = $(PREFIX)/lib/systemd/user
# Arch packages use /usr/lib; LibreWard looks in both.
LIBEXECDIR ?= $(PREFIX)/libexec
HELPERDIR = $(LIBEXECDIR)/libreward
# Whatever PREFIX is: this is the folder polkit reads.
POLKITDIR ?= /usr/share/polkit-1/actions
POLICY = io.github.anaisoob.LibreWard.policy
# One program per polkit action, see backends/linux_root.py.
ROOT_HELPERS = system-check internet-protection firewall-read firewall-change scan-files system-quarantine

MODULES = main.py config.py scanner.py excludes.py
PACKAGES = backends core ui

.PHONY: all install uninstall test bundled-deb

all:

install:
	install -d $(DESTDIR)$(APPDIR)
	install -m 644 $(MODULES) packaging/system_cleanup.py $(DESTDIR)$(APPDIR)/
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
	install -Dm 644 packaging/io.github.anaisoob.LibreWard.metainfo.xml \
		$(DESTDIR)$(DATADIR)/metainfo/io.github.anaisoob.LibreWard.metainfo.xml
	install -Dm 644 assets/icons/libreward.svg $(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/libreward.svg
	install -Dm 644 assets/icons/libreward-256.png $(DESTDIR)$(DATADIR)/icons/hicolor/256x256/apps/libreward.png
	install -d $(DESTDIR)$(USERUNITDIR)
	sed -e 's|@BINDIR@|$(BINDIR)|g' packaging/libreward-monitor.service.in \
		> $(DESTDIR)$(USERUNITDIR)/libreward-monitor.service
	chmod 644 $(DESTDIR)$(USERUNITDIR)/libreward-monitor.service
	rm -f $(DESTDIR)$(DATADIR)/polkit-1/actions/$(POLICY)  # where earlier versions put it
	install -d $(DESTDIR)$(HELPERDIR) $(DESTDIR)$(POLKITDIR)
	for helper in $(ROOT_HELPERS); do \
		sed -e 's|@PYTHON@|$(PYTHON)|g' -e 's|@APPDIR@|$(APPDIR)|g' -e "s|@ACTION@|$$helper|g" \
			packaging/libreward-root.in > $(DESTDIR)$(HELPERDIR)/$$helper; \
		chmod 755 $(DESTDIR)$(HELPERDIR)/$$helper; \
	done
	sed -e 's|@HELPERDIR@|$(HELPERDIR)|g' packaging/$(POLICY).in > $(DESTDIR)$(POLKITDIR)/$(POLICY)
	chmod 644 $(DESTDIR)$(POLKITDIR)/$(POLICY)
	$(PYTHON) -m compileall -q -d $(APPDIR) $(DESTDIR)$(APPDIR)

# Package scripts run system_cleanup.py on removal; `make uninstall` does the same
# for a direct installation (as root, without DESTDIR).
uninstall:
	if [ -z "$(DESTDIR)" ] && [ -f $(APPDIR)/system_cleanup.py ]; then $(PYTHON) -I $(APPDIR)/system_cleanup.py; fi
	rm -rf $(DESTDIR)$(APPDIR) $(DESTDIR)$(HELPERDIR)
	rm -f $(DESTDIR)$(BINDIR)/libreward $(DESTDIR)$(DATADIR)/applications/libreward.desktop \
		$(DESTDIR)$(DATADIR)/metainfo/io.github.anaisoob.LibreWard.metainfo.xml \
		$(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/libreward.svg \
		$(DESTDIR)$(DATADIR)/icons/hicolor/256x256/apps/libreward.png \
		$(DESTDIR)$(USERUNITDIR)/libreward-monitor.service $(DESTDIR)$(POLKITDIR)/$(POLICY)

test:
	QT_QPA_PLATFORM=offscreen $(PYTHON) -m unittest discover -s tests

# A .deb with its own PySide6 for Ubuntu 22.04/24.04, Mint 21/22 and Debian 12.
bundled-deb:
	$(PYTHON) packaging/bundled/build-deb.py --arch $(or $(ARCH),amd64)
