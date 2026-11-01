# Packaging

LibreWard is distributed as native packages. It is a system tool: it runs
programs as root through pkexec, installs a systemd service, writes owned files under `/etc`
and uses the host's NetworkManager, systemd-resolved, firewall and ClamAV. A
Flatpak sandbox blocks exactly these operations, and working around it with
`flatpak-spawn --host` would remove the sandbox while suggesting isolation.

## Layout

`make install DESTDIR=… PREFIX=/usr` is shared by all packages:

| Path | Contents |
| --- | --- |
| `/usr/bin/libreward` | Launcher (`packaging/libreward.in`); runs the system Python with `-s -E` |
| `/usr/share/libreward/` | Application modules, byte-compiled, and bundled data |
| `/usr/share/applications/libreward.desktop` | Menu entry |
| `/usr/share/metainfo/io.github.anaisoob.LibreWard.metainfo.xml` | AppStream metadata for GNOME Software and KDE Discover (`packaging/`) |
| `/usr/share/icons/hicolor/{scalable,256x256}/apps/libreward.*` | Icon |
| `/usr/lib/systemd/user/libreward-monitor.service` | Background service for all users, not enabled; see [Administration](administration.md) |
| `/usr/libexec/libreward/` (Arch: `/usr/lib/libreward/`) | The programs that run as root, one per polkit action (`packaging/libreward-root.in`) |
| `/usr/share/polkit-1/actions/io.github.anaisoob.LibreWard.policy` | The polkit actions (`packaging/`) |

The modules live in a private directory instead of site-packages because their
names (`core`, `ui`, `config`, …) would clash with other packages. LibreWard
installs no login autostart entry; Internet protection runs as a system service.
Folder monitoring, when a user turns it on, runs as that user's systemd service
`~/.config/systemd/user/libreward-monitor.service` (`libreward --monitor`),
written by LibreWard rather than the package.
Run `make test` for the test suite. `tests/test_packaging.py` checks that every
module is installed and that package versions match.

## Administrator rights

Everything LibreWard does as root goes through one of four small programs, each
with its own polkit action, so the password dialog says what LibreWard wants to do
instead of “run /usr/bin/python3”:

| Program | polkit action | Asks |
| --- | --- | --- |
| `system-check` | `io.github.anaisoob.LibreWard.system-check` | once, then kept for a few minutes (`auth_admin_keep`); nothing is changed |
| `scan-files` | `io.github.anaisoob.LibreWard.scan-files` | every time; nothing is changed |
| `internet-protection` | `io.github.anaisoob.LibreWard.internet-protection` | every time (`auth_admin`) |
| `firewall-read` | `io.github.anaisoob.LibreWard.firewall-read` | once, then kept for a few minutes; nothing is changed |
| `firewall-change` | `io.github.anaisoob.LibreWard.firewall-change` | every time |

Each program imports `backends/linux_root.py` from `/usr/share/libreward`, which
only root can change, and accepts only fixed choices: the system check takes no
arguments, `scan-files` a list of files and a database folder and chooses the
`clamscan` and all its options itself, the firewall programs a known firewall and a change that is validated
again as root, Internet protection a mode and a DNS service from a fixed list. They
find the system programs they run themselves. Installing ClamAV or the DNS
component runs the package manager through pkexec directly; that dialog shows the
exact install command.

LibreWard uses these programs only when they are installed next to it and owned by
root. Run from source, pkexec starts the system's `python3 -I` with LibreWard's
helper code, and the dialog shows the generic polkit message.

## Removal

Removing the package turns Internet protection off and deletes LibreWard's system
files: `/etc/libreward/`, the `libreward-dns` systemd units and its NetworkManager
or systemd-resolved snippets. The package scripts run
`/usr/bin/python3 -I /usr/share/libreward/system_cleanup.py` as root, only on removal,
not on upgrades: RPM `%preun` when `$1` is 0, Debian `prerm remove`, Arch
`pre_remove`. `make uninstall` does the same for a direct installation.

The cleanup uses the same transaction as **Turn off**, removes only files
LibreWard wrote, keeps anything else in `/etc/libreward`, and never fails the
removal; on errors it prints the manual steps. User data (settings, lists,
quarantine) stays in the home directory. When the removal runs through `sudo`
(`sudo make uninstall`, `sudo dnf remove`) or pkexec, the folder monitoring service
of that user is stopped and deleted too. Other users' services, and removals without
a known user (for example from a software center), leave the file behind; systemd
then skips it (`ConditionPathExists`).
Firewall rules belong to UFW or firewalld and are kept.

## Distribution support

| Distribution | Package | PySide6 from the distribution |
| --- | --- | --- |
| Arch, Manjaro, EndeavourOS | AUR (`packaging/arch/PKGBUILD`) | `pyside6` |
| Fedora | OBS, RPM (`packaging/rpm/libreward.spec`) | `python3-pyside6` |
| openSUSE Tumbleweed, Leap 16 | OBS, RPM | `python3XX-pyside6` (via `python3dist(pyside6)`) |
| Debian 13 (trixie) and newer | OBS, deb (`packaging/debian/`) | `python3-pyside6.*` 6.8 |
| Ubuntu 25.10 and newer | OBS, deb | `python3-pyside6.*` |
| Ubuntu 22.04 and 24.04 LTS, Linux Mint 21 and 22, Debian 12 | deb with its own PySide6 (`packaging/bundled/`) | not packaged; included |

### Package with its own PySide6

Ubuntu 24.04, Mint 22 and Debian 12 have no PySide6 packages. `make bundled-deb`
(or `python3 packaging/bundled/build-deb.py --arch amd64|arm64`) builds
`dist/libreward_<version>_<arch>.deb` that includes PySide6 and watchdog:

- The wheels are the ones pinned in `uv.lock`, downloaded from their recorded URLs
  and checked against their SHA256 hashes. PySide6 wheels are `abi3`, so they work
  with the system's Python 3.10 or newer; x86_64 needs glibc 2.34 (Ubuntu 22.04,
  Debian 12), arm64 glibc 2.39 (Ubuntu 24.04).
- They are unpacked into `/usr/share/libreward/vendor`, which `main.py` adds to the
  module path after the application folder. Root helpers never import it.
- Only QtCore, QtGui, QtWidgets and QtNetwork are kept; Qt Quick, QML, Designer and
  the developer tools are removed, then every library or plugin that needs a removed
  part (checked with `ldd`). The build fails if the X11, Wayland or offscreen
  platform plugins, SVG icons or the four modules are gone. The package is about
  28 MB (120 MB installed).
- `Depends` lists the system libraries Qt needs (X11/xcb, Wayland, EGL, fontconfig,
  D-Bus), and `prerm` is the same as in the Debian package.

The build needs Python 3.11+, `make` and `dpkg-deb`, and no root, debhelper or pip.

## Release

1. Set `APP_VERSION` in `core/constants.py`, the `CHANGELOG.md` heading, and the
   versions in `packaging/arch/PKGBUILD`, `packaging/rpm/libreward.spec`
   (`Version`, `%changelog`), `packaging/debian/changelog` and
   `packaging/obs/libreward.dsc`. Add a `<release>` entry with a short summary at
   the top of `packaging/io.github.anaisoob.LibreWard.metainfo.xml`; software
   centers show it as the update notes.
2. Run `make test`, commit, tag `vX.Y.Z` and push the tag.

### AUR

```bash
git clone ssh://aur@aur.archlinux.org/libreward.git aur-libreward
cp packaging/arch/PKGBUILD aur-libreward/
cd aur-libreward
updpkgsums                 # replaces SKIP with the tag tarball checksum
makepkg -si                # build, run the tests and install locally
namcap PKGBUILD *.pkg.tar.zst
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO && git commit -m "Update to X.Y.Z" && git push
```

### openSUSE Build Service (Fedora, openSUSE, Debian, Ubuntu)

Create a project such as `home:<user>:libreward`, enable the target
repositories from the table above, and add a `libreward` package with:

- the tag tarball `libreward-X.Y.Z.tar.gz` and `libreward.spec` (RPM targets);
- `libreward.dsc` from `packaging/obs/` and the Debian files renamed for OBS's
  debtransform: `debian.control`, `debian.rules`, `debian.changelog`,
  `debian.copyright`, `debian.libreward.docs` (deb targets).

OBS then publishes repositories with signed packages and upgrades through the
system's normal updates. Install instructions for users are on the OBS
project's download page.
