# Packaging

LibreWard is distributed as native packages. It is a system tool: it runs
`pkexec` helpers, installs a systemd service, writes owned files under `/etc`
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
| `/usr/share/icons/hicolor/{scalable,256x256}/apps/libreward.*` | Icon |

The modules live in a private directory instead of site-packages because their
names (`core`, `ui`, `config`, …) would clash with other packages. LibreWard
installs no login autostart entry; Internet protection runs as a system service.
Run `make test` for the test suite. `tests/test_packaging.py` checks that every
module is installed and that package versions match.

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
quarantine) stays in the home directory.
Firewall rules belong to UFW or firewalld and are kept.

## Distribution support

| Distribution | Package | PySide6 from the distribution |
| --- | --- | --- |
| Arch, Manjaro, EndeavourOS | AUR (`packaging/arch/PKGBUILD`) | `pyside6` |
| Fedora | OBS, RPM (`packaging/rpm/libreward.spec`) | `python3-pyside6` |
| openSUSE Tumbleweed, Leap 16 | OBS, RPM | `python3XX-pyside6` (via `python3dist(pyside6)`) |
| Debian 13 (trixie) and newer | OBS, deb (`packaging/debian/`) | `python3-pyside6.*` 6.8 |
| Ubuntu 25.10 and newer | OBS, deb | `python3-pyside6.*` |
| **Ubuntu 24.04 LTS, Linux Mint 22** | **not yet** | **not packaged** |

Ubuntu 24.04 and Mint 22 have no PySide6 packages. Supporting them needs a deb
that bundles the PySide6 wheel (architecture-specific, roughly 200 MB), or a
backport in a PPA.

## Release

1. Set `APP_VERSION` in `core/constants.py`, the `CHANGELOG.md` heading, and the
   versions in `packaging/arch/PKGBUILD`, `packaging/rpm/libreward.spec`
   (`Version`, `%changelog`), `packaging/debian/changelog` and
   `packaging/obs/libreward.dsc`.
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
