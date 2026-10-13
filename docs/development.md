# Development and testing

## Architecture

LibreWard uses one GUI, one shared core layer and separate platform backends.

| Location | Responsibility |
| --- | --- |
| `ui/` | PySide6 / Qt interface, dialogs, themes and widgets |
| `core/` | Scans, ClamD protocol/lifecycle, health checks, updates, database handling, quarantine, firewall validation and domain lists |
| `backends/` | Platform runtime detection, paths, processes, firewall and DNS changes/authorization and installation guidance |
| `scanner.py` | File collection, commands and ClamAV output parsing |
| `excludes.py` | Shared matching and ClamAV regex arguments |
| `tests/` | Core, socket-protocol, launcher and Qt workflow regressions |
| `assets/` | Images, including the README screenshot, and the app icon in `assets/icons/` |
| `packaging/` | Launcher, desktop entry, AUR, RPM, Debian and OBS files; see [Packaging](packaging.md) |

Long operations run in workers. The GUI consumes queued events with a Qt timer.
Only one app operation runs at a time; parallel file checks use a bounded pool.
OS-specific behavior belongs in backends. ClamAV is an external runtime;
LibreWard does not link to `libclamav`.

Launch with `python main.py`. The earlier `--qt` argument and
`requirements-qt.txt` remain compatibility aliases. Local contributor instructions may also be provided in
an `AGENTS.md` file; that file is excluded from the distribution repository.

## Automated checks

From an environment with the project dependencies installed:

```bash
python -m unittest discover -s tests -v
git diff --check
```

On headless Linux:

```bash
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
```

Qt tests require PySide6 and platform libraries; otherwise those tests are
skipped and core tests still run. Protocol tests use a local test server with
real socket framing, parallel requests, ownership checks and large-file handling.
GUI installation/update and firewall mutation operations are simulated. Automated
tests never enable the host firewall or modify its rules. The suite does not download
ClamAV or benchmark real antivirus scans.
Domain-list downloads are mocked and the public DNS helper is tested only
against temporary files. The database DNS filter is tested with real UDP/TCP queries on temporary loopback ports. Installer rollback, migration and failure recovery use temporary files and mocked service commands. Tests never alter system DNS settings.

## Release smoke checks

Verify on Windows and a desktop Linux installation:

- First run with missing components; accept, decline and suppress setup.
- Platform installation, component recheck and database update.
- Windows portable runtime download, repair and error recovery.
- Folder/Quick scans with exclusions and an unavailable daemon.
- Parallel scans using a system daemon and an owned daemon; confirm the system
  daemon stays running afterward.
- Large files, changing/inaccessible files, cancellation, progress and reports.
- Navigation away from an active scan and the sidebar activity indicator.
- Confirmed quarantine/restore/delete, including an occupied restore destination.
- Linux firewall detection, cancelled authorization, activation and LAN/all-address rules
  in a disposable VM. Verify matching traffic and UFW/firewalld persistence.
- Themes, exclusions and reopening resized or maximized windows.
- Linux Internet protection in a disposable VM: enable, cancel authorization,
  allow/block an exact domain, update lists, pause, restart, and check IPv4/IPv6
  resolution. Verify VPN/DNS connection settings remain intact.
  On NetworkManager/systemd, check that protection keeps working after closing the
  GUI, logging out and rebooting, that the first turn-on and first close show their
  one-time messages, that Turn off restores normal DNS,
  the filter behind systemd-resolved on Ubuntu Desktop and Fedora (each DNS
  service, TLS and blocked port 853, pause, close, reboot, killed GUI, unreachable
  service rollback, VPN split DNS and full-tunnel VPN), repeated enable/pause, and intentional
  filter termination/OOM recovery. Confirm normal DNS returns and the GUI stops
  claiming active protection. Test an occupied private port and failed reload.

The [README screenshot](../assets/libreward.png) is stored at
`assets/libreward.png`. Capture the actual Qt interface when updating it;
exclude private paths, findings and personal data.

Retain LibreWard and bundled ClamAV licenses in releases and review the Qt
requirements linked from the [project README](../README.md).
Archives bundling ClamAV must retain its copyright notices. Qt/PySide6
distribution must meet the applicable license terms, including library
replacement where required.
