# LibreWard

LibreWard is a security and privacy desktop application for Linux and Windows,
built with Python and PySide6 / Qt. It provides antivirus scanning through
ClamAV and Linux firewall management. Internet monitoring and
DNS/privacy tools are planned for future releases.

![LibreWard Virus scan page in the dark theme](assets/libreward.png)

## Features

- Linux firewall detection, rule inspection and UFW installation guidance.
- Confirmed UFW/firewalld activation, automatic status refresh and LAN or all-address rules.
- Folder scans and Quick system scans with configurable exclusions.
- Parallel scanning with `clamd` and standard scanning with `clamscan`.
- Live progress, current-file information, cancellation and scan reports.
- Threat detection and warnings for files that could not be fully checked.
- Quarantine, restore and permanent deletion with user confirmation.
- Guided ClamAV setup, virus database updates and Windows runtime updates.
- Dark, light and system themes, with remembered window size and position.

## Run from source

Clone or download the project and run these commands from its directory.
Python 3.10 or newer with virtual-environment support is required. Python
dependencies are listed in [requirements.txt](requirements.txt).

### Linux

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

### Windows (PowerShell)

```powershell
py -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe main.py
```

After launching, open **Settings → Enable antivirus protection / setup** to
set up ClamAV and its virus database. On supported Linux distributions, the app
can run the package installation after confirmation and system authorization,
or provide commands for manual installation. On Windows, it can download the official
portable runtime after confirmation. The optional `clamd` component enables
parallel scanning. See the [setup guide](docs/setup.md) for details.

## Documentation

- [Release notes](CHANGELOG.md)
- [Documentation index](docs/README.md)
- [Setup, updates and data locations](docs/setup.md)
- [Linux firewall setup and rules](docs/firewall.md)
- [Scanning, exclusions and results](docs/scanning.md)
- [Development, tests and release checks](docs/development.md)

## Licensing

LibreWard is licensed under **GPL-2.0-or-later**. See [LICENSE](LICENSE).
It executes external ClamAV tools including `clamscan`, `clamd` and `freshclam`.
ClamAV is developed by the ClamAV project/Cisco Talos and licensed separately
under GNU GPL version 2.

PySide6 / Qt is used under its open-source **LGPLv3** option.
See [Qt licensing](https://doc.qt.io/qt-6/licensing.html)
and [Qt for Python licensing](https://doc.qt.io/qtforpython-6/licenses.html).
