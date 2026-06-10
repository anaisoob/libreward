# LibreWard

LibreWard is a cross-platform security and privacy desktop app. The first
working module is antivirus scanning through ClamAV, and the project structure
is prepared for firewall controls, internet protection, DNS/privacy features,
and other system security integrations behind shared core logic and
platform-specific backends.

## Current Features

- CustomTkinter desktop UI with scan, quarantine, settings, firewall, and
  internet-protection sections.
- Antivirus scanning through ClamAV command-line tools: `clamscan` and
  `freshclam`.
- Platform-aware runtime detection, database locations, common excludes, and process handling.
- Windows portable ClamAV runtime update flow using an update manifest and official upstream ZIP URLs.
- Virus database update support.
- Quarantine list with restore and permanent delete actions.

## Running From Source

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

### Windows

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

If PowerShell blocks activation, run this once in the same PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

For antivirus scanning on Linux, LibreWard expects ClamAV to be installed by the
system package manager. On Windows, LibreWard can use a portable ClamAV runtime
in the user data directory.

## Windows Runtime Data

LibreWard keeps mutable Windows runtime data under `%APPDATA%\LibreWard\`:

- `clamav-runtime\current\` for the user-updated portable ClamAV runtime.
- `clamav-db\` for virus database files.
- `logs\` for update logs.
- `freshclam.conf` generated for managed database updates.

Do not store downloaded databases inside the ClamAV runtime directory.

## Licensing

LibreWard is intended to be released under the GNU General Public License.

LibreWard executes ClamAV tools such as `clamscan` and `freshclam`. ClamAV is
developed by the ClamAV project/Cisco Talos and is licensed under the GNU General
Public License.

Release archives that bundle ClamAV must include LibreWard license files and the
ClamAV license/copyright files from the official ClamAV distribution.
