Evo prijedlog za `AGENTS.md` koji možeš staviti u root projekta.

````md
# AGENTS.md

## Project overview

This project is **Clamanti**, a cross-platform GUI application for ClamAV.

The application should start as a simple ClamAV GUI scanner, but it may later grow into a broader security/privacy utility with features such as:

- ClamAV scanning
- Virus database updates
- Firewall management
- DNS regulation / DNS configuration
- Possibly system service/timer integration

Because of that, the codebase must be structured from the beginning so that platform-specific logic is isolated and does not leak into GUI code.

---

## Architecture principles

Do **not** create two completely separate applications for Windows and Linux.

Use:

```text
one shared GUI
one shared core logic layer
separate platform backends
````

Avoid:

```text
clamanti_windows.py
clamanti_linux.py
```

Prefer a structure like:

```text
clamanti/
  main.py
  gui/
    main_window.py
    exclude_window.py
    about_window.py
  core/
    scanner.py
    config.py
    models.py
    clamav_parser.py
  platform/
    base.py
    linux.py
    windows.py
  services/
    clamav/
      scanner.py
      updater.py
      parser.py
    firewall/
      base.py
      linux.py
      windows.py
    dns/
      base.py
      linux.py
      windows.py
```

For the early version, a simpler structure is acceptable:

```text
clamanti/
  main.py
  gui.py
  config.py
  platform_backend.py
```

But the design should allow future splitting into modules.

---

## Platform-specific backend

All OS-specific behavior must be placed behind a backend abstraction.

The GUI should not directly care whether it is running on Linux or Windows.

Platform-specific code includes:

* finding `clamscan`
* finding `freshclam`
* starting subprocesses
* stopping subprocesses
* choosing config/log/database locations
* detecting writable directories
* default exclude lists
* firewall commands
* DNS commands
* privilege/admin handling
* systemd integration on Linux
* Windows service/UAC handling on Windows

Example backend interface:

```python
class PlatformBackend:
    def find_clamscan(self) -> str | None:
        raise NotImplementedError

    def find_freshclam(self) -> str | None:
        raise NotImplementedError

    def start_process(self, cmd):
        raise NotImplementedError

    def stop_process(self, process):
        raise NotImplementedError

    def config_dir(self):
        raise NotImplementedError

    def default_common_excludes(self):
        raise NotImplementedError
```

Linux process handling may use:

```python
preexec_fn=os.setsid
os.killpg(os.getpgid(process.pid), signal.SIGTERM)
```

Windows process handling must not use `os.setsid` or `os.killpg`.

Windows should use something like:

```python
creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
process.terminate()
```

---

## ClamAV integration model

Clamanti should use ClamAV as an external command-line tool.

Prefer:

```text
subprocess -> clamscan / clamscan.exe
subprocess -> freshclam / freshclam.exe
```

Avoid directly linking to `libclamav` unless the whole project is intentionally designed around that.

Current intended model:

```text
Clamanti GUI
  -> calls bundled or installed clamscan
  -> calls bundled or installed freshclam
```

The scanner should parse `clamscan --verbose` output for progress when possible.

Do not assume ClamAV provides a stable official progress API for scanning. Treat progress parsing as best-effort.

Progress behavior:

* Count files before scan.
* Run one `clamscan --verbose` process.
* Parse result lines such as:

  * `/path/file: OK`
  * `/path/file: FOUND`
  * `/path/file: ERROR`
* Update GUI progress based on recognized scanned files.
* Do not show 100% until the ClamAV process actually exits.
* Cap visible progress at 99% while process is still running.

---

## Windows bundling strategy

For Windows releases, ClamAV should be bundled with the application.

This is preferred because asking ordinary Windows users to separately install ClamAV, find `clamscan.exe`, configure PATH, and run `freshclam` manually is too confusing.

Expected Windows release layout:

```text
Clamanti/
  Clamanti.exe
  clamav/
    clamscan.exe
    freshclam.exe
    sigtool.exe
    other required ClamAV DLLs/binaries
  licenses/
    GPL-2.0.txt
    ClamAV-COPYING.txt
  README.txt
```

The application should first try to use the bundled ClamAV binaries:

```text
./clamav/clamscan.exe
./clamav/freshclam.exe
```

Later it may also support:

```text
Use bundled ClamAV
Use custom ClamAV path
```

---

## Writable data vs bundled binaries

Do not write runtime data into the application/binary directory unless explicitly running in portable mode and the directory is writable.

On Windows, binaries should live next to the application:

```text
binaries:
  next to Clamanti.exe
```

Example:

```text
Clamanti/
  Clamanti.exe
  clamav/
    clamscan.exe
    freshclam.exe
```

Writable data should go to:

```text
%APPDATA%\Clamanti\
  config.json
  logs/
  clamav-db/
```

Specifically:

```text
config:
  %APPDATA%\Clamanti\config.json

logs:
  %APPDATA%\Clamanti\logs\

ClamAV database:
  %APPDATA%\Clamanti\clamav-db\
```

Reason:

* Users may install or extract the app somewhere not writable.
* `Program Files` is usually not writable without admin rights.
* Virus database updates must not require writing into the app installation directory.
* Logs and config should be per-user.

On Linux, use XDG-style paths where possible:

```text
~/.config/clamanti/config.json
~/.local/share/clamanti/
~/.cache/clamanti/
```

or a similar clean layout.

---

## ClamAV database handling

The app should not assume that virus databases already exist.

On first start, if the ClamAV database is missing, show a clear message:

```text
Virus database not found.
Please update the database before scanning.
```

Provide an `Update now` button that runs `freshclam`.

For bundled Windows ClamAV, generate or ship a `freshclam.conf` that writes the database to the writable app data directory.

Example Windows database location:

```text
%APPDATA%\Clamanti\clamav-db\
```

Example `freshclam.conf` content:

```text
DatabaseDirectory C:\Users\<user>\AppData\Roaming\Clamanti\clamav-db
UpdateLogFile C:\Users\<user>\AppData\Roaming\Clamanti\logs\freshclam.log
DatabaseMirror database.clamav.net
```

When scanning with bundled database path, pass the database explicitly:

```text
clamscan.exe --database <clamav-db-dir> ...
```

The same concept may be used on Linux if a custom database location is needed.

---

## Licensing and About page requirements

Clamanti is intended to be released under the GPL.

ClamAV is bundled as an external application/tool on Windows builds.

The About page must clearly state:

```text
Clamanti bundles ClamAV, an external open-source antivirus engine/toolkit.

ClamAV is licensed under the GNU General Public License.
Clamanti uses ClamAV by executing its command-line tools such as clamscan and freshclam.

ClamAV is developed by the ClamAV project/Cisco Talos.
```

The About page should include:

* Clamanti license
* ClamAV license
* ClamAV version detected at runtime
* path to bundled or selected `clamscan`
* path to bundled or selected `freshclam`
* link/reference to ClamAV source/license information
* note that ClamAV is a bundled third-party component

Example About text:

```text
Clamanti is a graphical interface for ClamAV.

This build includes ClamAV command-line tools as a bundled third-party component.
ClamAV is an open-source antivirus toolkit licensed under the GNU General Public License.

Clamanti does not claim ownership of ClamAV.
Clamanti executes ClamAV tools such as clamscan and freshclam to perform scanning and database updates.
```

Any installer, README, license dialog, or distribution archive should include ClamAV license files.

Recommended files:

```text
licenses/
  Clamanti-GPL.txt
  ClamAV-GPL.txt
  ClamAV-COPYING.txt
```

Do not remove ClamAV copyright notices.

Do not present ClamAV as original Clamanti code.

---

## README requirements

The README should mention that Windows builds bundle ClamAV.

Include a section like:

```md
## Bundled ClamAV

Windows builds of Clamanti include ClamAV command-line tools so that users do not need to install ClamAV separately.

ClamAV is an external open-source antivirus toolkit licensed under the GNU General Public License.

Clamanti uses ClamAV by running `clamscan` and `freshclam` as external processes.
```

Also document where writable data is stored:

```md
## Data locations

On Windows:

- Config: `%APPDATA%\Clamanti\config.json`
- Logs: `%APPDATA%\Clamanti\logs\`
- ClamAV database: `%APPDATA%\Clamanti\clamav-db\`

The bundled ClamAV binaries are stored next to `Clamanti.exe`, but runtime data is stored in `%APPDATA%`.
```

---

## Common excludes

Common excludes should be platform-aware.

Linux common excludes may include:

```text
Python virtual environments: .venv, venv, env
Python caches: __pycache__, .pytest_cache, .mypy_cache, .ruff_cache
Node.js: node_modules, .npm
Rust: target, .cargo
Git: .git
General cache: .cache
Podman rootless storage: ~/.local/share/containers/storage
```

Windows common excludes may include:

```text
Python virtual environments: .venv, venv, env
Python caches: __pycache__, .pytest_cache, .mypy_cache, .ruff_cache
Node.js: node_modules
Git: .git
Windows recycle bin: $RECYCLE.BIN
System Volume Information
Temp/cache directories
```

Do not hard-code Linux-only excludes into Windows builds.

---

## Path handling

All path logic must be cross-platform.

Use:

```python
os.path.abspath()
os.path.isabs()
pathlib.Path
```

Do not detect absolute paths only with:

```python
path.startswith("/")
```

That works on Linux but fails on Windows.

Windows path matching should be case-insensitive.

Example:

```python
def path_startswith(path: str, prefix: str) -> bool:
    if platform.system() == "Windows":
        return path.lower().startswith(prefix.lower())
    return path.startswith(prefix)
```

Normalize paths for regex-based exclude matching:

```python
normalized = path_abs.replace(os.sep, "/")
```

---

## Firewall and DNS future design

Firewall and DNS features will be heavily platform-specific.

Do not put firewall or DNS commands directly into GUI classes.

Use service backends.

Possible future structure:

```text
services/
  firewall/
    base.py
    linux_nftables.py
    linux_ufw.py
    linux_firewalld.py
    windows_firewall.py
  dns/
    base.py
    linux_networkmanager.py
    linux_resolved.py
    windows_dns.py
```

Linux firewall backends may need to support:

```text
nftables
ufw
firewalld
iptables legacy
```

Windows firewall backend may use:

```text
Windows Defender Firewall
PowerShell New-NetFirewallRule
netsh advfirewall
Windows Filtering Platform
```

Linux DNS backends may need to support:

```text
NetworkManager / nmcli
systemd-resolved / resolvectl
/etc/resolv.conf
dnsmasq
unbound
```

Windows DNS backend may use:

```text
PowerShell Set-DnsClientServerAddress
netsh interface ip set dns
per-interface DNS configuration
```

Privilege/admin handling must be isolated in platform backends.

The GUI should request actions like:

```python
backend.firewall.add_rule(...)
backend.dns.set_servers(...)
```

and should not know the actual shell commands.

---

## GUI principles

The GUI should stay responsive.

Do not run long scans or updates on the main UI thread.

Use:

```text
worker thread
queue
periodic GUI polling with after()
```

Do not call blocking subprocess code directly from button callbacks.

The GUI should show:

* current status
* current file when available
* progress percentage where possible
* indeterminate activity bar while work is running
* scan summary
* warnings/errors
* infected results

The activity bar should only be visible while scan/update is active.

---

## Safety defaults

Do not automatically delete infected files.

Avoid default use of:

```text
--remove
```

Prefer reporting first.

Possible future actions:

```text
quarantine
delete
ignore
open location
copy report
```

But deletion/quarantine should require explicit user confirmation.

---

## ClamAV scan behavior

Default scan options may include:

```text
-r
--verbose
--scan-archive=yes
--alert-encrypted=yes
```

Avoid scanning entire system roots by default.

Do not default to scanning:

Linux:

```text
/
/proc
/sys
/dev
/run
```

Windows:

```text
C:\
System Volume Information
Windows system directories
```

Prefer user-selected folders.

For rootless Podman on Linux, prefer scanning bind-mounted data volumes rather than internal overlay storage.

---

## Distribution notes

Windows distribution should ideally be a ZIP or installer that includes:

```text
Clamanti.exe
bundled ClamAV command-line tools
license files
README
```

If packaged as a portable ZIP, still store mutable data in `%APPDATA%\Clamanti\` by default unless a specific portable mode is implemented.

Portable mode, if implemented later, should be explicit:

```text
portable_config/
portable_logs/
portable_clamav-db/
```

and should verify that the app directory is writable before using it.

---

## General development rule

Whenever adding a feature, ask:

```text
Is this GUI logic?
Is this core app logic?
Is this platform-specific logic?
Is this third-party/bundled component logic?
```

Place the code accordingly.

Do not let Windows/Linux branching spread throughout the GUI.

Keep OS-specific code behind backend interfaces.

```
```
