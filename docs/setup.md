# Setup and updates

## Component checks

Open **Settings → Enable antivirus protection / setup**. The overview shows:

| Component | Purpose |
| --- | --- |
| Antivirus engine | `clamscan` provides standard scanning |
| Database updater | `freshclam` downloads virus signatures |
| Virus database | Required before scanning |
| Parallel scanner | Optional `clamd` enables concurrent file checks |

An installed daemon need not already be running. Missing parallel support does
not block standard scanning. Checking status does not start a daemon or download
files. Missing required components trigger setup at startup unless automatic
prompts are suppressed; the overview and Settings let you change that preference.

## Linux

In Settings, **Parallel file checks** defaults to the logical CPU count, capped
at 16. You can also select 4, 8 or 16 explicitly. With **Check larger files**,
Automatic uses at most two checks; manual choices can use substantially more
memory. These settings apply to parallel scans. Existing system clamd services
retain their own concurrency and scan limits. Compare scan times using the same
folder, exclusions and archive settings; more workers do not guarantee a
proportional speed increase.

The setup overview offers **Install ClamAV with system package manager** on
supported apt, pacman, dnf, apk and zypper systems. Review the packages and
command, then confirm and authorize through the system polkit dialog. LibreWard
streams installation output into a progress report, retains the result until
you close it, then checks components again. If signatures are missing, it
offers a separate virus database update.

Installation uses fixed package names from your distribution's configured
repositories. Dependencies and distribution service setup may be included.
LibreWard does not refresh repositories or perform a full system upgrade.
If metadata is outdated or the transaction requires a manual decision, use
the provided terminal instructions. Active package transactions must finish
before closing the app.

If automatic installation is unsupported or pkexec is unavailable, use
**Copy install command** or the displayed manual instructions, then select
**Check again** or **Check status**. Missing pkexec and failed desktop
authorization have separate explanations; LibreWard supplies distribution
installation guidance for polkit/pkexec and copies sudo commands for a terminal.
It does not ask for or store your password in its own widgets.

The distribution manages engine updates and normally stores signatures in
`/var/lib/clamav`. Database updates may request system authorization. LibreWard
does not automatically download a separate Linux runtime.

Package installation may start the system FreshClam updater. When it is already
running, LibreWard leaves it in charge instead of starting a second process
that could fail to lock `freshclam.log`. The report explains that the latest
update has not been confirmed. If the database is missing, close the report;
LibreWard checks availability every ten seconds for up to ten minutes of checks.
If it remains unavailable, inspect the system FreshClam service log.

Fedora's `/etc/freshclam.conf` contains an active `Example` line until an
administrator removes it, and freshclam refuses to run with it. LibreWard then
runs freshclam with a temporary copy of the configuration without that line,
keeping every other distribution setting (for example `DatabaseOwner clamupdate`)
and leaving `/etc/freshclam.conf` unchanged. Fedora's own scheduled updater
(`clamav-freshclam.service`) still needs the line removed. ClamAV tools in
`/usr/sbin`, such as Fedora's `clamd`, are found even when the desktop's `PATH`
lacks the sbin directories.

The setup window names one next step (install, download the database, or the
optional scan service). Component states and the terminal command are under
**Show details**; they start open only when installation must be done manually.
Choosing **Install** there is the consent, so no second confirmation follows.

## Windows

LibreWard uses an existing ClamAV installation or a managed portable runtime.
First-time runtime setup explains the third-party dependency and asks for consent
before fetching download information. Declining performs no runtime download.
You can suppress the prompt and reopen setup from Settings later.

Managed installation downloads the complete official portable ZIP, verifies
SHA256, validates extraction paths and runtime executables, and installs with
rollback. Engine installation is confirmed before download. After installation,
LibreWard starts database updating; scanning remains blocked until a database
is available.

Missing components can trigger repair using the same manifest version. Repair
does not downgrade newer installations. Managed updates do not overwrite system
runtime folders or the bundled fallback.

## Data locations

| Data | Windows | Linux |
| --- | --- | --- |
| Configuration | `%APPDATA%\LibreWard\config.json` | `$XDG_CONFIG_HOME/libreward/config.json`, default `~/.config/libreward/config.json` |
| Application data | `%APPDATA%\LibreWard\` | `$XDG_DATA_HOME/libreward/`, default `~/.local/share/libreward/` |
| Managed runtime | `clamav-runtime\current\` under application data | Distribution-managed |
| Virus database | `clamav-db\` under application data, or detected runtime/system database | Normally `/var/lib/clamav` |
| Logs | `logs\` under application data | `logs/` under application data |

Windows managed database updates use a generated `freshclam.conf` under
application data. Downloaded databases are separate from the managed runtime.
Mutable files are not written next to `LibreWard.exe`.

Configuration stores scan paths, exclusions, theme, setup preferences and window
geometry. Size, position and maximized state are saved on a successful close.
Closing during a scan requests Stop; close again after it finishes. Active
updates must finish before closing.
