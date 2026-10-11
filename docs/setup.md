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

Install through your distribution's package manager. The overview provides
distribution-specific instructions, including the daemon package where it is
separate. Run the displayed command in a terminal, then select **I have installed
it — check again** or **Check status** in LibreWard.

The distribution manages engine updates and normally stores signatures in
`/var/lib/clamav`. Database updates may request system authorization. LibreWard
does not automatically download a separate Linux runtime.

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
