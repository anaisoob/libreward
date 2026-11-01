# Scanning and results

## Starting and excluding files

Choose a folder and select **Start scan**, or use **Quick system scan** to check
the small places where threats arrive or start by themselves. It takes minutes, not
hours, and does not check every file on the machine; scan a folder for that.

| Platform | Quick scan checks |
|---|---|
| Linux | `/tmp`, `/var/tmp`, `/dev/shm`; the Downloads and Desktop folders (also translated names from the user folder settings) and the trash; `~/.config/autostart`, `~/.config/systemd/user`, `~/.local/share/applications`, `~/.local/bin`, `~/bin`; shell and session startup files such as `~/.profile` and `~/.bashrc` |
| Windows | `%TEMP%`, `%LOCALAPPDATA%\Temp`, the Downloads and Desktop folders, `C:\Users\Public`, and the Startup folders of the user and of all users |
| Both | the folders browsers download to (never the whole home folder), and the programs started at login wherever they are stored: from autostart entries and systemd user services on Linux, from the `Run` and `RunOnce` registry entries on Windows, including the script or library such an entry runs |

Private temporary folders of system services (`/tmp/systemd-private-*`), which only
root can read, are skipped instead of being reported as files that could not be
checked. Browser caches, `~/.cache` and `%APPDATA%` are not part of a Quick scan:
they are large, change all the time, and new downloads are checked by Live
protection when they arrive.

Common and custom exclusions, under **Excludes** on the Virus scan page or in
Settings, apply to both scan types. The common groups cover what is large and rarely
worth checking on most computers (containers, virtual machines, games, Flatpak and
Snap apps, caches), then folders for developers. None is on by default: what is
skipped is not checked. Only checked
common groups are active. A custom excluded folder includes its children, but
not similarly named siblings. Exclusions take precedence even when an excluded
location is itself a Quick scan target.
LibreWard always excludes its own quarantine directory, including stored files
and restore metadata. Restored files outside quarantine are scanned normally.

## Parallel scanning

Parallel scanning is enabled by default in Settings. LibreWard probes local
ClamD sockets and loopback ports, including common platform configuration
locations. It reuses a responding daemon without stopping or reconfiguring it.
On Linux it uses only a daemon that another user of the computer cannot have
started in its place, because files are sent to it and its verdict is trusted: a
socket in a folder that only root or a system account (such as `clamav`) can write,
or a local port that root or a system account listens on. `/tmp/clamd.socket` and
a port opened by an ordinary user are ignored.
If none responds, it attempts to start an installed `clamd` from the detected
runtime or PATH with a temporary configuration and the detected database.
If startup fails or the executable is absent, the log explains the fallback
to standard `clamscan` scanning.

The worker discovers files while scanning, removes overlapping roots and queues
at most 256 file paths. **Parallel file checks** in Settings defaults to
**Automatic: half of the CPU cores** (at least 1, at most 16), also when **Check
larger files** is on, which leaves the computer usable during a scan. Manual
choices list only counts the computer can run (1, 2, 4, 8 or 16 up to its cores);
a saved count above the current cores falls back to automatic. More checks at once
use more memory, especially with larger files. Owned daemons
open local paths directly, avoiding large-file transfers
through a socket. Reused daemons receive INSTREAM requests so they do not need
permission to open original paths; their configured streaming limits still apply.

A reused daemon keeps its administrator's engine settings and database, which
may differ from standard scanning. Owned daemons use a private Unix socket on
Linux or a loopback-only TCP listener on Windows. LibreWard stops its own daemon
after scanning, including cancellation or errors; existing daemons remain
running. An owned daemon therefore loads its database again on the next scan.

Parallelism can help with many small files. Actual speed depends on CPU, storage,
file types and available RAM; it does not guarantee a fixed improvement.

## Progress and reports

LibreWard discovers and counts candidate files while scanning. Until discovery
finishes, it shows the number found and processed with an activity indicator.
The status explicitly shows that scanning is already running, with a percentage
available once the total is known. Total discovery time cannot be predicted
reliably before traversing the folders. In parallel mode the scan queue is limited to 256 paths. A separate counting
worker traverses folders independently, so a full scan queue does not delay
the total or percentage. This requires a second directory traversal, without
reading file contents or keeping every path in memory. Counting can still take
time on slow storage or very large directory trees.

After discovery finishes, progress switches to a percentage and stays below 100%
while active. Standard `clamscan` scans count concurrently in a separate worker,
without storing a complete list. Estimates can differ from ClamAV counts when files
change, disappear, become inaccessible or reach engine limits. Parallel results
count processed requests, including warnings/errors; they do not guarantee that
every file was fully checked.

**Current File** stays on one line with the middle of long paths shortened.
Hover for the full path. During parallel scanning it shows the latest file
result; several other files can still be active. An animated icon appears beside
**Virus scan** when scanning is active and another page is open.

Completed parallel work reaches 100% even with warnings/errors. Final status
states the outcome separately; cancellation retains partial progress. The report
dialog opens automatically afterward. **View scan report**, next to the result,
reopens it.

The report leads with the outcome in colour (**No threats found**, **2 threats
found**, **The scan did not finish**) and one sentence such as “18,234 files checked
in 6 min 52 s.” Files that could not be checked get one calm note instead of a
list. Threats are listed by file name, threat name and folder, with **Move all to
quarantine**; quarantined files can be restored. Counts per cause, file paths and
the ClamAV summary are under **Show details**.

## Warnings and threats

The report groups incomplete checks by cause, with counts, explanations and
suggested next steps. File details retain the original reason, with up to 200
examples; counts include all warnings. These are separate from threat detections.

- Inaccessible, locked and disappearing files are warnings. Browsers frequently
  change cache and IndexedDB files during scanning.
- Engine limits are warnings: the affected file was not fully checked. Limit
  alerts from the managed parallel scanner are not presented as infections.
- Transport failures and fatal scanner errors are not reported as clean scans.
- Detections appear in the results table. Quarantine and permanent deletion
  require confirmation; nothing is automatically removed.

**Settings → Check larger files** raises the file-size limit from 100 MiB to
1 GiB and the total scanned contents limit from 400 MiB to 2 GiB. It uses at most
two parallel checks instead of four to reduce simultaneous memory demand.
This can check more large libraries and archives, but takes longer and uses more
resources. Archive recursion and other engine limits remain in place. Very large
disk images and containers may still be impossible to fully scan; where practical,
scan their extracted contents separately. Limits are never disabled completely.

These profiles apply to standard `clamscan` and LibreWard-owned `clamd` instances.
An existing system daemon keeps its own limits. To apply LibreWard's larger-file
profile in that situation, enable **Check larger files** and disable parallel
scanning. Encrypted-content alerts are reported as incomplete checks, not as
infections. Other heuristic and signature detections remain available for review.

Select detected rows to quarantine or delete them. Quarantine supports confirmed
restoration and permanent deletion, retains restore metadata and does not
overwrite an existing file at the original location. Failed actions remain
available for retry.

Quarantined files are stored encoded in the user's quarantine folder
(`~/.local/share/libreward/quarantine`, `%APPDATA%\LibreWard\quarantine`): a
header and the contents XOR-ed with a fixed key, read-only. A copy taken out by
hand cannot be run or opened, and other virus scanners, file indexers and thumbnail
previews do not see the harmful contents. The encoding neutralises the file but is
not secret: LibreWard is open source. The original is removed only after the
encoded copy is complete, and restoring decodes next to the original location,
compares the SHA256 recorded at quarantine time, and only then puts the file in
place, so a damaged copy is never restored. Files quarantined by earlier versions
are restored as they are.

## System check (Linux)

Virus signatures find known malicious files. **System check** on the Virus scan page
looks instead for signs that something is hiding on the computer, as rootkits and
backdoors do. It runs as your user, needs no password and takes about a second:

| Check | What is suspicious |
|---|---|
| Extra libraries forced into every program | `/etc/ld.so.preload` lists a library (normal systems do not use this file) |
| Extra libraries set in startup files | `LD_PRELOAD` in shell startup files, `~/.config/environment.d`, systemd user services, `/etc/environment` or `/etc/profile.d` |
| Programs running from temporary folders or only from memory | a process of your user runs from `/tmp`, `/var/tmp` or `/dev/shm` (AppImages excepted), or from memory without a file (`memfd`, container runtimes excepted) |
| Hidden programs | a process exists but is left out of the `/proc` listing; threads are told apart by their thread group |
| Hidden kernel modules | a module is loaded (`/sys/module/*/initstate`) but missing from `/proc/modules` |
| Programs that start by themselves | autostart entries, systemd user services, your crontab and `/etc/crontab`, `/etc/cron.d` that download and run a script (`curl … \| sh`), decode and run commands (`base64 -d \| sh`), or run a program from a temporary folder |

Findings are shown in plain words as things to look at, not as threats: some
programs do these things on purpose, and LibreWard never changes or deletes
anything here. Programs that kept running after a package update (`(deleted)`
executables in system folders) are not reported. A scheduled scan runs the system
check afterwards; findings come as a warning notification and are listed in the
service log, and the Scheduled scan card shows the latest result.

### Check deeper (administrator rights)

The result offers **Check deeper…**, which asks for the administrator password
(polkit) and takes a few minutes. It repeats the process and task checks for all
users and adds:

| Check | What is suspicious |
|---|---|
| System programs and libraries compared with their packages | contents differ from the package (`rpm -Va`, `dpkg --verify`, `pacman -Qkk`), only in program and library folders; changed configuration is normal and not reported |
| Programs with special rights (SUID/SGID) | such a program on a local filesystem belongs to no installed package |
| System services | a unit in the packages' folder belongs to no package, or a service runs a program from a temporary or home folder, or one that belongs to no package (normal for software installed by hand, and said so) |
| Scheduled tasks of all users | crontabs of all users and `/etc/cron.{hourly,daily,weekly,monthly}` that download, decode or run programs from temporary folders |

An installed LibreWard asks with its own polkit action, *Check the system for signs
of tampering*, through the program `/usr/libexec/libreward/system-check`, which takes
no arguments and finds the system's own `rpm`, `dpkg`, `pacman` and `find` itself
(see [Packaging](packaging.md#administrator-rights)). Run from source, root never
loads files from the application folder: pkexec starts the system's
`/usr/bin/python3 -I` with the source of `backends/linux_system_check.py`, which uses
only the Python standard library. Without a supported package
manager (for example Alpine) the package checks are skipped and listed as not run.

The check cannot prove that a computer is clean: a rootkit in the kernel can hide
from any check that runs on the same system. For certainty, check the disk from a
system started from a USB stick.

## Files a scan could not open

When your account may not open some files or folders, the scan report says how many
and offers **Check as administrator**. LibreWard asks for the password and checks only
those locations, not everything again: `clamscan` running as root reads untrusted files
with full rights, so it should read as little as possible. There is deliberately no
option to run whole scans this way, and parallel scanning could not help them.

The check reads and reports; it changes nothing. A dangerous file found this way is
listed under Detected files, but your account cannot move it, so it cannot go to
quarantine: remove it with an administrator account. Symbolic links are not followed.
The program is `/usr/libexec/libreward/scan-files` (see
[Packaging](packaging.md#administrator-rights)); run from source, pkexec starts the
system's `python3 -I` with the source of `backends/linux_root_scan.py`. Windows does not
have this check yet.

## Live protection for new files

Open **Live protection** and select **Turn on** under **New files and downloads**.
LibreWard finds the Downloads folders of the system and of Firefox, Chrome,
Chromium, Edge, Brave, Vivaldi and Opera by itself and checks new and changed files
there, including subfolders. **Choose folders…** adds or removes folders. When a
download folder is changed in a browser (or in the system's user folders) later,
the service notices it within seconds and protects the new folder too; turn off
**Also protect the folders my web browsers download to** in **Choose folders…** to
protect only the listed folders.

Files saved anywhere else, with **Save as** or a browser set to ask where to save,
are found in the browsers' lists of finished downloads (Firefox, LibreWolf,
Waterfox, Floorp, Zen, and Chrome, Chromium, Edge, Brave, Vivaldi and Opera) and checked within about ten seconds after
the download finishes. LibreWard reads a private copy of each browser's history
database after it changed, and from it only the downloads, never visited websites;
nothing leaves the computer. Downloads made by other programs outside the protected
folders are not checked.

While a browser downloads, the page shows **Waiting for a download to finish**
with the file name. The file is checked as soon as the browser finishes it (when
it renames its `.part` or `.crdownload` file, or removes the `.aria2` file), usually
within a second, then **Checking …** and the result appear. Unfinished downloads are
not checked: a partial file cannot be checked reliably. Scan
exclusions from Settings apply. Existing files form a baseline; use a manual scan to
check them. LibreWard’s own application data, configuration and log folders are
excluded. Files wait until their size and modification time settle, and incomplete
browser downloads until the final file is ready; other files wait about three
seconds after their last change. Filesystem notifications are
supplemented by a check every minute, which also covers network folders without
notifications. Protection scans after a change and does not block opening or
executing a file.

### Background service

Monitoring runs in the background, independently of the window, like Internet
protection: it keeps working when LibreWard is closed and starts again when you log
in. Closing the window explains this once. To stop it, select **Turn off** on the
Live protection page; with a scheduled scan chosen, the service keeps running for
the schedule only. When its service was removed outside LibreWard, for
example by uninstalling, LibreWard shows it as off and does not turn it back on by
itself; the folders are kept for the next **Turn on**. Folder and exclusion changes reach the running service within
a few seconds.

On Linux, LibreWard writes the systemd user service
`~/.config/systemd/user/libreward-monitor.service`, which runs `libreward --monitor`
at login, restarts it after a failure and scans with lower CPU and disk priority.
It works with GNOME, KDE Plasma and other desktops and does not need a tray icon.
Check it with:

```sh
systemctl --user status libreward-monitor.service
journalctl --user -u libreward-monitor.service
```

On Windows, LibreWard starts the same agent at login through the
`LibreWard Monitor` entry under
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`, and logs
to `%APPDATA%\LibreWard\logs\monitor.log`.

With parallel scanning enabled (the default) and `clamd` installed, the service uses
a running system `clamd`, or starts its own and keeps it running for ten minutes
after the last check: the virus database stays loaded (about 1 GB of memory while it
runs), so a series of downloads is checked in a fraction of a second. Without
`clamd`, it starts `clamscan` for each batch of files, which loads the database every
time. Install `clamd` from **Settings → Enable antivirus protection / setup**. While it runs, it also refreshes
LibreWard’s own virus database (when automatic updates are enabled). It pauses
while the antivirus engine or virus database is missing and while ClamAV is being
updated. A failed scan is retried every minute, with one notification after
repeated failures. Files still waiting when you log out are checked after the next
login.

## Scheduled scans

Open **Live protection** and choose **Every day** or **Every week** under
**Scheduled scan**. The background service then runs a Quick scan (the same places
as **Quick system scan**, see above), also when LibreWard is closed. Scan exclusions
and the scan profile from Settings apply.

There is no fixed time: a scan runs when a day or a week has passed since the last
one started. If the computer was off or you were logged out at that time, it runs
about ten minutes after the next login, never right at login. The first scan
starts a few minutes after choosing a schedule. A scan that does not finish (for
example a missing virus database) is tried again an hour later; a scan interrupted
by logging out runs again after the next login.

The scan runs alongside protection for new files, with low CPU and disk priority.
It uses a running system `clamd` when parallel scanning is enabled, otherwise one
`clamscan`; it does not start its own `clamd`. The card shows when the last scan
ran, its result and when the next one is due. The result comes as a notification
(only for dangerous files with **Notify me only when a dangerous file is found**).
A dangerous file is handled like one found in a new download: LibreWard opens by
itself and asks what to do, and the file is listed under Detected files.

Scheduled scans use the same background service as protection for new files and
work without it being turned on: the service runs while either is on, and stops
when both are off.

### Notifications and dangerous files

A download in progress gets no notification, so LibreWard does not feel like it
watches what you do; the Live protection page shows it. Once a file is checked, the
result comes as a notification (“No threats found” and the file name, or a warning),
which the desktop always shows as a banner. If the check takes more than two
seconds (large files), **Checking … for viruses** appears first and closes when the
result comes. **Notify me only when a dangerous file is found** keeps all but
dangerous files quiet.

Firefox starts downloading into its default folder while its save dialog is open and
moves the file once a folder is chosen; the result is shown for the moved file.

When a file is dangerous, the notification shows a warning sign and says not to
open the file. Like the others, it moves to the notification list after a few
seconds; every notification is one short `notify-send` call and nothing waits for a
click. LibreWard opens by itself if it is closed (if it is open, it asks right away)
and asks what to do: **Move to quarantine** (recommended), **Delete** (after a
confirmation) or **Keep file**. Dangerous files found while the question is open are
added to it, and the answer applies to all of them. While the question is open, the
window behind it is shaded. If LibreWard was opened only to ask (by the background
service), it closes itself after the answer and the chosen action; it stays open when
you started it yourself, used it meanwhile, or closed the question without answering. While LibreWard is open in the
background, GNOME does not bring its window forward without a click; the notification
reports the file and the question waits in LibreWard. Closing the question asks again next time while the
file is still there. The file is also listed under Detected files on the Virus scan
page. Starting LibreWard again while its window is open brings that window forward.

Linux notifications use `notify-send` (libnotify), which talks to the desktop’s
notification service directly. Install your distribution’s package providing
`notify-send` if needed (`libnotify` on Arch and Fedora, `libnotify-bin` on Debian
and Ubuntu, `libnotify-tools` on openSUSE). Use **Send a test notification** on the
Live protection page to check delivery. A successful send means the desktop accepted the notification;
desktop notification settings and Do Not Disturb can still suppress banners.

Monitoring requires `watchdog`, included in the packages and in `requirements.txt`.
When running from source, install dependencies in the Python environment used to
launch LibreWard; the service uses the same interpreter.

LibreWard checks these components and shows the install command for your
distribution on the Live protection page: a missing `watchdog` keeps the service
from starting (it is not restarted in a loop), and missing `notify-send` is noted
next to the status. After installing, select **Turn off** and **Turn on** to start
protection again. If PySide6 itself is missing, starting LibreWard from the menu
shows an error dialog with the command instead of the window.
