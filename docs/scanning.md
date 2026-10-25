# Scanning and results

## Starting and excluding files

Choose a folder and select **Start scan**, or use **Quick system scan** to check
platform-specific locations such as downloads, temporary directories, startup
locations and browser data. Quick scan does not check every file on the machine.

Common and custom exclusions in Settings apply to both scan types. Only checked
common groups are active. A custom excluded folder includes its children, but
not similarly named siblings. Exclusions take precedence even when an excluded
location is itself a Quick scan target.
LibreWard always excludes its own quarantine directory, including stored files
and restore metadata. Restored files outside quarantine are scanned normally.

## Parallel scanning

Parallel scanning is enabled by default in Settings. LibreWard probes local
ClamD sockets and loopback ports, including common platform configuration
locations. It reuses a responding daemon without stopping or reconfiguring it.
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
dialog opens automatically afterward. **View scan report** reopens it.

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
Live protection page. When its service was removed outside LibreWard, for
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

### Notifications and dangerous files

A download shows **Waiting for a download to finish** when it starts, and
**Checking … for viruses** in the same notification if the check takes more than two
seconds (large files). When the check is done, that notification closes and the
result comes as a new notification, which the desktop always shows as a banner.
Other new files get the result only. **Notify me only
when a dangerous file is found** keeps all but dangerous files quiet.

Firefox starts downloading into its default folder while its save dialog is open and
moves the file once a folder is chosen; the result is shown for the moved file. A
download that is cancelled loses its notification after half a minute.

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
