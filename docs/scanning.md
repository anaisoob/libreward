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
