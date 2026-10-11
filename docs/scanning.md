# Scanning and results

## Starting and excluding files

Choose a folder and select **Start scan**, or use **Quick system scan** to check
platform-specific locations such as downloads, temporary directories, startup
locations and browser data. Quick scan does not check every file on the machine.

Common and custom exclusions in Settings apply to both scan types. Only checked
common groups are active. A custom excluded folder includes its children, but
not similarly named siblings. Exclusions take precedence even when an excluded
location is itself a Quick scan target.

## Parallel scanning

Parallel scanning is enabled by default in Settings. LibreWard probes local
ClamD sockets and loopback ports, including common platform configuration
locations. It reuses a responding daemon without stopping or reconfiguring it.
If none responds, it attempts to start an installed `clamd` from the detected
runtime or PATH with a temporary configuration and the detected database.
If startup fails or the executable is absent, the log explains the fallback
to standard `clamscan` scanning.

The worker deduplicates the initial file list and submits up to four file checks
at once. Owned daemons open local paths directly, avoiding large-file transfers
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

LibreWard counts candidate files first. Progress advances as results arrive and
stays below 100% while active. Estimates can differ from ClamAV counts when files
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

## Warnings and threats

- Inaccessible, locked and disappearing files are warnings. Browsers frequently
  change cache and IndexedDB files during scanning.
- Engine limits are warnings: the affected file was not fully checked. Limit
  alerts from the managed parallel scanner are not presented as infections.
- Transport failures and fatal scanner errors are not reported as clean scans.
- Detections appear in the results table. Quarantine and permanent deletion
  require confirmation; nothing is automatically removed.

Select detected rows to quarantine or delete them. Quarantine supports confirmed
restoration and permanent deletion, retains restore metadata and does not
overwrite an existing file at the original location. Failed actions remain
available for retry.
