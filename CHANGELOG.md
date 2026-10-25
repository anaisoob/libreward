# Changelog

## Unreleased

- Protection for new files follows download folders chosen later in a browser (can be
  turned off in Choose folders…), shows downloads in progress (“Waiting for a download
  to finish”) and checks a finished download at once, usually within a second instead
  of four to seven seconds. A roadmap lists planned work, starting with blocking files
  until they are checked.

- Fix LibreWard not starting (and Open LibreWard in a threat notification doing nothing)
  while a threat found in the background was still waiting for a decision.

- While protection for new files is off, its folders are listed as “Folders to protect”
  instead of “Protected folders”. While a scan prepares, only one progress bar is shown;
  the thin activity bar appears once files are being checked.

- Live protection is right below Virus scan and shows how many protections are on:
  a green check when all are on, otherwise 1/2 in amber or 0/2 in red. Quarantine
  appears in the sidebar only when it holds files.
- Reinstalling no longer turns protection for new files back on by itself: when its
  service was removed outside LibreWard (for example by uninstalling), it shows as off.

- The Live protection page no longer checks the status every 30 seconds (which briefly
  disabled the buttons) or every 3 seconds: it reacts when a service records a new state.

- The Apply changes bar of Internet protection is a highlighted bar at the bottom of
  the page that stays in view while you change lists further down.

- Plain wording on the Websites part of Live protection: no technical terms such as
  DNS service, domain or lookup outside “Show how protection works”.

- Internet protection has Simple and Advanced. Simple (the default for new users)
  uses a protective DNS service and needs no lists: Dangerous websites (Quad9),
  Dangerous websites and ads (AdGuard DNS) or Family protection (AdGuard DNS Family).
  Advanced uses LibreWard's lists with allowed and blocked websites, and sends allowed
  lookups to a service that blocks nothing (Quad9 9.9.9.10 by default, Cloudflare
  1.1.1.1, Google 8.8.8.8, or the network's DNS with NetworkManager), so an allowed
  website is no longer blocked upstream. Users of earlier versions continue with
  Advanced. Behind NetworkManager, public services are now used over DNS-over-TLS too,
  with local network names still going to the network. The filter tells Firefox to
  keep its default DNS-over-HTTPS off (`use-application-dns.net`).

- AppStream metadata (`io.github.anaisoob.LibreWard.metainfo.xml`), installed to
  `/usr/share/metainfo`, so GNOME Software and KDE Discover show LibreWard with a
  description, screenshot and license.

- Uninstalling through sudo or pkexec (`sudo make uninstall`, `sudo dnf remove`) also
  stops and deletes that user's Live protection service.

- Fix the test notification and results without threats vanishing at once on GNOME:
  notifications are no longer sent as transient or with a desktop-entry hint (GNOME
  hides banners of the focused application).

- Live protection page (formerly Internet protection): protection for new files and
  downloads is one Turn on / Turn off switch at the top, finds the Downloads folders by
  itself, and folders can be changed with Choose folders…; website blocking follows
  below. Folder monitoring is no longer in Settings.
- A dangerous file found in the background opens LibreWard if it is closed (an open
  window asks by itself) and asks what to do: Move to quarantine, Delete or Keep file.
  Open LibreWard in the notification shows the Virus scan page and brings the window
  forward on GNOME Wayland using the notification's activation token (libnotify 0.8.4+).

- Missing components are explained with the install command for the distribution
  (dnf, zypper, apt, pacman; uv or pip when running from a virtual environment):
  missing PySide6 opens an error dialog (zenity or kdialog, otherwise a notification)
  instead of failing silently from the desktop menu; missing watchdog is shown under
  Folder monitoring and the service is not restarted in a loop; missing notify-send is
  shown under Folder monitoring and by Test notification.

- Folder monitoring: automatically scan new and changed files in chosen folders,
  with suggestions for the system Downloads folder and browser download folders.
  It runs as a background service (`libreward --monitor`; a systemd user service on
  Linux, a login entry on Windows) that keeps working when the window is closed and
  after logging in again, and needs no tray icon, so it also works on GNOME. Desktop
  notifications report each result; threats stay until dismissed, offer
  **Open LibreWard** and appear in Detected files. The service also refreshes
  LibreWard's own virus database. Starting LibreWard again brings the open window to
  the front. Packages now depend on watchdog (and Debian on the PySide6 network
  module) and recommend libnotify for notifications.

- Fix the scan report never opening when some files could not be checked (as on every
  quick scan): it counted the warnings flag as a list. A report failure now still shows
  the scan outcome and logs the details.

- Optional social media category (Facebook, Instagram, WhatsApp, TikTok, X) from The
  Block List Project. One-time messages after first turning Internet protection on and
  when first closing LibreWard while it is on explain that blocking keeps working.

- Internet protection is now a system setting, like the firewall: the filter keeps
  running when LibreWard is closed and after restarts, until turned off in LibreWard.
  Removes the app heartbeat, login autostart (old entries are deleted), the close
  question and the tray icon. Adds "Why is a website blocked?" help.

- Simpler Internet protection page: one Turn on / Turn off switch, choices saved at once,
  and an "Apply changes" bar only while protection is on (leaving the page asks too).
  Status checks no longer overwrite unapplied choices or block editing. Shorter
  confirmations, with a new DNS service still explained first.

- Plain scan report: coloured outcome, one sentence with files checked and time, a calm
  note for files that could not be checked, threats by file name with Move all to
  quarantine, and details folded away.

- Dark theme for context menus and other popups (the theme now applies to the whole
  application, with a matching palette). Progress windows show a title, one status line
  and progress; the technical log and the scan page event log are under Show details.

- Refresh LibreWard's own virus database automatically in the background while the
  app runs (every 12 hours, 2 hours after a failure), without a window or password.
  Can be turned off in Settings.

- Linux virus database: use a current system database (`/var/lib/clamav`), otherwise
  LibreWard's own database under `~/.local/share/libreward/clamav-db`, updated by
  freshclam as the user without a password. Distribution freshclam configs (Fedora's
  root-only file with its `Example` line) no longer matter, and freshclam is recognized
  with an empty private config. Replaces the privileged system freshclam run.

- Fedora: update the virus database and recognize freshclam although
  `/etc/freshclam.conf` still has its `Example` line (freshclam rejects it even for
  `--version`; a temporary copy without it is used and the system file is unchanged).
  Install freshclam by file path, since Fedora renamed `clamav-update` to
  `clamav-freshclam`, and find ClamAV tools in sbin, so installed ClamAV is no longer
  offered again. Register the app ID with the desktop portal only once.
- Simplify the antivirus setup window to one sentence and one next step, with details
  folded away, and drop the second confirmation after choosing Install.

- Removing the package turns Internet protection off and deletes LibreWard's system
  files (RPM `%preun`, Debian `prerm`, Arch `pre_remove`, `make uninstall`). Pausing
  no longer creates NetworkManager or resolved directories on systems without them.
  The login autostart entry is skipped once LibreWard is uninstalled.

- Prepare Linux packages: `make install` into a private `/usr/share/libreward`
  directory with a `/usr/bin/libreward` launcher, desktop entry and icon, plus AUR,
  RPM (Fedora/openSUSE via OBS) and Debian packaging. Login autostart uses the
  installed launcher. Replace the window icon, which was an old screenshot, with
  the LibreWard badge. Remove the archived Tk interface.

- Internet protection: check the internet connection before asking for authorization,
  explain unreachable websites after setup, offer Cancel while authorization is pending,
  skip single damaged lines in downloaded lists and show the filter-recovered notice once.

- Add Linux Internet protection. Where NetworkManager supports it, a local DNS filter
  checks website names against opt-in Block List Project lists (dangerous sites and
  phishing by default; tracking, ads and adult sites optional) and exact allowed/blocked
  websites. It is a standalone, hardened systemd service with a disk-backed SQLite index,
  bounded memory, UDP/TCP forwarding through NetworkManager's dnsmasq (network and VPN DNS
  routing are kept), health checks, rollback and failure recovery. When dnsmasq is missing it
  offers consented installation with apt, pacman, dnf or zypper.
- On systems using systemd-resolved (Ubuntu Desktop, Linux Mint, Fedora, Arch), the same
  local filter runs behind resolved and forwards allowed names over DNS-over-TLS to a chosen
  service: AdGuard DNS, AdGuard DNS Family, Quad9, Cloudflare (malware) or Cloudflare for
  Families. VPN and local network names stay with resolved. Consent, verification and
  rollback as with NetworkManager.
- Internet protection works while LibreWard is running, including from the system tray.
  Closing the window keeps LibreWard in the tray without asking (configurable in Settings);
  Quit from the tray asks once and turns protection off. A restart with protection on keeps
  it and starts LibreWard in the tray at login; if the app stops unexpectedly, the local
  filter restores normal DNS after about two minutes and the next start offers to turn
  protection on again.
- Keep the DNS filter serving when one socket operation fails, restart it after a crash,
  and wait for the previous resolver to release the local DNS port before starting it.
- Widen the left navigation so Internet protection is fully visible.

- Present editable firewall rules in a readable table with action, connection,
  app/port, network and configuration scope; keep raw output in optional details.

- Show firewall rules by default and offer confirmed deletion of saved UFW
  rules and firewalld zone services, ports and rich rules, with automatic refresh.

- Simplify the firewall page with plain-language protection status and optional
  technical rule details; remove its Copy sudo commands button. Firewall hints
  match whether protection is on, off or unconfirmed.

- Present scan reports in plain language, with optional technical details and
  scan durations formatted as hours, minutes and seconds.

- Choose parallel scan workers automatically as half of the CPU cores (1 to 16), also
  for larger-file scans, or pick a count the computer can run in Settings.

- Avoid competing with an existing Linux FreshClam updater; explain log-lock
  conflicts and monitor database availability after first installation.

- Offer confirmed Linux ClamAV package installation with progress, component
  recheck and follow-up database setup.
- Explain unavailable pkexec/desktop authorization and provide copyable
  terminal commands and installation guidance.
- Use themed Qt folder dialogs and explicit folder-view colors for readable
  dark/light mode across desktop environments.

## 0.2.0 — 2026-10-11

### Added

- Linux firewall detection and rule inspection for UFW, firewalld, nftables
  and IPv4/IPv6 iptables.
- Confirmed UFW enable/disable and firewalld start/stop through system
  authorization, with automatic status and rules refresh.
- UFW incoming, outgoing and combined-direction port rules; firewalld incoming
  rules by zone with explicit runtime or permanent configuration selection.
- LAN subnet detection and LAN/all-address rule scopes.
- Larger-file scan profile and grouped explanations for incomplete checks.

### Improved

- File discovery and scanning run concurrently with bounded memory use.
  Parallel scans count independently so progress can appear before the scan
  queue drains.
- Scan status describes ongoing work while the total is unknown.
- Firewall detection starts automatically on first opening its page, and
  waits for active operations when needed.
- Update dialogs retain the result until the user closes them.
- Firewall documentation and regression coverage.

### Fixed

- Quarantined files are always excluded from scans.
- Encrypted archive/document alerts count as incomplete checks rather than
  malware detections; other suspicious signatures remain detections.
- Firewall subprocess output handles merged stderr and empty output.

### Current limits

- Firewall changes support UFW and firewalld on Linux. Raw nftables/iptables
  rules remain available for inspection; Windows firewall support is pending.
- firewalld outgoing policies are not managed by the rule editor.
- Internet/all-address rules include LAN traffic; this scope is not an
  Internet-only filter.
