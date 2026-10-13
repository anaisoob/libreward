# Changelog

## Unreleased

- Keep the DNS filter running when one socket receive/accept fails, and restart it
  after a crash before falling back to normal DNS. Wait for the previous resolver to
  release the local DNS port before starting the filter, so enabling protection no
  longer fails intermittently after the NetworkManager reload.

- Internet protection now works only while LibreWard is open. Closing asks once and turns
  protection off; a restart with protection on keeps it and opens LibreWard minimized at
  login; if the app stops unexpectedly, the filter restores normal DNS after about two
  minutes and the next start offers to turn it on again. Remove the tray icon and the
  remembered close choice.

- Replace large dnsmasq hosts lists with a standalone SQLite-backed DNS filter: stream installation, bounded request/cache memory, UDP/TCP forwarding through NetworkManager, systemd lifecycle and failure recovery.
- Widen the left navigation so Internet protection is fully visible.

- Stream community-list downloads into a SQLite cache, read protection status in constant space, write helper payloads through temporary files and reject unsafe memory requirements before enabling DNS protection.

- Use a flag-free full NetworkManager reload for DNS setup and rollback; include
  the actual NetworkManager error and recovery instructions if reloading fails.

- Offer local DNS setup on default NetworkManager-based Debian/Ubuntu systems, including consented dnsmasq-base installation, reversible DNS mode configuration and Debian mdns lookup support. Replace the technical setup dead end with a short explanation.

- Add optional adult-site lists and a local DNS backend for existing NetworkManager/dnsmasq setups, with health checks, rollback and migration from LibreWard hosts entries. Limit the hosts fallback to small custom lists.

- Recognize systemd-resolved hosts lookup, accommodate larger community domain
  lists and preserve the Internet protection page position during status checks.

- Add Linux Internet protection with opt-in community domain lists, dangerous-site,
  tracking and ad categories, exact-domain exceptions, confirmed hosts-file
  application and pause. Keep DNS/VPN settings and existing hosts entries intact.

- Present editable firewall rules in a readable table with action, connection,
  app/port, network and configuration scope; keep raw output in optional details.

- Show firewall rules by default and offer confirmed deletion of saved UFW
  rules and firewalld zone services, ports and rich rules, with automatic refresh.

- Simplify the firewall page with plain-language protection status and optional
  technical rule details; remove its Copy sudo commands button. Firewall hints
  match whether protection is on, off or unconfirmed.

- Present scan reports in plain language, with optional technical details and
  scan durations formatted as hours, minutes and seconds.

- Choose parallel scan workers automatically from CPU count (up to 16), or
  select 4, 8 or 16 in Settings. Larger-file automatic scans remain capped at 2.

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
