# Changelog

## Unreleased

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
