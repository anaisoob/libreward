# Roadmap

Planned work that has been discussed but is not implemented yet.

## Next steps, in this order

1. **Scheduled scans in Live protection**: for example a weekly Quick scan, run by
   the background service so it also happens while LibreWard is closed.
2. **Virus database updates without the window or Live protection**: the database
   is refreshed while LibreWard is open or while protection for new files runs, but
   not when both are off. A small user timer could refresh it regardless.
3. **New repository owner**: replace `anaisoob` (GitHub URLs, AUR/RPM/Debian
   maintainer lines, AppStream metadata, update manifest URL) with the new owner.
4. Continue with the plan below: plain wording on the other pages, then packaging.

## Protection

- **Block opening a file until it is checked (on-access scanning).** ClamAV's
  `clamonacc` uses the kernel's fanotify interface to hold `open()` on a file until
  clamd has checked it (`OnAccessPrevention yes`). This is what Windows Defender
  does. It needs a system clamd that keeps the virus database in memory (about
  1–1.5 GB), root configuration, and care so that a stuck clamd cannot freeze
  applications. Offer it as an optional advanced setting next to the current
  protection for new files, which checks files right after they are saved.
- **DNS-over-HTTPS fallback for Internet protection** on networks that block
  DNS-over-TLS (port 853), using only the Python standard library in the root
  service.
- **Database mode setting**: LibreWard's own virus database, the detected system
  database, or a custom folder.

## Distribution

- An openSUSE Build Service project building Fedora, openSUSE, Debian and Ubuntu
  packages with update repositories.
- A Debian package with its own PySide6 for Ubuntu 24.04 LTS and Linux Mint 22,
  which have no PySide6 packages.
- A download page with one package per system that also adds the update
  repository, so updates arrive with normal system updates.
- A Windows installer that includes the ClamAV runtime.

## Interface

- Review the wording of the Virus scan, Quarantine, Firewall and Settings pages
  for people without technical knowledge, as done for Live protection.
