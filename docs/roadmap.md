# Roadmap

Planned work that has been discussed but is not implemented yet.

## Next steps, in this order

1. **New repository owner**: replace `anaisoob` (GitHub URLs, AUR/RPM/Debian
   maintainer lines, AppStream metadata, update manifest URL) with the new owner.
2. **Bring the dangerous file question to the front while LibreWard is open in the
   background.** GNOME on Wayland only shows a new process's window in front without
   a click, not a window of a running one (also not a separate window of it). A
   small question program started by the background service could work; keep it
   simple and avoid duplicating the question code.
3. Continue with the plan below: plain wording on the other pages, then packaging.

## Protection

- **Deeper system check with administrator rights (phase 2)**, on request through
  pkexec: system programs and libraries whose contents differ from their package
  (`rpm -Va`, `debsums`, `pacman -Qkk`; executables and libraries only, not
  configuration), SUID programs and system services or cron jobs that belong to no
  package, and the phase 1 process checks for all users.

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
