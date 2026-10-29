# Roadmap

Planned work that has been discussed but is not implemented yet.

## Next steps, in this order

1. **Bring the dangerous file question to the front while LibreWard is open in the
   background.** GNOME on Wayland only shows a new process's window in front without
   a click, not a window of a running one (also not a separate window of it). A
   small question program started by the background service could work; keep it
   simple and avoid duplicating the question code.
2. Continue with the plan below: plain wording on the other pages, then packaging.

## Protection

- **System quarantine, only with on-access blocking below.** Each user's
  quarantine stores files encoded, so a copy taken out by hand is unusable; only
  someone who decodes it on purpose gets it back. A quarantine only root can read
  (for example `/var/lib/libreward/quarantine`) needs a root service; it is worth
  that risk only together with the root service on-access blocking requires.

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
- A download page with one package per system that also adds the update
  repository, so updates arrive with normal system updates.
- A Windows installer that includes the ClamAV runtime.

## Windows

Windows has Microsoft Defender, which checks files before they open and detects
more than ClamAV. LibreWard does not compete with it there:

- Test and fix the basics on a real Windows: ClamAV runtime setup, database
  updates, folder and Quick scans. The background service, notifications and the
  threat question were developed on GNOME and are only covered by tests on Windows.
- Then focus on **Internet protection** for Windows (blocking dangerous websites,
  trackers and ads), which Defender does not offer in this form.

## Interface

- Review the wording of the Virus scan, Quarantine, Firewall and Settings pages
  for people without technical knowledge, as done for Live protection.
