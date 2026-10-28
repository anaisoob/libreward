# Computers set up by an administrator

For a children's computer, or computers in an organisation where people should
not change their protection, an administrator installs and configures LibreWard
once. Users who are not administrators cannot remove or turn off what matters.

## What protects what

| Part | Who can change it |
| --- | --- |
| The installed application | Only an administrator: it is a system package (`/usr`), and removing it needs the administrator password |
| Internet protection and the firewall | Only an administrator: they are system settings, and turning them off asks for the administrator password (polkit) |
| Protection for new files, scheduled scans, automatic virus database updates | Each user, unless the administrator's policy sets them |
| What happens with dangerous files | Each user, unless the policy says they are always quarantined |

## Set it up

1. Install the LibreWard package for your distribution.
2. Give children and other users accounts **without administrator rights** (not in
   the `wheel`, `sudo` or `admin` group). The Security status page says whether an
   account is an administrator.
3. Log in as the administrator, open LibreWard and turn on Internet protection and
   the firewall. They apply to all users of the computer.
4. Write the policy as root, readable by everyone and writable only by root:

   ```bash
   sudo install -d -m 755 /etc/libreward
   sudo tee /etc/libreward/policy.json >/dev/null <<'JSON'
   {
     "settings": {
       "watch_folders_enabled": true,
       "follow_download_folders": true,
       "watched_folders": ["~/Downloads"],
       "scheduled_scan": "weekly",
       "auto_update_database": true
     },
     "dangerous_files": "quarantine"
   }
   JSON
   sudo chmod 644 /etc/libreward/policy.json
   ```

5. Start the background service at every user's login:

   ```bash
   sudo systemctl --global enable libreward-monitor.service
   ```

   The packages install this unit for all users but do not enable it. It ends at
   once for users who use neither protection for new files nor scheduled scans.

6. Let the system keep the virus database current, so users need no copy of their
   own: `sudo systemctl enable --now clamav-freshclam.service` (Fedora, Debian and
   Ubuntu name it the same).

## The policy file

`/etc/libreward/policy.json` is used only when root owns it and neither it nor
`/etc/libreward` can be written by other users; otherwise it is ignored. Unknown
keys and invalid values are ignored one by one.

| Key | Values | Effect |
| --- | --- | --- |
| `settings.watch_folders_enabled` | `true`, `false` | Protection for new files on or off |
| `settings.follow_download_folders` | `true`, `false` | Also protect the folders browsers download to |
| `settings.watched_folders` | list of folders; `~` is each user's home | Folders to protect |
| `settings.notify_threats_only` | `true`, `false` | Notify only about dangerous files |
| `settings.scheduled_scan` | `"off"`, `"daily"`, `"weekly"` | Scheduled Quick scan |
| `settings.auto_update_database` | `true`, `false` | Automatic updates of LibreWard's own virus database |
| `dangerous_files` | `"ask"` (default), `"quarantine"` | `quarantine`: the threat question offers only quarantine or deletion, and files cannot be restored from quarantine |

The settings take the place of each user's own: LibreWard shows the controls as
**Set by your administrator** and cannot change them, and the background service
reads a changed policy within seconds.

## Limits

Quarantined files are stored encoded in each user's quarantine, so a file copied
out of it by hand cannot be run or opened, even though the user owns it.

A user can still stop programs that run under their own account, for example
`systemctl --user stop libreward-monitor.service` in a terminal. The policy keeps
LibreWard's own settings on and starts the service again at the next login, which
is enough for children and people who are not technical. Protection that a user
cannot stop at all needs a system service running as root; it is planned together
with blocking files until they are checked (see the [roadmap](roadmap.md)).

In organisations, distribute the policy file and the `systemctl --global enable`
step with the tools already in use (Ansible, Puppet, Salt, FreeIPA). The service
logs to the journal of each user (`journalctl --user -u libreward-monitor.service`).
