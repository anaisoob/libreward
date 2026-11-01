# Security status

**Security status** is the first page of LibreWard. The top says in one sentence
how protected the computer is, when the virus database was updated, when the last
scan finished and how many files are in quarantine. Its main button fixes the most
important problem, or runs a Quick scan when there is none. Parts that need
attention follow as cards, each with a button that fixes it or opens the page where
it is fixed; the most important is first. All other parts are small tiles, and
hovering over one explains it. The page reads the system as your user, needs no
password and changes nothing by itself. **Check again** reads it anew; it is also
read whenever the page opens.

| Part | Needs attention when | Button |
| --- | --- | --- |
| System updates | no automatic updates (`unattended-upgrades` on Debian/Ubuntu, a `dnf-automatic` timer on Fedora) and the last upgrade is more than 14 days old (from `/var/log/dpkg.log`, `rpm`, `/var/log/pacman.log`) | **Open software updates** (GNOME Software, KDE Discover, Mint or Ubuntu updater); otherwise the terminal command is shown |
| Firewall | firewalld is not running and UFW is not enabled (`/etc/ufw/ufw.conf`), or neither is installed | **Open Firewall** |
| Dangerous websites | Internet protection is off (only where it is available) | **Turn on** (Live protection) |
| New downloads | Live protection for new files is off | **Turn on** (Live protection) |
| Virus scanning | the antivirus engine or virus database is missing | **Set up** |
| Programs reachable from other computers | a program waits for TCP connections on a non-local address (`/proc/net/tcp`, `tcp6`) and no firewall is on; with a firewall it is information. Usual desktop services (local name lookup, KDE Connect) are not counted | **Open Firewall** |
| Screen lock | GNOME or KDE does not lock the screen by itself | **Turn on**: locks after five minutes without use (`gsettings` or `kwriteconfig`, a setting of your account only) |
| Disk encryption | information only: `/` or `/home` is not on an encrypted (LUKS) device; encryption is chosen when the system is installed | — |
| Administrator account | information only: the account is in the `wheel`, `sudo` or `admin` group; children are safer with an account without administrator rights | — |

Parts the system cannot tell (for example the screen lock on other desktops) are
left out rather than guessed. The page is available on Linux; other platforms show
that it is not available there yet.
