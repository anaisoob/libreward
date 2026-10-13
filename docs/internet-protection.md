# Internet protection

Open **Internet protection** to check the current state. Opening the page does
not download lists or change network settings. Linux is currently supported;
other platforms show an unavailable message.

LibreWard's local filter checks every website name on this computer against
downloaded lists and your own allowed and blocked websites. It works in one of
two places, chosen automatically:

- **With NetworkManager's dnsmasq** (for example Debian, Ubuntu Server/minimal,
  Raspberry Pi OS, and Arch or Manjaro without systemd-resolved). Allowed names
  go to the network's own DNS servers. Nothing is sent to an extra service.
- **Behind systemd-resolved** (for example Ubuntu Desktop, Linux Mint, Fedora
  and Arch with resolved). Allowed names go to a DNS service you choose, over
  TLS; see [Behind systemd-resolved](#behind-systemd-resolved).

Other setups show that Internet protection is unavailable and nothing is changed.

## Enable protection

Choose categories and select **Enable / apply protection**. Dangerous websites
and phishing are selected by default. Tracking, ads and adult websites are
optional; adult filtering is off by default. Missing lists are downloaded from
The Block List Project over HTTPS only after confirmation.

On supported Linux systems, LibreWard prepares an indexed domain database on
disk, then asks for system polkit authorization to install/update its local DNS
filter. If dnsmasq is missing, it first offers to install it through the
distribution's package manager: `dnsmasq-base` with apt, `dnsmasq` with pacman,
dnf or zypper. NetworkManager starts its own dnsmasq; the package's system
service is not enabled. Package installation and service setup may each
ask for authorization. Passwords go through the system dialog.

Protection works while LibreWard is open (see
[Protection follows the open app](#protection-follows-the-open-app)). Turning
protection off restores normal DNS. Setup may briefly interrupt name resolution.

## How the database backend works

```text
application -> LibreWard DNS filter -> NetworkManager resolver -> upstream DNS
                       |
                 SQLite domain index
```

The LibreWard filter listens only on `127.0.0.1:53` over UDP and TCP. It checks
one domain against a SQLite index, with a 2 MiB SQLite page cache and at most
2,048 cached membership results. Its queue is limited to 64 requests and eight
workers. The list is never expanded into a Python list or dnsmasq hosts records.
Blocked A/AAAA queries return null IPv4/IPv6 addresses. Other blocked record types
receive an empty answer. Allowed queries retain the original DNS request and are
forwarded to NetworkManager's dnsmasq on `127.0.0.1:5354`.

NetworkManager retains upstream servers and conditional VPN forwarding. LibreWard
sets no public DNS servers and changes no connection profiles. It does not provide
a VPN, hide your IP address, or encrypt DNS. See the
[NetworkManager DNS plugin documentation](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html).

The standalone Python service runs as a systemd dynamic user, with only the
capability needed to bind its local port, read-only system access, a 128 MiB
memory limit and a task limit. It imports only Python's standard library.

### Supported setup

Automatic setup requires:

- A running NetworkManager and systemd system service manager.
- NetworkManager's default DNS mode or existing dnsmasq plugin.
- A regular `/etc/resolv.conf` or a symlink owned by NetworkManager.
- NSS lookup reaching `dns` without an earlier resolver that bypasses the filter.
  Debian's minimal mDNS lookup is supported.
- Trusted system Python, nmcli, NetworkManager and systemctl executables.

systemd-resolved systems use the filter behind resolved instead; unmanaged DNS
and other resolver owners are not converted. If the private port is already occupied,
setup stops before changing DNS. Test the setup with the machine's actual VPN.
The detected method appears in the status before applying.

### Installed files

The root-owned database and service scripts are in `/etc/libreward/`:

- `domains.sqlite3`: indexed active domain list, read-only to the service.
- `dns-state.json`: installed count, digest and lifecycle state; no visit history.
- `dns-service.py` and `dns-recovery.py`: standalone service/recovery programs.

Systemd units are `libreward-dns.service` and `libreward-dns-recover.service`.
The owned NetworkManager snippets are:

- `/etc/NetworkManager/conf.d/90-libreward-dns.conf`: selects dnsmasq.
- `/etc/NetworkManager/dnsmasq.d/90-libreward.conf`: sets its private port.

Network connection settings and `/etc/hosts` are not changed.

## Behind systemd-resolved

On systems where systemd-resolved is the system resolver (`/etc/resolv.conf`
points to its stub and NSS asks it before any other network source), the same
filter runs behind resolved:

```text
application -> systemd-resolved -> LibreWard DNS filter -> DNS service over TLS
                      |                    |
     VPN and local network names     SQLite domain index
        go to their own servers
```

The page then also shows **Encrypted DNS service**. Allowed lookups go to it:

| Service | Also blocks on its own |
|---|---|
| AdGuard DNS (default) | Ads, trackers, malware and phishing |
| AdGuard DNS Family | Also adult content; turns on Safe Search |
| Quad9 | Malware and phishing (non-profit) |
| Cloudflare (malware blocking) | Malware |
| Cloudflare for Families | Malware and adult content |

Addresses and certificate names come from the services' official setup pages
and are defined in `core/dns_providers.py`. Before enabling, LibreWard explains
that the service is a third party, not part of LibreWard, used under its own
terms and privacy policy, that it sees which website names pass LibreWard's own
checks, and that it may block websites by mistake.

The filter listens on `127.0.0.1:5354` and becomes resolved's only global server
through one owned drop-in, `/etc/systemd/resolved.conf.d/90-libreward-filter.conf`:

```ini
# Managed by LibreWard
[Resolve]
DNS=127.0.0.1:5354
Domains=~.
```

Connection and VPN profiles are not changed. Routing domains from connections,
such as a VPN's `~corp.example` or a router's `lan` search domain, keep using
their own servers and are not filtered. A VPN that routes all names (`~.`)
through its own DNS can bypass the filter.

The filter forwards over DNS-over-TLS (port 853, TLS 1.2 or newer, certificate
checked against the service's name, connections reused). Where the network blocks
port 853, it uses plain DNS to the same service for a minute before trying TLS
again. Answers over 1,232 bytes make UDP clients retry over TCP.

Setup starts the filter and checks it directly before resolved points to it, so
DNS never points to a filter that is not running. It then reloads resolved and
checks that `resolvectl dns` lists the filter as the global server and that an
ordinary name resolves; otherwise the previous state is restored. NetworkManager
files are neither written nor reloaded in this mode. The unit passes the
service's IPv4 addresses to the filter; the root helper accepts only a key from
the built-in table. Your own allowed and blocked websites work as with
NetworkManager.

## Websites and exceptions

Enter exact names such as `example.org`, without `https://`, paths, IP addresses
or wildcards. International domains are normalized to IDNA. `example.org` does
not automatically include `www.example.org` or other subdomains.

Allowed websites override downloaded and custom blocks inside LibreWard. They
do not override other security tools or upstream filtering. Existing system hosts
entries retain their precedence over DNS.

Changes remain drafts until applied. Saved choices are not evidence of active
protection: the status reports the installed count and checks the running filter.
While its page is open, active protection is checked every 30 seconds when no
other operation is running. Counts represent installed domains, not blocked visits.

## Updates, pause and recovery

**Update protection lists** updates the local cache. Apply protection afterwards
to use the new lists. Downloads are manual; failed downloads leave the last cache
and active protection alone.

**Pause protection** stops/disables the filter and removes LibreWard's
NetworkManager snippets or resolved drop-in. Normal DNS is reloaded.
Choices and downloaded lists are kept. Pause persists until you enable protection
again. Installed service files/database remain available for the next enable.

Installation builds and validates the new root-owned database before changing
network settings. After the NetworkManager reload it waits until the previous
resolver has released `127.0.0.1:53`, because the reload returns before dnsmasq
has moved to the private port. After starting the service it checks a blocked domain and an
ordinary allowed domain. Failed setup restores the previous database/configuration
and reloads DNS. Recovery failures report both the original and recovery errors.

A failed receive or accept on one socket is skipped; the filter keeps serving.
If the filter process crashes or hits its systemd memory limit, systemd restarts
it after one second. Three failures within a minute, or a missing app heartbeat
(exit status 3, never restarted), trigger a separate root recovery service that removes LibreWard's DNS routing
snippets, reloads normal DNS and disables the failed filter. This restores internet
access while stopping domain protection; the GUI reports the recovered state.
If an interrupted setup needs attention, use **Pause protection** to restore DNS.
A recovery reload failure still needs administrator attention.

## Memory and privacy

Downloads, deduplication, selected-domain export, privileged database construction
and membership lookups operate incrementally with bounded caches. No full-domain
list is held in memory. Status
checks read small installed metadata and query the filter, not every domain.
Initial preparation still uses disk space and time proportional to the list size.

LibreWard records no browsing history or DNS query log. An existing upstream
resolver may have its own logging configuration. Downloading lists contacts
GitHub; custom domains are not uploaded.

The user cache is `internet-protection/lists.sqlite3` under LibreWard's data
directory. Old compressed JSON caches are not expanded; selected lists are fetched
into the new format when needed. Source URLs, SHA256 digests and source/license
headers are retained. Sources are The Block List Project's malware, phishing,
tracking, ads and porn domain lists under their
[upstream license terms](https://github.com/blocklistproject/Lists/blob/main/LICENSE).

Lists can be wrong or stale. This blocks listed domain names, not page contents,
and is not a complete parental-control system. Apps with their own DNS, direct IP
connections and cached addresses may bypass it. It cannot remove every ad or
establish that an allowed website is safe.

Automated tests use temporary databases/files and real UDP/TCP traffic on
unprivileged loopback ports. Service installation, NetworkManager changes,
reboot and crash recovery still require smoke tests on a supported Linux machine;
automated tests never change the development computer's system DNS.

### Protection follows the open app

Internet protection works while LibreWard is running, including from the system
tray. If LibreWard is not running, websites are not blocked.

- **Closing the window** with protection on keeps LibreWard running in the tray,
  without a question; the first time per session a short notification says so.
  Settings can change this to “Ask every time” or “Turn off protection and quit”.
  Without a tray (for example GNOME without a tray extension), closing asks:
  minimize, turn off protection and quit, or cancel. With protection off, closing
  simply quits.
- **Quit LibreWard** in the tray menu asks once, then turns protection off and
  quits. Turning off may need system authorization. LibreWard then remembers
  protection as off and does not start with the computer. If turning off fails,
  the app stays open and offers to quit anyway.
- **Restarting or shutting down** with protection on keeps it on. The filter
  service starts with the computer, and an XDG autostart entry
  (`~/.config/autostart/libreward.desktop`) starts LibreWard in the tray at login
  (minimized without a tray). Logging out does not ask to turn protection off.

The tray badge uses white lettering on a green background with a light outline so
it remains visible on both light and dark desktop panels.
- **If LibreWard stops unexpectedly** (crash, killed, or the user logged out
  without shutting down), the filter notices that the app no longer sends its
  heartbeat and restores normal DNS after about two minutes. The next start
  asks whether to turn protection on again; “No” remembers protection as off.

The open app sends a fire-and-forget DNS query for
`libreward-app-open.invalid` to `127.0.0.1:53` every 20 seconds. The filter
answers it locally and, after the first heartbeat, exits with a failure status
when none arrives for 120 seconds; `OnFailure=` then runs the recovery unit.
Before the first heartbeat, for example at boot while waiting for login, the
filter keeps protecting. Behind systemd-resolved the heartbeat goes to port 5354
and recovery also removes the resolved drop-in.
