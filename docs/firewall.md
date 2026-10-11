# Linux firewall setup and rules

Open **Firewall**. On the first visit, LibreWard automatically checks installed UFW,
firewalld, nftables and IPv4/IPv6 iptables tools in a background worker.
If another operation is running, detection waits until it finishes while this
page is open. Results are retained when switching pages; revisiting does not
repeat a completed check. Choose a detected tool to see its status and rules. Several tools may expose
the same underlying Linux netfilter configuration.

## Reading status and rules

Inactive managers appear in red; active/running managers appear in green.
Installed does not necessarily mean active. UFW shows its current status and
configured user rules, including inactive rules. Normal firewalld inspection
shows runtime and permanent zones separately when running. nftables and
iptables show rulesets; rules being present does not establish complete
network protection.

Select a tool and click **Read as administrator** if permission is required.
The system polkit dialog authorizes one fixed read query using pkexec.
UFW shows status and active rules; firewalld shows runtime zones. Reading
permanent firewalld configuration is part of initial detection and may require
permissions. The GUI remains unprivileged and never receives or stores passwords.
Cancelling authorization stops the request. If pkexec is missing, an explanation
dialog provides a distribution-specific installation command and copy buttons
for terminal sudo commands. If authorization fails, it explains that the
desktop polkit agent/service or system policy may need attention. The Firewall
page also has **Copy sudo commands** for the selected tool’s read queries.
Passwords are entered only into system tools, never into LibreWard widgets.

## Enabling protection

**Enable firewall** is available for UFW confirmed as Inactive and firewalld
confirmed as Not running. When active, the same button becomes **Disable
firewall**. Disabling UFW also disables it at startup while retaining saved
rules; stopping firewalld retains saved rules and does not change its boot
setting. If status is unknown, first read it as administrator.
Review the confirmation before authorizing the operation:

- UFW enables its existing rules and default policies now and at startup.
- firewalld starts its service now using saved configuration. Its boot setting
  is unchanged; service start currently requires systemd.

Enabling can interrupt incoming connections such as SSH or remote desktop.
Prepare required access rules first. If another installed manager is active
or its state cannot be verified, LibreWard refuses to enable a second manager.
It does not replace existing rules or configure default policies for you.
Raw nftables/iptables tools currently support inspection only.

## Adding a connection rule

Click **Add rule** for UFW or running firewalld. Connected LAN networks are
detected automatically with their actual interface prefixes, and the first
candidate is filled in. Choose another detected adapter/subnet or edit the CIDR
if needed. The list may include VPNs and virtual adapters. If detection is
unavailable (for example, the `ip` tool is missing), enter the CIDR manually. Choose Allow/Block, TCP/UDP
and a destination port or range between 1 and 65535 (for example `22` or
`8000-8010`). Each change shows a description and command for confirmation
before system authorization. Existing rules and their ordering can affect
whether a new rule matches traffic.

Network scope:

- **LAN — specific network**: enter the actual CIDR subnet, such as
  `192.168.1.0/24` or `fd12:3456::/64`. Incoming rules match the peer source;
  outgoing rules match the peer destination. A rule covers one address family;
  add separate IPv4 and IPv6 LAN rules when needed.
- **Internet / all addresses — includes LAN**: matches all peer addresses.
  This is not an Internet-only filter. It does not exclude LAN traffic.

Allowing a LAN port does not remove an existing all-address allow rule.
These rules do not configure router port forwarding or guarantee that a port
is reachable from the Internet.

UFW supports Incoming, Outgoing and **Incoming and outgoing**. The combined
choice creates two directional rules in one authorized operation. If either
rule fails, the report says the change was incomplete and refreshes the
current configuration; it does not silently roll back existing rules. It saves rules and applies them
immediately when active; rules added while inactive apply when it is enabled.
The current UFW IPv6 configuration determines whether IPv6 rules are enabled.

firewalld supports incoming rules in a selected zone. Choose the zone that
handles the connection, using the rules view to identify it. Choose either:

- **Apply now**: change runtime rules, lost on reload/restart.
- **Save only**: change permanent configuration, applied on the next
  reload/restart. LibreWard does not reload automatically or overwrite runtime
  rules with saved configuration.

Changes and their status/rules refresh use one authorized request, so there
is no second password prompt for refresh. After enabling or disabling, the
status color, Enable/Disable button and rules view update automatically.
Detected mutation failures also refresh rules before showing the error. If
authorization is cancelled or the request times out, inspect the configuration
before retrying; success is not assumed.
Normal queries time out after ten seconds each; authorized queries allow
120 seconds for authentication and execution.

## Installing a manager

If no supported command is detected, LibreWard recommends UFW and provides a
package installation command for apt, pacman or apk. For other distributions,
consult their package documentation. Missing commands do not prove that the
kernel has no firewall rules. LibreWard does not install packages automatically.
After installation, use **Read as administrator** to recheck detection if no
tool was previously found. Installing UFW does not enable it.

References: [UFW](https://help.ubuntu.com/community/UFW),
[firewalld commands](https://firewalld.org/documentation/man-pages/firewall-cmd.html),
[firewalld rich rules](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html),
[nftables](https://netfilter.org/projects/nftables/manpage.html).

Firewall features are currently unavailable on Windows.
