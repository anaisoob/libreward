"""systemd-resolved checks shared by the app and the privileged DNS installer.

Behind systemd-resolved, LibreWard's filter becomes resolved's global DNS server
for all names (`Domains=~.`). Connection and VPN profiles are not changed: VPN
routing domains and local network names keep using their own servers.
"""
import re  # noqa: F401  (used by exec of RESOLVED_CHECK)
from pathlib import Path  # noqa: F401

RESOLVED_CHECK = r'''
RESOLVED_STUB = '/run/systemd/resolve/stub-resolv.conf'
RESOLVED_CONF = '/etc/systemd/resolved.conf.d/90-libreward-filter.conf'
RESOLVED_FILTER = '127.0.0.1:5354'
RESOLVED_CONTENT = b'# Managed by LibreWard\n[Resolve]\nDNS=' + RESOLVED_FILTER.encode() + b'\nDomains=~.\n'


def resolved_is_system_resolver(nss, resolv_path='/etc/resolv.conf'):
    """Applications must ask resolved's stub, and NSS must not answer from DNS first."""
    path = Path(resolv_path)
    if not path.is_symlink() or str(path.resolve()) != RESOLVED_STUB:
        return False
    line = next((line.split('#', 1)[0] for line in nss.splitlines()
                 if re.match(r'^\s*hosts\s*:', line)), '')
    tokens = [token for token in re.findall(r'\[[^\]]*\]|[^\s]+', line.partition(':')[2])
              if not token.startswith('[')]
    first = next((index for index, token in enumerate(tokens) if token in ('resolve', 'dns')), None)
    if first is None:
        return False
    # Local sources only before resolved; custom NSS modules could bypass it.
    return all(token in ('files', 'myhostname', 'mymachines', 'mdns4_minimal', 'mdns_minimal')
               for token in tokens[:first])


def global_servers(resolvectl_dns_output):
    """Entries from the `resolvectl dns` "Global:" line, without #names or interfaces."""
    line = next((line for line in resolvectl_dns_output.splitlines() if line.startswith('Global:')), '')
    return {entry.split('#', 1)[0].split('%', 1)[0] for entry in line.partition(':')[2].split()}

'''
exec(RESOLVED_CHECK)


def filter_is_global(resolvectl_dns_output):
    return RESOLVED_FILTER in global_servers(resolvectl_dns_output)  # noqa: F821  (defined by exec)
