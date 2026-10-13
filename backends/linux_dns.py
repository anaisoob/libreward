"""Shared pieces of the privileged Linux DNS helpers and resolver checks.

LibreWard never replaces connection or VPN profiles. Privileged code uses fixed,
owned paths and is executed as standalone source; it imports no app modules.
"""
import configparser  # noqa: F401  (used by exec of COMPATIBILITY_CHECK)
import re  # noqa: F401
from pathlib import Path  # noqa: F401

SENTINEL = 'libreward-protection-check.invalid'


COMPATIBILITY_CHECK = r'''
def compatible(config, nss, resolv):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(config)
        if parser.get('main', 'dns', fallback='') != 'dnsmasq':
            return False
    except configparser.Error:
        return False
    line = next((line.split('#', 1)[0] for line in nss.splitlines()
                 if re.match(r'^\s*hosts\s*:', line)), '')
    tokens = re.findall(r'\[[^\]]*\]|[^\s]+', line.partition(':')[2])
    # resolve, mdns or custom NSS modules can return answers before our filter.
    if 'dns' not in tokens or any(t not in ('files', 'dns', 'myhostname', 'mdns4_minimal', 'mdns_minimal')
                                 for t in tokens[:tokens.index('dns')] if not t.startswith('[')):
        return False
    if any('SUCCESS' in t.upper() for t in tokens if t.startswith('[')):
        return False
    servers = re.findall(r'^\s*nameserver\s+(\S+)', resolv, re.M)
    return bool(servers) and set(servers) == {'127.0.0.1'}


def setup_supported(config, nss, resolv_path):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(config)
        if parser.get('main', 'dns', fallback='default') not in ('default', 'dnsmasq'):
            return False
        if parser.get('main', 'rc-manager', fallback='auto') not in ('auto', 'file', 'symlink'):
            return False
    except configparser.Error:
        return False
    # Never take over resolved, resolvconf, or a manually selected DNS symlink.
    path = Path(resolv_path)
    if not path.is_file():
        return False
    if path.is_symlink() and str(path.resolve()) != '/run/NetworkManager/resolv.conf':
        return False
    return compatible('[main]\ndns=dnsmasq', nss, 'nameserver 127.0.0.1')

'''
exec(COMPATIBILITY_CHECK)


SHARED_HELPER = r'''
import configparser, fcntl, json, os, re, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path  # noqa: F401
CONF = '/etc/NetworkManager/dnsmasq.d/90-libreward.conf'
SENTINEL = 'libreward-protection-check.invalid'
NMCLI = __NMCLI__
NETWORK_MANAGER = __NETWORK_MANAGER__
SETUP_CONF = '/etc/NetworkManager/conf.d/90-libreward-dns.conf'
SETUP_CONTENT = b'[main]\ndns=dnsmasq\n'

def owned_read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError('Unsafe DNS configuration file.')
        return stream.read(256 * 1024 + 1)

def write(path, data):
    if data is None:
        if os.path.exists(path):
            os.unlink(path)
        return
    fd, name = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.libreward-dns-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def reload_dns():
    # No flags is the documented full reload, including configuration and DNS.
    # Keep this compatible with older distro nmcli argument parsers as well.
    try:
        subprocess.run([NMCLI, 'general', 'reload'], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, encoding='utf-8', errors='replace', timeout=30)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or '').strip()
        raise RuntimeError('NetworkManager could not reload DNS settings '
                           '(exit ' + str(exc.returncode) + '). ' + detail) from exc

def probe(name, blocked, server=('127.0.0.1', 53)):
    # Query the actual system resolver with a bounded UDP exchange. The root
    # helper never calls unbounded getaddrinfo or sends user-selected domains.
    query_id = os.urandom(2)
    qname = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    packet = query_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(server)
        sock.send(packet)
        result = sock.recv(4096)
    if len(result) < 12 or result[:2] != query_id or result[3] & 15 or result[6:8] == b'\0\0':
        raise RuntimeError('Local DNS health check failed.')
    # The filter returns an A record, compressed name, ttl, rdlength, address.
    zero = result.endswith(b'\x00\x04\x00\x00\x00\x00')
    if blocked != zero:
        raise RuntimeError('The local DNS filter did not block the test domain.')

''' + COMPATIBILITY_CHECK


def helper(nmcli, network_manager):
    return SHARED_HELPER.replace('__NMCLI__', repr(nmcli)).replace('__NETWORK_MANAGER__', repr(network_manager))


def probe_filter(port=53):
    """Unprivileged check that LibreWard's filter answers and blocks its test name."""
    namespace = {'__name__': 'libreward_dns_probe'}
    exec(helper(None, None), namespace)
    try:
        namespace['probe'](SENTINEL, True, server=('127.0.0.1', port))
        return True
    except (OSError, RuntimeError):
        return False
