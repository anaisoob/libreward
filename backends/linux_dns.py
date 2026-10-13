"""Optional integration with NetworkManager's existing local dnsmasq resolver.

We never replace the resolver or change connection/VPN profiles. Unsupported
machines retain the hosts backend. Privileged code uses fixed, owned paths.
"""
import configparser
import re
from pathlib import Path

from .linux_hosts import HOSTS_HELPER, inspect_hosts

LIST_PATH = '/etc/NetworkManager/libreward-domains.hosts'
CONFIG_PATH = '/etc/NetworkManager/dnsmasq.d/90-libreward.conf'
CONFIG = 'addn-hosts=' + LIST_PATH + '\n'
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


def inspect():
    config = Path(CONFIG_PATH)
    if not config.exists():
        return None
    if config.is_symlink() or config.read_text() != CONFIG:
        raise ValueError('LibreWard DNS configuration was changed outside the app.')
    state = inspect_hosts(LIST_PATH)
    state['count'] = max(0, state['count'] - 1)  # internal health-check name
    state['engine'] = 'dnsmasq'
    if not filter_responds():
        state['supported'] = False
    state['message'] = ('Local DNS filtering uses NetworkManager’s dnsmasq. Network and VPN DNS routing is kept. '
                        'Apps using their own DNS may bypass protection.')
    if not state['supported']:
        state['message'] = 'Local DNS filtering is installed but its health check failed. Check the network or pause protection.'
    return state


def filter_responds():
    namespace = {'__name__': 'libreward_dns_probe'}
    exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager'), namespace)
    try:
        namespace['probe'](SENTINEL, True)
        return True
    except (OSError, RuntimeError):
        return False


def helper(nmcli, network_manager, *, setup=False):
    # Reuse validated, locked atomic list writes. Do not execute the hosts CLI.
    base = HOSTS_HELPER.split("if __name__ == '__main__':", 1)[0]
    return (base + '\nimport configparser\n' + COMPATIBILITY_CHECK + '\n' +
            DNS_HELPER.replace('__NMCLI__', repr(nmcli)).replace('__NETWORK_MANAGER__', repr(network_manager))
            .replace('__SETUP__', repr(setup)))


DNS_HELPER = r'''
import subprocess
import time
from pathlib import Path
LIST = '/etc/NetworkManager/libreward-domains.hosts'
CONF = '/etc/NetworkManager/dnsmasq.d/90-libreward.conf'
CONTENT = 'addn-hosts=' + LIST + '\n'
SENTINEL = 'libreward-protection-check.invalid'
NMCLI = __NMCLI__
NETWORK_MANAGER = __NETWORK_MANAGER__
ALLOW_SETUP = __SETUP__
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
        return stream.read(512 * 1024 * 1024 + 1)

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

def probe(name, blocked):
    # Query the actual system resolver with a bounded UDP exchange. The root
    # helper never calls unbounded getaddrinfo or sends user-selected domains.
    query_id = os.urandom(2)
    qname = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    packet = query_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(('127.0.0.1', 53))
        sock.send(packet)
        result = sock.recv(4096)
    if len(result) < 12 or result[:2] != query_id or result[3] & 15 or result[6:8] == b'\0\0':
        raise RuntimeError('Local DNS health check failed.')
    # dnsmasq returns an A record, compressed name, ttl, rdlength, address.
    zero = result.endswith(b'\x00\x04\x00\x00\x00\x00')
    if blocked != zero:
        raise RuntimeError('The local DNS filter did not block the test domain.')

def apply_dns(domains):
    directory = os.path.dirname(CONF)
    parent = os.lstat(os.path.dirname(LIST))
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise ValueError('Unsafe NetworkManager directory.')
    if ALLOW_SETUP:
        os.makedirs(directory, mode=0o755, exist_ok=True)
        os.makedirs(os.path.dirname(SETUP_CONF), mode=0o755, exist_ok=True)
    for folder in (directory, os.path.dirname(SETUP_CONF)):
        if not os.path.exists(folder):
            continue
        st = os.lstat(folder)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError('Unsafe DNS configuration directory.')
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Unsafe NetworkManager configuration directory.')
    lockfd = os.open(directory + '/.libreward-dns-lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'wb') as lock:
        st = os.fstat(lock.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
            raise ValueError('Unsafe DNS lock.')
        fcntl.flock(lock, fcntl.LOCK_EX)
        oldconf, oldlist = owned_read(CONF), owned_read(LIST)
        oldsetup = owned_read(SETUP_CONF)
        if oldsetup not in (None, SETUP_CONTENT):
            raise ValueError('DNS setup was changed outside LibreWard.')
        if domains:
            config = subprocess.run([NETWORK_MANAGER, '--print-config'], check=True, capture_output=True,
                                    text=True, timeout=10).stdout
            nss = Path('/etc/nsswitch.conf').read_text()
            ready = compatible(config, nss, Path('/etc/resolv.conf').read_text())
            if not ready and not (ALLOW_SETUP and setup_supported(config, nss, '/etc/resolv.conf')):
                raise RuntimeError('Network DNS settings changed. Check protection status before retrying.')
        if oldconf not in (None, CONTENT.encode()):
            raise ValueError('DNS configuration was changed outside LibreWard.')
        try:
            if domains:
                if oldlist is None:
                    write(LIST, b'')
                result = replace_hosts(LIST, sorted(set(domains) | {SENTINEL}))
                write(CONF, CONTENT.encode())
                if ALLOW_SETUP and oldsetup is None:
                    write(SETUP_CONF, SETUP_CONTENT)
            else:
                result = {'count': 0, 'skipped': 0}
                write(CONF, None)
                write(LIST, None)
                if oldsetup is not None:
                    write(SETUP_CONF, None)
            reload_dns()
            if domains:
                for attempt in range(15):
                    try:
                        effective = subprocess.run([NETWORK_MANAGER, '--print-config'], check=True, capture_output=True,
                                                   text=True, timeout=10).stdout
                        if not compatible(effective, Path('/etc/nsswitch.conf').read_text(), Path('/etc/resolv.conf').read_text()):
                            raise RuntimeError('The system did not activate local DNS filtering.')
                        probe(SENTINEL, True)
                        break
                    except (OSError, RuntimeError):
                        if attempt == 14:
                            raise
                        time.sleep(0.2)
                check_domain = next((name for name in ('example.org', 'example.net', 'example.com', 'www.iana.org')
                                     if name not in domains), None)
                if check_domain is None:
                    raise RuntimeError('Allow one example domain so Internet connectivity can be checked.')
                probe(check_domain, False)
            # Migrate only our old section after the new filter is healthy.
            replace_hosts('/etc/hosts', [])
        except Exception as original:
            write(SETUP_CONF, oldsetup)
            write(CONF, oldconf)
            write(LIST, oldlist)
            try:
                reload_dns()
            except Exception as rollback:
                raise RuntimeError('Protection was not enabled. The previous configuration files were restored, '
                                   'but NetworkManager could not reload them. Run sudo nmcli general reload '
                                   'to reload the restored settings. Original error: ' + str(original) +
                                   ' Reload error: ' + str(rollback)) from rollback
            raise
        result['count'] = len(domains)
        return result

if __name__ == '__main__':
    try:
        raw = sys.stdin.read(256 * 1024 * 1024 + 1)
        if len(raw) > 256 * 1024 * 1024:
            raise ValueError('Domain list is too large.')
        domains = json.loads(raw)
        if not isinstance(domains, list) or not domains or len(domains) > 5000000:
            if domains != []:
                raise ValueError('Invalid domain list.')
        # replace_hosts validates domains before any configuration activation.
        print(json.dumps(apply_dns(domains)))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
'''
