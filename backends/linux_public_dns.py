"""Public filtering DNS through systemd-resolved, for systems without the local filter.

LibreWard writes one owned drop-in with the selected service as global DNS for all
domains. Connection and VPN profiles are not changed; VPN routing domains keep
using their own servers. Pausing removes the drop-in.
"""
import re
from pathlib import Path

from core.dns_providers import PROVIDERS

DIRECTORY = '/etc/systemd/resolved.conf.d'
DROPIN = DIRECTORY + '/90-libreward-dns.conf'
STUB = '/run/systemd/resolve/stub-resolv.conf'


def dropin_content(provider):
    # Opportunistic DNS-over-TLS encrypts where the network allows it and still
    # filters (same servers, plain DNS) where port 853 is blocked.
    return ('# Managed by LibreWard\n# provider=' + provider.key + '\n[Resolve]\n'
            'DNS=' + ' '.join(provider.servers()) + '\nDomains=~.\nDNSOverTLS=opportunistic\n').encode('ascii')


def known_dropins():
    return {dropin_content(provider): key for key, provider in PROVIDERS.items()}


def resolved_is_system_resolver(nss, resolv_path='/etc/resolv.conf'):
    """Applications must ask resolved's stub, and NSS must not answer from DNS first."""
    path = Path(resolv_path)
    if not path.is_symlink() or str(path.resolve()) != STUB:
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
    """Addresses from `resolvectl dns` "Global:" line, without #names or ports."""
    line = next((line for line in resolvectl_dns_output.splitlines() if line.startswith('Global:')), '')
    servers = set()
    for entry in line.partition(':')[2].split():
        address = entry.split('#', 1)[0]
        if address.startswith('['):
            address = address[1:].split(']', 1)[0]
        servers.add(address.split('%', 1)[0])
    return servers


def inspect_public():
    path = Path(DROPIN)
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError('LibreWard DNS settings were changed outside the app.')
    with path.open('rb') as stream:
        data = stream.read(4097)
    key = known_dropins().get(data)
    if key is None:
        raise ValueError('LibreWard DNS settings were changed outside the app.')
    return key


def helper(systemctl, resolvectl):
    contents = {key: content for content, key in known_dropins().items()}
    addresses = {key: list(provider.addresses) for key, provider in PROVIDERS.items()}
    return (PUBLIC_HELPER.replace('__SYSTEMCTL__', repr(systemctl)).replace('__RESOLVECTL__', repr(resolvectl))
            .replace('__CONTENTS__', repr(contents)).replace('__ADDRESSES__', repr(addresses)))


PUBLIC_HELPER = r'''
import fcntl, json, os, socket, stat, subprocess, sys, tempfile, time
SYSTEMCTL = __SYSTEMCTL__
RESOLVECTL = __RESOLVECTL__
CONTENTS = __CONTENTS__
ADDRESSES = __ADDRESSES__
ROOT = '/etc/libreward'
DIRECTORY = '/etc/systemd/resolved.conf.d'
DROPIN = DIRECTORY + '/90-libreward-dns.conf'


def secure_directory(path, create=True):
    if create:
        os.makedirs(path, mode=0o755, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise ValueError('Unsafe DNS configuration directory.')


def owned_read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError('Unsafe DNS configuration file.')
        return stream.read(4097)


def write(path, data):
    if data is None:
        if os.path.lexists(path):
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


def reload_resolved():
    result = subprocess.run([SYSTEMCTL, 'reload-or-restart', 'systemd-resolved.service'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding='utf-8', errors='replace', timeout=30)
    if result.returncode:
        raise RuntimeError('The system resolver could not reload DNS settings. ' + result.stdout.strip())


def global_servers():
    output = subprocess.run([RESOLVECTL, 'dns'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding='utf-8', errors='replace', timeout=10).stdout
    line = next((line for line in output.splitlines() if line.startswith('Global:')), '')
    servers = set()
    for entry in line.partition(':')[2].split():
        address = entry.split('#', 1)[0]
        if address.startswith('['):
            address = address[1:].split(']', 1)[0]
        servers.add(address.split('%', 1)[0])
    return servers


def resolves(name):
    # Bounded query through resolved's stub; never sends user-selected domains.
    query_id = os.urandom(2)
    qname = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    packet = query_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(('127.0.0.53', 53))
        sock.send(packet)
        result = sock.recv(4096)
    return len(result) >= 12 and result[:2] == query_id and not result[3] & 15 and result[6:8] != b'\0\0'


def verify(key):
    expected = set(ADDRESSES[key])
    for attempt in range(25):
        try:
            if expected <= global_servers() and any(resolves(name) for name in ('example.org', 'example.com')):
                return
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(0.3)
    raise RuntimeError('The selected DNS service could not be reached on this network. '
                       'Your previous DNS settings were restored.')


def apply(key):
    secure_directory(ROOT)
    secure_directory('/etc/systemd', create=False)
    secure_directory(DIRECTORY)
    lockfd = os.open(ROOT + '/.public-dns-lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'wb') as lock:
        st = os.fstat(lock.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
            raise ValueError('Unsafe DNS lock.')
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = owned_read(DROPIN)
        if old is not None and old not in CONTENTS.values():
            raise ValueError('DNS settings were changed outside LibreWard.')
        try:
            write(DROPIN, CONTENTS[key] if key else None)
            reload_resolved()
            if key:
                verify(key)
        except BaseException as original:
            try:
                write(DROPIN, old)
                reload_resolved()
            except Exception as rollback:
                raise RuntimeError('The DNS service could not be changed and restoring the previous settings failed. '
                                   'Run sudo systemctl restart systemd-resolved. Original error: ' + str(original) +
                                   ' Restore error: ' + str(rollback)) from rollback
            raise
        return {'provider': key}


if __name__ == '__main__':
    try:
        raw = sys.stdin.read(4097)
        request = json.loads(raw)
        key = request.get('provider') if isinstance(request, dict) else ''
        if key is not None and key not in CONTENTS:
            raise ValueError('Unknown DNS service.')
        print(json.dumps(apply(key)))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
'''
