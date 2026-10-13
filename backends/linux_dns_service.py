"""Linux installation/lifecycle for the disk-backed DNS filter.

Two modes, chosen by the app:

- networkmanager: the filter listens on 127.0.0.1:53; NetworkManager's dnsmasq
  keeps forwarding normal and VPN queries on the private port 5354.
- resolved: the filter listens on 127.0.0.1:5354 as systemd-resolved's global DNS
  server and forwards allowed queries to the selected public service over TLS.
  VPN routing domains and local network names stay with resolved.
"""
import json
from pathlib import Path

from core.dns_providers import PROVIDERS
from core.dns_proxy import SERVICE_SOURCE
from .linux_dns import helper as shared_helper, probe_filter
from .linux_resolved import RESOLVED_CHECK

DIRECTORY = '/etc/libreward'
STATE = DIRECTORY + '/dns-state.json'
PROXY_CONFIG = 'port=5354\n'
# Seconds without a heartbeat from the open app before normal DNS is restored.
IDLE_LIMIT = 120


def inspect_service():
    path = Path(STATE)
    if not path.exists():
        return None
    with path.open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError('Invalid DNS service status.')
    state = json.loads(raw)
    active = state.get('active') is True
    mode = state.get('mode', 'networkmanager')
    port = 5354 if mode == 'resolved' else 53
    healthy = probe_filter(port) if active else True
    provider = PROVIDERS.get(state.get('provider'))
    message = 'Local filtering checks domains from disk with a small memory cache. Network and VPN DNS routing is kept.'
    if provider is not None:
        message += f' Allowed lookups go to {provider.name}, encrypted where the network allows it.'
    return {'active': active, 'supported': healthy, 'count': state.get('count', 0) if active else 0,
            'engine': 'sqlite-dns', 'digest': state.get('digest'), 'mode': mode, 'port': port,
            'provider': state.get('provider') if active else None,
            'message': message if healthy else 'The local filter needs attention. Pause protection to restore normal DNS.',
            'recovered': state.get('phase') == 'recovered'}


def system_cleanup():
    """Run as root by package removal (no pkexec). Never fails the removal."""
    import os
    import shutil
    import sys
    path = '/usr/sbin:/usr/bin:/sbin:/bin'
    tools = {name: shutil.which(name, path=path) for name in
             ('nmcli', 'NetworkManager', 'systemctl', 'python3', 'resolvectl')}
    try:
        if os.geteuid() != 0:
            raise PermissionError('LibreWard system cleanup must run as root.')
        if not tools['systemctl']:
            return 0
        namespace = {'__name__': 'libreward_cleanup'}
        exec(helper(tools['nmcli'], tools['NetworkManager'], tools['systemctl'],
                    tools['python3'] or sys.executable, tools['resolvectl']), namespace)
        namespace['uninstall']()
    except Exception as exc:
        print('LibreWard could not remove its Internet protection files: ' + str(exc) + '\n'
              'Normal DNS returns within a few minutes. To finish manually: '
              'sudo systemctl disable --now libreward-dns.service; '
              'sudo rm -f /etc/NetworkManager/dnsmasq.d/90-libreward.conf '
              '/etc/NetworkManager/conf.d/90-libreward-dns.conf '
              '/etc/systemd/resolved.conf.d/90-libreward-filter.conf; '
              'then restart NetworkManager or systemd-resolved.', file=sys.stderr)
    return 0


def upstream_table():
    """IPv4 DNS-over-TLS servers per provider; the service is limited to AF_INET."""
    return {key: [[address, provider.tls_name] for address in provider.addresses if ':' not in address]
            for key, provider in PROVIDERS.items()}


def helper(nmcli, network_manager, systemctl, python, resolvectl=None):
    # Share fixed-file helpers and resolver checks.
    prefix = shared_helper(nmcli, network_manager) + RESOLVED_CHECK
    recovery = RECOVERY_SOURCE.replace('__NMCLI__', repr(nmcli)).replace('__SYSTEMCTL__', repr(systemctl))
    # Protection follows the open app. The filter starts at boot so a computer
    # restarted with protection on keeps it; once LibreWard has sent heartbeats,
    # their absence (app crashed or the user logged out) makes the filter exit
    # as failed and the recovery unit restores normal DNS.
    service_unit = ('# Managed by LibreWard\n[Unit]\nDescription=LibreWard local DNS filter\n'
                    'After=NetworkManager.service\nOnFailure=libreward-dns-recover.service\n'
                    'StartLimitIntervalSec=60\nStartLimitBurst=3\n'
                    '[Service]\nType=simple\nDynamicUser=yes\n'
                    # Restart after a crash; exit status 3 (no app heartbeat) and
                    # repeated crashes go to the recovery unit instead.
                    'Restart=on-failure\nRestartSec=1\nRestartPreventExitStatus=3\n'
                    f'ExecStart={python} -I /etc/libreward/dns-service.py --database /etc/libreward/domains.sqlite3 '
                    f'--idle-limit {IDLE_LIMIT} __ARGS__\n'
                    'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'
                    'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
                    'RestrictAddressFamilies=AF_INET AF_UNIX\nMemoryMax=128M\nTasksMax=32\n'
                    'TimeoutStopSec=8\n[Install]\nWantedBy=multi-user.target\n')
    recovery_unit = ('# Managed by LibreWard\n[Unit]\nDescription=Restore DNS after a LibreWard filter failure\n'
                     'After=NetworkManager.service systemd-resolved.service\n[Service]\nType=oneshot\n'
                     f'ExecStart={python} -I /etc/libreward/dns-recovery.py\n')
    return prefix + '\n' + INSTALLER_SOURCE.replace('__SYSTEMCTL__', repr(systemctl)).replace(
        '__RESOLVECTL__', repr(resolvectl)).replace('__UPSTREAMS__', repr(upstream_table())).replace(
        '__SERVICE_SOURCE__', repr(SERVICE_SOURCE)).replace('__RECOVERY_SOURCE__', repr(recovery)).replace(
        '__SERVICE_UNIT__', repr(service_unit)).replace('__RECOVERY_UNIT__', repr(recovery_unit))


RECOVERY_SOURCE = r'''
# Managed by LibreWard
import fcntl, json, os, stat, subprocess, tempfile
NMCLI = __NMCLI__
SYSTEMCTL = __SYSTEMCTL__
ROOT = '/etc/libreward'
STATE = ROOT + '/dns-state.json'
CONF = '/etc/NetworkManager/dnsmasq.d/90-libreward.conf'
SETUP = '/etc/NetworkManager/conf.d/90-libreward-dns.conf'
RESOLVED = '/etc/systemd/resolved.conf.d/90-libreward-filter.conf'
RESOLVED_CONTENT = '# Managed by LibreWard\n[Resolve]\nDNS=127.0.0.1:5354\nDomains=~.\n'

def service_running(name):
    return subprocess.run([SYSTEMCTL, 'is-active', '--quiet', name],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0

def reload_or_skip(command, service):
    # Early at boot the network service may not run yet; it then starts
    # without the removed files. A running service must reload.
    try:
        subprocess.run(command, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        if service_running(service):
            raise

def recover():
    lock = os.open(ROOT + '/.dns-lock', os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(lock, 'wb') as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != os.geteuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Unsafe recovery lock')
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            with open(STATE) as state_file:
                state = json.load(state_file)
        except FileNotFoundError:
            return
        if not state.get('active'):
            return
        if service_running('libreward-dns.service'):
            return
        removed = set()
        for path, expected in ((CONF, 'port=5354\n'), (SETUP, '[main]\ndns=dnsmasq\n'), (RESOLVED, RESOLVED_CONTENT)):
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                continue
            with os.fdopen(fd) as config:
                st = os.fstat(config.fileno())
                if st.st_uid != os.geteuid() or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or config.read(4097) != expected:
                    raise ValueError('DNS configuration changed outside LibreWard')
            os.unlink(path)
            removed.add(path)
        if removed & {CONF, SETUP}:
            reload_or_skip([NMCLI, 'general', 'reload'], 'NetworkManager.service')
        if RESOLVED in removed:
            reload_or_skip([SYSTEMCTL, 'reload-or-restart', 'systemd-resolved.service'], 'systemd-resolved.service')
        subprocess.run([SYSTEMCTL, 'disable', 'libreward-dns.service'], check=True, timeout=30)
        fd, name = tempfile.mkstemp(dir=ROOT, prefix='.dns-state-')
        try:
            with os.fdopen(fd, 'w') as output:
                os.fchmod(output.fileno(), 0o644)
                json.dump({'active': False, 'count': 0, 'phase': 'recovered'}, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, STATE)
        finally:
            if os.path.exists(name): os.unlink(name)

if __name__ == '__main__':
    recover()
'''


INSTALLER_SOURCE = r'''
import contextlib
import io
import shutil
import sqlite3
import hashlib
import signal
SYSTEMCTL = __SYSTEMCTL__
RESOLVECTL = __RESOLVECTL__
UPSTREAMS = __UPSTREAMS__
SERVICE_SOURCE = __SERVICE_SOURCE__
RECOVERY_SOURCE = __RECOVERY_SOURCE__
SERVICE_UNIT = __SERVICE_UNIT__
RECOVERY_UNIT = __RECOVERY_UNIT__
ROOT = '/etc/libreward'
DATABASE = ROOT + '/domains.sqlite3'
STATE = ROOT + '/dns-state.json'
SERVICE = ROOT + '/dns-service.py'
RECOVERY = ROOT + '/dns-recovery.py'
UNIT = '/etc/systemd/system/libreward-dns.service'
RECOVERY_UNIT_PATH = '/etc/systemd/system/libreward-dns-recover.service'
PROXY_CONFIG = b'port=5354\n'


def systemctl(*args, required=True):
    result = subprocess.run([SYSTEMCTL, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding='utf-8', errors='replace', timeout=30)
    if required and result.returncode:
        raise RuntimeError('DNS service operation failed: ' + (result.stderr or result.stdout).strip())
    return result.returncode == 0


def secure_directory(path, create=True):
    if create:
        os.makedirs(path, mode=0o755, exist_ok=True)
    elif not os.path.lexists(path):
        return
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise ValueError('Unsafe DNS service directory.')


def build_database(stream, expected):
    fd, path = tempfile.mkstemp(dir=ROOT, prefix='.domains-', suffix='.sqlite3')
    os.close(fd)
    connection = None
    digest, previous, count = hashlib.sha256(), None, 0
    valid = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
    try:
        connection = sqlite3.connect(path)
        connection.execute('PRAGMA cache_size=-2048')
        connection.execute('PRAGMA temp_store=FILE')
        connection.execute('CREATE TABLE blocked(domain TEXT PRIMARY KEY) WITHOUT ROWID')
        while True:
            raw = stream.readline(256)
            if not raw:
                break
            if not raw.endswith(b'\n') or len(raw) > 254:
                raise ValueError('Invalid domain record.')
            value = raw[:-1].decode('ascii')
            if (len(value) > 253 or '.' not in value or not all(valid.fullmatch(part) for part in value.split('.'))
                    or value == 'localhost.localdomain' or value.endswith(('.local', '.localhost', '.arpa'))
                    or re.fullmatch(r'[0-9.]+', value) or previous is not None and value <= previous):
                raise ValueError('Invalid domain record.')
            count += 1
            if count > expected:
                raise ValueError('Domain count does not match.')
            connection.execute('INSERT INTO blocked VALUES (?)', (value,))
            digest.update(raw)
            previous = value
        if count != expected:
            raise ValueError('Domain list is incomplete.')
        connection.execute('INSERT OR IGNORE INTO blocked VALUES (?)', (SENTINEL,))
        connection.commit()
        connection.close()
        connection = None
        os.chmod(path, 0o644)
        with open(path, 'rb') as source: os.fsync(source.fileno())
        return path, count, digest.hexdigest()
    except BaseException:
        if connection is not None: connection.close()
        for item in (path, path + '-journal'):
            if os.path.exists(item): os.unlink(item)
        raise


def owned_small(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1 or st.st_mode & 0o022:
            raise ValueError('Unsafe DNS configuration file.')
        data = stream.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise ValueError('Unexpected DNS configuration size.')
    return data


def service_unit(mode, provider):
    if mode == 'resolved':
        upstream = ' '.join('--tls-upstream ' + address + '#' + name for address, name in UPSTREAMS[provider])
        return SERVICE_UNIT.replace('__ARGS__', '--listen-port 5354 ' + upstream)
    return SERVICE_UNIT.replace('__ARGS__', '--listen-port 53')


def reload_resolved():
    result = subprocess.run([SYSTEMCTL, 'reload-or-restart', 'systemd-resolved.service'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding='utf-8', errors='replace', timeout=30)
    if result.returncode:
        raise RuntimeError('The system resolver could not reload DNS settings. ' + result.stdout.strip())


def network_ready(mode):
    nss = Path('/etc/nsswitch.conf').read_text()
    if mode == 'resolved':
        return (systemctl('is-active', '--quiet', 'systemd-resolved.service', required=False)
                and resolved_is_system_resolver(nss))
    config = subprocess.run([NETWORK_MANAGER, '--print-config'], check=True, capture_output=True,
                            text=True, timeout=10).stdout
    return compatible(config, nss, Path('/etc/resolv.conf').read_text()) or setup_supported(config, nss, '/etc/resolv.conf')


def filter_health():
    # Behind resolved, query the filter directly: resolved may turn a synthetic
    # answer for a signed zone into SERVFAIL, which still blocks but is not a check.
    for attempt in range(20):
        try:
            if not systemctl('is-active', '--quiet', 'libreward-dns.service', required=False):
                raise RuntimeError('Local DNS service is not running.')
            probe(SENTINEL, True, server=('127.0.0.1', 5354))
            return
        except (OSError, RuntimeError):
            if attempt == 19: raise
            time.sleep(0.2)


def resolved_health(allowed):
    for attempt in range(25):
        try:
            output = subprocess.run([RESOLVECTL, 'dns'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, encoding='utf-8', errors='replace', timeout=10).stdout
            if RESOLVED_FILTER not in global_servers(output):
                raise RuntimeError('The system resolver did not activate local DNS filtering.')
            probe(allowed, False, server=('127.0.0.53', 53))
            return
        except (OSError, RuntimeError, subprocess.SubprocessError):
            if attempt == 24:
                raise RuntimeError('Websites could not be reached through the selected DNS service on this network.')
            time.sleep(0.3)


def check_owned_files():
    if owned_small(CONF) not in (None, PROXY_CONFIG):
        raise ValueError('DNS configuration changed outside LibreWard.')
    if owned_small(RESOLVED_CONF) not in (None, RESOLVED_CONTENT):
        raise ValueError('DNS configuration changed outside LibreWard.')
    if owned_small(SETUP_CONF) not in (None, SETUP_CONTENT):
        raise ValueError('DNS setup changed outside LibreWard.')
    for path in (SERVICE, RECOVERY, UNIT, RECOVERY_UNIT_PATH):
        data = owned_small(path)
        if data is not None and not data.lstrip().startswith(b'# Managed by LibreWard'):
            raise ValueError('DNS service file belongs to another configuration.')


def query_health(count):
    for attempt in range(20):
        try:
            if not systemctl('is-active', '--quiet', 'libreward-dns.service', required=False):
                raise RuntimeError('Local DNS service is not running.')
            effective = subprocess.run([NETWORK_MANAGER, '--print-config'], check=True, capture_output=True,
                                       text=True, timeout=10).stdout
            if not compatible(effective, Path('/etc/nsswitch.conf').read_text(), Path('/etc/resolv.conf').read_text()):
                raise RuntimeError('The system did not activate local DNS filtering.')
            probe(SENTINEL, True)
            return
        except (OSError, RuntimeError):
            if attempt == 19: raise
            time.sleep(0.2)


def check_upstream_port():
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        with socket.socket(socket.AF_INET, kind) as check:
            try:
                check.bind(('127.0.0.1', 5354))
            except OSError as exc:
                raise RuntimeError('The private DNS port is already in use. No DNS settings were changed.') from exc


def wait_for_dns_port(attempts=50):
    # nmcli reload returns before NetworkManager has restarted dnsmasq on the
    # private port. Starting the filter earlier fails with "address in use".
    for attempt in range(attempts):
        try:
            for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                with socket.socket(socket.AF_INET, kind) as check:
                    if kind == socket.SOCK_STREAM:
                        check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    check.bind(('127.0.0.1', 53))
            return
        except OSError:
            if attempt == attempts - 1:
                raise RuntimeError('The previous DNS resolver did not release the local DNS port. '
                                   'No protection was enabled.')
            time.sleep(0.2)


def allowed_example():
    with contextlib.closing(sqlite3.connect('file:' + DATABASE + '?mode=ro', uri=True)) as database:
        allowed = next((name for name in ('example.org', 'example.net', 'example.com', 'www.iana.org')
                        if database.execute('SELECT 1 FROM blocked WHERE domain=?', (name,)).fetchone() is None), None)
    if allowed is None: raise RuntimeError('An example domain must be allowed for the connectivity check.')
    return allowed


def apply_database(stream, count, mode='networkmanager', provider=None):
    secure_directory(ROOT)
    secure_directory(os.path.dirname(UNIT))
    # Installing creates the target mode's directories; pausing only checks the
    # existing ones, so it never adds NetworkManager or resolved directories.
    resolved_dirs = [os.path.dirname(RESOLVED_CONF)]
    nm_dirs = [os.path.dirname(os.path.dirname(CONF)), os.path.dirname(CONF), os.path.dirname(SETUP_CONF)]
    for path in resolved_dirs + nm_dirs:
        secure_directory(path, create=bool(count) and path in (resolved_dirs if mode == 'resolved' else nm_dirs))
    lockfd = os.open(ROOT + '/.dns-lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'wb') as lock:
        st = os.fstat(lock.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
            raise ValueError('Unsafe DNS service lock.')
        fcntl.flock(lock, fcntl.LOCK_EX)
        check_owned_files()
        staged = None
        running = systemctl('is-active', '--quiet', 'libreward-dns.service', required=False)
        # Port 5354 is for NetworkManager's dnsmasq or, behind resolved, for the filter.
        if count and not running and not (mode == 'networkmanager' and owned_small(CONF) == PROXY_CONFIG):
            check_upstream_port()
        if count:
            if not network_ready(mode):
                raise RuntimeError('Network settings changed. Check protection status before retrying.')
            staged, actual, digest = build_database(stream, count)
        else:
            if stream.read(1): raise ValueError('Unexpected pause payload.')
            actual, digest = 0, None
        paths = (CONF, SETUP_CONF, RESOLVED_CONF, STATE, SERVICE, RECOVERY, UNIT, RECOVERY_UNIT_PATH)
        try:
            snapshot = {path: owned_small(path) for path in paths}
            was_active = systemctl('is-active', '--quiet', 'libreward-dns.service', required=False)
            was_enabled = systemctl('is-enabled', '--quiet', 'libreward-dns.service', required=False)
        except BaseException:
            if staged is not None and os.path.exists(staged): os.unlink(staged)
            raise
        backup = None
        # Reload only the resolvers whose files LibreWard had or now changes.
        touched_nm = mode == 'networkmanager' and bool(count) or snapshot[CONF] is not None or snapshot[SETUP_CONF] is not None
        touched_resolved = mode == 'resolved' and bool(count) or snapshot[RESOLVED_CONF] is not None
        state = {'active': True, 'count': actual, 'digest': digest, 'mode': mode, 'provider': provider}
        try:
            if snapshot[UNIT] is not None and was_active:
                systemctl('stop', 'libreward-dns.service')
            if count:
                if os.path.lexists(DATABASE):
                    info = os.lstat(DATABASE)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                        raise ValueError('Unsafe DNS database.')
                    fd, backup = tempfile.mkstemp(dir=ROOT, prefix='.previous-db-')
                    os.close(fd)
                    os.replace(DATABASE, backup)
                os.replace(staged, DATABASE)
                staged = None
                write(SERVICE, b'# Managed by LibreWard\n' + SERVICE_SOURCE.encode())
                write(RECOVERY, RECOVERY_SOURCE.encode())
                write(UNIT, service_unit(mode, provider).encode())
                write(RECOVERY_UNIT_PATH, RECOVERY_UNIT.encode())
                write(STATE, json.dumps(dict(state, phase='installing')).encode())
                systemctl('daemon-reload')
                allowed = allowed_example()
                if mode == 'resolved':
                    # Start and check the filter before resolved points to it.
                    write(CONF, None)
                    write(SETUP_CONF, None)
                    if touched_nm:
                        reload_dns()
                    systemctl('start', 'libreward-dns.service')
                    filter_health()
                    write(RESOLVED_CONF, RESOLVED_CONTENT)
                    reload_resolved()
                    resolved_health(allowed)
                else:
                    write(RESOLVED_CONF, None)
                    if touched_resolved:
                        reload_resolved()
                    write(CONF, PROXY_CONFIG)
                    write(SETUP_CONF, SETUP_CONTENT)
                    reload_dns()
                    wait_for_dns_port()
                    systemctl('start', 'libreward-dns.service')
                    query_health(count)
                    try:
                        probe(allowed, False)
                    except (OSError, RuntimeError) as exc:
                        raise RuntimeError('Websites could not be reached through the network’s DNS servers. '
                                           'Check the internet connection and try again.') from exc
                systemctl('enable', 'libreward-dns.service')
                write(STATE, json.dumps(dict(state, phase='enabled')).encode())
            else:
                write(CONF, None)
                write(SETUP_CONF, None)
                write(RESOLVED_CONF, None)
                if touched_nm:
                    reload_dns()
                if touched_resolved:
                    reload_resolved()
                if snapshot[UNIT] is not None:
                    systemctl('disable', 'libreward-dns.service')
                write(STATE, json.dumps({'active': False, 'count': 0, 'phase': 'paused'}).encode())
        except BaseException as original:
            try:
                # Release a new database before restoring small config files,
                # so rollback can still work if staging exhausted free space.
                if owned_small(UNIT) is not None:
                    systemctl('stop', 'libreward-dns.service', required=False)
                if backup is not None:
                    os.replace(backup, DATABASE)
                    backup = None
                elif count and snapshot[STATE] is None and os.path.exists(DATABASE):
                    os.unlink(DATABASE)
                for path, data in snapshot.items(): write(path, data)
                systemctl('daemon-reload')
                if touched_nm: reload_dns()
                if touched_resolved: reload_resolved()
                if was_enabled: systemctl('enable', 'libreward-dns.service')
                else: systemctl('disable', 'libreward-dns.service', required=False)
                if was_active: systemctl('start', 'libreward-dns.service')
            except Exception as rollback:
                raise RuntimeError('The filter could not be applied and DNS recovery needs attention. '
                                   'Original error: ' + str(original) + ' Recovery error: ' + str(rollback)) from rollback
            raise
        finally:
            for path in (staged, backup):
                if path is not None and os.path.exists(path): os.unlink(path)
        return {'count': actual, 'digest': digest, 'skipped': 0}

MANAGED_FILES = ('domains.sqlite3', 'dns-state.json', 'dns-service.py', 'dns-recovery.py',
                 '.dns-lock', '.public-dns-lock')
STAGING_PREFIXES = ('.domains-', '.previous-db-', '.libreward-dns-', '.dns-state-')


def uninstall():
    """Package removal: turn protection off, then remove LibreWard's system files."""
    if not os.path.isdir(ROOT):
        return
    owned_dns = any(owned_small(path) is not None for path in (CONF, SETUP_CONF, RESOLVED_CONF))
    unit_present = owned_small(UNIT) is not None
    if owned_dns or unit_present:
        # Same transaction as Pause: removes DNS routing and reloads the resolver.
        apply_database(io.BytesIO(b''), 0)
    if unit_present:
        systemctl('stop', 'libreward-dns.service', required=False)
        systemctl('disable', 'libreward-dns.service', required=False)
    for path in (UNIT, RECOVERY_UNIT_PATH):
        data = owned_small(path)
        if data is not None and data.lstrip().startswith(b'# Managed by LibreWard'):
            os.unlink(path)
    systemctl('daemon-reload', required=False)
    for name in os.listdir(ROOT):
        path = os.path.join(ROOT, name)
        if name in MANAGED_FILES or name.startswith(STAGING_PREFIXES):
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                os.unlink(path)
    try:
        os.rmdir(ROOT)
    except OSError:
        pass  # keeps anything LibreWard did not create


if __name__ == '__main__':
    try:
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(RuntimeError('DNS setup interrupted.')))
        header = sys.stdin.buffer.readline(4097)
        if len(header) > 4096: raise ValueError('Invalid DNS setup header.')
        request = json.loads(header)
        count = request.get('count')
        # Mode and provider are arguments, so the prepared domain file is sent unchanged.
        mode = sys.argv[1] if len(sys.argv) > 1 else 'networkmanager'
        provider = sys.argv[2] if len(sys.argv) > 2 else None
        if request.get('version') != 1 or type(count) is not int or not 0 <= count <= 5000000:
            raise ValueError('Invalid DNS setup request.')
        if mode not in ('networkmanager', 'resolved') or (mode == 'resolved') != (provider is not None):
            raise ValueError('Invalid DNS setup request.')
        if provider is not None and not UPSTREAMS.get(provider):
            raise ValueError('Unknown DNS service.')
        print(json.dumps(apply_database(sys.stdin.buffer, count, mode, provider)))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
'''
