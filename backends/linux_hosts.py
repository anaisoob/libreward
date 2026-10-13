"""Standalone fixed-target privileged helper, also testable against temporary files.

Only HOSTS_HELPER is executed with privileges. No app modules are imported there.
"""
HOSTS_HELPER = r'''
import fcntl, hashlib, json, os, re, socket, stat, sys, tempfile

BEGIN = b'# BEGIN LIBREWARD DOMAIN PROTECTION\n'
END = b'# END LIBREWARD DOMAIN PROTECTION\n'

def split_hosts(data):
    if BEGIN not in data and END not in data:
        return data, b''
    if data.count(BEGIN) != 1 or data.count(END) != 1:
        raise ValueError('LibreWard hosts section is damaged. Restore it before making changes.')
    before, rest = data.split(BEGIN)
    body, after = rest.split(END)
    if b'# separator-added=yes\n' in body and before.endswith(b'\n'):
        expected = b'# prefix-sha256=' + hashlib.sha256(before[:-1]).hexdigest().encode('ascii') + b'\n'
        if expected in body:
            before = before[:-1]
    return before + after, body

def replace_hosts(path, domains):
    if not isinstance(domains, list) or len(domains) > 5000000:
        raise ValueError('Invalid domain list.')
    valid = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
    for value in domains:
        if (not isinstance(value, str) or len(value) > 253 or '.' not in value
                or not all(valid.fullmatch(part) for part in value.split('.'))
                or value == 'localhost.localdomain' or value.endswith(('.localhost', '.local', '.arpa'))
                or re.fullmatch(r'[0-9.]+', value)):
            raise ValueError('Invalid domain list.')
    directory = os.path.dirname(path)
    lock = os.open(path + '.libreward-lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError('Unsafe hosts lock file.')
        fcntl.flock(lock, fcntl.LOCK_EX)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as original:
            info = os.fstat(original.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise ValueError('The hosts file must be a regular system-owned file.')
            data = original.read(512 * 1024 * 1024 + 1)
        if len(data) > 512 * 1024 * 1024:
            raise ValueError('The hosts file is too large.')
        clean, old = split_hosts(data)
        existing = {value.decode('ascii', errors='ignore').lower() for line in clean.splitlines()
                    for value in line.split(b'#', 1)[0].split()[1:]}
        existing.add(socket.gethostname().lower())
        selected = sorted(set(domains) - existing)
        output = clean
        if selected:
            separator = bool(clean and not clean.endswith(b'\n'))
            output += (b'\n' if separator else b'') + BEGIN
            output += b'# separator-added=' + (b'yes' if separator else b'no') + b'\n'
            output += b'# prefix-sha256=' + hashlib.sha256(clean).hexdigest().encode('ascii') + b'\n'
            output += b'# Exact domains only. Managed by LibreWard; keep other hosts entries outside this section.\n'
            output += b''.join(b'0.0.0.0 ' + value.encode('ascii') + b'\n:: ' + value.encode('ascii') + b'\n'
                               for value in selected)
            output += END
        if output == data:
            return {'count': len(selected), 'skipped': len(set(domains) & existing)}
        if not old:
            try:
                backup_fd = os.open(path + '.libreward-backup', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                backup_fd = None
            if backup_fd is not None:
                with os.fdopen(backup_fd, 'wb') as backup:
                    backup.write(data)
                    backup.flush()
                    os.fsync(backup.fileno())
        temp_fd, name = tempfile.mkstemp(prefix='.libreward-hosts-', dir=directory)
        try:
            with os.fdopen(temp_fd, 'wb') as stream:
                stream.write(output)
                os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                for attribute in os.listxattr(path, follow_symlinks=False):
                    os.setxattr(name, attribute, os.getxattr(path, attribute, follow_symlinks=False))
                stream.flush()
                os.fsync(stream.fileno())
            current = os.lstat(path)
            if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size) != (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size):
                raise ValueError('The hosts file changed during setup. Check status and try again.')
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return {'count': len(selected), 'skipped': len(set(domains) & existing)}
    finally:
        os.close(lock)

if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(256 * 1024 * 1024 + 1)
        if len(raw) > 256 * 1024 * 1024:
            raise ValueError('Domain list is too large.')
        print(json.dumps(replace_hosts('/etc/hosts', json.loads(raw))))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
'''


def inspect_hosts(path):
    """Inspect generated records in constant space, even for old huge lists."""
    import hashlib
    from core.internet import normalize_domain
    digest = hashlib.sha256()
    inside = False
    seen = False
    ended = False
    previous = None
    pending = None
    count = 0
    total = 0
    with open(path, 'rb') as stream:
        while True:
            line = stream.readline(65537)
            if not line:
                break
            total += len(line)
            if len(line) > 65536 or total > 512 * 1024 * 1024:
                raise ValueError('The domain protection file is too large or has invalid lines.')
            if line == b'# BEGIN LIBREWARD DOMAIN PROTECTION\n':
                if seen:
                    raise ValueError('LibreWard hosts section is damaged.')
                inside = seen = True
                continue
            if line == b'# END LIBREWARD DOMAIN PROTECTION\n':
                if not inside or pending is not None:
                    raise ValueError('LibreWard hosts section is damaged.')
                inside, ended = False, True
                continue
            if not inside or line.startswith(b'#'):
                continue
            parts = line.split()
            if len(parts) != 2:
                raise ValueError('The domain protection section was changed outside LibreWard.')
            address, raw = parts
            value = raw.decode('ascii')
            if address == b'0.0.0.0' and pending is None:
                if normalize_domain(value) != value or (previous is not None and value <= previous):
                    raise ValueError('The domain protection section was changed outside LibreWard.')
                pending = value
            elif address == b'::' and value == pending:
                if count:
                    digest.update(b'\n')
                digest.update(raw)
                count += 1
                previous, pending = value, None
            else:
                raise ValueError('The domain protection section was changed outside LibreWard.')
    if inside or seen != ended:
        raise ValueError('LibreWard hosts section is damaged.')
    return {'supported': True, 'active': bool(count), 'count': count,
            'digest': digest.hexdigest(),
            'message': 'Exact-domain blocking uses the system hosts file. Applications with their own DNS can bypass it.'}
