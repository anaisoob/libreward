"""System quarantine: files only an administrator may move, kept where only root reads.

pkexec runs this program. It trusts nothing in the request and nothing in folders
that other accounts can write to, where a program could swap a folder for a link
while root works:

- a path is opened folder by folder without following links, and every step
  afterwards uses the open folder;
- a file is touched only if clamscan detects it right now, on the file that is
  open, so this program cannot be asked to remove an arbitrary file;
- it is removed only if it is still the file that was read.

Standard library only: run from source, pkexec starts a trusted python3 -I with this
source after that of linux_root_scan, so root imports nothing a user can change.

One line of JSON on stdin, one on stdout, with a result for each item:
{"action": "move", "items": [[path, threat], ...], "database": folder or null,
 "discard": false}, {"action": "restore", "names": [...]} or
{"action": "delete", "names": [...]}.
"""
import datetime
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys

if __name__ != '__main__':  # otherwise the same source was started just before this
    from .linux_root_scan import MAX_REQUEST, trusted_clamscan, valid_path

# Encoded quarantine files start with this header; shared with core/quarantine.py.
HEADER = b"LibreWard quarantine 1\n"
KEY = b"LibreWard keeps this file from running or opening."
CHUNK = 1024 * 1024
STORE = '/var/lib/libreward/quarantine'
NAME = re.compile(r'[0-9a-f]{32}\Z')
FOLDER_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refused(Exception):
    """A reason for the user, for this item only."""


def xor(data: bytes, offset: int) -> bytes:
    """XOR with KEY, continuing at `offset` bytes into the payload."""
    key = KEY[offset % len(KEY):] + KEY[:offset % len(KEY)]
    repeated = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(repeated, "big")).to_bytes(len(data), "big")


def open_store(store=STORE):
    """The folder of the quarantine: root's alone, or nothing is done."""
    os.makedirs(os.path.dirname(store), mode=0o755, exist_ok=True)
    try:
        os.mkdir(store, 0o700)
    except FileExistsError:
        pass
    folder = os.open(store, FOLDER_FLAGS)
    status = os.fstat(folder)
    if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & 0o077:
        os.close(folder)
        raise Refused('The system quarantine folder has unsafe permissions.')
    return folder


def open_parent(path):
    """(open folder, file name) of `path`, without following a link on the way."""
    if not valid_path(path):
        raise Refused('Invalid location.')
    parts = path.strip('/').split('/')
    folder = os.open('/', FOLDER_FLAGS)
    try:
        for part in parts[:-1]:
            following = os.open(part, FOLDER_FLAGS, dir_fd=folder)
            os.close(folder)
            folder = following
    except OSError as exc:
        os.close(folder)
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Refused('The location goes through a link.') from exc
        raise
    return folder, parts[-1]


def identity(status):
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def still_detected(clamscan, descriptor, database):
    """clamscan's verdict on the open file: it gets the contents, not a path to swap."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = subprocess.run([clamscan, '--no-summary', *([f'--database={database}'] if database else []), '-'],
                            stdin=descriptor, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, check=False)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return result.returncode == 1


def take_away(folder, name, read):
    """Remove the name only if it is still the file that was read."""
    held = f'.libreward-quarantine-{secrets.token_hex(8)}'
    os.rename(name, held, src_dir_fd=folder, dst_dir_fd=folder)
    try:
        if identity(os.stat(held, dir_fd=folder, follow_symlinks=False)) != read:
            raise Refused('The file changed, so it was left in place.')
        os.unlink(held, dir_fd=folder)
    except (OSError, Refused):
        try:
            os.link(held, name, src_dir_fd=folder, dst_dir_fd=folder, follow_symlinks=False)
            os.unlink(held, dir_fd=folder)
        except FileExistsError:
            raise Refused(f'A new file took its place; the old one is kept as {held}.') from None
        raise


def store_encoded(store, name, source):
    digest = hashlib.sha256()
    offset = 0
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=store)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(HEADER)
        while chunk := os.read(source, CHUNK):
            digest.update(chunk)
            target.write(xor(chunk, offset))
            offset += len(chunk)
        target.flush()
        os.fsync(target.fileno())
    return digest.hexdigest()


def write_metadata(store, name, metadata):
    descriptor = os.open(name + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=store)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(metadata, stream)


def remove_entry(store, name):
    for entry in (name, name + '.json'):
        try:
            os.unlink(entry, dir_fd=store)
        except FileNotFoundError:
            pass


def move(store, clamscan, path, threat, database, discard):
    """Metadata of the stored file, or None when it was only removed."""
    folder, file_name = open_parent(path)
    try:
        try:
            source = os.open(file_name, FILE_FLAGS, dir_fd=folder)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise Refused('This is a link, not a file.') from exc
            raise
        try:
            status = os.fstat(source)
            if not stat.S_ISREG(status.st_mode):
                raise Refused('This is not a regular file.')
            if status.st_nlink != 1:
                raise Refused('This file has several names; remove it by hand.')
            if not still_detected(clamscan, source, database):
                raise Refused('The file is no longer detected, so it was left in place.')
            if discard:
                take_away(folder, file_name, identity(status))
                return None
            name = secrets.token_hex(16)
            metadata = {'schema_version': 1, 'original_path': path, 'original_mode': stat.S_IMODE(status.st_mode),
                        'original_uid': status.st_uid, 'original_gid': status.st_gid, 'threat_name': threat,
                        'quarantined_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'original_size': status.st_size, 'quarantine_name': name, 'system': True}
            try:
                metadata['sha256'] = store_encoded(store, name, source)
                if identity(os.fstat(source)) != identity(status):
                    raise Refused('The file changed while it was being copied.')
                write_metadata(store, name, metadata)
                take_away(folder, file_name, identity(status))
            except (OSError, Refused):
                remove_entry(store, name)
                raise
            return metadata
        finally:
            os.close(source)
    finally:
        os.close(folder)


def decoded_into(store, name, target, expected):
    digest = hashlib.sha256()
    offset = 0
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=store)
    with os.fdopen(descriptor, 'rb') as source:
        if source.read(len(HEADER)) != HEADER:
            raise Refused('The quarantined copy is damaged.')
        while chunk := source.read(CHUNK):
            data = xor(chunk, offset)
            digest.update(data)
            os.write(target, data)
            offset += len(chunk)
    if digest.hexdigest() != expected:
        raise Refused('The quarantined copy is damaged.')


def read_metadata(store, name):
    if not isinstance(name, str) or not NAME.match(name):
        raise Refused('Invalid quarantine name.')
    try:
        descriptor = os.open(name + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=store)
    except FileNotFoundError:
        raise Refused('This file is no longer in the system quarantine.') from None
    with os.fdopen(descriptor, encoding='utf-8') as stream:
        return json.load(stream)


def restore(store, name):
    metadata = read_metadata(store, name)
    folder, file_name = open_parent(metadata['original_path'])
    temporary = f'.libreward-restore-{secrets.token_hex(8)}'
    try:
        target = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=folder)
        try:
            decoded_into(store, name, target, metadata['sha256'])
            os.fchown(target, metadata['original_uid'], metadata['original_gid'])
            os.fchmod(target, metadata['original_mode'] & 0o777)  # no special privilege bits
            os.fsync(target)
        finally:
            os.close(target)
        try:
            os.link(temporary, file_name, src_dir_fd=folder, dst_dir_fd=folder, follow_symlinks=False)
        except FileExistsError:
            raise Refused('Original file already exists.') from None
    finally:
        try:
            os.unlink(temporary, dir_fd=folder)
        except FileNotFoundError:
            pass
        os.close(folder)
    remove_entry(store, name)


def delete(store, name):
    read_metadata(store, name)
    remove_entry(store, name)


def attempt(work):
    try:
        return {'ok': True, 'metadata': work()}
    except Refused as exc:
        return {'ok': False, 'error': str(exc)}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {'ok': False, 'error': str(exc)}


def answer(request, store):
    if not isinstance(request, dict):
        raise ValueError('Invalid request.')
    action = request.get('action')
    if action == 'move':
        items, database, discard = request.get('items'), request.get('database'), request.get('discard')
        if (not isinstance(items, list) or not isinstance(discard, bool)
                or not all(isinstance(item, list) and len(item) == 2 and all(isinstance(part, str) for part in item)
                           for item in items)):
            raise ValueError('Invalid request.')
        if database is not None and not (valid_path(database) and os.path.isdir(database)):
            raise ValueError('Invalid database folder.')
        clamscan = trusted_clamscan()
        if clamscan is None:
            raise ValueError('clamscan was not found in a system folder.')
        return [attempt(lambda path=path, threat=threat: move(store, clamscan, path, threat, database, discard))
                for path, threat in items]
    if action in ('restore', 'delete'):
        names = request.get('names')
        if not isinstance(names, list):
            raise ValueError('Invalid request.')
        work = restore if action == 'restore' else delete
        return [attempt(lambda name=name: work(store, name)) for name in names]
    raise ValueError('Invalid request.')


def quarantine_main():
    try:
        if os.geteuid() != 0:
            raise PermissionError('This LibreWard program runs as root through pkexec.')
        line = sys.stdin.readline(MAX_REQUEST + 1)
        if len(line) > MAX_REQUEST:
            raise ValueError('The list is too long.')
        store = open_store()
        print(json.dumps({'results': answer(json.loads(line), store)}), flush=True)
        return 0
    except (OSError, ValueError, Refused) as exc:
        print(json.dumps({'error': str(exc)}), flush=True)
        return 2
