"""Local ClamD protocol client and ownership-aware daemon lifecycle.

One request per connection allows parallel work. Owned daemons open local paths;
existing daemons receive streams independently of their filesystem permissions.
"""
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from core.scan_policy import scan_limits


class ScanCancelled(Exception):
    pass


class FileScanWarning(OSError):
    """A file changed or was inaccessible, while the daemon remains usable."""


def connect(endpoint, timeout=1):
    kind, address = endpoint
    if kind == 'tcp':
        return socket.create_connection(address, timeout)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(address)
        return connection
    except BaseException:
        connection.close()
        raise


def response(connection, stopped=lambda: False, timeout=300):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while b'\0' not in data:
        if stopped():
            raise ScanCancelled()
        if time.monotonic() >= deadline:
            raise TimeoutError('ClamD response timed out')
        try:
            chunk = connection.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise OSError('ClamD closed the connection without a result')
        data.extend(chunk)
        if len(data) > 65536:
            raise OSError('Invalid ClamD response')
    return data.split(b'\0', 1)[0].decode('utf-8', errors='replace')


def ping(endpoint):
    try:
        with connect(endpoint, .2) as connection:
            connection.sendall(b'zPING\0')
            return response(connection, timeout=.5) == 'PONG'
    except OSError:
        return False


def scan_file(endpoint, path, stopped, *, direct=False):
    if stopped():
        raise ScanCancelled()
    if direct:
        # Only our own daemon has the same user and filesystem view. Avoid
        # copying large local files through INSTREAM (and its size limit).
        with connect(endpoint) as connection:
            connection.sendall(b'zSCAN ' + str(Path(path).absolute()).encode('utf-8') + b'\0')
            result = response(connection, stopped)
        _, separator, status = result.rpartition(': ')
        if separator and (status == 'OK' or status.endswith(' FOUND')):
            return status
        if separator and status.endswith(' ERROR') and any(
            text in status.lower() for text in (
                'permission denied', 'access denied', 'no such file',
                "can't open file", "can't get file status", 'lstat() failed',
            )
        ):
            raise FileScanWarning(status)
        raise OSError(result)
    with connect(endpoint) as connection, open(path, 'rb') as source:
        connection.sendall(b'zINSTREAM\0')
        while True:
            if stopped():
                raise ScanCancelled()
            chunk = source.read(64 * 1024)
            if not chunk:
                break
            connection.sendall(struct.pack('!I', len(chunk)) + chunk)
        connection.sendall(b'\0\0\0\0')
        result = response(connection, stopped)
    if result == 'stream: OK':
        return 'OK'
    if result.startswith('stream: ') and result.endswith(' FOUND'):
        return result[len('stream: '):]
    raise OSError(result)


class ClamdSession:
    """Reuse a responding daemon; only stop a process started by this object."""
    def __init__(self, backend, scan_profile='standard'):
        self.backend = backend
        self.limits = scan_limits(scan_profile)
        self.process = None
        self.directory = None
        self.log = None
        self.endpoint = None
        self.reused = False

    def acquire(self, clamscan, database, stopped):
        for endpoint in self.backend.clamd_endpoints():
            if stopped():
                raise ScanCancelled()
            if ping(endpoint):
                self.endpoint, self.reused = endpoint, True
                return endpoint
        executable = self.backend.find_clamd(clamscan)
        if not executable:
            raise OSError('clamd is not installed')
        if database is None:
            raise OSError('No readable virus database found for clamd')
        self.directory = tempfile.TemporaryDirectory(prefix='libreward-clamd-')
        work = Path(self.directory.name)
        self.endpoint, listener = self.backend.clamd_listen_config(work)
        config = work / 'clamd.conf'
        lines = ['Foreground yes', f'DatabaseDirectory "{database}"',
                 f'MaxThreads {self.limits.workers}', 'MaxQueue 16', 'StreamMaxLength 2048M',
                 f'MaxFileSize {self.limits.file_size}', f'MaxScanSize {self.limits.scan_size}',
                 'ScanArchive yes', 'AlertEncrypted yes', 'AlertExceedsMax yes', *listener]
        config.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        self.log = (work / 'startup.log').open('wb')
        self.process = self.backend.start_process(
            [executable, '--config-file', str(config)],
            stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if stopped():
                raise ScanCancelled()
            if self.process.poll() is not None:
                raise OSError('clamd could not start; using standard scanning')
            if ping(self.endpoint):
                return self.endpoint
            # Interruptible wait keeps Stop responsive during database loading.
            time.sleep(.1)
        raise TimeoutError('clamd startup timed out')

    def close(self):
        try:
            if self.process is not None and self.process.poll() is None:
                self.backend.stop_process(self.process)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            if self.log is not None:
                self.log.close()
            if self.directory is not None:
                self.directory.cleanup()
