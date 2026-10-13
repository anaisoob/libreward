"""Standalone local DNS filter. Shared source is installed by the Linux backend.

Only exact-domain membership is cached. Allowed queries go either to the
existing NetworkManager resolver (VPN forwarding and network changes stay there)
or, behind systemd-resolved, to the selected public DNS service over TLS.
"""
SERVICE_SOURCE = r'''
import argparse
import collections
import concurrent.futures
import selectors
import signal
import queue
import socket
import sqlite3
import ssl
import struct
import threading
import time

SENTINEL = 'libreward-protection-check.invalid'
# The open LibreWard window sends this name periodically. After the first one,
# a missing heartbeat (app crashed, user logged out) makes the service exit as
# failed, and its OnFailure unit restores normal DNS. Before it, e.g. at boot
# while waiting for login and autostart, protection stays as it was.
HEARTBEAT = 'libreward-app-open.invalid'
MAX_QUERY = 4096
# Larger answers make UDP clients retry over TCP (EDNS default buffer size).
MAX_UDP_REPLY = 1232

def question(packet):
    if len(packet) < 12:
        raise ValueError('Short DNS packet')
    ident, flags, count, _, _, _ = struct.unpack('!6H', packet[:12])
    if flags & 0xF800 or count != 1:
        raise ValueError('Unsupported DNS query')
    offset, labels, length = 12, [], 0
    # Ordinary DNS questions are uncompressed. Reject pointers rather than
    # following attacker-controlled cycles or copying unrelated packet bytes.
    while True:
        if offset >= len(packet):
            raise ValueError('Incomplete DNS name')
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            raise ValueError('Invalid DNS label')
        raw = packet[offset:offset + size]
        labels.append(raw.decode('ascii').lower())
        length += size + 1
        if length > 254:
            raise ValueError('DNS name too long')
        offset += size
    if offset + 4 > len(packet):
        raise ValueError('Incomplete DNS question')
    kind, cls = struct.unpack('!HH', packet[offset:offset + 4])
    return '.'.join(labels), kind, cls, offset + 4

def error_response(packet, code=2):
    ident = packet[:2].ljust(2, b'\0')
    flags = (int.from_bytes(packet[2:4], 'big') & 0x0100) | 0x8080 | code
    try:
        _, _, _, end = question(packet)
        return ident + struct.pack('!5H', flags, 1, 0, 0, 0) + packet[12:end]
    except (ValueError, UnicodeError):
        return ident + struct.pack('!5H', flags, 0, 0, 0, 0)

def blocked_response(packet, kind, cls, end):
    # Clear DNSSEC AD/CD and EDNS options for synthetic answers. A/AAAA return
    # null addresses; other record types get an empty successful answer.
    data = b'\0' * (4 if kind == 1 else 16) if cls == 1 and kind in (1, 28) else None
    flags = 0x8080 | (int.from_bytes(packet[2:4], 'big') & 0x0100)
    result = packet[:2] + struct.pack('!5H', flags, 1, int(data is not None), 0, 0) + packet[12:end]
    if data is not None:
        result += b'\xc0\x0c' + struct.pack('!HHIH', kind, cls, 30, len(data)) + data
    return result

def receive_exact(sock, size, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + 3
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('DNS exchange timed out')
        sock.settimeout(remaining)
        part = sock.recv(size - len(result))
        if not part:
            raise OSError('Connection ended')
        result.extend(part)
    return bytes(result)

class DomainIndex:
    def __init__(self, path, cache_entries=2048):
        self.connection = sqlite3.connect('file:' + path + '?mode=ro&immutable=1', uri=True, check_same_thread=False)
        self.connection.execute('PRAGMA cache_size=-2048')
        self.connection.execute('PRAGMA mmap_size=0')
        self.connection.execute('PRAGMA trusted_schema=OFF')
        self.connection.execute('SELECT domain FROM blocked LIMIT 1').fetchone()
        self.cache = collections.OrderedDict()
        self.cache_entries = cache_entries
        self.lock = threading.Lock()

    def blocked(self, domain):
        with self.lock:
            if domain in self.cache:
                self.cache.move_to_end(domain)
                return self.cache[domain]
            result = self.connection.execute('SELECT 1 FROM blocked WHERE domain=?', (domain,)).fetchone() is not None
            self.cache[domain] = result
            if len(self.cache) > self.cache_entries:
                self.cache.popitem(last=False)
            return result

    def close(self):
        self.connection.close()

def truncated_response(packet, end):
    flags = 0x8280 | (int.from_bytes(packet[2:4], 'big') & 0x0100)
    return packet[:2] + struct.pack('!5H', flags, 1, 0, 0, 0) + packet[12:end]

class PlainUpstream:
    """Forward over the client's transport, e.g. to NetworkManager's dnsmasq."""
    def __init__(self, address, timeout=3):
        self.addresses = [address] if isinstance(address, tuple) else list(address)
        self.timeout = timeout

    def exchange(self, packet, tcp):
        error = OSError('No upstream DNS server')
        for address in self.addresses:
            try:
                return self._exchange(address, packet, tcp)
            except OSError as exc:
                error = exc
        raise error

    def _exchange(self, address, packet, tcp):
        family = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, family) as upstream:
            upstream.settimeout(self.timeout)
            upstream.connect(address)
            if tcp:
                upstream.sendall(struct.pack('!H', len(packet)) + packet)
                deadline = time.monotonic() + self.timeout
                length = struct.unpack('!H', receive_exact(upstream, 2, deadline))[0]
                return receive_exact(upstream, length, deadline)
            upstream.send(packet)
            return upstream.recv(65535)

class TlsUpstream:
    """DNS-over-TLS with certificate checks and reused connections.

    Opportunistic like systemd-resolved: if TLS is unreachable (port 853 blocked),
    the same service is used over plain DNS for a minute before TLS is retried.
    """
    def __init__(self, servers, timeout=3, pool=4, context=None, port=853, plain=None):
        self.servers = list(servers)  # [(address, certificate name)]
        self.timeout = timeout
        self.pool = pool
        self.port = port
        self.idle = queue.LifoQueue()
        self.context = context or ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.plain = plain or PlainUpstream([(address, 53) for address, _ in self.servers], timeout)
        self.plain_until = 0

    def _connect(self):
        error = OSError('No DNS-over-TLS server')
        for address, name in self.servers:
            raw = None
            try:
                raw = socket.create_connection((address, self.port), timeout=self.timeout)
                return self.context.wrap_socket(raw, server_hostname=name)
            except (OSError, ssl.SSLError) as exc:
                if raw is not None:
                    raw.close()
                error = exc
        raise error

    def _take(self):
        while True:
            try:
                connection, used = self.idle.get_nowait()
            except queue.Empty:
                return None
            if time.monotonic() - used < 15:
                return connection
            connection.close()

    def _give(self, connection):
        if self.idle.qsize() < self.pool:
            self.idle.put((connection, time.monotonic()))
        else:
            connection.close()

    def exchange(self, packet, tcp):
        if time.monotonic() >= self.plain_until:
            connection = self._take()
            # A pooled connection may have been closed by the server: retry once with a
            # fresh one. A failed fresh connection means TLS is unreachable right now.
            while True:
                pooled = connection is not None
                try:
                    if connection is None:
                        connection = self._connect()
                    deadline = time.monotonic() + self.timeout
                    connection.settimeout(self.timeout)
                    connection.sendall(struct.pack('!H', len(packet)) + packet)
                    length = struct.unpack('!H', receive_exact(connection, 2, deadline))[0]
                    reply = receive_exact(connection, length, deadline)
                    self._give(connection)
                    return reply
                except (OSError, ssl.SSLError, struct.error):
                    if connection is not None:
                        connection.close()
                    connection = None
                    if not pooled:
                        break
            self.plain_until = time.monotonic() + 60
        return self.plain.exchange(packet, tcp)

    def close(self):
        while True:
            try:
                self.idle.get_nowait()[0].close()
            except queue.Empty:
                return

class Filter:
    def __init__(self, database, upstream=('127.0.0.1', 5354), timeout=3):
        self.index = DomainIndex(database)
        self.upstream = upstream if hasattr(upstream, 'exchange') else PlainUpstream(upstream, timeout)
        self.timeout = timeout
        self.last_heartbeat = None

    def answer(self, packet, tcp=False):
        if len(packet) > MAX_QUERY:
            return error_response(packet, 1)
        try:
            domain, kind, cls, end = question(packet)
        except (ValueError, UnicodeError):
            return error_response(packet, 1)
        if domain == HEARTBEAT:
            self.last_heartbeat = time.monotonic()
            return blocked_response(packet, kind, cls, end)
        try:
            if self.index.blocked(domain):
                return blocked_response(packet, kind, cls, end)
            reply = self.upstream.exchange(packet, tcp)
            if len(reply) < 12 or reply[:2] != packet[:2] or not reply[2] & 0x80:
                raise ValueError('Invalid upstream DNS response')
            # Response questions use the same parser after clearing QR/RCODE.
            check = reply[:2] + b'\x01\x00' + reply[4:]
            name, rkind, rcls, _ = question(check)
            if (name, rkind, rcls) != (domain, kind, cls):
                raise ValueError('Unmatched upstream response')
            if not tcp and len(reply) > MAX_UDP_REPLY:
                return truncated_response(packet, end)
            return reply
        except (OSError, ValueError, UnicodeError, sqlite3.Error):
            return error_response(packet, 2)

class Server:
    def __init__(self, filter_, address=('127.0.0.1', 53), workers=8, pending=64, idle_limit=0):
        self.filter = filter_
        self.idle_limit = idle_limit
        self.expired = False
        self.stop_event = threading.Event()
        self.slots = threading.BoundedSemaphore(pending)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        self.selector = selectors.DefaultSelector()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.udp.bind(address)
            self.address = self.udp.getsockname()
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp.bind(self.address)
            self.tcp.listen(32)
            self.udp.setblocking(False)
            self.tcp.setblocking(False)
            self.selector.register(self.udp, selectors.EVENT_READ, 'udp')
            self.selector.register(self.tcp, selectors.EVENT_READ, 'tcp')
        except BaseException:
            self.udp.close()
            self.tcp.close()
            self.selector.close()
            self.executor.shutdown(wait=False, cancel_futures=True)
            self.filter.index.close()
            raise

    def _udp(self, packet, client):
        try:
            reply = self.filter.answer(packet)
            self.udp.sendto(reply, client)
        except OSError:
            pass
        finally:
            self.slots.release()

    def _tcp(self, client):
        try:
            with client:
                client.settimeout(3)
                deadline = time.monotonic() + 10
                for _ in range(16):
                    if self.stop_event.is_set() or time.monotonic() >= deadline:
                        break
                    query_deadline = min(deadline, time.monotonic() + 3)
                    size = struct.unpack('!H', receive_exact(client, 2, query_deadline))[0]
                    if size > MAX_QUERY:
                        return
                    reply = self.filter.answer(receive_exact(client, size, query_deadline), tcp=True)
                    client.sendall(struct.pack('!H', len(reply)) + reply)
        except (OSError, ValueError):
            pass
        finally:
            self.slots.release()

    def serve(self):
        try:
            while not self.stop_event.is_set():
                seen = self.filter.last_heartbeat
                if self.idle_limit and seen is not None and time.monotonic() - seen > self.idle_limit:
                    self.expired = True
                    break
                for key, _ in self.selector.select(timeout=0.2):
                    # One failed receive/accept (aborted connection, descriptor
                    # limit, spurious wakeup) must not stop DNS for everyone.
                    try:
                        self._dispatch(key.data)
                    except OSError:
                        time.sleep(0.01)
        finally:
            self.executor.shutdown(wait=True, cancel_futures=True)
            self.selector.close()
            self.udp.close()
            self.tcp.close()
            self.filter.index.close()

    def _dispatch(self, kind):
        if kind == 'udp':
            packet, client = self.udp.recvfrom(MAX_QUERY + 1)
            if self.slots.acquire(blocking=False):
                self.executor.submit(self._udp, packet, client)
            else:
                self.udp.sendto(error_response(packet), client)
        else:
            client, _ = self.tcp.accept()
            if self.slots.acquire(blocking=False):
                self.executor.submit(self._tcp, client)
            else:
                client.close()

    def stop(self):
        self.stop_event.set()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', required=True)
    parser.add_argument('--idle-limit', type=float, default=0)
    parser.add_argument('--listen-port', type=int, default=53)
    # Behind systemd-resolved: ADDRESS#CERTIFICATE-NAME entries of the selected service.
    parser.add_argument('--tls-upstream', action='append', default=[])
    args = parser.parse_args()
    upstream = ('127.0.0.1', 5354)
    if args.tls_upstream:
        upstream = TlsUpstream([tuple(entry.split('#', 1)) for entry in args.tls_upstream])
    server = Server(Filter(args.database, upstream=upstream), address=('127.0.0.1', args.listen_port),
                    idle_limit=args.idle_limit)
    signal.signal(signal.SIGTERM, lambda *_: server.stop())
    signal.signal(signal.SIGINT, lambda *_: server.stop())
    server.serve()
    raise SystemExit(3 if server.expired else 0)
'''
exec(SERVICE_SOURCE)
