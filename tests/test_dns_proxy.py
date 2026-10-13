"""Real DNS traffic on temporary loopback ports; never changes system DNS."""
import concurrent.futures
import shutil
import ssl
import subprocess
import socket
import sqlite3
from contextlib import closing
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.dns_proxy import Filter, Server, DomainIndex, question, receive_exact, TlsUpstream, PlainUpstream


def query(domain, kind=1, ident=1234):
    name = b''.join(bytes([len(part)]) + part.encode() for part in domain.split('.')) + b'\0'
    return struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', kind, 1)


def reply(packet):
    _, kind, cls, end = question(packet)
    address = socket.inet_aton('192.0.2.9') if kind == 1 else socket.inet_pton(socket.AF_INET6, '2001:db8::9')
    return packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + packet[12:end] + b'\xc0\x0c' + struct.pack('!HHIH', kind, cls, 60, len(address)) + address


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name, 'domains.sqlite3')
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE blocked(domain TEXT PRIMARY KEY) WITHOUT ROWID')
            db.executemany('INSERT INTO blocked VALUES (?)', [('blocked.example.org',), ('libreward-protection-check.invalid',)])

    def test_blocked_ipv4_ipv6_and_other_types_do_not_contact_upstream(self):
        filter_ = Filter(str(self.db))
        self.addCleanup(filter_.index.close)
        with patch('core.dns_proxy.socket.socket', side_effect=AssertionError('Blocked domain was forwarded')):
            for kind, size in ((1, 4), (28, 16)):
                answer = filter_.answer(query('Blocked.Example.Org', kind))
                self.assertEqual(answer[-size:], b'\0' * size)
                self.assertEqual(answer[6:8], b'\0\1')
            self.assertEqual(filter_.answer(query('blocked.example.org', 16))[6:8], b'\0\0')

    def test_invalid_questions_and_failed_upstream_return_errors(self):
        filter_ = Filter(str(self.db), upstream=('127.0.0.1', 1), timeout=0.05)
        self.addCleanup(filter_.index.close)
        for packet in (b'\0', query('x.org')[:13], query('x.org')[:12] + b'\xc0\x0c\0\1\0\1',
                       query('x.org') + b'x' * 4096):
            self.assertEqual(filter_.answer(packet)[3] & 15, 1)
        self.assertEqual(filter_.answer(query('allowed.example.org'))[3] & 15, 2)

    def test_membership_cache_is_bounded_and_exact(self):
        index = DomainIndex(str(self.db), cache_entries=4)
        self.addCleanup(index.close)
        self.assertTrue(index.blocked('blocked.example.org'))
        self.assertFalse(index.blocked('sub.blocked.example.org'))
        for number in range(100):
            self.assertFalse(index.blocked(f'{number}.example.org'))
        self.assertLessEqual(len(index.cache), 4)

    def test_udp_and_tcp_forwarding_with_persistent_client_connection(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(udp.getsockname())
        tcp.listen()
        self.addCleanup(udp.close)
        self.addCleanup(tcp.close)
        errors = []
        def udp_upstream():
            try:
                for _ in range(3):
                    packet, client = udp.recvfrom(4096)
                    udp.sendto(reply(packet), client)
            except Exception as exc: errors.append(exc)
        def tcp_upstream():
            try:
                for _ in range(2):
                    client, _ = tcp.accept()
                    with client:
                        packet = receive_exact(client, struct.unpack('!H', receive_exact(client, 2))[0])
                        answer = reply(packet)
                        client.sendall(struct.pack('!H', len(answer)) + answer)
            except Exception as exc: errors.append(exc)
        udp.settimeout(3)
        tcp.settimeout(3)
        upstream_threads = [threading.Thread(target=udp_upstream), threading.Thread(target=tcp_upstream)]
        for thread in upstream_threads: thread.start()
        server = Server(Filter(str(self.db), upstream=udp.getsockname()), address=('127.0.0.1', 0))
        thread = threading.Thread(target=server.serve)
        thread.start()
        try:
            def ask(number):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    client.sendto(query('allowed.example.org', ident=number), server.address)
                    return client.recv(4096)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                answers = list(pool.map(ask, range(3)))
            self.assertTrue(all(answer.endswith(socket.inet_aton('192.0.2.9')) for answer in answers))
            with socket.create_connection(server.address, timeout=3) as client:
                for kind in (1, 28):
                    packet = query('allowed.example.org', kind)
                    client.sendall(struct.pack('!H', len(packet)) + packet)
                    answer = receive_exact(client, struct.unpack('!H', receive_exact(client, 2))[0])
                    self.assertEqual(answer[3] & 15, 0)
                    self.assertEqual(answer[:2], packet[:2])
        finally:
            server.stop()
            thread.join(8)
            for upstream in upstream_threads: upstream.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_filter_waits_for_first_app_heartbeat_then_exits_without_it(self):
        from core.dns_proxy import HEARTBEAT
        filter_ = Filter(str(self.db), upstream=('127.0.0.1', 1), timeout=0.05)
        server = Server(filter_, address=('127.0.0.1', 0), idle_limit=0.3)
        thread = threading.Thread(target=server.serve)
        thread.start()
        try:
            # Before the app has started (boot, waiting for login) protection stays on.
            time.sleep(0.6)
            self.assertTrue(thread.is_alive())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(query(HEARTBEAT), server.address)
                self.assertEqual(client.recv(4096)[3] & 15, 0)
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertTrue(server.expired)
        finally:
            server.stop()
            thread.join(3)

    def test_failed_accept_does_not_stop_the_filter(self):
        original = socket.socket.accept
        failures = []
        def accept(sock):
            if not failures:
                failures.append(True)
                raise ConnectionAbortedError('aborted')
            return original(sock)
        server = Server(Filter(str(self.db)), address=('127.0.0.1', 0))
        with patch.object(socket.socket, 'accept', accept):
            thread = threading.Thread(target=server.serve)
            thread.start()
            try:
                with socket.create_connection(server.address, timeout=3) as client:
                    packet = query('blocked.example.org')
                    client.sendall(struct.pack('!H', len(packet)) + packet)
                    answer = receive_exact(client, struct.unpack('!H', receive_exact(client, 2))[0])
                self.assertEqual(answer[-4:], b'\0' * 4)
                self.assertTrue(failures)
                self.assertTrue(thread.is_alive())
            finally:
                server.stop()
                thread.join(3)

    def test_service_unit_restarts_crashes_but_not_missing_heartbeat(self):
        from backends.linux_dns_service import helper
        namespace = {'__name__': 'test_units'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager', '/usr/bin/systemctl', '/usr/bin/python3'), namespace)
        unit = namespace['SERVICE_UNIT']
        self.assertIn('Restart=on-failure\n', unit)
        self.assertIn('RestartPreventExitStatus=3\n', unit)
        self.assertLess(unit.index('StartLimitBurst'), unit.index('[Service]'))

    def test_stop_is_not_reported_as_expired(self):
        server = Server(Filter(str(self.db)), address=('127.0.0.1', 0), idle_limit=60)
        thread = threading.Thread(target=server.serve)
        thread.start()
        server.stop()
        thread.join(3)
        self.assertFalse(server.expired)

    def test_bad_upstream_transaction_is_not_relayed(self):
        filter_ = Filter(str(self.db))
        self.addCleanup(filter_.index.close)
        from unittest.mock import MagicMock
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = reply(query('different.example.org', ident=999))
        with patch('core.dns_proxy.socket.socket', return_value=sock):
            self.assertEqual(filter_.answer(query('allowed.example.org'))[3] & 15, 2)


@unittest.skipUnless(shutil.which('openssl'), 'openssl creates the temporary test certificate')
class TlsUpstreamTests(unittest.TestCase):
    """Real DNS-over-TLS on a loopback port with a temporary certificate authority."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        self.cert, self.key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=dns.test.example', '-addext', 'subjectAltName=DNS:dns.test.example',
                        '-keyout', str(self.key), '-out', str(self.cert)],
                       check=True, capture_output=True)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.addCleanup(self.listener.close)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.queries = []

    def serve(self, count, connections=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        def run():
            self.listener.settimeout(5)
            try:
                while len(self.queries) < count or (connections and self.connections < connections):
                    raw, _ = self.listener.accept()
                    self.connections += 1
                    try:
                        client = context.wrap_socket(raw, server_side=True)
                    except OSError:
                        raw.close()
                        continue
                    with client:
                        while len(self.queries) < count:
                            try:
                                size = struct.unpack('!H', receive_exact(client, 2))[0]
                            except OSError:
                                break
                            packet = receive_exact(client, size)
                            self.queries.append(packet)
                            answer = reply(packet)
                            client.sendall(struct.pack('!H', len(answer)) + answer)
            except OSError:
                pass
        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(thread.join, 5)

    def client_context(self):
        context = ssl.create_default_context(cafile=str(self.cert))
        return context

    def test_queries_are_encrypted_verified_and_reuse_one_connection(self):
        self.serve(3)
        upstream = TlsUpstream([('127.0.0.1', 'dns.test.example')], port=self.port, context=self.client_context())
        self.addCleanup(upstream.close)
        for number in range(3):
            answer = upstream.exchange(query('allowed.example.org', ident=number), tcp=False)
            self.assertTrue(answer.endswith(socket.inet_aton('192.0.2.9')))
        self.assertEqual(len(self.queries), 3)
        self.assertEqual(self.connections, 1)

    def test_closed_pooled_connection_is_replaced_without_falling_back(self):
        self.serve(2)
        upstream = TlsUpstream([('127.0.0.1', 'dns.test.example')], port=self.port, context=self.client_context())
        self.addCleanup(upstream.close)
        upstream.exchange(query('allowed.example.org', ident=1), tcp=False)
        # Simulate the server closing the idle connection.
        connection, used = upstream.idle.get_nowait()
        connection.close()
        upstream.idle.put((connection, used))
        answer = upstream.exchange(query('allowed.example.org', ident=2), tcp=False)
        self.assertEqual(answer[:2], struct.pack('!H', 2))
        self.assertEqual(upstream.plain_until, 0)

    def test_wrong_certificate_name_falls_back_to_plain_dns_of_the_same_service(self):
        self.serve(0, connections=1)
        plain = PlainUpstream(('127.0.0.1', 1))
        with patch.object(plain, 'exchange', return_value=b'plain answer') as fallback:
            upstream = TlsUpstream([('127.0.0.1', 'other.example')], port=self.port,
                                   context=self.client_context(), plain=plain)
            self.assertEqual(upstream.exchange(query('allowed.example.org'), tcp=False), b'plain answer')
            # TLS is not retried on every query while it is unreachable.
            upstream.exchange(query('allowed.example.org'), tcp=False)
            self.assertEqual(fallback.call_count, 2)
            self.assertGreater(upstream.plain_until, 0)
            self.assertEqual(self.connections, 1)

    def test_large_answers_make_udp_clients_retry_over_tcp(self):
        class Large:
            def exchange(self, packet, tcp):
                return reply(packet) + b'\0' * 2000
        with closing(sqlite3.connect(Path(self.temp.name, 'db.sqlite3'))) as db, db:
            db.execute('CREATE TABLE blocked(domain TEXT PRIMARY KEY) WITHOUT ROWID')
        filter_ = Filter(str(Path(self.temp.name, 'db.sqlite3')), upstream=Large())
        self.addCleanup(filter_.index.close)
        packet = query('allowed.example.org')
        udp = filter_.answer(packet)
        self.assertTrue(udp[2] & 0x02)  # TC bit
        self.assertEqual(udp[6:8], b'\0\0')
        self.assertGreater(len(filter_.answer(packet, tcp=True)), 2000)
