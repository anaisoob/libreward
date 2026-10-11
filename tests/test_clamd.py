"""Exercise real socket framing, parallel work, cancellation and ownership."""
import socketserver
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from core.clamd import ClamdSession, ScanCancelled, scan_file
from core.scan_service import ScanService


class Handler(socketserver.BaseRequestHandler):
    def receive(self, size):
        data = b''
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise EOFError()
            data += chunk
        return data

    def handle(self):
        command = b''
        while not command.endswith(b'\0'):
            command += self.receive(1)
        if command == b'zPING\0':
            self.request.sendall(b'PONG\0')
            return
        if command.startswith(b'zSCAN '):
            path = Path(command[len(b'zSCAN '):-1].decode('utf-8'))
            if path.stat().st_size > 2 * 1024 ** 3:
                status = b'Heuristics.Limits.Exceeded.MaxFileSize FOUND'
            else:
                status = b'Test FOUND' if path.read_bytes() == b'infected' else b'OK'
            self.request.sendall(str(path).encode('utf-8') + b': ' + status + b'\0')
            return
        if command != b'zINSTREAM\0':
            return
        payload = b''
        while True:
            size = struct.unpack('!I', self.receive(4))[0]
            if size == 0:
                break
            payload += self.receive(size)
        with self.server.lock:
            self.server.active += 1
            self.server.maximum = max(self.server.maximum, self.server.active)
            self.server.payloads.append(payload)
        time.sleep(.04)
        result = b'stream: Test FOUND\0' if payload == b'infected' else b'stream: OK\0'
        self.request.sendall(result)
        with self.server.lock:
            self.server.active -= 1


class ClamdTests(unittest.TestCase):
    def setUp(self):
        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        self.server.lock = threading.Lock()
        self.server.active = self.server.maximum = 0
        self.server.payloads = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.shutdown)
        self.endpoint = ('tcp', self.server.server_address)

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_existing_daemon_reused_and_never_stopped(self):
        backend = Mock()
        backend.clamd_endpoints.return_value = [self.endpoint]
        session = ClamdSession(backend)
        self.assertEqual(session.acquire('clamscan', None, lambda: False), self.endpoint)
        self.assertTrue(session.reused)
        session.close()
        backend.start_process.assert_not_called()
        backend.stop_process.assert_not_called()

    def test_stream_protocol_reports_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'file'
            path.write_bytes(b'infected')
            self.assertEqual(scan_file(self.endpoint, path, lambda: False), 'Test FOUND')

    def test_owned_daemon_large_file_does_not_use_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'large.iso'
            with path.open('wb') as output:
                output.truncate(3 * 1024 ** 3)
            status = scan_file(self.endpoint, path, lambda: False, direct=True)
            self.assertEqual(status, 'Heuristics.Limits.Exceeded.MaxFileSize FOUND')
            self.assertEqual(self.server.payloads, [])
            service = ScanService()
            infected, warnings, errors = service._run_parallel([str(path)], self.endpoint, direct=True)
            self.assertEqual(infected, [])
            self.assertTrue(warnings)
            self.assertFalse(errors)
            self.assertEqual(service.parallel_warnings, 1)

    def test_direct_scan_preserves_infection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'file'
            path.write_bytes(b'infected')
            self.assertEqual(scan_file(self.endpoint, path, lambda: False, direct=True), 'Test FOUND')

    def test_cancel_before_stream_opens_file(self):
        with self.assertRaises(ScanCancelled):
            scan_file(self.endpoint, 'missing', lambda: True)

    def test_parallel_service_respects_excludes_and_finishes_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excluded = root / 'skip'
            excluded.mkdir()
            (excluded / 'private').write_bytes(b'must not be sent')
            for index in range(8):
                (root / str(index)).write_bytes(b'infected' if index == 0 else b'clean')
            backend = Mock()
            backend.clamd_endpoints.return_value = [self.endpoint]
            backend.scan_may_need_admin.return_value = False
            service = ScanService()
            with patch('core.scan_service.backend', backend), \
                 patch('core.scan_service._first_database_dir', return_value=None):
                service.run([tmp, tmp], [str(excluded)], 'clamscan', parallel=True)
            self.assertFalse(service.result['errors'])
            self.assertEqual(service.result['total'], 8)
            self.assertEqual(service.result['scanned'], 8)
            self.assertEqual(len(service.result['infected']), 1)
            self.assertEqual(len(self.server.payloads), 8)
            self.assertNotIn(b'must not be sent', self.server.payloads)
            self.assertGreater(self.server.maximum, 1)
            self.assertLessEqual(self.server.maximum, 4)
            progress = [event for event in service.output_queue.queue
                        if isinstance(event, tuple) and event[0] == '__PROGRESS__']
            self.assertEqual(progress[-1], ('__PROGRESS__', 8, 8, True))
            backend.stop_process.assert_not_called()

    def test_transport_failure_is_not_clean_scan(self):
        service = ScanService()
        with patch('core.scan_service.scan_file', side_effect=OSError('lost connection')):
            infected, warnings, errors = service._run_parallel(['file'], self.endpoint)
        self.assertTrue(errors)
        self.assertEqual(infected, [])

    def test_completed_parallel_failure_reaches_100_with_failed_status(self):
        backend = Mock()
        backend.clamd_endpoints.return_value = [self.endpoint]
        backend.scan_may_need_admin.return_value = False
        service = ScanService()
        with patch('core.scan_service.backend', backend), \
             patch('core.file_discovery.iter_scan_files', side_effect=lambda *args: iter(['file'])), \
             patch('core.scan_service._first_database_dir', return_value=None), \
             patch('core.scan_service.scan_file', side_effect=OSError('connection lost')):
            service.run('root', [], 'clamscan', parallel=True)
        self.assertTrue(service.result['errors'])
        progress = [event for event in service.output_queue.queue
                    if isinstance(event, tuple) and event[0] == '__PROGRESS__']
        self.assertEqual(progress[-1], ('__PROGRESS__', 1, 1, True))
        self.assertIn('Errors: 1\n', service.result['summary_lines'])

    def test_owned_daemon_starts_only_after_failed_probe_and_is_stopped(self):
        backend = Mock()
        backend.clamd_endpoints.return_value = [self.endpoint]
        backend.find_clamd.return_value = 'clamd'
        backend.clamd_listen_config.side_effect = lambda work: (self.endpoint, ['TCPAddr 127.0.0.1', 'TCPSocket 3310'])
        process = Mock()
        process.poll.return_value = None
        backend.start_process.return_value = process
        session = ClamdSession(backend)
        with patch('core.clamd.ping', side_effect=[False, True]):
            session.acquire('clamscan', Path('/database'), lambda: False)
        self.assertFalse(session.reused)
        backend.start_process.assert_called_once()
        session.close()
        backend.stop_process.assert_called_once_with(process)

    def test_stop_does_not_enqueue_more_files(self):
        service = ScanService()
        service.stop()
        with patch('core.scan_service.scan_file') as worker:
            service._run_parallel(['one', 'two'], self.endpoint)
        worker.assert_not_called()

    def test_inaccessible_file_is_warning(self):
        service = ScanService()
        with patch('core.scan_service.scan_file', side_effect=PermissionError('access denied')):
            _, warnings, errors = service._run_parallel(['file'], self.endpoint)
        self.assertTrue(warnings)
        self.assertFalse(errors)

    def test_missing_daemon_falls_back_to_standard_scan(self):
        import io
        from types import SimpleNamespace
        process = SimpleNamespace(stdout=io.StringIO(''), poll=lambda: 0, wait=lambda: 0)
        backend = Mock()
        backend.scan_may_need_admin.return_value = False
        backend.clamd_endpoints.return_value = []
        backend.find_clamd.return_value = None
        backend.start_process.return_value = process
        service = ScanService()
        with patch('core.scan_service.backend', backend), \
             patch('core.file_discovery.iter_scan_files', side_effect=lambda *args: iter(['file'])), \
             patch('core.scan_service._first_database_dir', return_value=None), \
             patch('core.scan_service.build_clamscan_command', return_value=['clamscan']):
            service.run('root', [], 'clamscan', parallel=True)
        backend.start_process.assert_called_once()
        self.assertFalse(service.result['errors'])
        self.assertTrue(any('Using clamscan' in event for event in service.output_queue.queue
                            if isinstance(event, str)))
