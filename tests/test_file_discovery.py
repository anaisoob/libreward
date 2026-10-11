"""Concurrent discovery must scan early, bound memory and preserve exclusions."""
import tempfile
import io
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from core.file_discovery import FileDiscovery
from core.scan_service import ScanService
from scanner import iter_scan_files


class DiscoveryTests(unittest.TestCase):
    def test_standard_process_starts_before_counting_finishes(self):
        process_started = threading.Event()

        def paths(*args):
            yield 'first'
            if not process_started.wait(2):
                raise RuntimeError('Standard scan waited for counting')
            yield 'second'

        process = Mock()
        process.stdout = io.StringIO('')
        process.poll.return_value = process.wait.return_value = 0
        backend = Mock()
        backend.scan_may_need_admin.return_value = False

        def start(*args, **kwargs):
            process_started.set()
            return process

        backend.start_process.side_effect = start
        service = ScanService()
        with patch('core.file_discovery.iter_scan_files', side_effect=paths), \
             patch('core.scan_service.backend', backend), \
             patch('core.scan_service.build_clamscan_command', return_value=['clamscan']):
            service.run('folder', [], 'clamscan')
        self.assertFalse(service.result['errors'])
        self.assertEqual(service.result['total'], 2)

    def test_scans_before_discovery_finishes(self):
        scanned = threading.Event()
        service = ScanService()
        events = []

        def paths(*args):
            yield 'first'
            if not scanned.wait(2):
                raise RuntimeError('Scan did not start during discovery')
            yield 'second'

        def check(*args, **kwargs):
            scanned.set()
            return 'OK'

        with patch('core.file_discovery.iter_scan_files', side_effect=paths), \
             patch('core.scan_service.scan_file', side_effect=check):
            with FileDiscovery([], [], lambda: False, events.append,
                               lambda: service.scanned_files) as discovery:
                _, _, errors = service._run_parallel(discovery, ('tcp', ('localhost', 1)))
        self.assertFalse(errors)
        self.assertEqual(service.scanned_files, 2)
        self.assertEqual(discovery.total, 2)
        self.assertTrue(discovery.done.is_set())

    def test_queue_is_bounded_and_cancellable_when_full(self):
        with patch('core.file_discovery.iter_scan_files', return_value=iter(map(str, range(10000)))):
            with FileDiscovery([], [], lambda: False, lambda event: None,
                               lambda: 0) as discovery:
                deadline = time.monotonic() + 2
                while not discovery.queue.full() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(discovery.queue.full())
                self.assertLessEqual(discovery.total, 256)
        self.assertFalse(discovery.thread.is_alive())

    def test_independent_counter_finishes_while_scan_queue_is_full(self):
        with patch('core.file_discovery.iter_scan_files', side_effect=lambda *args: iter(map(str, range(1000)))):
            with FileDiscovery([], [], lambda: False, lambda event: None, lambda: 0) as paths:
                with FileDiscovery([], [], lambda: False, lambda event: None, lambda: 0, count_only=True) as counter:
                    counter.thread.join(timeout=2)
                    self.assertTrue(counter.done.is_set())
                    self.assertEqual(counter.total, 1000)
                    self.assertLessEqual(paths.total, 256)

    def test_discovery_prunes_overlapping_roots_and_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / 'nested'
            nested.mkdir()
            keep = nested / 'keep'
            keep.write_text('test')
            skip = root / 'skip'
            skip.mkdir()
            (skip / 'private').write_text('test')
            files = list(iter_scan_files([str(nested), tmp, tmp], [str(skip)], lambda: False))
            self.assertEqual(files, [str(keep)])

    def test_cancel_before_discovery_yields_nothing(self):
        self.assertEqual(list(iter_scan_files(['.'], [], lambda: True)), [])
