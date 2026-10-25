import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.folder_watch import FolderMonitor
from scanner import iter_scan_files


class FolderMonitorTests(unittest.TestCase):
    def test_waits_for_stable_file_and_coalesces_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_text('one')
            monitor = FolderMonitor([folder], [], settle=3)
            with patch('core.folder_watch.time.monotonic', return_value=0):
                monitor.changed(str(path))
            with patch('core.folder_watch.time.monotonic', return_value=4):
                self.assertEqual(monitor.ready(), [])
            path.write_text('longer contents')
            with patch('core.folder_watch.time.monotonic', return_value=8):
                self.assertEqual(monitor.ready(), [])
            with patch('core.folder_watch.time.monotonic', return_value=12):
                self.assertEqual(monitor.ready(), [str(path)])
                self.assertEqual(monitor.ready(), [])

    def test_excluded_and_deleted_files_are_not_scanned(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_text('one')
            monitor = FolderMonitor([folder], [str(path)], settle=0)
            monitor.changed(str(path))
            self.assertEqual(monitor.pending, {})
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path))
            path.unlink()
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.pending, {})

    def test_incomplete_downloads_wait_for_final_name(self):
        with tempfile.TemporaryDirectory() as folder:
            monitor = FolderMonitor([folder], [], settle=0)
            for suffix in ('.part', '.crdownload', '.CRDOWNLOAD', '.aria2', '.!qB', '.filepart'):
                path = Path(folder) / ('sample' + suffix)
                path.write_text('unfinished')
                monitor.changed(str(path))
            self.assertEqual(monitor.pending, {})
            temporary = Path(folder) / 'sample.crdownload'
            final = Path(folder) / 'finished.zip'
            temporary.rename(final)
            monitor.changed(str(final))
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [str(final)])

    def test_sidecar_blocks_stable_file_until_download_finishes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'archive.zip'
            path.write_text('still downloading')
            sidecar = Path(str(path) + '.aria2')
            sidecar.write_text('control')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path))
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [])
            sidecar.unlink()
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [str(path)])

    def test_native_sidecar_removal_queues_existing_final_file(self):
        try:
            import watchdog
        except ImportError:
            self.skipTest('watchdog required')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'file.zip'
            path.write_text('data')
            sidecar = Path(str(path) + '.part')
            sidecar.write_text('partial')
            monitor = FolderMonitor([folder], [], settle=.01)
            monitor.start()
            try:
                self.assertTrue(monitor.baseline_ready.wait(3))
                self.assertEqual(monitor.ready(), [])
                sidecar.unlink()
                deadline = time.monotonic() + 3
                found = []
                while time.monotonic() < deadline and not found:
                    found.extend(monitor.ready())
                    time.sleep(.02)
                self.assertEqual(found, [str(path)])
            finally:
                monitor.stop()

    def test_file_targets_work_with_parallel_discovery(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_text('one')
            self.assertEqual(list(iter_scan_files([str(path)], [], lambda: False)), [str(path)])
            self.assertEqual(list(iter_scan_files([str(path)], [folder], lambda: False)), [])

    def test_duplicate_notification_does_not_rescan_unchanged_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_text('one')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path))
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [str(path)])
            monitor.changed(str(path))
            self.assertEqual(monitor.ready(), [])
            path.write_text('new contents')
            monitor.changed(str(path))
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [str(path)])
            monitor.changed(str(path), retry=True)
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [str(path)])

    def test_startup_baseline_does_not_queue_existing_files(self):
        try:
            import watchdog
        except ImportError:
            self.skipTest('watchdog required')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'existing'
            path.write_text('already here')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.start()
            try:
                self.assertTrue(monitor.baseline_ready.wait(3))
                self.assertEqual(monitor.ready(), [])
                self.assertEqual(monitor.pending, {})
                # Force reconciliation without changing any content.
                monitor.reconcile.set()
                time.sleep(.1)
                self.assertEqual(monitor.ready(), [])
                path.write_text('changed after startup')
                deadline = time.monotonic() + 3
                found = []
                while time.monotonic() < deadline and not found:
                    found.extend(monitor.ready())
                    time.sleep(.01)
                self.assertEqual(found, [str(path)])
            finally:
                monitor.stop()

    def test_native_monitor_detects_new_nested_file(self):
        try:
            import watchdog
        except ImportError:
            self.skipTest('watchdog required')
        with tempfile.TemporaryDirectory() as folder:
            monitor = FolderMonitor([folder], [], settle=.03)
            monitor.start()
            try:
                self.assertTrue(monitor.baseline_ready.wait(3))
                nested = Path(folder) / 'nested'
                nested.mkdir()
                path = nested / 'file'
                path.write_text('hello')
                deadline = time.monotonic() + 5
                found = []
                while time.monotonic() < deadline and str(path) not in found:
                    found.extend(monitor.ready())
                    time.sleep(.03)
                self.assertIn(str(path), found)
            finally:
                monitor.stop()
            self.assertFalse(monitor.thread.is_alive())
