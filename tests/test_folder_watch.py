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

    def test_downloads_in_progress_are_named_and_finished_ones_need_no_waiting(self):
        with tempfile.TemporaryDirectory() as folder:
            monitor = FolderMonitor([folder], [], settle=3)
            partial = Path(folder) / 'setup.zip.part'
            partial.write_text('half')
            chrome = Path(folder) / 'Unconfirmed 4711.crdownload'
            chrome.write_text('half')
            monitor.started(str(partial))
            monitor.started(str(chrome))
            self.assertEqual(sorted(monitor.downloads()), sorted([str(partial), str(chrome)]))
            final = Path(folder) / 'setup.zip'
            partial.rename(final)
            monitor.finished(str(partial))
            monitor.changed(str(final), finished=True)
            self.assertEqual(monitor.ready(), [str(final)])  # no 3 second settling
            chrome.unlink()
            self.assertEqual(monitor.downloads(), [])

    def test_native_rename_of_a_partial_download_is_checked_at_once(self):
        try:
            import watchdog  # noqa: F401
        except ImportError:
            self.skipTest('watchdog required')
        with tempfile.TemporaryDirectory() as folder:
            monitor = FolderMonitor([folder], [], settle=30)
            monitor.start()
            try:
                self.assertTrue(monitor.baseline_ready.wait(3))
                partial = Path(folder) / 'report.pdf.crdownload'
                partial.write_text('downloading')
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not monitor.downloads():
                    time.sleep(.02)
                self.assertEqual(monitor.downloads(), [str(partial)])
                final = Path(folder) / 'report.pdf'
                partial.rename(final)
                found = []
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not found:
                    found.extend(monitor.ready())
                    time.sleep(.02)
                self.assertEqual(found, [str(final)])  # well before the 30 second settling
                self.assertEqual(monitor.downloads(), [])
            finally:
                monitor.stop()

    def test_new_modification_time_with_same_contents_is_not_checked_again(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'download.zip'
            path.write_text('contents')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path))
            monitor.ready()
            self.assertEqual(monitor.ready(), [str(path)])
            os.utime(path, (1_000_000, 1_000_000))  # the server's Last-Modified, set by the browser
            monitor.changed(str(path))
            monitor.ready()
            self.assertEqual(monitor.ready(), [])
            path.write_text('CONTENTS')  # same size, different contents
            os.utime(path, (2_000_000, 2_000_000))
            monitor.changed(str(path))
            monitor.ready()
            self.assertEqual(monitor.ready(), [str(path)])

    def test_the_same_file_downloaded_again_is_checked_again(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'eicar.com'
            path.write_text('same test contents')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path))
            monitor.ready()
            self.assertEqual(monitor.ready(), [str(path)])
            # Deleted without the monitor noticing, then downloaded again: a new file.
            path.unlink()
            replacement = Path(folder) / 'other'
            replacement.write_text('keeps the old inode from being reused')
            path.write_text('same test contents')
            monitor.changed(str(path))
            monitor.ready()
            self.assertEqual(monitor.ready(), [str(path)])
            monitor.forget(str(path))  # deleted while watched
            self.assertNotIn(str(path), monitor.dispatched)

    def test_native_delete_and_download_again_is_checked(self):
        try:
            import watchdog  # noqa: F401
        except ImportError:
            self.skipTest('watchdog required')
        with tempfile.TemporaryDirectory() as folder:
            monitor = FolderMonitor([folder], [], settle=.05)
            monitor.start()
            try:
                self.assertTrue(monitor.baseline_ready.wait(3))
                path = Path(folder) / 'eicar.com'
                for attempt in range(2):
                    partial = Path(str(path) + '.part')
                    partial.write_text('same test contents')
                    partial.rename(path)
                    found = []
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline and not found:
                        found.extend(monitor.ready())
                        time.sleep(.02)
                    self.assertEqual(found, [str(path)], f'download {attempt + 1}')
                    path.unlink()
                    time.sleep(.2)
            finally:
                monitor.stop()

    def test_chrome_naming_its_download_keeps_it_in_progress(self):
        try:
            import watchdog  # noqa: F401
        except ImportError:
            self.skipTest('watchdog required')
        with tempfile.TemporaryDirectory() as folder:
            monitor = FolderMonitor([folder], [], settle=30)
            monitor.start()
            try:
                self.assertTrue(monitor.baseline_ready.wait(3))
                unconfirmed = Path(folder) / 'Unconfirmed 4711.crdownload'
                unconfirmed.write_text('downloading')
                named = Path(folder) / 'setup.zip.crdownload'
                unconfirmed.rename(named)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and monitor.downloads() != [str(named)]:
                    time.sleep(.02)
                self.assertEqual(monitor.downloads(), [str(named)])
                self.assertEqual(monitor.ready(), [])
            finally:
                monitor.stop()

    def test_reasons_say_why_a_file_is_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'file.zip'
            path.write_text('x')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path), finished=True)
            # The folder check finding the same unchanged file keeps the first reason.
            monitor.changed(str(path), reason='found by the folder check')
            self.assertEqual(monitor.reason(str(path)), 'download finished')
            monitor.changed(str(path), finished=True, reason="in a browser's list of downloads")
            self.assertEqual(monitor.reason(str(path)), "in a browser's list of downloads")
            self.assertEqual(monitor.reason(str(path)), 'new or changed file')  # reported once

    def test_metadata_added_after_saving_does_not_check_again(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'download.zip'
            path.write_text('contents')
            monitor = FolderMonitor([folder], [], settle=0)
            monitor.changed(str(path))
            monitor.ready()
            self.assertEqual(monitor.ready(), [str(path)])
            os.chmod(path, 0o600)  # changes ctime only, like a browser's download address
            monitor.changed(str(path))
            self.assertEqual(monitor.ready(), [])
            self.assertEqual(monitor.ready(), [])

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
