"""A changed update manifest must not be able to run programs on users' computers."""
import copy
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import runtime, updater

MANIFEST = json.loads((Path(__file__).resolve().parent.parent / 'updates/clamav-runtime-windows.json').read_text())
ENTRY = MANIFEST['platforms']['windows-x64']


class UpdateLockTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.data = Path(temp.name) / 'data'
        for target, name, value in ((runtime.backend, 'data_dir', self.data),
                                    (runtime.backend, 'updates_dir', self.data / 'updates')):
            patcher = patch.object(target, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def holder(self):
        """Another process that holds the update lock until it is stopped."""
        code = ('import sys; from pathlib import Path; from backends import backend\n'
                'lock = backend.acquire_instance_lock(Path(sys.argv[1]))\n'
                'print("taken" if lock else "refused", flush=True); sys.stdin.read()\n')
        process = subprocess.Popen([sys.executable, '-c', code, str(runtime._lock_path())],
                                   cwd=Path(__file__).resolve().parent.parent, text=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        def stop():
            process.stdin.close()
            process.stdout.close()
            process.kill()
            process.wait()
        self.addCleanup(stop)
        self.assertEqual(process.stdout.readline().strip(), 'taken')
        return process

    def test_only_one_holder_at_a_time(self):
        first = runtime.acquire_update_lock()
        self.addCleanup(first.close)
        self.assertIsNone(runtime.acquire_update_lock())
        first.close()
        second = runtime.acquire_update_lock()
        self.assertIsNotNone(second)
        second.close()

    def test_nothing_is_locked_without_an_update(self):
        self.assertFalse(runtime.is_update_locked())
        self.assertFalse(self.data.exists())  # asking changes nothing on disk

    def test_a_lock_file_left_by_an_older_version_does_not_block(self):
        self.data.mkdir()
        runtime._lock_path().write_text('locked')
        self.assertFalse(runtime.is_update_locked())
        lock = runtime.acquire_update_lock()
        self.assertIsNotNone(lock)
        lock.close()

    def test_a_running_update_in_another_process_is_seen_and_refused(self):
        self.holder()
        self.assertTrue(runtime.is_update_locked())
        self.assertIsNone(runtime.acquire_update_lock())
        with patch.object(updater.backend, 'manages_own_runtime', return_value=True), \
                patch.object(updater, '_download_file', side_effect=AssertionError('downloaded')), \
                patch.object(updater, 'cleanup_stale_update_artifacts') as cleanup:
            error = updater.perform_update(copy.deepcopy(ENTRY))
        self.assertIn('already in progress', str(error))
        cleanup.assert_not_called()  # the other update's files stay

    @unittest.skipIf(os.name == 'nt', 'POSIX signal')
    def test_the_lock_ends_with_a_killed_process(self):
        process = self.holder()
        process.send_signal(signal.SIGKILL)
        process.wait()
        self.assertFalse(runtime.is_update_locked())
        lock = runtime.acquire_update_lock()
        self.assertIsNotNone(lock)
        lock.close()

    def test_a_failed_update_lets_the_next_one_start(self):
        with patch.object(updater.backend, 'manages_own_runtime', return_value=True), \
                patch.object(updater, '_download_file', side_effect=OSError('no network')):
            self.assertIn('no network', str(updater.perform_update(copy.deepcopy(ENTRY))))
        self.assertFalse(runtime.is_update_locked())

    def test_a_folder_that_cannot_be_created_is_a_reported_failure(self):
        self.data.parent.joinpath('data').write_text('a file, not a folder')
        with patch.object(updater.backend, 'manages_own_runtime', return_value=True):
            error = updater.perform_update(copy.deepcopy(ENTRY))
        self.assertIsInstance(error, RuntimeError)
        self.assertIn('Update failed', str(error))


class UpdaterSafetyTests(unittest.TestCase):
    def refused(self, change):
        entry = copy.deepcopy(ENTRY)
        change(entry)
        with patch.object(updater.backend, 'manages_own_runtime', return_value=True), \
                patch.object(updater, '_download_file', side_effect=AssertionError('downloaded')) as download:
            error = updater.perform_update(entry)
        download.assert_not_called()
        return str(error)

    def test_the_bundled_manifest_is_accepted(self):
        self.assertIsNone(updater._unsafe_entry(ENTRY))

    def test_downloads_come_only_from_official_clamav_releases(self):
        for url in ('https://evil.example/clamav.zip', 'http://github.com/Cisco-Talos/clamav/releases/download/x.zip',
                    'https://github.com/Cisco-Talos/clamav/releases/download/../../../attacker/x.zip',
                    'https://github.com/attacker/clamav/releases/download/v1/x.zip'):
            message = self.refused(lambda entry, url=url: entry['download'].update(url=url))
            self.assertIn('not an official ClamAV release', message)

    def test_unsafe_folder_or_missing_checksum_is_refused(self):
        self.assertIn('unsafe folder', self.refused(lambda entry: entry['download'].update(extract_dir='../../Users')))
        self.assertIn('SHA256', self.refused(lambda entry: entry['download'].update(sha256='')))

    def test_validation_never_runs_a_program_outside_the_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'ran'
            runtime = Path(folder) / 'runtime'
            runtime.mkdir()
            for command in (f'../../../../../../../usr/bin/touch {marker}', '..\\..\\Windows\\System32\\cmd.exe /c x'):
                with self.assertRaises(RuntimeError):
                    updater._validate_runtime(runtime, [command])
            self.assertFalse(marker.exists())
        self.assertEqual(updater.VALIDATION_COMMANDS, ('clamscan.exe --version', 'freshclam.exe --version'))


if __name__ == '__main__':
    unittest.main()
