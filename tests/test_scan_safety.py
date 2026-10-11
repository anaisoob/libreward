"""Regression checks for findings, quarantine boundaries and scan outcomes."""
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import core.quarantine as quarantine
import core.scan_service as scans
from core.runtime import StartupStatus
from backends.base import RuntimeInfo
from excludes import path_is_excluded, build_clamscan_exclude_args
from excludes import _clamav_literal
from scanner import collect_files, parse_clamscan_result_line


class ScanSafetyTests(unittest.TestCase):
    def run_scan(self, output, return_code, start_hook=None):
        proc = SimpleNamespace(stdout=io.StringIO(output), wait=lambda: return_code,
                               poll=lambda: return_code)
        service = scans.ScanService()
        def start(*args, **kwargs):
            if start_hook:
                start_hook(service)
            return proc
        fake = SimpleNamespace(start_process=start, stop_process=lambda p: None,
                               scan_may_need_admin=lambda roots: False)
        with patch.object(scans, 'backend', fake), \
             patch.object(scans, 'collect_files', return_value=['/known']), \
             patch.object(scans, 'build_clamscan_command', return_value=['clamscan']):
            service.run('/scan', [], 'clamscan')
        return service

    def test_new_file_detection_survives_initial_file_count(self):
        # Use native absolute paths on both Windows and Linux.
        new = os.path.abspath('new-file')
        service = self.run_scan(f'{new}: Eicar-Test FOUND\n', 1)
        self.assertEqual(service.result['infected'], [(new, 'Eicar-Test FOUND')])
        self.assertEqual(scans.scan_outcome(service.result), 'Infected files found!')

    def test_exit_one_without_parsed_paths_is_never_clean(self):
        result = self.run_scan('Unparsed detection output\n', 1).result
        self.assertEqual(result['infected'], [])
        self.assertEqual(scans.scan_outcome(result), 'Infected files found!')

    def test_database_load_failure_is_fatal(self):
        result = self.run_scan('ERROR: database load failed\n', 2).result
        self.assertTrue(result['errors'])
        self.assertEqual(scans.scan_outcome(result), 'Scan failed')

    def test_access_warning_in_completed_scan_remains_warning(self):
        path = os.path.abspath('locked')
        output = (f"{path}: Can't open file ERROR\n"
                  '----------- SCAN SUMMARY -----------\nScanned files: 1\n')
        result = self.run_scan(output, 2).result
        self.assertFalse(result['errors'])
        self.assertTrue(result['warnings'])

    def test_fatal_error_is_not_hidden_by_a_file_warning(self):
        path = os.path.abspath('locked')
        result = self.run_scan(
            f"{path}: Can't open file ERROR\nERROR: database load failed\n"
            '----------- SCAN SUMMARY -----------\nScanned files: 1\n', 2,
        ).result
        self.assertTrue(result['errors'])

    def test_real_subprocess_invalid_utf8_keeps_detection(self):
        path = os.path.abspath('new-file')
        payload = f"{path}: Test-".encode() + bytes([255]) + b" FOUND\n"
        service = scans.ScanService()
        def start(cmd, **kwargs):
            return subprocess.Popen(
                [sys.executable, '-c', f'import sys; sys.stdout.buffer.write({payload!r}); sys.exit(1)'],
                **kwargs,
            )
        fake = SimpleNamespace(start_process=start, scan_may_need_admin=lambda roots: False)
        with patch.object(scans, 'backend', fake), \
             patch.object(scans, 'collect_files', return_value=['/known']), \
             patch.object(scans, 'build_clamscan_command', return_value=['clamscan']):
            service.run('/scan', [], 'clamscan')
        self.assertEqual(len(service.result['infected']), 1)
        self.assertFalse(service.result['errors'])
        self.assertIn('\ufffd', service.result['infected'][0][1])

    def test_stop_during_process_start_is_honoured(self):
        service = self.run_scan('', -15, lambda service: service.stop())
        self.assertTrue(service.result['stopped'])
        self.assertFalse(service.result['errors'])
        self.assertEqual(scans.scan_outcome(service.result), 'Scan stopped by user')

    def test_progress_finishes_only_after_successful_process_exit(self):
        service = self.run_scan('', 0)
        events = list(service.output_queue.queue)
        progress = [e for e in events if isinstance(e, tuple) and e[0] == '__PROGRESS__']
        self.assertEqual(progress[-1], ('__PROGRESS__', 1, 1, True))
        failed = self.run_scan('ERROR: database load failed\n', 2)
        self.assertFalse(any(isinstance(e, tuple) and e[0] == '__PROGRESS__' and e[-1]
                             for e in failed.output_queue.queue))

    def test_summary_is_not_mistaken_for_file_result(self):
        self.assertEqual(parse_clamscan_result_line('Scanned files: 3', set()), (None, None))

    def test_exclude_respects_directory_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            excluded = str(Path(tmp) / 'skip')
            self.assertTrue(path_is_excluded(str(Path(excluded) / 'file'), [excluded]))
            sibling = excluded + '-important/file'
            self.assertFalse(path_is_excluded(sibling, [excluded]))
            expression = build_clamscan_exclude_args([excluded])[0].split('=', 1)[1]
            self.assertIsNone(re.search(expression, sibling.replace(os.sep, '/')))

    def test_file_count_respects_explicit_file_exclude(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'skip.txt'
            path.write_text('dummy')
            self.assertEqual(collect_files(tmp, [str(path)], lambda: False), [])
            arg = build_clamscan_exclude_args([str(path)])[0]
            self.assertTrue(arg.startswith('--exclude='))

    @unittest.skipUnless(os.name != 'nt' and shutil.which('grep'), 'requires POSIX grep')
    def test_custom_folder_exclude_matches_in_posix_regex_engine(self):
        # Python re accepts (?:...), whereas ClamAV's POSIX engine does not.
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'skip folder+[1]'
            folder.mkdir()
            (folder / 'private.txt').write_text('excluded')
            sibling = Path(str(folder) + '-keep')
            sibling.mkdir()
            visible = sibling / 'visible.txt'
            visible.write_text('included')
            self.assertEqual(collect_files(tmp, [str(folder)], lambda: False), [str(visible)])
            expression = build_clamscan_exclude_args([str(folder)])[0].split('=', 1)[1]
            paths = [str(folder), str(folder / 'private.txt'), str(visible)]
            result = subprocess.run(['grep', '-E', '--', expression],
                                    input='\n'.join(paths) + '\n', text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), paths[:2])

    def test_windows_clamav_literal_matches_both_separators(self):
        with patch('excludes.os.name', 'nt'):
            expression = '^' + _clamav_literal('C:/Users/Name/My folder') + '$'
        self.assertIsNotNone(re.search(expression, r'C:\Users\Name\My folder'))
        self.assertIsNotNone(re.search(expression, 'C:/Users/Name/My folder'))

    def test_missing_database_blocks_core_scan_readiness(self):
        runtime = RuntimeInfo('system-path', 'clamscan', 'freshclam', 'ClamAV 1', '1')
        self.assertFalse(StartupStatus(runtime, True, False, True, True).can_scan)


class QuarantineSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.qdir = self.root / 'quarantine'
        self.qdir.mkdir()
        self.backend_patch = patch.object(quarantine, 'backend', SimpleNamespace(quarantine_dir=lambda: self.qdir))
        self.backend_patch.start()
        self.addCleanup(self.backend_patch.stop)

    def test_delete_and_restore_reject_paths_outside_quarantine(self):
        outside = self.root / 'outside'
        outside.write_text('dummy')
        for name in ('../outside', str(outside), '..\\outside', 'C:outside'):
            self.assertIn('Invalid', quarantine.delete_quarantined_file(name))
            self.assertIn('Invalid', quarantine.restore_file(name))
            self.assertTrue(outside.exists())

    @unittest.skipIf(os.name == 'nt', 'symlink creation requires Windows privileges')
    def test_listing_rejects_symlink_and_metadata_path_escape(self):
        outside = self.root / 'outside'
        outside.write_text('dummy')
        (self.qdir / 'link').symlink_to(outside)
        self.assertIn('Invalid', quarantine.delete_quarantined_file('link'))
        (self.qdir / 'escape.json').write_text('{"quarantine_name": "../outside"}')
        self.assertEqual(quarantine.list_quarantined_files(), [])
        self.assertTrue(outside.exists())

    def test_metadata_write_failure_leaves_original_untouched(self):
        original = self.root / 'sample'
        original.write_text('dummy')
        with patch.object(Path, 'write_text', side_effect=OSError('disk full')):
            message = quarantine.quarantine_file(str(original), 'Test')
        self.assertTrue(message.startswith('Cannot quarantine:'))
        self.assertEqual(original.read_text(), 'dummy')
        self.assertEqual(list(self.qdir.iterdir()), [])

    def test_binary_json_payload_does_not_break_quarantine_list(self):
        original = self.root / 'sample.json'
        original.write_bytes(bytes([255, 254]))
        self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Quarantined:'))
        self.assertEqual(len(quarantine.list_quarantined_files()), 1)

    def test_move_failure_cleans_metadata(self):
        original = self.root / 'sample'
        original.write_text('dummy')
        with patch.object(quarantine.shutil, 'move', side_effect=OSError('locked')):
            self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Cannot quarantine:'))
        self.assertTrue(original.exists())
        self.assertEqual(list(self.qdir.iterdir()), [])

    def test_round_trip_preserves_payload_and_permissions(self):
        original = self.root / 'sample'
        original.write_text('dummy')
        original.chmod(0o750)
        mode = stat.S_IMODE(original.stat().st_mode) & 0o777
        self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Quarantined:'))
        items = quarantine.list_quarantined_files()
        self.assertEqual(len(items), 1)
        self.assertFalse(original.exists())
        self.assertTrue(quarantine.restore_file(items[0]['quarantine_name']).startswith('Restored:'))
        self.assertEqual(original.read_text(), 'dummy')
        self.assertEqual(stat.S_IMODE(original.stat().st_mode) & 0o777, mode)
        self.assertEqual(quarantine.list_quarantined_files(), [])


if __name__ == '__main__':
    unittest.main()
