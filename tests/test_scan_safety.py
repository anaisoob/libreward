"""Regression checks for findings, quarantine boundaries and scan outcomes."""
import io
import json
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
import core.runtime as runtime_module
import core.scan_service as scans
from core.runtime import StartupStatus
from backends.base import RuntimeInfo, newest_database_time
from excludes import path_is_excluded, build_clamscan_exclude_args
from excludes import _clamav_literal
from scanner import _first_database_dir, collect_files, parse_clamscan_result_line


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
             patch('core.file_discovery.iter_scan_files', return_value=iter(['/known'])), \
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
             patch('core.file_discovery.iter_scan_files', return_value=iter(['/known'])), \
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


class DatabaseFileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)

    def assert_no_database(self):
        self.assertFalse(runtime_module._check_database_dir(self.directory))
        self.assertEqual(runtime_module.database_files(self.directory), [])
        self.assertIsNone(newest_database_time(self.directory))
        with patch('scanner.backend', SimpleNamespace(system_db_locations=lambda: [self.directory])):
            self.assertIsNone(_first_database_dir())

    def test_a_folder_named_like_a_database_is_not_a_database(self):
        (self.directory / 'fake.cvd').mkdir()
        self.assert_no_database()

    def test_an_empty_file_is_not_a_database(self):
        (self.directory / 'daily.cld').touch()
        self.assert_no_database()

    def test_a_link_to_nowhere_is_not_a_database(self):
        (self.directory / 'main.cvd').symlink_to(self.directory / 'missing')
        self.assert_no_database()

    @unittest.skipIf(os.name == 'nt' or (hasattr(os, 'geteuid') and os.geteuid() == 0), 'root reads everything')
    def test_an_unreadable_file_is_not_a_database(self):
        path = self.directory / 'main.cvd'
        path.write_bytes(b'db')
        path.chmod(0)
        self.assert_no_database()

    def test_a_folder_that_does_not_exist_has_no_database(self):
        self.directory = self.directory / 'missing'
        self.assert_no_database()

    def test_real_files_are_found_next_to_fake_ones(self):
        (self.directory / 'fake.cvd').mkdir()
        (self.directory / 'daily.cld').write_bytes(b'db')
        (self.directory / 'main.cvd').write_bytes(b'db')
        self.assertTrue(runtime_module._check_database_dir(self.directory))
        self.assertEqual(runtime_module.database_files(self.directory), ['daily.cld', 'main.cvd'])
        self.assertIsNotNone(newest_database_time(self.directory))
        with patch('scanner.backend', SimpleNamespace(system_db_locations=lambda: [self.directory])):
            self.assertEqual(_first_database_dir(), self.directory)


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

    def test_failure_while_writing_or_removing_keeps_the_original(self):
        original = self.root / 'sample'
        original.write_text('dummy')
        with patch.object(quarantine, '_encode_into', side_effect=OSError('disk full')):
            self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Cannot quarantine:'))
        self.assertEqual(original.read_text(), 'dummy')
        self.assertEqual(list(self.qdir.iterdir()), [])
        real_unlink = os.unlink
        refused = []
        def unlink(path, **kwargs):
            if '.libreward-quarantine-' in str(path) and not refused:
                refused.append(path)
                raise OSError('read-only folder')
            real_unlink(path, **kwargs)
        with patch('os.unlink', unlink):
            self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Cannot quarantine:'))
        self.assertTrue(refused)
        self.assertEqual(original.read_text(), 'dummy')
        self.assertEqual(list(self.qdir.iterdir()), [])
        self.assertEqual([entry.name for entry in self.root.iterdir() if entry.name.startswith('.')], [])

    def encoding_then(self, change):
        real = quarantine._encode_into
        def encode(src, dest):
            result = real(src, dest)
            change(src)
            return result
        return patch.object(quarantine, '_encode_into', encode)

    def test_a_file_swapped_in_during_quarantine_is_kept(self):
        original = self.root / 'sample'
        original.write_text('harmful')
        def swap(path):
            replacement = self.root / 'replacement'
            replacement.write_text('new user file')
            os.replace(replacement, path)
        with self.encoding_then(swap):
            message = quarantine.quarantine_file(str(original), 'Test')
        self.assertTrue(message.startswith('Cannot quarantine:'), message)
        self.assertEqual(original.read_text(), 'new user file')
        self.assertEqual(list(self.qdir.iterdir()), [])
        self.assertEqual([entry.name for entry in self.root.iterdir() if entry.name.startswith('.')], [])

    def test_a_file_changed_during_quarantine_is_kept(self):
        original = self.root / 'sample'
        original.write_text('harmful')
        def change(path):
            with open(path, 'a') as stream:
                stream.write(' and more')
        with self.encoding_then(change):
            message = quarantine.quarantine_file(str(original), 'Test')
        self.assertTrue(message.startswith('Cannot quarantine:'), message)
        self.assertEqual(original.read_text(), 'harmful and more')
        self.assertEqual(list(self.qdir.iterdir()), [])

    def test_a_file_written_while_it_is_read_is_not_quarantined(self):
        original = self.root / 'sample'
        original.write_bytes(b'x' * 10)
        real = quarantine._xor
        def write_more(data, offset):
            if not offset:  # once: the reader would otherwise never reach the end
                with open(original, 'ab') as stream:
                    stream.write(b'more')
            return real(data, offset)
        with patch.object(quarantine, '_xor', write_more):
            message = quarantine.quarantine_file(str(original), 'Test')
        self.assertTrue(message.startswith('Cannot quarantine:'), message)
        self.assertTrue(original.exists())
        self.assertEqual(list(self.qdir.iterdir()), [])

    def test_a_new_file_at_the_path_while_the_old_one_is_held_is_kept(self):
        original = self.root / 'sample'
        original.write_text('harmful')
        real = quarantine._identity
        calls = []
        def identity(status):
            calls.append(status)
            if len(calls) == 3:  # after the rename, before the removal is decided
                original.write_text('new user file')
                return ('changed',)
            return real(status)
        with patch.object(quarantine, '_identity', identity):
            message = quarantine.quarantine_file(str(original), 'Test')
        self.assertTrue(message.startswith('Cannot quarantine:'), message)
        self.assertIn('kept as', message)
        self.assertEqual(original.read_text(), 'new user file')
        kept = [entry for entry in self.root.iterdir() if entry.name.startswith('.libreward-quarantine-')]
        self.assertEqual([entry.read_text() for entry in kept], ['harmful'])

    def test_quarantined_copy_cannot_be_used_and_restores_exactly(self):
        original = self.root / 'tool.sh'
        payload = b'#!/bin/sh\necho X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR\n' + bytes(range(256)) * 9000
        original.write_bytes(payload)
        self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Quarantined:'))
        item = quarantine.list_quarantined_files()[0]
        stored = Path(item['quarantine_path']).read_bytes()
        self.assertTrue(stored.startswith(quarantine.HEADER))
        self.assertNotIn(b'#!/bin/sh', stored)
        self.assertNotIn(b'EICAR', stored)  # no scanner or indexer sees the harmful content
        self.assertEqual(len(stored), len(quarantine.HEADER) + len(payload))
        self.assertTrue(item['encoded'])
        # The file name once used for decoding may be somebody's file.
        (self.root / '.tool.sh.libreward-restore').write_bytes(b'not ours')
        self.assertTrue(quarantine.restore_file(item['quarantine_name']).startswith('Restored:'))
        self.assertEqual(original.read_bytes(), payload)
        self.assertEqual((self.root / '.tool.sh.libreward-restore').read_bytes(), b'not ours')
        self.assertEqual(self.hidden_files(), ['.tool.sh.libreward-restore'])

    def hidden_files(self):
        return sorted(entry.name for entry in self.root.iterdir() if entry.name.startswith('.'))

    def quarantined(self, name='sample', contents=b'original'):
        original = self.root / name
        original.write_bytes(contents)
        self.assertTrue(quarantine.quarantine_file(str(original), 'Test').startswith('Quarantined:'))
        return original, quarantine.list_quarantined_files()[0]

    def decoding_then(self, change):
        real = quarantine._decode_into
        def decode(*args):
            digest = real(*args)
            change()
            return digest
        return patch.object(quarantine, '_decode_into', decode)

    def test_a_file_created_during_restore_is_not_overwritten(self):
        original, item = self.quarantined()
        with self.decoding_then(lambda: original.write_bytes(b'new user file')):
            message = quarantine.restore_file(item['quarantine_name'])
        self.assertEqual(message, f'Original file already exists: {original}')
        self.assertEqual(original.read_bytes(), b'new user file')
        self.assertEqual(self.hidden_files(), [])
        # The quarantined copy and its metadata remain, the restore can be retried.
        original.unlink()
        self.assertTrue(quarantine.restore_file(item['quarantine_name']).startswith('Restored:'))
        self.assertEqual(original.read_bytes(), b'original')

    def test_a_dangling_link_created_during_restore_is_not_replaced(self):
        original, item = self.quarantined()
        with self.decoding_then(lambda: original.symlink_to(self.root / 'nowhere')):
            message = quarantine.restore_file(item['quarantine_name'])
        self.assertIn('already exists', message)
        self.assertTrue(original.is_symlink())

    def test_overwrite_replaces_the_existing_file_when_asked(self):
        original, item = self.quarantined()
        original.write_bytes(b'newer')
        self.assertTrue(quarantine.restore_file(item['quarantine_name'], overwrite=True).startswith('Restored:'))
        self.assertEqual(original.read_bytes(), b'original')

    def test_restore_without_hard_links_still_refuses_a_taken_name(self):
        original, item = self.quarantined(contents=b'original')
        with patch('os.link', side_effect=PermissionError('no hard links')):
            with self.decoding_then(lambda: original.write_bytes(b'new user file')):
                message = quarantine.restore_file(item['quarantine_name'])
            self.assertIn('already exists', message)
            self.assertEqual(original.read_bytes(), b'new user file')
            original.unlink()
            self.assertTrue(quarantine.restore_file(item['quarantine_name']).startswith('Restored:'))
        self.assertEqual(original.read_bytes(), b'original')
        self.assertEqual(stat.S_IMODE(original.stat().st_mode), item['original_mode'])

    def test_parallel_restores_of_one_location_leave_one_file(self):
        original, first = self.quarantined(contents=b'first')
        original.write_bytes(b'second')
        quarantine.quarantine_file(str(original), 'Test')
        second = next(item for item in quarantine.list_quarantined_files()
                      if item['quarantine_name'] != first['quarantine_name'])
        real = quarantine._decode_into
        done = []
        def decode(*args):
            digest = real(*args)
            if not done:
                done.append(True)  # the other restore runs while this one is decoding
                self.assertTrue(quarantine.restore_file(second['quarantine_name']).startswith('Restored:'))
            return digest
        with patch.object(quarantine, '_decode_into', decode):
            message = quarantine.restore_file(first['quarantine_name'])
        self.assertIn('already exists', message)
        self.assertEqual(original.read_bytes(), b'second')
        self.assertEqual(self.hidden_files(), [])

    def test_old_unencoded_files_restore_with_the_same_protection(self):
        original, item = self.quarantined()
        path = Path(item['quarantine_path'])
        path.chmod(0o600)
        path.write_bytes(b'stored as it was')
        metadata = Path(item['metadata_path'])
        old = json.loads(metadata.read_text())
        del old['sha256'], old['encoded']
        metadata.write_text(json.dumps(old))
        with self.decoding_then(lambda: original.write_bytes(b'new user file')):
            self.assertIn('already exists', quarantine.restore_file(item['quarantine_name']))
        self.assertEqual(original.read_bytes(), b'new user file')
        original.unlink()
        self.assertTrue(quarantine.restore_file(item['quarantine_name']).startswith('Restored:'))
        self.assertEqual(original.read_bytes(), b'stored as it was')
        self.assertFalse(path.exists())

    def test_a_damaged_quarantined_copy_is_not_restored(self):
        original = self.root / 'report.pdf'
        original.write_bytes(b'%PDF-1.7 harmful')
        quarantine.quarantine_file(str(original), 'Test')
        item = quarantine.list_quarantined_files()[0]
        path = Path(item['quarantine_path'])
        path.chmod(0o600)
        damaged = bytearray(path.read_bytes())
        damaged[-1] ^= 1
        path.write_bytes(bytes(damaged))
        message = quarantine.restore_file(item['quarantine_name'])
        self.assertIn('damaged', message)
        self.assertFalse(original.exists())
        self.assertTrue(path.exists())  # still in quarantine
        self.assertEqual([entry.name for entry in self.root.iterdir() if entry.name.startswith('.')], [])

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
