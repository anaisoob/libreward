"""System quarantine: what root does to files, with temporary folders and a stand-in clamscan."""
import ast
import inspect
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from backends import linux_root_quarantine as root, linux_root_scan
from backends.linux import LinuxBackend
from core import quarantine as user_quarantine, system_quarantine


def script(path, text):
    path.write_text('#!/bin/sh\n' + text)
    path.chmod(0o755)
    return str(path)


@unittest.skipIf(os.name == 'nt', 'Linux')
class RootProgramTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(os.path.realpath(temporary.name))
        self.files = self.folder / 'files'
        self.files.mkdir()
        self.file = self.files / 'harmful'
        self.file.write_bytes(b'harmful contents')
        self.file.chmod(0o640)
        self.store_path = self.folder / 'store'
        self.store = root.open_store(str(self.store_path))
        self.addCleanup(os.close, self.store)
        self.detected = script(self.folder / 'detected', 'cat > /dev/null\necho "stdin: Test FOUND"\nexit 1\n')

    def move(self, clamscan=None, *, discard=False, path=None):
        return root.move(self.store, clamscan or self.detected, str(path or self.file), 'Test', None, discard)

    def stored(self):
        return sorted(entry.name for entry in self.store_path.iterdir())

    def test_moved_file_is_encoded_and_only_root_reads_the_store(self):
        metadata = self.move()
        self.assertFalse(self.file.exists())
        data = (self.store_path / metadata['quarantine_name']).read_bytes()
        self.assertTrue(data.startswith(root.HEADER))
        self.assertNotIn(b'harmful', data)
        self.assertEqual(stat.S_IMODE(self.store_path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.store_path / metadata['quarantine_name']).stat().st_mode), 0o600)
        self.assertEqual(self.stored(), [metadata['quarantine_name'], metadata['quarantine_name'] + '.json'])
        self.assertEqual([entry.name for entry in self.files.iterdir()], [])

    def test_a_file_that_is_no_longer_detected_stays(self):
        with self.assertRaisesRegex(root.Refused, 'no longer detected'):
            self.move(script(self.folder / 'clean', 'cat > /dev/null\nexit 0\n'))
        self.assertTrue(self.file.exists())
        self.assertEqual(self.stored(), [])

    def test_a_failed_scanner_is_not_a_detection(self):
        with self.assertRaises(root.Refused):
            self.move(script(self.folder / 'broken', 'exit 2\n'))
        self.assertTrue(self.file.exists())

    def test_clamscan_reads_the_open_file_not_a_path(self):
        seen = self.folder / 'seen'
        self.move(script(self.folder / 'reader', f'cat > {seen}\nexit 1\n'))
        self.assertEqual(seen.read_bytes(), b'harmful contents')

    def test_a_link_on_the_way_is_refused(self):
        link = self.folder / 'link'
        link.symlink_to(self.files)
        with self.assertRaisesRegex(root.Refused, 'link'):
            self.move(path=link / 'harmful')
        self.assertTrue(self.file.exists())

    def test_a_link_is_never_followed(self):
        link = self.files / 'link'
        link.symlink_to(self.file)
        with self.assertRaisesRegex(root.Refused, 'link'):
            self.move(path=link)
        self.assertTrue(self.file.exists())
        self.assertTrue(link.is_symlink())

    def test_only_regular_files_with_one_name(self):
        with self.assertRaises(root.Refused):
            self.move(path=self.files)
        os.link(self.file, self.files / 'second')
        with self.assertRaisesRegex(root.Refused, 'several names'):
            self.move()

    def test_invalid_paths_are_refused(self):
        for path in ('relative', '/', '/proc/1/mem', '/a/../etc/passwd'):
            with self.subTest(path), self.assertRaises(root.Refused):
                self.move(path=path)

    def swap_after_detection(self):
        real = root.still_detected

        def detect(*arguments):
            result = real(*arguments)
            replacement = self.files / 'replacement'
            replacement.write_bytes(b'new user file')
            os.replace(replacement, self.file)
            return result
        return patch.object(root, 'still_detected', detect)

    def test_a_file_swapped_in_meanwhile_is_kept(self):
        with self.swap_after_detection(), self.assertRaisesRegex(root.Refused, 'changed'):
            self.move()
        self.assertEqual(self.file.read_bytes(), b'new user file')
        self.assertEqual(self.stored(), [])
        self.assertEqual([entry.name for entry in self.files.iterdir()], ['harmful'])

    def test_discarding_stores_nothing_and_checks_the_same(self):
        with self.swap_after_detection(), self.assertRaises(root.Refused):
            self.move(discard=True)
        self.assertEqual(self.file.read_bytes(), b'new user file')
        self.file.write_bytes(b'harmful again')
        self.assertIsNone(self.move(discard=True))
        self.assertFalse(self.file.exists())
        self.assertEqual(self.stored(), [])

    def test_restore_brings_back_contents_and_permissions(self):
        name = self.move()['quarantine_name']
        root.restore(self.store, name)
        self.assertEqual(self.file.read_bytes(), b'harmful contents')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o640)
        self.assertEqual(self.stored(), [])
        self.assertEqual([entry.name for entry in self.files.iterdir()], ['harmful'])

    def test_restore_never_overwrites_and_keeps_the_copy(self):
        name = self.move()['quarantine_name']
        self.file.write_bytes(b'new user file')
        with self.assertRaisesRegex(root.Refused, 'already exists'):
            root.restore(self.store, name)
        self.assertEqual(self.file.read_bytes(), b'new user file')
        self.assertEqual(len(self.stored()), 2)
        self.assertEqual([entry.name for entry in self.files.iterdir()], ['harmful'])

    def test_special_privilege_bits_do_not_come_back(self):
        self.file.chmod(0o4755)
        name = self.move()['quarantine_name']
        root.restore(self.store, name)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o755)

    def test_a_damaged_copy_is_not_restored(self):
        name = self.move()['quarantine_name']
        copy = self.store_path / name
        data = bytearray(copy.read_bytes())
        data[-1] ^= 1
        copy.write_bytes(bytes(data))
        with self.assertRaisesRegex(root.Refused, 'damaged'):
            root.restore(self.store, name)
        self.assertFalse(self.file.exists())
        self.assertEqual([entry.name for entry in self.files.iterdir()], [])

    def test_names_cannot_leave_the_store(self):
        for name in ('../passwd', 'x', '/etc/passwd', 'A' * 32, None, 'a' * 32 + '\n'):
            with self.subTest(name), self.assertRaises(root.Refused):
                root.delete(self.store, name)

    def test_delete_removes_the_entry(self):
        root.delete(self.store, self.move()['quarantine_name'])
        self.assertEqual(self.stored(), [])

    def test_a_store_others_can_reach_is_refused(self):
        unsafe = self.folder / 'unsafe'
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaisesRegex(root.Refused, 'unsafe'):
            root.open_store(str(unsafe))

    def test_one_bad_item_does_not_stop_the_others(self):
        request = {'action': 'move', 'items': [['/nonexistent/x', 'T'], [str(self.file), 'T']],
                   'database': None, 'discard': False}
        with patch.object(root, 'trusted_clamscan', return_value=self.detected):
            results = root.answer(request, self.store)
        self.assertEqual([result['ok'] for result in results], [False, True])

    def test_invalid_requests_are_refused(self):
        for request in (['x'], {'action': 'chmod'}, {'action': 'move', 'items': 'x', 'discard': False},
                        {'action': 'move', 'items': [['/a']], 'discard': False},
                        {'action': 'move', 'items': [], 'discard': 'no'},
                        {'action': 'move', 'items': [], 'discard': False, 'database': '/does/not/exist'},
                        {'action': 'restore', 'names': 'x'}):
            with self.subTest(request), self.assertRaises(ValueError):
                root.answer(request, self.store)

    def test_the_source_pkexec_gets_from_a_checkout_runs_alone(self):
        source = (inspect.getsource(linux_root_scan) + '\n' + inspect.getsource(root) + (
            f'\nimport sys\nSTORE = {str(self.store_path)!r}\n'
            f'trusted_clamscan = lambda: {self.detected!r}\nsys.exit(quarantine_main())\n'))
        request = {'action': 'move', 'items': [[str(self.file), 'T']], 'database': None, 'discard': True}
        source = source.replace('store = open_store()', 'store = open_store(STORE)').replace(
            'if os.geteuid() != 0:\n            raise PermissionError', 'if False:\n            raise PermissionError')
        result = subprocess.run([sys.executable, '-I', '-c', source],
                                input=json.dumps(request) + '\n', capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['results'][0]['ok'])
        self.assertFalse(self.file.exists())

    def test_the_program_imports_only_the_standard_library(self):
        tree = ast.parse(Path(root.__file__).read_text())
        names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        names |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and not node.level}
        self.assertLessEqual(names, set(sys.stdlib_module_names))

    def test_it_needs_root(self):
        if os.geteuid() == 0:
            self.skipTest('runs as root')
        with patch('sys.stdout') as output:
            self.assertEqual(root.quarantine_main(), 2)
        self.assertIn('runs as root', ''.join(call.args[0] for call in output.write.call_args_list))


class ScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def test_a_file_behind_a_closed_folder_is_not_gone(self):
        self.assertTrue(system_quarantine.is_gone(str(self.folder / 'missing')))
        with patch('os.lstat', side_effect=PermissionError):
            self.assertFalse(system_quarantine.is_gone('/root/file'))
        (self.folder / 'there').write_text('x')
        self.assertFalse(system_quarantine.is_gone(str(self.folder / 'there')))

    def test_own_files_need_no_password(self):
        path = self.folder / 'mine'
        path.write_text('x')
        with patch.object(system_quarantine, 'backend', Mock(root_quarantine_available=lambda: True)):
            self.assertFalse(system_quarantine.needs_administrator(str(path)))
            with patch('os.access', return_value=False):
                self.assertTrue(system_quarantine.needs_administrator(str(path)))
        with patch.object(system_quarantine, 'backend', Mock(root_quarantine_available=lambda: False)), \
                patch('os.access', return_value=False):
            self.assertFalse(system_quarantine.needs_administrator(str(path)))

    def fake_backend(self, results):
        return SimpleNamespace(quarantine_dir=lambda: self.folder, quarantine_as_root=Mock(return_value=results),
                               root_quarantine_available=lambda: True)

    def test_a_note_without_contents_lists_the_file_until_it_is_handled(self):
        metadata = {'quarantine_name': 'a' * 32, 'original_path': '/root/x', 'threat_name': 'T', 'system': True}
        fake = self.fake_backend([{'ok': True, 'metadata': metadata}])
        with patch.object(system_quarantine, 'backend', fake), patch.object(user_quarantine, 'backend', fake), \
                patch.object(system_quarantine, '_first_database_dir', return_value=None):
            self.assertEqual(system_quarantine.move([('/root/x', 'T')]), [('/root/x', True, 'Quarantined: /root/x')])
            listed = user_quarantine.list_quarantined_files()
            self.assertEqual([item['original_path'] for item in listed], ['/root/x'])
            self.assertEqual(system_quarantine.delete(['a' * 32])[0][1], True)
            self.assertEqual(user_quarantine.list_quarantined_files(), [])

    def test_a_refused_item_keeps_its_note(self):
        (self.folder / ('a' * 32 + '.json')).write_text('{}')
        fake = self.fake_backend([{'ok': False, 'error': 'Original file already exists.'}])
        with patch.object(system_quarantine, 'backend', fake):
            report = system_quarantine.restore(['a' * 32])
        self.assertEqual(report[0][1], False)
        self.assertIn('already exists', report[0][2])
        self.assertTrue((self.folder / ('a' * 32 + '.json')).exists())

    def test_discarding_leaves_no_note(self):
        fake = self.fake_backend([{'ok': True, 'metadata': None}])
        with patch.object(system_quarantine, 'backend', fake), \
                patch.object(system_quarantine, '_first_database_dir', return_value=None):
            self.assertEqual(system_quarantine.move([('/root/x', 'T')], discard=True),
                             [('/root/x', True, 'Deleted: /root/x')])
        self.assertEqual(list(self.folder.iterdir()), [])


@unittest.skipIf(os.name == 'nt', 'Linux')
class BackendTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def run_with(self, pkexec_text):
        pkexec = script(self.folder / 'pkexec', pkexec_text)
        with patch.object(LinuxBackend, '_require_authorizer', return_value=pkexec), \
                patch.object(LinuxBackend, '_root_helper', return_value='ignored'):
            return LinuxBackend().quarantine_as_root({'action': 'delete', 'names': []})

    def test_results_come_back(self):
        self.assertEqual(self.run_with("cat > /dev/null\necho '{\"results\": [{\"ok\": true}]}'\n"), [{'ok': True}])

    def test_a_refused_password_is_an_authorization_error(self):
        from core.authorization import AuthorizationError
        with self.assertRaises(AuthorizationError):
            self.run_with('exit 126\n')

    def test_a_failure_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            self.run_with("cat > /dev/null\necho '{\"error\": \"unsafe\"}'\nexit 2\n")

    def test_the_password_note_is_for_running_from_source(self):
        with patch.object(LinuxBackend, '_root_helper', return_value=None):
            self.assertIn('Python', LinuxBackend().password_note())
        with patch.object(LinuxBackend, '_root_helper', return_value='/usr/libexec/libreward/scan-files'):
            self.assertEqual(LinuxBackend().password_note(), '')

    def test_package_owners_are_asked_with_the_path_as_data(self):
        with patch.object(LinuxBackend, '_trusted_firewall_executable',
                          side_effect=lambda name: '/usr/bin/rpm' if name == 'rpm' else None), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(LinuxBackend().installed_by_package('/usr/bin/ls'))
        self.assertEqual(run.call_args.args[0], ['/usr/bin/rpm', '-qf', '--', '/usr/bin/ls'])


if __name__ == '__main__':
    unittest.main()
