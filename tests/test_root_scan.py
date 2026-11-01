"""Checking skipped files as root: what the root program accepts, and the way there."""
import ast
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backends import linux_root_scan as root_scan
from backends.linux import LinuxBackend
from core import root_scan as core_root_scan
from core.scan_warnings import WarningSummary, denied_path
from scanner import iter_scan_files

ROOT = Path(__file__).resolve().parent.parent
# Runs the real program with root's two checks replaced.
RUNNER = '''
import os, sys
sys.path.insert(0, {root!r})
from backends import linux_root_scan as program
os.geteuid = lambda: 0
program.trusted_clamscan = lambda: {clamscan!r}
sys.exit(program.root_main())
'''


class RequestTests(unittest.TestCase):
    def refused(self, request):
        with self.assertRaises((ValueError, TypeError)):
            root_scan.read_request(json.dumps(request))

    def test_only_absolute_clean_paths_of_real_files_pass(self):
        self.assertEqual(root_scan.read_request(json.dumps({'database': None, 'paths': ['/root/a b', '/etc/shadow']})),
                         (None, ['/root/a b', '/etc/shadow']))
        for path in ('relative', '--remove=yes', '/', '/root/../etc', '/root//a', '/proc/1/mem', '/sys', '/dev/sda',
                     '/a\0b', '', 7, None):
            with self.subTest(path):
                self.refused({'database': None, 'paths': [path]})

    def test_nothing_else_can_be_asked_for(self):
        self.refused({'database': None, 'paths': [], 'options': ['--remove=yes']})
        self.refused({'paths': []})
        self.refused({'database': '/does/not/exist', 'paths': []})
        self.refused({'database': '--remove', 'paths': []})
        self.refused(['/root'])
        with self.assertRaises(ValueError):
            root_scan.read_request('not json')

    def test_the_options_never_change_a_file_or_follow_a_link(self):
        command = root_scan.clamscan_command('/usr/bin/clamscan', '/db', ['/root/a'])
        self.assertEqual(command[-1], '/root/a')
        self.assertIn('--database=/db', command)
        self.assertIn('--follow-dir-symlinks=0', command)
        self.assertIn('--follow-file-symlinks=0', command)
        self.assertFalse([option for option in command if option.startswith(('--remove', '--move', '--copy'))])
        self.assertNotIn('--infected', command)  # each file's line is the progress

    def test_the_program_imports_only_the_standard_library(self):
        tree = ast.parse(Path(root_scan.__file__).read_text())
        names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        names |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertLessEqual(names, set(sys.stdlib_module_names))

    def test_clamscan_must_be_out_of_the_users_reach(self):
        with tempfile.TemporaryDirectory() as folder:
            program = Path(folder, 'clamscan')
            program.write_text('#!/bin/sh\n')
            program.chmod(0o755)
            if os.geteuid():
                self.assertIsNone(root_scan.trusted_clamscan((folder,)))
        self.assertIsNone(root_scan.trusted_clamscan(('/nonexistent',)))


@unittest.skipIf(os.name == 'nt', 'Linux')
class RootProgramTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.file = self.folder / 'skipped file'
        self.file.write_text('x')

    def program(self, text):
        path = self.folder / 'clamscan'
        path.write_text('#!/bin/sh\n' + text)
        path.chmod(0o755)
        return str(path)

    def start(self, clamscan):
        return subprocess.Popen([sys.executable, '-c', RUNNER.format(root=str(ROOT), clamscan=clamscan)], text=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def request(self, process, paths, database=None):
        process.stdin.write(json.dumps({'database': database, 'paths': paths}) + '\n')
        process.stdin.flush()

    def test_results_and_the_exit_code_come_through(self):
        process = self.start(self.program('printf "%s\\n" "$@"\necho "/x/eicar: Eicar FOUND"\nexit 1\n'))
        self.request(process, [str(self.file), str(self.folder / 'gone')])
        output = process.stdout.read()  # the input stays open: closing it means stop
        self.assertEqual(process.wait(timeout=5), 1)
        process.stdin.close()
        process.stdout.close()
        self.assertIn(str(self.file), output)
        self.assertNotIn('gone', output)  # a file gone meanwhile is not an error
        self.assertIn('/x/eicar: Eicar FOUND', output)

    def test_links_are_not_passed_on(self):
        link = self.folder / 'link'
        link.symlink_to('/etc/passwd')
        process = self.start(self.program('echo STARTED\n'))
        self.request(process, [str(link)])
        output, _ = process.communicate()
        self.assertEqual((process.returncode, output), (0, ''))

    def test_a_bad_request_is_refused_without_starting_clamscan(self):
        process = self.start(self.program('echo STARTED\n'))
        process.stdin.write('{"paths": ["relative"], "database": null}\n')
        output, _ = process.communicate()
        self.assertEqual(process.returncode, 2)
        self.assertNotIn('STARTED', output)

    def test_closing_the_input_stops_the_check(self):
        process = self.start(self.program('exec sleep 60\n'))
        self.request(process, [str(self.file)])
        time.sleep(.3)
        started = time.monotonic()
        process.stdin.close()
        process.wait(timeout=5)
        process.stdout.close()
        self.assertLess(time.monotonic() - started, 4)
        self.assertNotIn(process.returncode, (0, 1))


@unittest.skipIf(os.name == 'nt', 'Linux')
class BackendTests(unittest.TestCase):
    """The real pipes, with a stand-in for pkexec."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.file = self.folder / 'skipped'
        self.file.write_text('x')
        self.backend = LinuxBackend()

    def install(self, clamscan_text):
        clamscan = self.folder / 'clamscan'
        clamscan.write_text('#!/bin/sh\n' + clamscan_text)
        clamscan.chmod(0o755)
        helper = self.folder / 'helper.py'
        helper.write_text(RUNNER.format(root=str(ROOT), clamscan=str(clamscan)))
        pkexec = self.folder / 'pkexec'
        pkexec.write_text(f'#!/bin/sh\nshift\nexec {sys.executable} {helper}\n')
        pkexec.chmod(0o755)
        patcher = patch.object(LinuxBackend, '_require_authorizer', return_value=str(pkexec))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(LinuxBackend, '_root_helper', return_value='ignored')
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_lines_arrive_and_the_code_is_returned(self):
        self.install('echo "/root/x: Eicar FOUND"\nexit 1\n')
        lines = []
        self.assertEqual(self.backend.scan_as_root([str(self.file)], None, lines.append), (1, False))
        self.assertEqual(lines, ['/root/x: Eicar FOUND\n'])

    def test_a_large_request_does_not_block(self):
        self.install('exit 0\n')
        paths = [str(self.file)] * 8000  # more than a pipe holds
        self.assertEqual(self.backend.scan_as_root(paths, None, lambda _line: None), (0, False))

    def test_stop_after_authorization_closes_the_input(self):
        self.install('exec sleep 60\n')
        import threading
        results = []
        worker = threading.Thread(target=lambda: results.append(
            self.backend.scan_as_root([str(self.file)], None, lambda _line: None)))
        worker.start()
        time.sleep(.5)
        with patch.object(self.backend, 'cancel_authorization', return_value=False):
            self.backend.stop_root_scan()
        worker.join(6)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0][1])

    def test_a_refused_password_is_an_authorization_error(self):
        from core.authorization import AuthorizationError
        pkexec = self.folder / 'pkexec'
        pkexec.write_text('#!/bin/sh\nexit 126\n')
        pkexec.chmod(0o755)
        with patch.object(LinuxBackend, '_require_authorizer', return_value=str(pkexec)), \
                patch.object(LinuxBackend, '_root_helper', return_value='ignored'), \
                self.assertRaises(AuthorizationError):
            self.backend.scan_as_root([str(self.file)], None, lambda _line: None)


class CoreTests(unittest.TestCase):
    def run_check(self, paths, code=0, lines=()):
        def scan(_paths, _database, on_line):
            for line in lines:
                on_line(line)
            return code, False
        logged = []
        with patch.object(core_root_scan, 'backend', Mock(scan_as_root=Mock(side_effect=scan))), \
                patch.object(core_root_scan, '_first_database_dir', return_value=None):
            return core_root_scan.check_as_administrator(paths, logged.append), logged

    def test_findings_are_read_from_the_output(self):
        result, logged = self.run_check(['/a'], 1, ['/root/a: b: Win.Test-1 FOUND\n', 'noise\n'])
        self.assertEqual(result['infected'], [('/root/a: b', 'Win.Test-1')])
        self.assertTrue(result['complete'])
        self.assertIn('noise\n', logged)

    def test_every_file_is_counted_and_shown_as_it_is_checked(self):
        seen = []
        def scan(_paths, _database, on_line):
            for line in ('/root/a: OK\n', '/root/b: c: OK\n', '/root/d: Win.Test-1 FOUND\n', 'noise\n'):
                on_line(line)
            return 1, False
        logged = []
        with patch.object(core_root_scan, 'backend', Mock(scan_as_root=Mock(side_effect=scan))), \
                patch.object(core_root_scan, '_first_database_dir', return_value=None):
            result = core_root_scan.check_as_administrator(['/root'], logged.append,
                                                           lambda count, path: seen.append((count, path)))
        self.assertEqual(seen, [(1, '/root/a'), (2, '/root/b: c'), (3, '/root/d')])
        self.assertEqual(result['files'], 3)
        self.assertIn('/root/a: OK\n', logged)  # also under Show details
        self.assertEqual(logged[-1], 'Checked 3 files.')

    def test_a_failed_check_is_never_called_clean(self):
        result, _ = self.run_check(['/a'], 2)
        self.assertFalse(result['complete'])
        self.assertIn('did not finish', core_root_scan.outcome(result)[0])
        self.assertTrue(core_root_scan.outcome(result)[2])

    def test_outcomes_say_what_happened(self):
        clean = {'infected': [], 'checked': 3, 'files': 1200, 'complete': True, 'left_out': 0}
        self.assertEqual(core_root_scan.outcome(clean)[0], 'No threats found')
        self.assertIn('1,200 files in 3 skipped locations', core_root_scan.outcome(clean)[1])
        self.assertFalse(core_root_scan.outcome(clean)[2])
        self.assertIn('2 more', core_root_scan.outcome(dict(clean, left_out=2))[1])
        found = dict(clean, infected=[('/x', 'Eicar')])
        self.assertIn('administrator password', core_root_scan.outcome(found)[1])
        # A finding counts even when the check ended early.
        self.assertIn('dangerous', core_root_scan.outcome(dict(found, complete=False))[0])

    def test_requests_stay_under_the_limit_of_the_root_program(self):
        paths = ['/a/' + 'x' * 200] * 10000
        kept, left_out = core_root_scan.limited(paths)
        self.assertEqual(len(kept) + left_out, len(paths))
        self.assertGreater(left_out, 0)
        self.assertLess(len(json.dumps({'database': '/d', 'paths': kept})), root_scan.MAX_REQUEST)
        self.assertEqual(core_root_scan.limited(['/a']), (['/a'], 0))


class SkippedFilesTests(unittest.TestCase):
    def test_paths_are_read_from_clamscan_lines(self):
        for line, path in (('/root/a b: Access denied. ERROR', '/root/a b'),
                           ("/root/x: Can't open file ERROR", '/root/x'),
                           ("WARNING: Can't open file /root/x: Permission denied", '/root/x'),
                           ("ERROR: Can't open file /root/x", '/root/x'),
                           ('/root/a: b: Permission denied', '/root/a: b'),
                           ('Permission denied', '')):
            with self.subTest(line):
                self.assertEqual(denied_path(line), path)

    def test_only_denied_files_are_collected_once_each(self):
        summary = WarningSummary()
        summary.add('/root/a', 'Permission denied')
        summary.add('/root/a', 'Permission denied')
        summary.add('/big', 'exceeds limit', 'limits')
        summary.add('', 'Permission denied')
        self.assertEqual(list(summary.denied), ['/root/a'])

    @unittest.skipIf(os.name == 'nt' or os.geteuid() == 0, 'folder permissions')
    def test_folders_that_cannot_be_read_are_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            locked = Path(folder, 'locked')
            locked.mkdir()
            Path(folder, 'open').write_text('x')
            locked.chmod(0)
            try:
                denied = []
                files = list(iter_scan_files([folder], [], lambda: False, denied.append))
                self.assertEqual(files, [str(Path(folder, 'open'))])
                self.assertEqual(denied, [str(locked)])
                self.assertEqual(list(iter_scan_files([folder], [], lambda: False)), files)  # no listener needed
            finally:
                locked.chmod(stat.S_IRWXU)


if __name__ == '__main__':
    unittest.main()
