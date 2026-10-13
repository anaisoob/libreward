"""Do not compete with distribution-managed signature downloads."""
import unittest
from unittest.mock import Mock, patch

from backends.linux import LinuxBackend
from core import db_manager


class DatabaseUpdateTests(unittest.TestCase):
    def test_active_service_prevents_manual_update(self):
        backend = Mock()
        backend.manages_own_database.return_value = False
        backend.freshclam_activity.return_value = 'clamav-freshclam.service'
        with patch.object(db_manager, 'backend', backend), patch.object(
                db_manager, '_try_privileged_freshclam') as run:
            result = db_manager.run_freshclam_update('freshclam')
        self.assertTrue(result.pending)
        self.assertFalse(result.success)
        run.assert_not_called()

    def test_lock_race_is_pending_but_other_errors_fail(self):
        backend = Mock()
        backend.manages_own_database.return_value = False
        backend.freshclam_activity.return_value = None
        with patch.object(db_manager, 'backend', backend), patch.object(
                db_manager, '_try_privileged_freshclam') as run:
            run.return_value = (False, 'Failed to lock the log file freshclam.log', False)
            self.assertTrue(db_manager.run_freshclam_update('freshclam').pending)
            run.return_value = (False, 'Download failed', False)
            self.assertEqual(db_manager.run_freshclam_update('freshclam'),
                             (False, 'Download failed'))

    def test_detects_active_service(self):
        backend = LinuxBackend()
        with patch.object(backend, '_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(
                backend, '_firewall_query', return_value=(0, 'active')) as query:
            self.assertEqual(backend.freshclam_activity(), 'clamav-freshclam.service')
        self.assertEqual(query.call_count, 1)

    def test_detects_process_without_systemd(self):
        backend = LinuxBackend()
        with patch.object(backend, '_firewall_executable', side_effect=lambda name: '/usr/bin/pgrep' if name == 'pgrep' else None), patch.object(
                backend, '_firewall_query', return_value=(0, '1234')):
            self.assertIsNotNone(backend.freshclam_activity())

    def test_no_updater_detected(self):
        backend = LinuxBackend()
        with patch.object(backend, '_firewall_executable', return_value=None):
            self.assertIsNone(backend.freshclam_activity())


class FedoraClamAVTests(unittest.TestCase):
    """Fedora ships ClamAV tools in sbin and an `Example` line in freshclam.conf."""
    def test_clamav_tools_are_found_in_sbin_without_it_in_path(self):
        def which(name, path=None):
            return f'/usr/sbin/{name}' if path and '/usr/sbin' in path else None
        with patch('backends.linux.shutil.which', side_effect=which):
            self.assertEqual(LinuxBackend.__new__(LinuxBackend).find_clamd('/usr/bin/clamscan'), '/usr/sbin/clamd')

    def test_example_line_is_detected_only_when_active(self):
        import tempfile
        from pathlib import Path
        from backends.linux import freshclam_example_config
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory, 'freshclam.conf')
            config.write_text('# Comment out or remove the line below.\nExample\nDatabaseOwner clamupdate\n')
            self.assertEqual(freshclam_example_config([str(config)]), str(config))
            config.write_text('# Comment out or remove the line below.\n#Example\nDatabaseOwner clamupdate\n')
            self.assertIsNone(freshclam_example_config([str(config)]))
            self.assertIsNone(freshclam_example_config([str(Path(directory, 'missing.conf'))]))

    def run_helper(self, config_text):
        import json
        import sys
        import tempfile
        from pathlib import Path
        from backends.linux import FRESHCLAM_HELPER
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__('shutil').rmtree, directory)
        config = Path(directory, 'freshclam.conf')
        config.write_text(config_text)
        record = Path(directory, 'record.json')
        fake = Path(directory, 'freshclam')
        # Records its arguments and the config it was given, like a real freshclam reads it.
        fake.write_text(f'#!{sys.executable}\nimport json, sys\nargs = sys.argv[1:]\n'
                        'text = open(args[1]).read() if args[:1] == ["--config-file"] else None\n'
                        f'json.dump({{"args": args, "config": text}}, open({str(record)!r}, "w"))\n')
        fake.chmod(0o755)
        namespace = {'__name__': 'test_freshclam_helper'}
        exec(FRESHCLAM_HELPER, namespace)
        code = namespace['run'](str(fake), configs=(str(config),), require_root=False)
        return code, json.loads(record.read_text()), config

    def test_helper_uses_a_copy_without_example_and_keeps_the_system_config(self):
        import os
        original = '# Comment out or remove the line below.\nExample\nDatabaseOwner clamupdate\nDatabaseMirror database.clamav.net\n'
        code, record, config = self.run_helper(original)
        self.assertEqual(code, 0)
        self.assertEqual(record['args'][0], '--config-file')
        self.assertNotIn('\nExample\n', record['config'])
        self.assertIn('DatabaseOwner clamupdate\nDatabaseMirror database.clamav.net\n', record['config'])
        self.assertFalse(os.path.exists(record['args'][1]))
        self.assertEqual(config.read_text(), original)

    def test_helper_runs_plain_freshclam_when_config_is_ready(self):
        code, record, _ = self.run_helper('DatabaseOwner clamupdate\n')
        self.assertEqual((code, record['args']), (0, []))

    def test_helper_refuses_a_writable_executable(self):
        import tempfile
        from pathlib import Path
        from backends.linux import FRESHCLAM_HELPER
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory, 'freshclam')
            fake.write_text('#!/bin/sh\n')
            fake.chmod(0o777)
            namespace = {'__name__': 'test_freshclam_helper'}
            exec(FRESHCLAM_HELPER, namespace)
            with self.assertRaises(SystemExit):
                namespace['run'](str(fake), configs=(), require_root=False)

    def test_privileged_update_uses_the_backend_command(self):
        backend = Mock()
        backend.freshclam_privileged_command.return_value = ['/usr/bin/python3', '-I', '-c', 'helper', '/usr/bin/freshclam']
        with patch.object(db_manager, 'backend', backend), patch.object(db_manager, '_is_root', return_value=False), \
                patch.object(db_manager, '_find_pkexec', return_value='/usr/bin/pkexec'), \
                patch.object(db_manager, '_run_freshclam_cmd', return_value=(True, 'updated')) as run:
            db_manager._try_privileged_freshclam('/usr/bin/freshclam')
        self.assertEqual(run.call_args.args[0],
                         ['/usr/bin/pkexec', '/usr/bin/python3', '-I', '-c', 'helper', '/usr/bin/freshclam'])

    def test_helper_is_used_only_while_the_example_line_is_active(self):
        backend = LinuxBackend.__new__(LinuxBackend)
        with patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/python3'), \
                patch('backends.linux.freshclam_example_config', return_value='/etc/freshclam.conf'):
            self.assertEqual(backend.freshclam_privileged_command('/usr/bin/freshclam')[:3], ['/usr/bin/python3', '-I', '-c'])
        with patch('backends.linux.freshclam_example_config', return_value=None):
            self.assertEqual(backend.freshclam_privileged_command('/usr/bin/freshclam'), ['/usr/bin/freshclam'])


class FreshclamVersionTests(unittest.TestCase):
    def test_version_check_survives_fedoras_unedited_config(self):
        import sys
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory, 'freshclam.conf')
            config.write_text('# Comment out or remove the line below.\nExample\nDatabaseOwner clamupdate\n')
            fake = Path(directory, 'freshclam')
            # Like Fedora's freshclam: --version parses the config and rejects `Example`.
            fake.write_text(f'#!{sys.executable}\nimport sys\nargs = sys.argv[1:]\n'
                            f'path = args[1] if args[:1] == ["--config-file"] else {str(config)!r}\n'
                            'if any(line.strip() == "Example" for line in open(path)):\n'
                            '    print("ERROR: Can\'t open/parse the config file " + path); sys.exit(1)\n'
                            'print("ClamAV 1.4.3/27800/Tue Oct 13 2026")\n')
            fake.chmod(0o755)
            backend = LinuxBackend.__new__(LinuxBackend)
            with patch('backends.linux.freshclam_example_config', return_value=str(config)):
                self.assertIsNone(backend.get_clamav_version(str(fake)))
                self.assertEqual(backend.get_freshclam_version(str(fake)), 'ClamAV 1.4.3/27800/Tue Oct 13 2026')
            self.assertIn('\nExample\n', config.read_text())

    def test_dnf_asks_for_freshclam_by_file_path(self):
        backend = LinuxBackend.__new__(LinuxBackend)
        with patch.object(backend, 'distro_info', return_value={'pkg_manager': 'dnf'}):
            _, spec = backend._clamav_install_spec()
        self.assertEqual(spec[2], ['clamav', '/usr/bin/freshclam', 'clamd'])
