"""Database updates: a current system database, LibreWard's own, and the system updater."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backends.linux import LinuxBackend
from core import db_manager


class DatabaseUpdateTests(unittest.TestCase):
    def backend(self, *, current=False, activity=None):
        backend = Mock()
        backend.system_database_current.return_value = current
        backend.freshclam_activity.return_value = activity
        return backend

    def test_current_system_database_needs_no_download(self):
        with patch.object(db_manager, 'backend', self.backend(current=True)), \
                patch.object(db_manager, '_run_freshclam_cmd') as run:
            ok, message = db_manager.run_freshclam_update('/usr/bin/freshclam')
        self.assertTrue(ok)
        self.assertIn('up to date', message)
        run.assert_not_called()

    def test_system_updater_fetching_a_first_database_is_awaited(self):
        with patch.object(db_manager, 'backend', self.backend(activity='clamav-freshclam.service')), \
                patch('core.runtime.database_files', return_value=[]), \
                patch.object(db_manager, '_run_freshclam_cmd') as run:
            result = db_manager.run_freshclam_update('/usr/bin/freshclam')
        self.assertTrue(result.pending)
        run.assert_not_called()

    def test_own_database_updates_as_the_user_with_own_config(self):
        with patch.object(db_manager, 'backend', self.backend(activity='clamav-freshclam.service')), \
                patch('core.runtime.database_files', return_value=['/var/lib/clamav/main.cvd']), \
                patch.object(db_manager, 'generate_freshclam_conf', return_value='/home/u/.local/share/libreward/freshclam.conf'), \
                patch.object(db_manager, '_run_freshclam_cmd', return_value=(True, 'updated')) as run:
            self.assertEqual(db_manager.run_freshclam_update('/usr/bin/freshclam'), (True, 'updated'))
        # No pkexec or sudo: the user's own directory needs no password.
        self.assertEqual(run.call_args.args[0],
                         ['/usr/bin/freshclam', '--config-file', '/home/u/.local/share/libreward/freshclam.conf'])

    def test_lock_race_is_pending_but_other_errors_fail(self):
        with patch.object(db_manager, 'backend', self.backend()), \
                patch.object(db_manager, 'generate_freshclam_conf', return_value='/tmp/freshclam.conf'), \
                patch.object(db_manager, '_run_freshclam_cmd') as run:
            run.return_value = (False, 'Failed to lock the log file freshclam.log')
            self.assertTrue(db_manager.run_freshclam_update('freshclam').pending)
            run.return_value = (False, 'Download failed')
            self.assertEqual(db_manager.run_freshclam_update('freshclam'), (False, 'Download failed'))

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


class CombinedDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.system, self.own = root / 'system', root / 'own'
        self.system.mkdir()
        self.own.mkdir()
        self.backend = LinuxBackend.__new__(LinuxBackend)
        patcher = patch('backends.linux.SYSTEM_DATABASE', self.system)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(LinuxBackend, 'db_dir', return_value=self.own)
        patcher.start()
        self.addCleanup(patcher.stop)

    def database(self, directory, age_days):
        path = directory / 'daily.cld'
        path.write_bytes(b'db')
        stamp = time.time() - age_days * 86400
        import os
        os.utime(path, (stamp, stamp))

    def test_current_system_database_is_preferred(self):
        self.database(self.system, 1)
        self.database(self.own, 0)
        self.assertTrue(self.backend.system_database_current())
        self.assertEqual(self.backend.system_db_locations(), [self.system, self.own])

    def test_stale_or_missing_system_database_uses_libreward_own(self):
        self.database(self.system, 10)
        self.database(self.own, 0)
        self.assertFalse(self.backend.system_database_current())
        self.assertEqual(self.backend.system_db_locations(), [self.own, self.system])
        (self.system / 'daily.cld').unlink()
        self.assertEqual(self.backend.system_db_locations(), [self.own, self.system])

    def test_stale_system_database_beats_having_none(self):
        self.database(self.system, 10)
        self.assertEqual(self.backend.system_db_locations(), [self.system, self.own])

    def test_scans_name_the_chosen_database(self):
        import scanner
        self.database(self.own, 0)
        from backends.base import RuntimeInfo
        runtime = RuntimeInfo('system-path', '/usr/bin/clamscan', '/usr/bin/freshclam', 'ClamAV 1.4.6', '1.4.6')
        with patch.object(scanner, 'backend', self.backend), \
                patch.object(self.backend, 'detect_clamav_runtime', return_value=runtime, create=True):
            command = scanner.build_clamscan_command(self.temp.name, [])
        self.assertIn(f'--database={self.own.resolve()}', command)


class FedoraClamAVTests(unittest.TestCase):
    """Fedora ships ClamAV tools in sbin and a root-only /etc/freshclam.conf with `Example`."""
    def test_clamav_tools_are_found_in_sbin_without_it_in_path(self):
        def which(name, path=None):
            return f'/usr/sbin/{name}' if path and '/usr/sbin' in path else None
        with patch('backends.linux.shutil.which', side_effect=which):
            self.assertEqual(LinuxBackend.__new__(LinuxBackend).find_clamd('/usr/bin/clamscan'), '/usr/sbin/clamd')

    def test_version_check_does_not_need_the_system_config(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory, 'freshclam')
            # Like Fedora's freshclam: --version parses the unreadable system config.
            fake.write_text(f'#!{sys.executable}\nimport sys\nargs = sys.argv[1:]\n'
                            'if args[:1] != ["--config-file"]:\n'
                            '    print("ERROR: Can\'t open/parse the config file /etc/freshclam.conf"); sys.exit(1)\n'
                            'assert open(args[1]).read() == ""\n'
                            'print("ClamAV 1.4.6")\n')
            fake.chmod(0o755)
            backend = LinuxBackend.__new__(LinuxBackend)
            self.assertIsNone(backend.get_clamav_version(str(fake)))
            self.assertEqual(backend.get_freshclam_version(str(fake)), 'ClamAV 1.4.6')

    def test_dnf_asks_for_freshclam_by_file_path(self):
        backend = LinuxBackend.__new__(LinuxBackend)
        with patch.object(backend, 'distro_info', return_value={'pkg_manager': 'dnf'}):
            _, spec = backend._clamav_install_spec()
        self.assertEqual(spec[2], ['clamav', '/usr/bin/freshclam', 'clamd'])
