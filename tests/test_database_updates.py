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
