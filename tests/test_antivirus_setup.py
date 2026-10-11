"""Setup recommendations and runtime repair without live installation."""
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

from backends.base import RuntimeInfo
from core.runtime import StartupStatus, setup_components, setup_next_action
import core.updater as updater


class AntivirusSetupTests(unittest.TestCase):
    def setUp(self):
        self.ready = StartupStatus(RuntimeInfo('system-path', 'clamscan', 'freshclam',
                                              'ClamAV 1.5.4', '1.5.4'),
                                   True, True, False, True, 'clamd', False)

    def test_installed_daemon_does_not_need_to_be_running(self):
        self.assertEqual(setup_next_action(self.ready), ('ready', 'Done'))
        self.assertIn(('Parallel scanner', 'Installed — starts when needed'), setup_components(self.ready))

    def test_missing_database_precedes_optional_daemon(self):
        status = replace(self.ready, db_found=False, clamd_path=None)
        self.assertEqual(setup_next_action(status)[0], 'database')
        self.assertFalse(status.can_scan)

    def test_missing_daemon_does_not_block_scanning(self):
        status = replace(self.ready, clamd_path=None)
        self.assertTrue(status.can_scan)
        self.assertEqual(setup_next_action(status)[1], 'Set up parallel scanning')

    def test_missing_updater_requires_runtime_install(self):
        self.assertEqual(setup_next_action(replace(self.ready, freshclam_ok=False))[0], 'runtime')

    def test_running_system_daemon_does_not_require_local_binary(self):
        self.assertEqual(setup_next_action(replace(self.ready, clamd_path=None, clamd_running=True))[0], 'ready')

    def test_repair_allows_same_version_but_never_downgrade(self):
        backend = Mock()
        backend.manages_own_runtime.return_value = True
        backend.detect_clamav_runtime.return_value = self.ready.runtime
        entry = {'latest_version': '1.5.4'}
        with patch.object(updater, 'backend', backend), \
             patch.object(updater, 'fetch_manifest', return_value={}), \
             patch.object(updater, 'get_platform_entry', return_value=entry):
            self.assertIsNone(updater.check_for_updates())
            self.assertEqual(updater.check_for_updates(repair=True), entry)
            entry['latest_version'] = '1.5.3'
            self.assertIsNone(updater.check_for_updates(repair=True))
