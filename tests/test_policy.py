"""Administrator policy: only a root-owned file counts, and it replaces the user's settings."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import policy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.file = Path(directory.name) / 'policy.json'
        patcher = patch.object(policy.backend, 'policy_file', return_value=self.file)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, data):
        self.file.write_text(json.dumps(data))

    def test_a_file_that_other_users_could_write_is_ignored(self):
        self.write({'settings': {'scheduled_scan': 'weekly'}})
        if os.geteuid() != 0:
            self.assertFalse(policy._trusted(self.file))  # owned by this user, not root
            self.assertEqual(policy.load_policy()['settings'], {})

    def test_valid_settings_apply_and_invalid_ones_are_dropped(self):
        self.write({'settings': {'scheduled_scan': 'weekly', 'watch_folders_enabled': 'yes',
                                 'watched_folders': ['~/Downloads'], 'qt_theme': 'light',
                                 'auto_update_database': True},
                    'dangerous_files': 'quarantine'})
        with patch.object(policy, '_trusted', return_value=True):
            loaded = policy.load_policy()
            merged = policy.apply_policy({'scheduled_scan': 'off', 'qt_theme': 'dark'})
        self.assertEqual(loaded['settings'], {'scheduled_scan': 'weekly', 'auto_update_database': True,
                                              'watched_folders': [os.path.expanduser('~/Downloads')]})
        self.assertEqual(loaded['dangerous_files'], 'quarantine')
        self.assertEqual((merged['scheduled_scan'], merged['qt_theme']), ('weekly', 'dark'))

    def test_settings_are_loaded_with_the_policy_also_without_a_settings_file(self):
        import config
        self.write({'settings': {'watch_folders_enabled': True}})
        missing = Path(self.file.parent) / 'missing.json'
        with patch.object(policy, '_trusted', return_value=True), patch.object(config, 'CONFIG_FILE', missing):
            self.assertEqual(config.load_config(), {'watch_folders_enabled': True})
        with patch.object(config, 'CONFIG_FILE', missing):
            self.file.unlink()
            self.assertIsNone(config.load_config())

    def test_no_policy_and_broken_files_change_nothing(self):
        self.assertEqual(policy.load_policy(), {'settings': {}, 'dangerous_files': 'ask'})
        self.file.write_text('{"settings": ')
        with patch.object(policy, '_trusted', return_value=True):
            self.assertEqual(policy.load_policy()['settings'], {})
            self.assertEqual(policy.apply_policy({'a': 1}), {'a': 1})
        self.file.write_text(' ' * (policy.MAX_BYTES + 1))
        with patch.object(policy, '_trusted', return_value=True):
            self.assertEqual(policy.load_policy()['settings'], {})

    def test_the_signature_follows_the_file(self):
        self.assertIsNone(policy.policy_signature())
        self.write({'settings': {}})
        first = policy.policy_signature()
        self.write({'settings': {'scheduled_scan': 'daily'}})
        self.assertNotEqual(policy.policy_signature(), first)


if __name__ == '__main__':
    unittest.main()
