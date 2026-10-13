"""The supported application entry point always launches Qt."""
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main


class LauncherTests(unittest.TestCase):
    def test_default_launch_uses_qt(self):
        run = Mock(return_value=0)
        with patch.object(sys, 'argv', ['main.py']), patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}):
            self.assertEqual(main.main(), 0)
        run.assert_called_once_with(autostart=False)

    def test_preview_flag_still_launches_qt(self):
        run = Mock(return_value=0)
        with patch.object(sys, 'argv', ['main.py', '--qt']), patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}):
            self.assertEqual(main.main(), 0)
        run.assert_called_once_with(autostart=False)

    def test_old_login_autostart_entry_is_passed_on_for_removal(self):
        run = Mock(return_value=0)
        with patch.object(sys, 'argv', ['main.py', '--autostart']), patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}):
            self.assertEqual(main.main(), 0)
        run.assert_called_once_with(autostart=True)
