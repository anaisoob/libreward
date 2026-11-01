"""The supported application entry point always launches Qt."""
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipIf(os.name == 'nt' or importlib.util.find_spec('PySide6') is None, 'a real window on Linux')
class QuitSignalTests(unittest.TestCase):
    def assert_quits_on(self, number):
        with tempfile.TemporaryDirectory() as temporary:
            folders = {name: Path(temporary, name) for name in ('config', 'data', 'runtime', 'home')}
            for folder in folders.values():
                folder.mkdir(mode=0o700)
            environment = dict(os.environ, QT_QPA_PLATFORM='offscreen', HOME=str(folders['home']),
                               XDG_CONFIG_HOME=str(folders['config']), XDG_DATA_HOME=str(folders['data']),
                               XDG_RUNTIME_DIR=str(folders['runtime']))
            process = subprocess.Popen([sys.executable, 'main.py'], cwd=ROOT, env=environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(process.wait)
            self.addCleanup(process.kill)
            time.sleep(3)  # the window and the setup question are open
            self.assertIsNone(process.poll())
            process.send_signal(number)
            self.assertEqual(process.wait(timeout=10), 0)

    def test_ctrl_c_ends_the_application(self):
        self.assert_quits_on(signal.SIGINT)

    def test_a_termination_request_ends_the_application(self):
        self.assert_quits_on(signal.SIGTERM)


class LauncherTests(unittest.TestCase):
    def test_default_launch_uses_qt(self):
        run = Mock(return_value=0)
        with patch.object(sys, 'argv', ['main.py']), patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}):
            self.assertEqual(main.main(), 0)
        run.assert_called_once_with(autostart=False, threats=False)

    def test_preview_flag_still_launches_qt(self):
        run = Mock(return_value=0)
        with patch.object(sys, 'argv', ['main.py', '--qt']), patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}):
            self.assertEqual(main.main(), 0)
        run.assert_called_once_with(autostart=False, threats=False)

    def test_old_login_autostart_entry_is_passed_on_for_removal(self):
        run = Mock(return_value=0)
        with patch.object(sys, 'argv', ['main.py', '--autostart']), patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}):
            self.assertEqual(main.main(), 0)
        run.assert_called_once_with(autostart=True, threats=False)
