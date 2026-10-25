"""Missing components are reported with install commands for the platform."""
import io
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main
from backends.linux import LinuxBackend
from core.dependencies import missing_components, missing_message


def failing_import(missing):
    from importlib import import_module

    def importer(name):
        if name in missing:
            raise ImportError(f'No module named {name!r}')
        return import_module(name)

    return importer


class MissingComponentTests(unittest.TestCase):
    def test_import_failures_are_collected_with_reasons(self):
        with patch('core.dependencies.import_module', side_effect=failing_import({'watchdog.observers'})):
            self.assertEqual(missing_components(['watchdog']), {'watchdog': "No module named 'watchdog.observers'"})
        with patch('core.dependencies.import_module'):
            self.assertEqual(missing_components(['pyside6', 'qtnetwork', 'watchdog']), {})

    def test_message_names_component_and_install_command(self):
        with patch('core.dependencies.backend.dependency_install_commands',
                   return_value=['sudo dnf install python3-watchdog']):
            message = missing_message({'watchdog': 'missing'}, 'Folder monitoring')
        self.assertIn('Folder monitoring needs watchdog', message)
        self.assertIn('Install with:\nsudo dnf install python3-watchdog', message)
        with patch('core.dependencies.backend.dependency_install_commands', return_value=[]):
            self.assertIn('with your package manager', missing_message({'notify-send': ''}, 'Notifications'))


@unittest.skipIf(sys.platform == 'win32', 'Linux backend')
class LinuxInstallCommandTests(unittest.TestCase):
    def commands(self, manager, components, *, virtual_environment=False):
        backend = LinuxBackend()
        prefix = '/home/user/app/.venv' if virtual_environment else sys.base_prefix
        with patch.object(backend, 'distro_info', return_value={'pkg_manager': manager}), \
                patch.object(sys, 'prefix', prefix):
            return backend.dependency_install_commands(components)

    def test_distribution_packages(self):
        self.assertEqual(self.commands('dnf', ['pyside6', 'qtnetwork', 'watchdog', 'notify-send']),
                         ['sudo dnf install python3-pyside6 python3-watchdog libnotify'])
        self.assertEqual(self.commands('apt', ['qtnetwork', 'notify-send']),
                         ['sudo apt install python3-pyside6.qtnetwork libnotify-bin'])
        self.assertEqual(self.commands('pacman', ['watchdog']), ['sudo pacman -S --needed python-watchdog'])
        self.assertEqual(self.commands('zypper', ['watchdog']), ["sudo zypper install 'python3dist(watchdog)'"])

    def test_virtual_environment_installs_python_packages_there(self):
        commands = self.commands('dnf', ['watchdog', 'notify-send'], virtual_environment=True)
        self.assertEqual(len(commands), 2)
        self.assertTrue(commands[0].endswith('uv sync') or ' -m pip install -r ' in commands[0], commands)
        self.assertEqual(commands[1], 'sudo dnf install libnotify')

    def test_unknown_distribution(self):
        self.assertEqual(self.commands('', ['notify-send']), [])
        self.assertEqual(len(self.commands('', ['watchdog'])), 1)

    def test_error_without_gui_uses_a_dialog_then_a_notification(self):
        backend = LinuxBackend()
        with patch('backends.linux.shutil.which', side_effect=lambda name: f'/usr/bin/{name}' if name == 'zenity' else None), \
                patch('backends.linux.subprocess.run') as run:
            backend.show_error_without_gui('LibreWard cannot start', 'needs <PySide6> & more')
        self.assertEqual(run.call_args.args[0],
                         ['/usr/bin/zenity', '--error', '--title=LibreWard cannot start',
                          '--text=needs &lt;PySide6&gt; &amp; more'])
        with patch('backends.linux.shutil.which', return_value=None), \
                patch.object(backend, 'send_desktop_notification') as notify:
            backend.show_error_without_gui('Title', 'Text')
        notify.assert_called_once_with('Title', 'Text', warning=True)

    def test_monitor_unit_does_not_restart_for_missing_components(self):
        self.assertIn('RestartPreventExitStatus=78\n', LinuxBackend().monitor_unit())


class LauncherDependencyTests(unittest.TestCase):
    def test_missing_qt_is_shown_without_a_terminal_and_gui_is_not_started(self):
        run = Mock(return_value=0)
        stderr = io.StringIO()
        with patch.object(sys, 'argv', ['main.py']), \
                patch.dict(sys.modules, {'ui.main_window': SimpleNamespace(run=run)}), \
                patch('core.dependencies.import_module', side_effect=failing_import({'PySide6.QtNetwork'})), \
                patch('core.dependencies.backend.dependency_install_commands',
                      return_value=['sudo apt install python3-pyside6.qtnetwork']), \
                patch('backends.backend.show_error_without_gui') as shown, \
                patch.object(sys, 'stderr', stderr):
            self.assertEqual(main.main(), 1)
        run.assert_not_called()
        title, message = shown.call_args.args
        self.assertEqual(title, 'LibreWard cannot start')
        self.assertIn('the PySide6 network module', message)
        self.assertIn('sudo apt install python3-pyside6.qtnetwork', stderr.getvalue())

    def test_old_autostart_entry_never_shows_a_dialog(self):
        with patch.object(sys, 'argv', ['main.py', '--autostart']), \
                patch('core.dependencies.import_module', side_effect=failing_import({'PySide6.QtWidgets'})), \
                patch('backends.backend.show_error_without_gui') as shown, \
                patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(main.main(), 1)
        shown.assert_not_called()


if __name__ == '__main__':
    unittest.main()
