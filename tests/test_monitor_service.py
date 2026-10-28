"""Linux user service for folder monitoring; systemctl is always mocked."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backends.linux import MONITOR_UNIT, LinuxBackend


@unittest.skipIf(sys.platform == 'win32', 'Linux backend')
class MonitorServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'XDG_CONFIG_HOME': self.directory.name})
        self.environment.start()
        self.backend = LinuxBackend()
        self.unit = Path(self.directory.name) / 'systemd/user' / MONITOR_UNIT

    def tearDown(self):
        self.environment.stop()
        self.directory.cleanup()

    def test_unit_runs_this_installation_quoted_and_is_skipped_once_removed(self):
        with patch.object(self.backend, 'application_command',
                          return_value=['/usr/bin/python3', '-s', '-E', '/opt/My Apps/100%/main.py', '--monitor']):
            unit = self.backend.monitor_unit()
        self.assertIn('ExecStart="/usr/bin/python3" "-s" "-E" "/opt/My Apps/100%%/main.py" "--monitor"\n', unit)
        self.assertIn('ConditionPathExists=/usr/bin/python3\n', unit)
        self.assertIn('ConditionPathExists=/opt/My Apps/100%%/main.py\n', unit)
        self.assertIn('Restart=on-failure\n', unit)
        self.assertIn('WantedBy=default.target\n', unit)

    def test_default_command_is_this_checkout_with_isolated_python(self):
        command = self.backend.application_command('--monitor')
        self.assertEqual(command[:3], [sys.executable, '-s', '-E'])
        self.assertEqual(Path(command[3]), Path(__file__).resolve().parents[1] / 'main.py')
        self.assertEqual(command[4], '--monitor')

    def test_enable_writes_unit_once_and_disable_removes_it(self):
        with patch.object(self.backend, '_systemctl') as systemctl:
            self.backend.set_monitor_service(True)
            self.assertEqual(self.unit.read_text(), self.backend.monitor_unit())
            self.assertEqual([call.args for call in systemctl.call_args_list],
                             [('daemon-reload',), ('enable', MONITOR_UNIT), ('restart', MONITOR_UNIT)])
            systemctl.reset_mock()
            self.backend.set_monitor_service(True)
            self.assertEqual([call.args for call in systemctl.call_args_list],
                             [('enable', MONITOR_UNIT), ('start', MONITOR_UNIT)])
            systemctl.reset_mock()
            self.backend.set_monitor_service(False)
            self.assertFalse(self.unit.exists())
            self.assertEqual([call.args for call in systemctl.call_args_list],
                             [('disable', '--now', MONITOR_UNIT), ('daemon-reload',)])
            systemctl.reset_mock()
            self.backend.set_monitor_service(False)
            systemctl.assert_not_called()

    def test_systemctl_errors_explain_the_problem(self):
        with patch('backends.linux.shutil.which', return_value=None), \
                self.assertRaisesRegex(OSError, 'needs systemd'):
            self.backend.set_monitor_service(True)
        self.assertFalse(self.unit.exists())
        with patch('backends.linux.shutil.which', return_value='/usr/bin/systemctl'), \
                patch('backends.linux.subprocess.run',
                      return_value=Mock(returncode=1, stderr='Failed to connect to bus\n', stdout='')) as run, \
                self.assertRaisesRegex(OSError, 'Failed to connect to bus'):
            self.backend.set_monitor_service(True)
        self.assertEqual(run.call_args.args[0][:3], ['/usr/bin/systemctl', '--user', 'daemon-reload'])

    def test_instance_lock_is_exclusive_until_closed(self):
        path = Path(self.directory.name) / 'monitor/agent.lock'
        first = self.backend.acquire_instance_lock(path)
        self.assertIsNotNone(first)
        self.assertIsNone(self.backend.acquire_instance_lock(path))
        first.close()
        second = self.backend.acquire_instance_lock(path)
        self.assertIsNotNone(second)
        second.close()


@unittest.skipIf(sys.platform == 'win32', 'Linux backend')
class RemovalTests(unittest.TestCase):
    def test_uninstall_removes_the_invoking_users_service(self):
        from backends.linux import remove_user_monitor_service
        with tempfile.TemporaryDirectory() as home:
            units = Path(home) / '.config/systemd/user'
            (units / 'default.target.wants').mkdir(parents=True)
            unit = units / MONITOR_UNIT
            unit.write_text('[Unit]\n')
            (units / 'default.target.wants' / MONITOR_UNIT).symlink_to(unit)
            other = units / 'other.service'
            other.write_text('[Unit]\n')
            with patch('pwd.getpwnam', return_value=Mock(pw_dir=home, pw_uid=os.getuid())), \
                    patch('backends.linux.shutil.which', return_value='/usr/bin/systemctl'), \
                    patch('backends.linux.subprocess.run') as run:
                self.assertIn('Removed', remove_user_monitor_service('anaisoob'))
            self.assertFalse(unit.exists())
            self.assertFalse((units / 'default.target.wants' / MONITOR_UNIT).is_symlink())
            self.assertTrue(other.exists())
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0], ['/usr/bin/systemctl', '--user', '--machine=anaisoob@.host',
                                           'disable', '--now', MONITOR_UNIT])
            self.assertEqual(commands[1][-1], 'daemon-reload')
            with patch('pwd.getpwnam', return_value=Mock(pw_dir=home, pw_uid=os.getuid())):
                self.assertIsNone(remove_user_monitor_service('anaisoob'))  # nothing left
        with patch('pwd.getpwnam', side_effect=KeyError('nobody')):
            self.assertIsNone(remove_user_monitor_service('missing'))

    def test_uninstall_never_deletes_through_a_link_in_the_users_home(self):
        from backends.linux import remove_user_monitor_service
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as elsewhere:
            target = Path(elsewhere) / MONITOR_UNIT  # for example a file in /etc
            target.write_text('[Unit]\n')
            (Path(home) / '.config/systemd').mkdir(parents=True)
            (Path(home) / '.config/systemd/user').symlink_to(elsewhere)
            with patch('pwd.getpwnam', return_value=Mock(pw_dir=home, pw_uid=os.getuid())), \
                    patch('backends.linux.subprocess.run') as run:
                message = remove_user_monitor_service('anaisoob')
            self.assertIn('Did not remove', message)
            self.assertTrue(target.exists())
            run.assert_not_called()

    def test_cleanup_script_finds_the_user_behind_sudo_or_pkexec(self):
        import importlib.util
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('system_cleanup_script', root / 'packaging/system_cleanup.py')
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        with patch.dict(os.environ, {'SUDO_USER': 'anaisoob'}, clear=True):
            self.assertEqual(script.invoking_user(), 'anaisoob')
        with patch.dict(os.environ, {'SUDO_USER': 'root'}, clear=True):
            self.assertIsNone(script.invoking_user())
        with patch.dict(os.environ, {'PKEXEC_UID': '1000'}, clear=True), \
                patch('pwd.getpwuid', return_value=Mock(pw_name='ana')):
            self.assertEqual(script.invoking_user(), 'ana')
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(script.invoking_user())


@unittest.skipIf(sys.platform == 'win32', 'Linux backend')
class NotificationActionTests(unittest.TestCase):
    def test_gui_started_by_the_agent_gets_the_session_display(self):
        backend = LinuxBackend()
        shown = Mock(returncode=0, stdout="WAYLAND_DISPLAY=wayland-0\nDISPLAY=:0\nOTHER=x\nXAUTHORITY=$'odd\\n'\n")
        with patch.dict(os.environ, {}, clear=True), \
                patch('backends.linux.shutil.which', return_value='/usr/bin/systemctl'), \
                patch('backends.linux.subprocess.run', return_value=shown), \
                patch('subprocess.Popen') as popen:
            backend.open_application('--threats', activation_token='token-9')
        environment = popen.call_args.kwargs['env']
        self.assertEqual(environment['WAYLAND_DISPLAY'], 'wayland-0')
        self.assertEqual(environment['DISPLAY'], ':0')
        self.assertNotIn('OTHER', environment)
        self.assertNotIn('XAUTHORITY', environment)
        self.assertEqual(environment['XDG_ACTIVATION_TOKEN'], 'token-9')
        self.assertEqual(popen.call_args.args[0][-1], '--threats')

    def test_notifications_with_one_key_replace_each_other(self):
        backend = LinuxBackend()
        LinuxBackend._notification_ids.clear()
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0, stdout='17\n')) as run:
            self.assertTrue(backend.send_desktop_notification('Download', 'Waiting', replace='download:a.zip'))
            self.assertIn('--print-id', run.call_args.args[0])
            self.assertFalse(any(a.startswith('--replace-id') for a in run.call_args.args[0]))
            self.assertTrue(backend.send_desktop_notification('Checked', 'Clean', replace='download:a.zip'))
            self.assertIn('--replace-id=17', run.call_args.args[0])
        # Without the newer options, a plain notification is still shown.
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', side_effect=[Mock(returncode=1, stdout=''),
                                                                    Mock(returncode=0, stdout='')]) as run:
            self.assertTrue(backend.send_desktop_notification('Download', 'Waiting', replace='download:b.zip'))
        self.assertNotIn('--print-id', run.call_args.args[0])
        LinuxBackend._notification_ids.clear()

    def test_a_warning_is_one_short_call_without_buttons(self):
        LinuxBackend._notification_ids.clear()
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0, stdout='31\n')) as run, \
                patch('backends.linux.subprocess.Popen') as popen:
            self.assertTrue(LinuxBackend().send_desktop_notification(
                '⚠ LibreWard — dangerous file found', 'eicar.com', warning=True, replace='check:/d/eicar.com'))
        popen.assert_not_called()  # nothing waits for a click
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertIn('--urgency=normal', command)  # moved to the list after a few seconds
        self.assertIn('--icon=dialog-warning', command)
        self.assertFalse(any(argument.startswith('--action') for argument in command))
        self.assertEqual(LinuxBackend._notification_ids['check:/d/eicar.com'], 31)
        LinuxBackend._notification_ids.clear()

    def test_firefox_based_browsers_are_found(self):
        labels = {label for label, _root, kind in LinuxBackend().browser_profile_locations() if kind == 'firefox'}
        self.assertTrue({'Firefox', 'LibreWolf', 'Waterfox', 'Floorp', 'Zen', 'LibreWolf (Flatpak)'} <= labels)

    def test_warnings_use_the_exclamation_mark_icon(self):
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0, stdout='')) as run:
            LinuxBackend().send_desktop_notification('Title', 'Text', warning=True)
        self.assertIn('--icon=dialog-warning', run.call_args.args[0])

    def test_routine_results_stay_visible(self):
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(LinuxBackend().send_desktop_notification('Title', 'Text'))
        command = run.call_args.args[0]
        # GNOME Shell removes these banners at once (the hint while LibreWard has focus).
        self.assertNotIn('--transient', command)
        self.assertNotIn('--hint=string:desktop-entry:libreward', command)
        self.assertIn('--urgency=normal', command)


if __name__ == '__main__':
    unittest.main()
