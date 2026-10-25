"""Linux user service for folder monitoring; systemctl is always mocked."""
import os
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
class NotificationActionTests(unittest.TestCase):
    def test_open_action_runs_when_chosen(self):
        import subprocess
        import threading
        chosen = threading.Event()
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired('notify-send', 2), 0]
        process.stdout.read.return_value = 'open\n'
        process.stdout.__enter__ = Mock(return_value=process.stdout)
        process.stdout.__exit__ = Mock(return_value=False)
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.Popen', return_value=process) as popen:
            self.assertTrue(LinuxBackend().send_desktop_notification(
                'LibreWard — threat found', 'eicar.com', warning=True, on_open=chosen.set))
            self.assertTrue(chosen.wait(3))
        command = popen.call_args.args[0]
        self.assertIn('--action=open=Open LibreWard', command)
        self.assertIn('--hint=string:desktop-entry:libreward', command)
        self.assertIn('--urgency=critical', command)

    def test_old_notify_send_falls_back_to_plain_notification(self):
        failed = Mock()
        failed.wait.return_value = 1
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.Popen', return_value=failed), \
                patch('backends.linux.subprocess.run',
                      side_effect=[Mock(returncode=1), Mock(returncode=0)]) as run:
            self.assertTrue(LinuxBackend().send_desktop_notification('Title', 'Text', warning=True,
                                                                     on_open=lambda: None))
        plain = run.call_args.args[0]
        self.assertNotIn('--hint=string:desktop-entry:libreward', plain)
        self.assertEqual(plain[-2:], ['Title', 'Text'])

    def test_routine_results_are_transient(self):
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(LinuxBackend().send_desktop_notification('Title', 'Text'))
        self.assertIn('--transient', run.call_args.args[0])
        self.assertIn('--urgency=normal', run.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
