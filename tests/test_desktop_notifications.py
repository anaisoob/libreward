"""Linux notification delivery must not depend on desktop status icons."""
import subprocess
import unittest
from unittest.mock import patch, Mock

from backends.linux import LinuxBackend


class DesktopNotificationTests(unittest.TestCase):
    def test_delivery_uses_arguments_and_escapes_filename_markup(self):
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(LinuxBackend().send_desktop_notification(
                'LibreWard', 'file <test> & other', warning=True))
        args = run.call_args.args[0]
        self.assertIn('--urgency=critical', args)
        self.assertEqual(args[-2:], ['LibreWard', 'file &lt;test&gt; &amp; other'])
        self.assertEqual(run.call_args.kwargs['timeout'], 5)

    def test_missing_helper_or_failed_service_requests_fallback(self):
        backend = LinuxBackend()
        with patch('backends.linux.shutil.which', return_value=None):
            self.assertFalse(backend.send_desktop_notification('Test', 'Hello'))
        for failure in (OSError('missing'), subprocess.TimeoutExpired('notify-send', 5)):
            with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                    patch('backends.linux.subprocess.run', side_effect=failure):
                self.assertFalse(backend.send_desktop_notification('Test', 'Hello'))
        with patch('backends.linux.shutil.which', return_value='/usr/bin/notify-send'), \
                patch('backends.linux.subprocess.run', return_value=Mock(returncode=1)):
            self.assertFalse(backend.send_desktop_notification('Test', 'Hello'))
