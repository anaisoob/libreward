"""System authorization and installation tests never install real packages."""
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from backends.linux import LinuxBackend
from backends.windows import WindowsBackend
from core.authorization import AuthorizationError


class SystemInstallTests(unittest.TestCase):
    def setUp(self):
        self.backend = LinuxBackend()

    def test_missing_pkexec_has_distro_specific_manual_recovery(self):
        with patch.object(self.backend, '_trusted_firewall_executable', return_value=None), patch.object(self.backend, 'distro_info', return_value={'pkg_manager': 'apt'}):
            status = self.backend.authorization_status()
            self.assertFalse(status.available)
            self.assertEqual(status.install_command, 'sudo apt install pkexec')
            with self.assertRaises(AuthorizationError) as caught:
                self.backend._require_authorizer()
            self.assertEqual(caught.exception.kind, 'missing')

    def test_cancel_and_agent_failure_are_distinct(self):
        for code, kind in ((126, 'cancelled'), (127, 'unavailable')):
            with self.subTest(code=code), self.assertRaises(AuthorizationError) as caught:
                self.backend._check_authorization_exit(code)
            self.assertEqual(caught.exception.kind, kind)
        self.backend._check_authorization_exit(0)

    def test_fixed_package_plans_never_refresh_or_upgrade_repositories(self):
        packages = {'apt': 'clamav-freshclam', 'pacman': 'clamav', 'dnf': 'clamd', 'apk': 'freshclam', 'zypper': 'clamav'}
        for manager, expected in packages.items():
            with self.subTest(manager=manager), patch.object(self.backend, 'distro_info', return_value={'pkg_manager': manager}), patch.object(self.backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name):
                plan = self.backend.clamav_install_plan()
                self.assertIn(expected, plan.packages)
                self.assertNotIn('upgrade', plan.command)
                self.assertNotIn('-Sy', plan.command)
                self.assertNotIn('update', plan.command.split())

    def test_unknown_manager_is_manual_only(self):
        with patch.object(self.backend, 'distro_info', return_value={'pkg_manager': 'unknown'}), patch.object(self.backend, 'start_process') as start:
            self.assertIsNone(self.backend.clamav_install_plan())
            with self.assertRaises(RuntimeError):
                self.backend.install_clamav()
            start.assert_not_called()
        self.assertIsNone(WindowsBackend().clamav_install_plan())

    def test_install_uses_fixed_pkexec_arguments_and_streams_output(self):
        process = SimpleNamespace(stdout=io.StringIO('Downloading packages…\nInstalled\n'), wait=lambda: 0)
        messages = []
        with patch.object(self.backend, 'distro_info', return_value={'pkg_manager': 'apt'}), patch.object(self.backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(self.backend, 'start_process', return_value=process) as start:
            self.backend.install_clamav(log=messages.append)
        self.assertEqual(start.call_args.args[0], ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/apt-get', 'install', '--assume-yes', '--no-remove', 'clamav', 'clamav-freshclam', 'clamav-daemon'])
        self.assertEqual(start.call_args.kwargs['encoding'], 'utf-8')
        self.assertEqual(start.call_args.kwargs['errors'], 'replace')
        self.assertIn('Installed\n', messages)

    def test_failed_install_is_not_success_and_missing_auth_never_starts(self):
        process = SimpleNamespace(stdout=io.StringIO('error\n'), wait=lambda: 1)
        with patch.object(self.backend, 'distro_info', return_value={'pkg_manager': 'apt'}), patch.object(self.backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(self.backend, 'start_process', return_value=process):
            with self.assertRaisesRegex(RuntimeError, 'did not complete'):
                self.backend.install_clamav()
        with patch.object(self.backend, 'distro_info', return_value={'pkg_manager': 'apt'}), patch.object(self.backend, '_trusted_firewall_executable', side_effect=lambda name: None if name == 'pkexec' else '/usr/bin/' + name), patch.object(self.backend, 'start_process') as start:
            with self.assertRaises(AuthorizationError):
                self.backend.install_clamav()
            start.assert_not_called()
