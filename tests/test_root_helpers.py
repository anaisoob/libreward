"""Installed root programs: one per polkit action, each validating its own arguments."""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backends import linux_root
from backends.linux import LinuxBackend
from core.firewall import FirewallRemoval, FirewallRule

ROOT = Path(__file__).resolve().parent.parent
HELPERS = Path('/usr/libexec/libreward')


def trusted(name):
    return '/usr/bin/' + name


class ClientTests(unittest.TestCase):
    """With a package installed, pkexec starts a fixed program instead of python3 -c."""

    def backend(self):
        backend = LinuxBackend()
        patch.object(backend, '_root_helper', side_effect=lambda name: str(HELPERS / name)).start()
        patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec').start()
        patch.object(backend, '_trusted_firewall_executable', side_effect=trusted).start()
        self.addCleanup(patch.stopall)
        return backend

    def test_from_source_there_is_no_helper(self):
        # This checkout is not owned by root, so pkexec gets python3 with the helper code.
        self.assertIsNone(LinuxBackend()._root_helper('system-check'))

    def test_helpers_are_looked_up_next_to_the_installed_application(self):
        backend = LinuxBackend()
        prefix = Path(sys.modules['backends.linux'].__file__).resolve().parents[3]
        wanted = prefix / 'lib/libreward/firewall-read'
        with patch.object(LinuxBackend, '_root_executable', side_effect=lambda path: str(path) if path == wanted else None):
            self.assertEqual(backend._root_helper('firewall-read'), str(wanted))

    def installed_with_prefix(self, prefix):
        """(temporary folder, code result) of an application installed by `make install`."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        subprocess.run(['make', '-s', 'install', f'DESTDIR={directory.name}', f'PREFIX={prefix}'],
                       cwd=Path(__file__).resolve().parent.parent, check=True, capture_output=True)
        return Path(directory.name)

    def test_an_installed_application_finds_its_programs(self):
        for prefix in ('/usr', '/usr/local'):
            with self.subTest(prefix):
                stage = self.installed_with_prefix(prefix)
                application = stage / prefix.lstrip('/') / 'share/libreward'
                code = ('import sys\nfrom pathlib import Path\n'
                        f'sys.path.insert(0, {str(application)!r})\n'
                        'from backends.linux import LinuxBackend\n'
                        'LinuxBackend._root_executable = staticmethod(lambda path: str(path) if Path(path).exists() else None)\n'
                        'print(LinuxBackend()._root_helper("scan-files"))\n'
                        'print(repr(LinuxBackend().password_note()))\n')
                output = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True).stdout
                self.assertEqual(output.split(), [str(stage / prefix.lstrip('/') / 'libexec/libreward/scan-files'), "''"])

    def test_the_policy_goes_where_polkit_reads_it_for_any_prefix(self):
        for prefix in ('/usr', '/usr/local'):
            with self.subTest(prefix):
                stage = self.installed_with_prefix(prefix)
                policy = stage / 'usr/share/polkit-1/actions/io.github.anaisoob.LibreWard.policy'
                self.assertIn(f'{prefix}/libexec/libreward/scan-files', policy.read_text())
                self.assertFalse((stage / 'usr/local/share/polkit-1').exists())

    def test_system_check_passes_no_arguments(self):
        backend = self.backend()
        process = Mock(returncode=0)
        process.communicate.return_value = ('{"findings": [], "checks": ["Root"]}', '')
        with patch.object(backend, 'start_process', return_value=process) as start:
            self.assertEqual(backend.deep_system_check(), ([], ['Root']))
        self.assertEqual(start.call_args.args[0],
                         ['/usr/bin/pkexec', '--disable-internal-agent', str(HELPERS / 'system-check')])

    def test_internet_protection_passes_only_mode_and_service(self):
        from core.internet import PreparedDomains
        backend = self.backend()
        process = Mock(returncode=0)
        process.communicate.return_value = ('{"count": 1, "digest": "d"}', None)
        states = [{'supported': True, 'engine': 'sqlite-setup', 'mode': 'resolved'},
                  {'count': 1, 'supported': True, 'active': True, 'upstream': 'quad9'}]
        with tempfile.NamedTemporaryFile() as payload, \
                patch.object(backend, 'inspect_internet_protection', side_effect=states), \
                patch.object(backend, 'start_process', return_value=process) as start:
            backend.apply_internet_protection(PreparedDomains(payload.name, 1, 'd'), upstream='quad9')
        self.assertEqual(start.call_args.args[0], ['/usr/bin/pkexec', '--disable-internal-agent',
                                                   str(HELPERS / 'internet-protection'), 'resolved', 'quad9'])

    def test_firewall_read_passes_only_the_tool(self):
        backend = self.backend()
        with patch.object(backend, '_firewall_query', return_value=(0, 'Status: active')) as query:
            snapshot = backend.inspect_firewall(privileged=True, tool_name='UFW')
        self.assertEqual(snapshot.tools[0].state, 'Active')
        query.assert_called_once_with(['/usr/bin/pkexec', '--disable-internal-agent',
                                       str(HELPERS / 'firewall-read'), 'UFW'], timeout=120)

    def change(self, backend, **change):
        def respond(command, *, timeout):
            marker = command[-1]
            return 0, f'done\n{marker}:CHANGE:0\nStatus: active\n{marker}:READ:0'

        with patch.object(backend, '_firewall_query', side_effect=respond) as query:
            self.assertTrue(backend.change_firewall('UFW', **change).success)
        return query.call_args.args[0]

    def test_root_builds_the_same_firewall_change_as_the_application(self):
        backend = self.backend()
        changes = [{'rule': FirewallRule('allow', 'both', 'lan', 'tcp', '22', '192.168.1.0/24')},
                   {'removal': FirewallRemoval('ufw allow 22/tcp')}, {'enabled': False}]
        for change in changes:
            with self.subTest(change):
                command = self.change(backend, **change)
                self.assertEqual(command[:3], ['/usr/bin/pkexec', '--disable-internal-agent',
                                               str(HELPERS / 'firewall-change')])
                request, marker = command[3:]
                expected = backend.firewall_change_script('UFW', marker=marker, **change)[1]
                with patch.object(linux_root.os, 'geteuid', return_value=0), \
                        patch.object(LinuxBackend, '_trusted_firewall_executable', side_effect=trusted), \
                        patch.object(linux_root.os, 'execv') as execv:
                    linux_root.main('firewall-change', [request, marker])
                execv.assert_called_once_with('/usr/bin/sh', ['/usr/bin/sh', '-c', expected])


class RootProgramTests(unittest.TestCase):
    """What a user process can send to an installed program."""

    def run_as_root(self, action, arguments):
        errors = io.StringIO()
        with patch.object(linux_root.os, 'geteuid', return_value=0), \
                patch.object(linux_root.os, 'execv') as execv, \
                patch.object(LinuxBackend, '_trusted_firewall_executable', side_effect=trusted), \
                patch('sys.stderr', errors):
            code = linux_root.main(action, arguments)
        return code, errors.getvalue(), execv

    def test_needs_root(self):
        if os.geteuid() == 0:
            self.skipTest('runs as root')
        with patch('sys.stderr', io.StringIO()) as errors:
            self.assertEqual(linux_root.main('system-check', []), 1)
        self.assertIn('runs as root through pkexec', errors.getvalue())

    def test_firewall_change_refuses_anything_but_a_valid_change(self):
        marker = 'LIBREWARD_' + '0' * 32
        rule = {'action': 'allow', 'direction': 'in', 'scope': 'internet', 'protocol': 'tcp', 'port': '22'}
        refused = [
            [json.dumps({'tool': 'UFW', 'rule': dict(rule, port='22; rm -rf /')}), marker],
            [json.dumps({'tool': 'UFW', 'rule': dict(rule, program='/bin/sh')}), marker],
            [json.dumps({'tool': 'UFW', 'rule': rule, 'enabled': True}), marker],
            [json.dumps({'tool': 'UFW', 'enabled': 'yes'}), marker],
            [json.dumps({'tool': 'nftables', 'enabled': True}), marker],
            [json.dumps({'tool': 'UFW', 'removal': {'text': 'ufw allow 22 --dry-run'}}), marker],
            [json.dumps({'tool': 'UFW', 'enabled': True}), 'x"; reboot; echo "'],
            [json.dumps({'tool': 'UFW', 'enabled': True})],
            ['not json', marker],
        ]
        for arguments in refused:
            with self.subTest(arguments):
                code, errors, execv = self.run_as_root('firewall-change', arguments)
                self.assertEqual(code, 1)
                self.assertTrue(errors.strip())
                execv.assert_not_called()

    def test_firewall_read_runs_only_the_fixed_commands_of_a_known_tool(self):
        for arguments in (['UFW; reboot'], ['UFW', '--force'], []):
            with self.subTest(arguments):
                self.assertEqual(self.run_as_root('firewall-read', arguments)[0], 1)
        result = Mock(returncode=0, stdout=b'Status: active\n')
        with patch.object(linux_root.subprocess, 'run', return_value=result) as run, \
                patch('sys.stdout', Mock()):
            self.assertEqual(self.run_as_root('firewall-read', ['UFW'])[0], 0)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [['/usr/bin/ufw', 'status', 'verbose'], ['/usr/bin/ufw', 'show', 'added']])

    def test_system_check_takes_no_settings_from_the_user(self):
        settings = json.dumps({'tools': {'rpm': '/home/user/evil'}})
        with patch('backends.linux_system_check.run_root_checks') as checks:
            self.assertEqual(self.run_as_root('system-check', [settings])[0], 1)
        checks.assert_not_called()

    def test_internet_protection_installer_checks_its_arguments(self):
        with patch('sys.stdin', io.TextIOWrapper(io.BytesIO(b'{"version": 1, "count": 0}\n'))), \
                patch.object(sys, 'argv', list(sys.argv)), self.assertRaises(SystemExit) as stop:
            self.run_as_root('internet-protection', ['networkmanager', 'unknown-service'])
        self.assertEqual(stop.exception.code, 1)


@unittest.skipUnless(shutil.which('make') and os.name == 'posix', 'make is required')
class InstalledProgramTests(unittest.TestCase):
    def test_each_polkit_action_names_an_installed_program(self):
        import xml.etree.ElementTree as ElementTree
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['make', '-s', '-C', str(ROOT), 'install', f'DESTDIR={directory}', 'PREFIX=/usr',
                            f'PYTHON={sys.executable}'], check=True, capture_output=True)
            stage = Path(directory)
            policy = ElementTree.parse(stage / 'usr/share/polkit-1/actions/io.github.anaisoob.LibreWard.policy')
            paths = {action.get('id'): action.find("annotate[@key='org.freedesktop.policykit.exec.path']").text
                     for action in policy.getroot().iter('action')}
            self.assertEqual(paths, {f'io.github.anaisoob.LibreWard.{name}': f'/usr/libexec/libreward/{name}'
                                     for name in LinuxBackend.ROOT_HELPERS})
            self.assertEqual(sorted(path.name for path in (stage / 'usr/libexec/libreward').iterdir()),
                             sorted(LinuxBackend.ROOT_HELPERS))
            for action in policy.getroot().iter('action'):
                self.assertTrue(action.findtext('message'))
            program = stage / 'usr/libexec/libreward/firewall-read'
            self.assertTrue(os.access(program, os.X_OK))
            text = program.read_text()
            self.assertTrue(text.startswith(f'#!{sys.executable} -I\n'))
            self.assertIn("sys.path.insert(0, '/usr/share/libreward')", text)
            self.assertIn("main('firewall-read', sys.argv[1:])", text)
            if os.geteuid() == 0:
                return
            # The installed copy imports from the installed application folder.
            runnable = text.replace("'/usr/share/libreward'", repr(str(stage / 'usr/share/libreward')))
            result = subprocess.run([sys.executable, '-I', '-c', runnable, 'UFW'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('runs as root through pkexec', result.stderr)


if __name__ == '__main__':
    unittest.main()
