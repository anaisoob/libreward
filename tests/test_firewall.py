import unittest
from unittest.mock import patch

from backends.linux import LinuxBackend
from backends.windows import WindowsBackend


class FirewallTests(unittest.TestCase):
    def inspect(self, installed, responses):
        backend = LinuxBackend()
        with patch.object(backend, '_firewall_executable', side_effect=lambda name: '/usr/sbin/' + name if name in installed else None), patch.object(backend, '_firewall_query', side_effect=lambda cmd: responses[tuple(cmd[1:])]) as query:
            result = backend.inspect_firewall()
            self.assertTrue(all(call.args[0][1:] in [list(key) for key in responses] for call in query.call_args_list))
            return result

    def test_inactive_ufw_retains_configured_rules(self):
        result = self.inspect({'ufw'}, {
            ('status', 'verbose'): (0, 'Status: inactive'),
            ('show', 'added'): (0, 'ufw allow 22/tcp'),
        })
        self.assertEqual(result.tools[0].state, 'Inactive')
        self.assertIn('ufw allow 22/tcp', result.tools[0].rules)
        self.assertIn('may be inactive', result.tools[0].rules)

    def test_permission_failure_is_not_reported_as_disabled(self):
        result = self.inspect({'nft'}, {('list', 'ruleset'): (1, 'Operation not permitted')})
        self.assertIn('administrator permission required', result.tools[0].state)
        self.assertEqual(result.tools[0].command, 'sudo /usr/sbin/nft list ruleset')

    def test_firewalld_reads_runtime_and_saved_rules(self):
        result = self.inspect({'firewall-cmd'}, {
            ('--state',): (0, 'running'),
            ('--list-all-zones',): (0, 'public: runtime'),
            ('--permanent', '--list-all-zones'): (0, 'public: saved'),
        })
        self.assertEqual(result.tools[0].state, 'Running')
        self.assertIn('runtime', result.tools[0].rules)
        self.assertIn('saved', result.tools[0].rules)

    def test_missing_tools_recommend_ufw_without_claiming_no_firewall(self):
        backend = LinuxBackend()
        with patch.object(backend, '_firewall_executable', return_value=None), patch.object(backend, 'distro_info', return_value={'pkg_manager': 'apt'}):
            result = backend.inspect_firewall()
        self.assertFalse(result.tools)
        self.assertIn('sudo apt install ufw', result.instructions)
        self.assertIn('does not prove', result.instructions)

    def test_windows_returns_unsupported_without_commands(self):
        self.assertFalse(WindowsBackend().inspect_firewall().supported)

    def test_query_reads_merged_output_from_real_subprocess(self):
        import sys
        code, output = LinuxBackend._firewall_query([
            sys.executable, '-c', 'import sys; print("permission denied", file=sys.stderr); sys.exit(1)',
        ])
        self.assertEqual(code, 1)
        self.assertEqual(output, 'permission denied')

    def test_query_handles_silent_real_subprocess(self):
        import sys
        code, output = LinuxBackend._firewall_query([sys.executable, '-c', 'pass'])
        self.assertEqual(code, 0)
        self.assertEqual(output, '')

    def test_query_timeout_is_reported(self):
        import subprocess
        with patch('backends.linux.subprocess.run', side_effect=subprocess.TimeoutExpired(['nft'], 10)):
            code, message = LinuxBackend._firewall_query(['nft', 'list', 'ruleset'])
        self.assertEqual(code, -1)
        self.assertIn('timed out', message)

    def test_elevation_only_runs_selected_fixed_read_command(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', return_value=(0, 'table inet filter {}')) as query:
            result = backend.inspect_firewall(privileged=True, tool_name='nftables')
        query.assert_called_once_with(['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/nft', 'list', 'ruleset'], timeout=120)
        self.assertEqual([tool.name for tool in result.tools], ['nftables'])

    def test_cancelled_authorization_stops_further_queries(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', return_value=(126, 'dismissed')) as query:
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                backend.inspect_firewall(privileged=True, tool_name='UFW')
        self.assertEqual(query.call_count, 1)

    def test_elevation_rejects_arbitrary_tool(self):
        with self.assertRaises(ValueError):
            LinuxBackend().inspect_firewall(privileged=True, tool_name='sh')

    def test_missing_authorizer_gives_terminal_fallback(self):
        with patch.object(LinuxBackend, '_trusted_firewall_executable', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'terminal'):
                LinuxBackend().inspect_firewall(privileged=True, tool_name='UFW')

    def test_authorized_ufw_uses_one_query(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', return_value=(0, 'Status: inactive')) as query:
            result = backend.inspect_firewall(privileged=True, tool_name='UFW')
        self.assertEqual(query.call_count, 1)
        self.assertEqual(result.tools[0].state, 'Inactive')

    def test_authorized_firewalld_reads_runtime_in_one_query(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', return_value=(0, 'public (active)')) as query:
            result = backend.inspect_firewall(privileged=True, tool_name='firewalld')
        query.assert_called_once_with(['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/firewall-cmd', '--list-all-zones'], timeout=120)
        self.assertEqual(result.tools[0].state, 'Running')


class FirewallChangeTests(unittest.TestCase):
    def rule(self, **changes):
        from core.firewall import FirewallRule
        fields = dict(action='allow', direction='in', scope='lan', protocol='tcp',
                      port='22', subnet='192.168.1.0/24')
        return FirewallRule(**{**fields, **changes})

    def test_ufw_lan_rule_limits_source(self):
        executable, args = LinuxBackend._firewall_change_arguments('UFW', self.rule())
        self.assertEqual(executable, 'ufw')
        self.assertEqual(args, ['allow', 'in', 'proto', 'tcp', 'from', '192.168.1.0/24', 'to', 'any', 'port', '22'])

    def test_ufw_outgoing_lan_rule_limits_destination_and_range(self):
        _, args = LinuxBackend._firewall_change_arguments('UFW', self.rule(direction='out', action='deny', protocol='udp', port='8000-8010'))
        self.assertEqual(args, ['deny', 'out', 'proto', 'udp', 'from', 'any', 'to', '192.168.1.0/24', 'port', '8000:8010'])

    def test_internet_scope_is_explicitly_all_addresses(self):
        rule = self.rule(scope='internet', subnet='ignored')
        _, args = LinuxBackend._firewall_change_arguments('UFW', rule)
        self.assertEqual(args[args.index('from') + 1], 'any')
        self.assertIn('including LAN and Internet', rule.description('UFW'))

    def test_firewalld_lan_ipv6_saved_rule(self):
        executable, args = LinuxBackend._firewall_change_arguments('firewalld', self.rule(
            subnet='fd12:3456::42/64', port='443', zone='home', lifetime='permanent'))
        self.assertEqual(executable, 'firewall-cmd')
        self.assertEqual(args, ['--zone=home', '--permanent', '--add-rich-rule=rule family="ipv6" source address="fd12:3456::/64" port port="443" protocol="tcp" accept'])

    def test_firewalld_internet_runtime_block(self):
        _, args = LinuxBackend._firewall_change_arguments('firewalld', self.rule(
            scope='internet', action='deny', zone='public'))
        self.assertEqual(args, ['--zone=public', '--add-rich-rule=rule port port="22" protocol="tcp" drop'])

    def test_invalid_fields_never_reach_privileged_execution(self):
        backend = LinuxBackend()
        cases = [dict(action='allow; id'), dict(direction='route'), dict(scope='unknown'),
                 dict(protocol='all'), dict(port='22; id'), dict(port='0'), dict(port='65536'),
                 dict(port='99-22'), dict(subnet='0.0.0.0/0'), dict(subnet='bad'),
                 dict(zone='public --panic-on'), dict(lifetime='forever')]
        with patch.object(backend, '_firewall_query') as query:
            for changes in cases:
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    backend.change_firewall('UFW', rule=self.rule(**changes))
        query.assert_not_called()

    def test_firewalld_requires_zone_and_rejects_outgoing_form(self):
        for rule in (self.rule(), self.rule(zone='home', direction='out')):
            with self.assertRaises(ValueError):
                LinuxBackend._firewall_change_arguments('firewalld', rule)

    def test_only_supported_managers_can_be_changed(self):
        for name in ('nftables', 'iptables (IPv4)', 'sh'):
            with self.assertRaises(ValueError):
                LinuxBackend._firewall_change_arguments(name)

    def test_enable_commands_have_fixed_targets(self):
        self.assertEqual(LinuxBackend._firewall_change_arguments('UFW'), ('ufw', ['--force', 'enable']))
        self.assertEqual(LinuxBackend._firewall_change_arguments('firewalld'), ('systemctl', ['start', 'firewalld.service']))

    @staticmethod
    def batch_response(command, *, timeout):
        import re
        marker = re.search(r'LIBREWARD_[a-f0-9]+', command[-1]).group()
        return 0, f'Rule added\n{marker}:CHANGE:0\nStatus: active\n22/tcp ALLOW Anywhere\n{marker}:READ:0'

    def test_change_uses_one_authorization_with_verified_refresh(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', side_effect=self.batch_response) as query:
            result = backend.change_firewall('UFW', rule=self.rule())
        self.assertTrue(result.success)
        self.assertEqual(result.message, 'Rule added')
        self.assertEqual(result.snapshot.tools[0].state, 'Active')
        self.assertIn('22/tcp ALLOW', result.snapshot.tools[0].rules)
        self.assertEqual(query.call_count, 1)
        command = query.call_args.args[0]
        self.assertEqual(command[:4], ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/sh', '-c'])
        self.assertIn('/usr/bin/ufw allow in proto tcp from 192.168.1.0/24 to any port 22', command[-1])
        self.assertIn('/usr/bin/ufw status verbose', command[-1])

    def test_both_directions_generate_two_rules_with_one_authorization(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', side_effect=self.batch_response) as query:
            backend.change_firewall('UFW', rule=self.rule(direction='both'))
        script = query.call_args.args[0][-1]
        self.assertIn('allow in proto tcp from 192.168.1.0/24 to any port 22 &&', script)
        self.assertIn('allow out proto tcp from any to 192.168.1.0/24 port 22', script)
        self.assertEqual(query.call_count, 1)

    def test_disable_is_followed_by_read_in_same_authorization(self):
        import re
        backend = LinuxBackend()
        def response(command, **kwargs):
            marker = re.search(r'LIBREWARD_[a-f0-9]+', command[-1]).group()
            # Silent mutation also has to parse correctly when output starts with a marker.
            return 0, f'{marker}:CHANGE:0\nStatus: inactive\n{marker}:READ:0'
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', side_effect=response) as query:
            result = backend.change_firewall('UFW', enabled=False)
        self.assertEqual(result.snapshot.tools[0].state, 'Inactive')
        self.assertIn('ufw --force disable', query.call_args.args[0][-1])
        self.assertEqual(query.call_count, 1)

    def test_partial_failure_still_returns_refreshed_rules(self):
        import re
        backend = LinuxBackend()
        def response(command, **kwargs):
            marker = re.search(r'LIBREWARD_[a-f0-9]+', command[-1]).group()
            return 0, f'first rule added; second failed\n{marker}:CHANGE:1\nStatus: active\n22/tcp ALLOW\n{marker}:READ:0'
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', side_effect=response):
            result = backend.change_firewall('UFW', rule=self.rule(direction='both'))
        self.assertFalse(result.success)
        self.assertIn('Some rules may have been applied', result.message)
        self.assertEqual(result.snapshot.tools[0].state, 'Active')

    def test_network_detection_uses_real_prefixes_and_excludes_loopback(self):
        import json
        backend = LinuxBackend()
        addresses = [
            {'ifname': 'lo', 'flags': ['LOOPBACK'], 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]},
            {'ifname': 'eth0', 'addr_info': [
                {'family': 'inet', 'local': '192.168.8.12', 'prefixlen': 23},
                {'family': 'inet6', 'local': 'fd12:3456::1', 'prefixlen': 64},
                {'family': 'inet6', 'local': 'fe80::1', 'prefixlen': 64}]},
        ]
        with patch.object(backend, '_firewall_executable', return_value='/usr/bin/ip'), patch.object(backend, '_firewall_query', return_value=(0, json.dumps(addresses))) as query:
            networks = backend.firewall_networks()
        self.assertEqual(networks, [('eth0', '192.168.8.0/23'), ('eth0', 'fd12:3456::/64')])
        query.assert_called_once_with(['/usr/bin/ip', '-j', 'address', 'show', 'up'], timeout=3)

    def test_cancellation_or_failure_is_not_success(self):
        backend = LinuxBackend()
        for code in (126, 127, 1, -1):
            with self.subTest(code=code), patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_query', return_value=(code, 'failure')) as query:
                with self.assertRaises(RuntimeError):
                    backend.change_firewall('UFW', rule=self.rule())
                self.assertEqual(query.call_count, 1)

    def test_enable_rejects_other_active_manager(self):
        backend = LinuxBackend()
        with patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), patch.object(backend, '_firewall_executable', return_value='/usr/bin/firewall-cmd'), patch.object(backend, '_firewall_query', return_value=(0, 'running')) as query:
            with self.assertRaisesRegex(RuntimeError, 'Another firewall manager is active'):
                backend.change_firewall('UFW')
        query.assert_called_once_with(['/usr/bin/firewall-cmd', '--state'])

    def test_unsupported_platform_cannot_mutate(self):
        with self.assertRaises(NotImplementedError):
            WindowsBackend().change_firewall('UFW')

    def test_generated_batch_runs_against_fake_tool_without_root(self):
        import subprocess
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        backend = LinuxBackend()
        with tempfile.TemporaryDirectory(prefix='libreward firewall ') as folder:
            tool = Path(folder, 'fake ufw')
            tool.write_text('#!/bin/sh\ncase "$1" in\nallow) printf "Rule added\\n" ;;\nstatus) printf "Status: active\\n22/tcp ALLOW Anywhere\\n" ;;\n*) exit 3 ;;\nesac\n')
            tool.chmod(0o700)
            def trusted(name):
                return str(tool) if name == 'ufw' else '/bin/sh' if name == 'sh' else '/not/executed/pkexec'
            def execute(command, *, timeout):
                self.assertEqual(command[:2], ['/not/executed/pkexec', '--disable-internal-agent'])
                completed = subprocess.run(command[2:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, encoding='utf-8', errors='replace', timeout=timeout)
                return completed.returncode, completed.stdout.strip()
            with patch.object(backend, '_trusted_firewall_executable', side_effect=trusted), patch.object(backend, '_firewall_query', side_effect=execute):
                result = backend.change_firewall('UFW', rule=self.rule(direction='both'))
            self.assertTrue(result.success)
            self.assertEqual(result.message.count('Rule added'), 2)
            self.assertEqual(result.snapshot.tools[0].state, 'Active')
            self.assertIn('22/tcp ALLOW', result.snapshot.tools[0].rules)
