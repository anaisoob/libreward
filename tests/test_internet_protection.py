"""Internet protection: lists, resolver checks and privileged helpers on temporary files only."""
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from core.internet import normalize_domain, preferences


class DomainTests(unittest.TestCase):
    def test_domains_are_exact_validated_names(self):
        self.assertEqual(normalize_domain('BÜCHER.de.'), 'xn--bcher-kva.de')
        for value in ('https://example.org', '*.example.org', '127.0.0.1', 'example.org/a',
                      'printer.local', 'localhost', 'bad_name.org', 'x.org\n0.0.0.0 good.org'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_internet_check_resolves_ordinary_names_with_a_bound(self):
        from core.internet import internet_available
        with patch('socket.getaddrinfo', return_value=[('addr',)]):
            self.assertTrue(internet_available())
        with patch('socket.getaddrinfo', side_effect=OSError('offline')):
            self.assertFalse(internet_available())
        import threading
        blocked = threading.Event()
        self.addCleanup(blocked.set)
        with patch('socket.getaddrinfo', side_effect=lambda *a, **k: blocked.wait(5)):
            self.assertFalse(internet_available(timeout=0.1))

    def test_default_categories_provider_and_invalid_settings(self):
        self.assertEqual(preferences({})['categories'], ['dangerous'])
        self.assertEqual(preferences({})['provider'], 'adguard')
        self.assertEqual(preferences({'internet_protection': {'provider': 'quad9'}})['provider'], 'quad9')
        self.assertEqual(preferences({'internet_protection': {'provider': 'unknown'}})['provider'], 'adguard')
        with self.assertRaises(ValueError):
            preferences({'internet_protection': {'allowed': 'example.org'}})


class LocalDnsTests(unittest.TestCase):
    def test_requires_existing_networkmanager_dnsmasq_without_bypass(self):
        from backends.linux_dns import compatible
        self.assertTrue(compatible('[main]\ndns=dnsmasq', 'hosts: files dns', 'nameserver 127.0.0.1\n'))
        for config, nss, resolv in (
                ('[main]\ndns=systemd-resolved', 'hosts: files dns', 'nameserver 127.0.0.1'),
                ('[main]\ndns=dnsmasq', 'hosts: resolve files dns', 'nameserver 127.0.0.1'),
                ('[main]\ndns=dnsmasq', 'hosts: files dns', 'nameserver 127.0.0.1\nnameserver 1.1.1.1')):
            self.assertFalse(compatible(config, nss, resolv))

class DnsSetupTests(unittest.TestCase):
    def test_debian_default_and_mdns_are_supported_but_external_resolver_is_not(self):
        from backends.linux_dns import setup_supported
        with tempfile.TemporaryDirectory() as directory:
            resolv = Path(directory, 'resolv.conf')
            resolv.write_text('nameserver 192.168.1.1\n')
            nss = 'hosts: files myhostname mdns4_minimal [NOTFOUND=return] dns'
            self.assertTrue(setup_supported('[main]\nplugins=ifupdown,keyfile', nss, resolv))
            self.assertFalse(setup_supported('[main]\ndns=systemd-resolved', nss, resolv))
            self.assertFalse(setup_supported('[main]\nrc-manager=unmanaged', nss, resolv))
            self.assertFalse(setup_supported('[main]', 'hosts: resolve files dns', resolv))
            resolv.unlink()
            resolv.symlink_to('/run/systemd/resolve/stub-resolv.conf')
            self.assertFalse(setup_supported('[main]', nss, resolv))

class DnsReloadTests(unittest.TestCase):
    def test_full_reload_uses_flag_free_command(self):
        from backends.linux_dns import helper
        namespace = {'__name__': 'test_dns_reload'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager'), namespace)
        with patch('subprocess.run') as run:
            namespace['reload_dns']()
        self.assertEqual(run.call_args.args[0], ['/usr/bin/nmcli', 'general', 'reload'])
        self.assertEqual(run.call_args.kwargs['timeout'], 30)

    def test_reload_error_preserves_networkmanager_explanation(self):
        import subprocess
        from backends.linux_dns import helper
        namespace = {'__name__': 'test_dns_reload'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager'), namespace)
        failure = subprocess.CalledProcessError(2, ['nmcli'], stderr='Error: invalid arguments')
        with patch('subprocess.run', side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, 'exit 2.*invalid arguments'):
                namespace['reload_dns']()

class DiskDomainListTests(unittest.TestCase):
    def response(self, value):
        stream = io.BytesIO(value)
        stream.geturl = lambda: 'https://raw.githubusercontent.com/blocklistproject/Lists/master/test.txt'
        return stream

    def test_streamed_download_deduplication_exceptions_and_metadata(self):
        from core.internet import DiskDomainLists
        with tempfile.TemporaryDirectory() as directory:
            store = DiskDomainLists(directory)
            response = self.response(b'# license\nadult.example.org\nsafe.example.org\nadult.example.org\n')
            response.read = Mock(side_effect=AssertionError('Do not read the whole download'))
            with patch('core.internet.urlopen', return_value=response):
                metadata = store.update(['adult'])
            self.assertEqual(metadata['lists'], {'adult': 2})
            self.assertEqual(metadata['count'], 2)
            self.assertIn('# license', metadata['sources'][0]['header'])
            self.assertEqual(store.load(), metadata)
            with store.prepare({'categories': ['adult'], 'blocked': ['extra.example.org'],
                                'allowed': ['safe.example.org']}) as prepared:
                with prepared.path.open('rb') as stream:
                    stream.readline()
                    self.assertEqual(stream.read(), b'adult.example.org\nextra.example.org\n')
            with self.assertRaisesRegex(ValueError, 'Download'):
                store.prepare({'categories': ['ads'], 'blocked': [], 'allowed': []})

    def test_damaged_line_is_skipped_instead_of_failing_the_list(self):
        from core.internet import DiskDomainLists
        with tempfile.TemporaryDirectory() as directory:
            store = DiskDomainLists(directory)
            with patch('core.internet.urlopen', return_value=self.response(b'good.example.org\nbad\xff.example.org\nnext.example.org\n')):
                metadata = store.update(['adult'])
            self.assertEqual(metadata['lists'], {'adult': 2})

    def test_failed_download_retains_previous_database(self):
        from core.internet import DiskDomainLists
        with tempfile.TemporaryDirectory() as directory:
            store = DiskDomainLists(directory)
            with patch('core.internet.urlopen', return_value=self.response(b'original.example.org\n')):
                store.update(['adult'])
            previous = store.path.read_bytes()
            with patch('core.internet.urlopen', return_value=self.response(b'<html>error</html>\n')), self.assertRaises(ValueError):
                store.update(['adult'])
            self.assertEqual(store.path.read_bytes(), previous)
            self.assertFalse(list(store.path.parent.glob('.lists-*')))


class ProviderTests(unittest.TestCase):
    def test_provider_table_is_validated_and_names_tls_hosts(self):
        from core.dns_providers import DnsProvider, PROVIDERS, validate_providers
        self.assertEqual(set(PROVIDERS), {'adguard', 'adguard-family', 'quad9', 'cloudflare-security', 'cloudflare-family'})
        self.assertEqual(PROVIDERS['quad9'].servers()[0], '9.9.9.9#dns.quad9.net')
        bad = DnsProvider('bad', 'Bad', '', ('9.9.9.9\nDNS=1.2.3.4',), 'dns.example', '')
        with self.assertRaises(ValueError):
            validate_providers({'bad': bad})


class ResolvedTests(unittest.TestCase):
    def test_only_resolved_stub_with_resolver_first_in_nss_is_supported(self):
        from backends.linux_resolved import resolved_is_system_resolver
        with tempfile.TemporaryDirectory() as directory:
            resolv = Path(directory, 'resolv.conf')
            resolv.symlink_to('/run/systemd/resolve/stub-resolv.conf')
            with patch.object(Path, 'resolve', return_value=Path('/run/systemd/resolve/stub-resolv.conf')):
                for nss in ('hosts: files mdns4_minimal [NOTFOUND=return] dns',
                            'hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns'):
                    self.assertTrue(resolved_is_system_resolver(nss, resolv), nss)
                for nss in ('hosts: files', 'hosts: files wins dns', ''):
                    self.assertFalse(resolved_is_system_resolver(nss, resolv), nss)
            plain = Path(directory, 'plain.conf')
            plain.write_text('nameserver 127.0.0.53\n')
            self.assertFalse(resolved_is_system_resolver('hosts: files dns', plain))

    def test_filter_must_be_resolveds_global_server(self):
        from backends.linux_resolved import filter_is_global, global_servers
        output = 'Global: 127.0.0.1:5354\nLink 2 (wlan0): 192.168.1.1\nLink 5 (tun0): 10.0.0.1#vpn.example\n'
        self.assertTrue(filter_is_global(output))
        self.assertEqual(global_servers('Global: 1.1.1.1#one.one.one.one 9.9.9.9%eth0\n'), {'1.1.1.1', '9.9.9.9'})
        self.assertFalse(filter_is_global('Global:\nLink 2 (wlan0): 127.0.0.1:5354\n'))

    def test_upstream_table_has_ipv4_tls_servers_for_every_provider(self):
        from backends.linux_dns_service import upstream_table
        from core.dns_providers import PROVIDERS
        table = upstream_table()
        self.assertEqual(set(table), set(PROVIDERS))
        self.assertIn(['9.9.9.9', 'dns.quad9.net'], table['quad9'])
        self.assertTrue(all(':' not in address for servers in table.values() for address, _ in servers))


class InternetBackendTests(unittest.TestCase):
    def backend(self):
        from backends.linux import LinuxBackend
        return LinuxBackend.__new__(LinuxBackend)

    def inspect(self, backend, *, local=False, setup=False, resolved=False):
        with patch('backends.linux_dns_service.inspect_service', return_value=None), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/tool'), \
             patch('backends.linux.Path.is_dir', return_value=True), \
             patch.object(backend, '_local_dns_available', return_value=local), \
             patch.object(backend, '_dns_setup_available', return_value=setup), \
             patch.object(backend, '_resolved_available', return_value=resolved), \
             patch.object(backend, 'distro_info', return_value={'pkg_manager': 'apt'}):
            return backend.inspect_internet_protection()

    def test_networkmanager_filter_is_preferred_then_resolved(self):
        backend = self.backend()
        self.assertEqual(self.inspect(backend, local=True, resolved=True)['mode'], 'networkmanager')
        self.assertEqual(self.inspect(backend, setup=True, resolved=True)['mode'], 'networkmanager')
        state = self.inspect(backend, resolved=True)
        self.assertEqual((state['engine'], state['mode'], state['supported']), ('sqlite-setup', 'resolved', True))
        self.assertFalse(state['needs_dns_install'])
        state = self.inspect(backend)
        self.assertFalse(state['supported'])
        self.assertIsNone(state['engine'])

    def test_active_resolved_filter_must_be_the_global_server(self):
        backend = self.backend()
        service = {'active': True, 'supported': True, 'count': 3, 'engine': 'sqlite-dns', 'mode': 'resolved',
                   'provider': 'quad9', 'message': 'ok'}
        with patch('backends.linux_dns_service.inspect_service', return_value=dict(service)), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/tool'), \
             patch.object(backend, '_resolved_available', return_value=True), \
             patch.object(backend, '_firewall_query', return_value=(0, 'Global: 127.0.0.1:5354\n')):
            self.assertTrue(backend.inspect_internet_protection()['supported'])
            with patch.object(backend, '_firewall_query', side_effect=[(0, ''), (0, 'Global: 192.168.1.1\n')]):
                self.assertFalse(backend.inspect_internet_protection()['supported'])

    def apply(self, backend, state, provider, final=None):
        from core.internet import PreparedDomains
        process = Mock(returncode=0)
        process.communicate.return_value = ('{"count": 1, "digest": "d", "skipped": 0}', None)
        with tempfile.NamedTemporaryFile() as payload:
            prepared = PreparedDomains(payload.name, 1, 'd')
            with patch.object(backend, 'inspect_internet_protection', side_effect=[state, final or {
                    'count': 1, 'supported': True, 'active': True, 'provider': provider}]), \
                 patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
                 patch.object(backend, '_install_dns_runtime') as install, \
                 patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), \
                 patch.object(backend, 'start_process', return_value=process) as start:
                result = backend.apply_internet_protection(prepared, provider=provider)
        return result, start.call_args.args[0], install

    def test_resolved_apply_passes_mode_and_provider_and_verifies_them(self):
        backend = self.backend()
        state = {'supported': True, 'engine': 'sqlite-setup', 'mode': 'resolved'}
        result, command, install = self.apply(backend, state, 'adguard-family')
        self.assertEqual(command[:4], ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/python3', '-I'])
        self.assertEqual(command[-2:], ['resolved', 'adguard-family'])
        install.assert_not_called()
        self.assertEqual(result['provider'], 'adguard-family')
        with self.assertRaisesRegex(RuntimeError, 'could not be verified'):
            self.apply(backend, state, 'quad9', final={'count': 1, 'supported': True, 'active': True, 'provider': 'adguard'})

    def test_networkmanager_apply_installs_dnsmasq_and_passes_mode(self):
        backend = self.backend()
        _, command, install = self.apply(backend, {'supported': True, 'engine': 'sqlite-setup', 'mode': 'networkmanager'}, None)
        self.assertEqual(command[-1], 'networkmanager')
        install.assert_called_once()

    def test_unknown_provider_and_unsupported_system_are_not_changed(self):
        from core.internet import PreparedDomains
        backend = self.backend()
        prepared = PreparedDomains('/nonexistent', 1, 'd')
        with patch.object(backend, 'start_process') as start:
            with patch.object(backend, 'inspect_internet_protection', return_value={
                    'supported': True, 'engine': 'sqlite-setup', 'mode': 'resolved'}), \
                    self.assertRaisesRegex(ValueError, 'supported DNS service'):
                backend.apply_internet_protection(prepared, provider='evil')
            with patch.object(backend, 'inspect_internet_protection', return_value={
                    'supported': False, 'engine': None, 'message': 'Unsupported resolver'}), \
                    self.assertRaisesRegex(RuntimeError, 'Unsupported resolver'):
                backend.apply_internet_protection(prepared, provider='quad9')
        start.assert_not_called()

    def test_pause_only_acts_on_an_active_filter(self):
        backend = self.backend()
        with patch.object(backend, 'inspect_internet_protection', return_value={'engine': 'sqlite-dns', 'active': True}), \
             patch.object(backend, '_apply_database_protection', return_value={'active': False}) as local:
            backend.apply_internet_protection([])
        local.assert_called_once_with(None)
        with patch.object(backend, 'inspect_internet_protection', return_value={'engine': 'sqlite-setup', 'active': False}), \
             patch.object(backend, '_apply_database_protection') as local:
            self.assertFalse(backend.apply_internet_protection([])['active'])
        local.assert_not_called()
        with self.assertRaises(ValueError):
            backend.apply_internet_protection(['example.org'])

    def test_cancel_stops_pkexec_only_before_authorization(self):
        from core.authorization import AuthorizationError
        backend = self.backend()
        backend.reset_cancellation()
        # Nothing started yet: the helper is never started.
        self.assertTrue(backend.cancel_authorization())
        with patch.object(backend, 'start_process') as start, self.assertRaises(AuthorizationError):
            backend.start_privileged(['/usr/bin/pkexec'])
        start.assert_not_called()
        process = Mock(pid=4321)
        process.poll.return_value = None
        with patch.object(backend, 'start_process', return_value=process):
            backend.start_privileged(['/usr/bin/pkexec'])
        with patch('backends.linux.os.kill') as kill:
            self.assertTrue(backend.cancel_authorization())
        kill.assert_called_once()
        with self.assertRaisesRegex(AuthorizationError, 'No changes were made'):
            backend._privileged_finished(process)
        # Authorized: pkexec runs as root and the signal is refused.
        with patch.object(backend, 'start_process', return_value=process):
            backend.start_privileged(['/usr/bin/pkexec'])
        with patch('backends.linux.os.kill', side_effect=PermissionError):
            self.assertFalse(backend.cancel_authorization())
        backend._privileged_finished(process)

    def test_authorization_cancellation_is_reported(self):
        from core.authorization import AuthorizationError
        backend = self.backend()
        process = Mock(returncode=126)
        process.communicate.return_value = ('cancelled', None)
        with patch.object(backend, 'inspect_internet_protection', return_value={'engine': 'sqlite-dns', 'active': True}), \
             patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/python3'), \
             patch.object(backend, 'start_process', return_value=process), self.assertRaises(AuthorizationError):
            backend.apply_internet_protection([])

    def test_dnsmasq_is_installed_with_each_supported_package_manager(self):
        backend = self.backend()
        expected = {'apt': ['/usr/bin/apt-get', 'install', '--assume-yes', '--no-remove', 'dnsmasq-base'],
                    'pacman': ['/usr/bin/pacman', '-S', '--needed', '--noconfirm', 'dnsmasq'],
                    'dnf': ['/usr/bin/dnf', 'install', '--assumeyes', 'dnsmasq'],
                    'zypper': ['/usr/bin/zypper', '--non-interactive', 'install', '--no-recommends', 'dnsmasq']}
        for manager, command in expected.items():
            installed = []
            def trusted(name):
                return '/usr/sbin/dnsmasq' if name == 'dnsmasq' and installed else (
                    None if name == 'dnsmasq' else '/usr/bin/' + name)
            process = Mock(stdout=iter(['done\n']))
            def start(arguments, **kwargs):
                installed.append(True)
                return process
            process.wait.return_value = 0
            with self.subTest(manager=manager), \
                    patch.object(backend, 'distro_info', return_value={'pkg_manager': manager}), \
                    patch.object(backend, '_trusted_firewall_executable', side_effect=trusted), \
                    patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
                    patch.object(backend, 'start_process', side_effect=start) as started:
                backend._install_dns_runtime()
                self.assertEqual(started.call_args.args[0], ['/usr/bin/pkexec', '--disable-internal-agent', *command])
        with patch.object(backend, 'distro_info', return_value={'pkg_manager': 'emerge'}), \
                patch.object(backend, '_trusted_firewall_executable', return_value=None), \
                self.assertRaisesRegex(RuntimeError, 'missing'):
            backend._install_dns_runtime()



@unittest.skipUnless(os.name == 'posix', 'XDG autostart is Linux-specific')
class AutostartTests(unittest.TestCase):
    def test_autostart_entry_is_created_quoted_and_removed(self):
        from backends.linux import LinuxBackend
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'XDG_CONFIG_HOME': directory}):
            linux = LinuxBackend.__new__(LinuxBackend)
            with patch('sys.executable', '/opt/Lib Ward/py$thon "3"%'):
                linux.set_autostart(True)
            path = Path(directory, 'autostart', 'libreward.desktop')
            text = path.read_text()
            self.assertIn('[Desktop Entry]\nType=Application\n', text)
            self.assertIn('Exec="/opt/Lib Ward/py\\\\$thon \\\\"3\\\\"%%" ', text)
            self.assertIn('main.py" "--autostart"\n', text)
            linux.set_autostart(True)
            self.assertEqual(path.read_text(), text.replace('/opt/Lib Ward/py\\\\$thon \\\\"3\\\\"%%', __import__('sys').executable))
            self.assertEqual([item.name for item in path.parent.iterdir()], ['libreward.desktop'])
            linux.set_autostart(False)
            self.assertFalse(path.exists())
            linux.set_autostart(False)

    def test_service_unit_passes_heartbeat_limit_and_starts_at_boot(self):
        from backends.linux_dns_service import helper, IDLE_LIMIT
        namespace = {'__name__': 'test_units'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager', '/usr/bin/systemctl', '/usr/bin/python3'), namespace)
        self.assertIn(f'--idle-limit {IDLE_LIMIT} __ARGS__\n', namespace['SERVICE_UNIT'])
        self.assertIn('--listen-port 53\n', namespace['service_unit']('networkmanager', None))
        self.assertIn('OnFailure=libreward-dns-recover.service', namespace['SERVICE_UNIT'])
        self.assertIn('WantedBy=multi-user.target', namespace['SERVICE_UNIT'])
