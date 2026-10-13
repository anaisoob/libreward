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


class PublicDnsTests(unittest.TestCase):
    def test_dropin_uses_global_routing_and_opportunistic_tls(self):
        from core.dns_providers import PROVIDERS
        from backends.linux_public_dns import dropin_content
        text = dropin_content(PROVIDERS['adguard-family']).decode()
        self.assertTrue(text.startswith('# Managed by LibreWard\n# provider=adguard-family\n[Resolve]\n'))
        self.assertIn('DNS=94.140.14.15#family.adguard-dns.com 94.140.15.16#family.adguard-dns.com', text)
        self.assertIn('\nDomains=~.\nDNSOverTLS=opportunistic\n', text)

    def test_only_resolved_stub_with_resolver_first_in_nss_is_supported(self):
        from backends.linux_public_dns import resolved_is_system_resolver
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

    def test_global_servers_ignore_names_ports_and_links(self):
        from backends.linux_public_dns import global_servers
        output = ('Global: 94.140.14.14#dns.adguard-dns.com [2a10:50c0::ad1:ff]:853#dns.adguard-dns.com 1.1.1.1%eth0\n'
                  'Link 2 (wlan0): 192.168.1.1\n')
        self.assertEqual(global_servers(output), {'94.140.14.14', '2a10:50c0::ad1:ff', '1.1.1.1'})
        self.assertEqual(global_servers('Link 2 (wlan0): 192.168.1.1\n'), set())

    def test_inspect_recognizes_only_generated_dropins(self):
        from core.dns_providers import PROVIDERS
        import backends.linux_public_dns as public
        with tempfile.TemporaryDirectory() as directory, patch.object(public, 'DROPIN', str(Path(directory, 'x.conf'))):
            self.assertIsNone(public.inspect_public())
            Path(public.DROPIN).write_bytes(public.dropin_content(PROVIDERS['quad9']))
            self.assertEqual(public.inspect_public(), 'quad9')
            Path(public.DROPIN).write_bytes(public.dropin_content(PROVIDERS['quad9']) + b'DNS=203.0.113.1\n')
            with self.assertRaisesRegex(ValueError, 'changed outside'):
                public.inspect_public()


@unittest.skipUnless(os.name == 'posix', 'Linux helper uses POSIX locks')
class PublicDnsHelperTests(unittest.TestCase):
    def setUp(self):
        from backends.linux_public_dns import helper
        self.ns = {'__name__': 'test_public_dns'}
        exec(helper('/usr/bin/systemctl', '/usr/bin/resolvectl'), self.ns)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.dropin = root / 'resolved.conf.d' / '90-libreward-dns.conf'
        self.ns.update(ROOT=str(root / 'libreward'), DIRECTORY=str(self.dropin.parent), DROPIN=str(self.dropin))
        self.ns['secure_directory'] = lambda path, create=True: os.makedirs(path, exist_ok=True) if create else None
        self.ns['reload_resolved'] = Mock()
        self.ns['verify'] = Mock()

    def test_select_switch_and_pause_write_only_the_owned_dropin(self):
        self.assertEqual(self.ns['apply']('adguard'), {'provider': 'adguard'})
        self.assertEqual(self.dropin.read_bytes(), self.ns['CONTENTS']['adguard'])
        self.assertEqual(self.dropin.stat().st_mode & 0o777, 0o644)
        self.ns['apply']('quad9')
        self.assertIn(b'9.9.9.9#dns.quad9.net', self.dropin.read_bytes())
        self.ns['apply'](None)
        self.assertFalse(self.dropin.exists())
        self.assertEqual(self.ns['reload_resolved'].call_count, 3)
        self.assertEqual([item.name for item in self.dropin.parent.iterdir()], [])

    def test_unreachable_service_restores_previous_selection(self):
        self.ns['apply']('quad9')
        previous = self.dropin.read_bytes()
        self.ns['verify'].side_effect = RuntimeError('could not be reached')
        with self.assertRaisesRegex(RuntimeError, 'could not be reached'):
            self.ns['apply']('adguard')
        self.assertEqual(self.dropin.read_bytes(), previous)
        self.ns['apply'](None)
        self.ns['verify'].side_effect = RuntimeError('could not be reached')
        with self.assertRaises(RuntimeError):
            self.ns['apply']('adguard')
        self.assertFalse(self.dropin.exists())

    def test_failed_restore_explains_manual_recovery(self):
        self.ns['verify'].side_effect = RuntimeError('could not be reached')
        self.ns['reload_resolved'].side_effect = [None, RuntimeError('reload failed')]
        with self.assertRaisesRegex(RuntimeError, 'systemctl restart systemd-resolved.*could not be reached.*reload failed'):
            self.ns['apply']('adguard')
        self.assertFalse(self.dropin.exists())

    def test_foreign_dropin_is_never_replaced(self):
        self.dropin.parent.mkdir(parents=True)
        self.dropin.write_text('[Resolve]\nDNS=192.0.2.1\n')
        with self.assertRaisesRegex(ValueError, 'changed outside'):
            self.ns['apply']('adguard')
        self.assertEqual(self.dropin.read_text(), '[Resolve]\nDNS=192.0.2.1\n')
        self.ns['reload_resolved'].assert_not_called()

    def test_verify_requires_effective_servers_and_working_lookups(self):
        from backends.linux_public_dns import helper
        real = {'__name__': 'test_public_dns_verify'}
        exec(helper('/usr/bin/systemctl', '/usr/bin/resolvectl'), real)
        real['global_servers'] = Mock(return_value=set(real['ADDRESSES']['quad9']))
        real['resolves'] = Mock(return_value=True)
        real['verify']('quad9')
        real['global_servers'] = Mock(return_value={'192.168.1.1'})
        with patch('time.sleep'), self.assertRaisesRegex(RuntimeError, 'could not be reached'):
            real['verify']('quad9')
        real['global_servers'] = Mock(return_value=set(real['ADDRESSES']['quad9']))
        real['resolves'] = Mock(return_value=False)
        with patch('time.sleep'), self.assertRaisesRegex(RuntimeError, 'could not be reached'):
            real['verify']('quad9')


class InternetBackendTests(unittest.TestCase):
    def backend(self):
        from backends.linux import LinuxBackend
        return LinuxBackend.__new__(LinuxBackend)

    def inspect(self, backend, *, local=False, setup=False, public=False):
        with patch('backends.linux_dns_service.inspect_service', return_value=None), \
             patch('backends.linux_public_dns.inspect_public', return_value=None), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/tool'), \
             patch('backends.linux.Path.is_dir', return_value=True), \
             patch.object(backend, '_local_dns_available', return_value=local), \
             patch.object(backend, '_dns_setup_available', return_value=setup), \
             patch.object(backend, '_public_dns_available', return_value=public):
            return backend.inspect_internet_protection()

    def test_local_filter_is_preferred_and_public_dns_is_the_fallback(self):
        backend = self.backend()
        self.assertEqual(self.inspect(backend, local=True, public=True)['engine'], 'sqlite-setup')
        self.assertEqual(self.inspect(backend, setup=True, public=True)['engine'], 'sqlite-setup')
        state = self.inspect(backend, public=True)
        self.assertEqual((state['engine'], state['supported'], state['active']), ('public-dns-setup', True, False))
        state = self.inspect(backend)
        self.assertFalse(state['supported'])
        self.assertIsNone(state['engine'])

    def test_active_public_dns_requires_effective_global_servers(self):
        from core.dns_providers import PROVIDERS
        backend = self.backend()
        addresses = ' '.join(PROVIDERS['quad9'].addresses)
        with patch('backends.linux_dns_service.inspect_service', return_value=None), \
             patch('backends.linux_public_dns.inspect_public', return_value='quad9'), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/resolvectl'), \
             patch.object(backend, '_public_dns_available', return_value=True), \
             patch.object(backend, '_firewall_query', return_value=(0, 'Global: ' + addresses + '\n')):
            state = backend.inspect_internet_protection()
            self.assertEqual((state['engine'], state['provider'], state['active'], state['supported']),
                             ('public-dns', 'quad9', True, True))
            with patch.object(backend, '_firewall_query', return_value=(0, 'Global:\n')):
                self.assertFalse(backend.inspect_internet_protection()['supported'])

    def test_apply_public_dns_sends_only_the_provider_key_and_verifies(self):
        import json
        backend = self.backend()
        process = Mock(returncode=0)
        sent = []
        def communicate():
            sent.append(json.loads(start.call_args.kwargs['stdin'].read()))
            return ('{"provider": "quad9"}', None)
        process.communicate.side_effect = communicate
        states = [{'supported': True, 'engine': 'public-dns-setup', 'active': False},
                  {'supported': True, 'engine': 'public-dns', 'active': True, 'provider': 'quad9', 'count': 0}]
        with patch.object(backend, 'inspect_internet_protection', side_effect=states), \
             patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
             patch.object(backend, '_trusted_firewall_executable', side_effect=lambda name: '/usr/bin/' + name), \
             patch.object(backend, 'start_process', return_value=process) as start:
            state = backend.apply_public_dns('quad9')
        self.assertEqual(sent, [{'provider': 'quad9'}])
        self.assertEqual(state['provider'], 'quad9')
        command = start.call_args.args[0]
        self.assertEqual(command[:4], ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/python3', '-I'])
        self.assertNotIn('shell', start.call_args.kwargs)

    def test_unknown_provider_and_unsupported_system_are_not_changed(self):
        backend = self.backend()
        with patch.object(backend, 'start_process') as start:
            with self.assertRaisesRegex(ValueError, 'supported DNS service'):
                backend.apply_public_dns('evil\nDNS=1.2.3.4')
            with patch.object(backend, 'inspect_internet_protection', return_value={
                    'supported': False, 'engine': None, 'message': 'Unsupported resolver'}), \
                    self.assertRaisesRegex(RuntimeError, 'Unsupported resolver'):
                backend.apply_public_dns('quad9')
        start.assert_not_called()

    def test_pause_removes_whichever_protection_is_active(self):
        backend = self.backend()
        with patch.object(backend, 'inspect_internet_protection', return_value={'engine': 'public-dns', 'active': True}), \
             patch.object(backend, 'apply_public_dns', return_value={'active': False}) as public:
            backend.apply_internet_protection([])
        public.assert_called_once_with(None)
        with patch.object(backend, 'inspect_internet_protection', return_value={'engine': 'sqlite-dns', 'active': True}), \
             patch.object(backend, '_apply_database_protection', return_value={'active': False}) as local:
            backend.apply_internet_protection([])
        local.assert_called_once_with(None)
        with self.assertRaises(ValueError):
            backend.apply_internet_protection(['example.org'])

    def test_authorization_cancellation_is_reported(self):
        from core.authorization import AuthorizationError
        backend = self.backend()
        process = Mock(returncode=126)
        process.communicate.return_value = ('cancelled', None)
        with patch.object(backend, 'inspect_internet_protection', return_value={'supported': True, 'engine': 'public-dns-setup'}), \
             patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/python3'), \
             patch.object(backend, 'start_process', return_value=process), self.assertRaises(AuthorizationError):
            backend.apply_public_dns('adguard')


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
        self.assertIn(f'--idle-limit {IDLE_LIMIT}\n', namespace['SERVICE_UNIT'])
        self.assertIn('OnFailure=libreward-dns-recover.service', namespace['SERVICE_UNIT'])
        self.assertIn('WantedBy=multi-user.target', namespace['SERVICE_UNIT'])
