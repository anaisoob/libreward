"""Domain compilation and privileged helper tests never touch system hosts."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from core.internet import DomainLists, domain_lines, normalize_domain, preferences


class DomainListTests(unittest.TestCase):
    def test_domains_are_exact_validated_names(self):
        self.assertEqual(normalize_domain('BÜCHER.de.'), 'xn--bcher-kva.de')
        for value in ('https://example.org', '*.example.org', '127.0.0.1', 'example.org/a',
                      'printer.local', 'localhost', 'bad_name.org', 'x.org\n0.0.0.0 good.org'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)
        self.assertEqual(domain_lines('# source\nexample.org\n*.invalid.org\nexample.org\n'), {'example.org'})

    def test_allowlist_overrides_lists_and_custom_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DomainLists(directory)
            with patch.object(store, 'load', return_value={'lists': {'dangerous': ['bad.org', 'safe.org']}}):
                result = store.compile({'categories': ['dangerous'], 'allowed': ['safe.org'], 'blocked': ['safe.org', 'extra.org']})
                self.assertEqual(result, ['bad.org', 'extra.org'])
            with self.assertRaisesRegex(ValueError, 'Download'):
                store.compile({'categories': ['ads'], 'allowed': [], 'blocked': []})

    def response(self, text, url='https://raw.githubusercontent.com/blocklistproject/Lists/master/list.txt'):
        stream = io.BytesIO(text.encode())
        stream.geturl = lambda: url
        return stream

    def test_cache_replaced_only_after_all_downloads_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DomainLists(directory)
            with patch('core.internet.urlopen', side_effect=[self.response('malware.org'), self.response('phishing.org')]):
                store.update(['dangerous'])
            old = store.path.read_bytes()
            with patch('core.internet.urlopen', side_effect=[self.response('new.org'), OSError('offline')]):
                with self.assertRaises(OSError):
                    store.update(['dangerous'])
            self.assertEqual(store.path.read_bytes(), old)
            self.assertEqual(store.load()['lists']['dangerous'], ['malware.org', 'phishing.org'])

    def test_invalid_download_does_not_replace_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DomainLists(directory)
            for response in (self.response('<html>error</html>'), self.response('example.org', 'https://untrusted.org/')):
                with patch('core.internet.urlopen', return_value=response), self.assertRaises(ValueError):
                    store.update(['ads'])
            self.assertFalse(store.path.exists())

    def test_default_categories_and_invalid_settings(self):
        self.assertEqual(preferences({})['categories'], ['dangerous'])
        with self.assertRaises(ValueError):
            preferences({'internet_protection': {'allowed': 'example.org'}})


@unittest.skipUnless(os.name == 'posix', 'Linux hosts helper uses POSIX locks')
class HostsHelperTests(unittest.TestCase):
    def setUp(self):
        from backends.linux_hosts import HOSTS_HELPER
        self.namespace = {'__name__': 'test_hosts_helper'}
        exec(HOSTS_HELPER, self.namespace)
        self.replace = self.namespace['replace_hosts']
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name, 'hosts')

    def test_apply_update_pause_preserves_existing_and_external_changes(self):
        from backends.linux_hosts import inspect_hosts
        original = b'127.0.0.1 localhost\n192.168.1.3 local.example.org\n'
        self.path.write_bytes(original)
        self.path.chmod(0o640)
        result = self.replace(str(self.path), ['blocked.org', 'local.example.org'])
        self.assertEqual(result, {'count': 1, 'skipped': 1})
        self.assertEqual(inspect_hosts(self.path)['count'], 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(Path(str(self.path) + '.libreward-backup').read_bytes(), original)
        self.path.write_bytes(self.path.read_bytes() + b'192.168.1.4 new.example.org\n')
        self.replace(str(self.path), ['other.org'])
        self.assertNotIn(b'blocked.org', self.path.read_bytes())
        self.replace(str(self.path), [])
        self.assertEqual(self.path.read_bytes(), original + b'192.168.1.4 new.example.org\n')

    def test_no_final_newline_roundtrip(self):
        original = b'127.0.0.1 localhost'
        self.path.write_bytes(original)
        self.replace(str(self.path), ['example.org'])
        self.replace(str(self.path), [])
        self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_payload_never_modifies_hosts(self):
        self.path.write_bytes(b'127.0.0.1 localhost\n')
        for value in [['127.0.0.1'], ['example.org\n127.0.0.1 hacked.org'], ['x.local'], 'example.org']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.replace(str(self.path), value)
        self.assertEqual(self.path.read_bytes(), b'127.0.0.1 localhost\n')

    def test_symlink_and_damaged_markers_are_refused(self):
        other = Path(self.temp.name, 'other')
        other.write_bytes(b'127.0.0.1 localhost\n')
        self.path.symlink_to(other)
        with self.assertRaises(OSError):
            self.replace(str(self.path), ['example.org'])
        self.assertEqual(other.read_bytes(), b'127.0.0.1 localhost\n')
        self.path.unlink()
        self.path.write_bytes(self.namespace['BEGIN'] + b'broken\n')
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.replace(str(self.path), [])
        self.assertEqual(self.path.read_bytes(), before)

    def test_replace_failure_leaves_original_untouched(self):
        self.path.write_bytes(b'127.0.0.1 localhost\n')
        with patch('os.replace', side_effect=OSError('read-only filesystem')), self.assertRaises(OSError):
            self.replace(str(self.path), ['example.org'])
        self.assertEqual(self.path.read_bytes(), b'127.0.0.1 localhost\n')
        self.assertFalse(list(Path(self.temp.name).glob('.libreward-hosts-*')))


class InternetBackendTests(unittest.TestCase):
    def test_resolved_before_files_is_supported_when_it_reads_hosts(self):
        from backends.linux import LinuxBackend
        backend = LinuxBackend()
        nss = 'hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n'
        with patch('backends.linux_hosts.inspect_hosts', return_value={'supported': True, 'active': False, 'count': 0}), \
             patch('backends.linux.Path.read_text', return_value=nss), \
             patch.object(backend, '_firewall_executable', return_value='/usr/bin/systemd-analyze'), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/python3'), \
             patch.object(backend, '_firewall_query', return_value=(0, '[Resolve]\n#ReadEtcHosts=yes\n')):
            state = backend.inspect_internet_protection()
        self.assertTrue(state['supported'])
        self.assertIn('systemd-resolved', state['message'])

    def test_apply_uses_fixed_isolated_helper_and_verifies_result(self):
        from backends.linux import LinuxBackend
        from backends.linux_hosts import HOSTS_HELPER
        backend = LinuxBackend()
        process = Mock(returncode=0)
        process.communicate.return_value = ('{"count":1,"skipped":0}', None)
        received = []
        def start_helper(*args, **kwargs):
            received.append(json.load(kwargs['stdin']))
            return process
        with patch.object(backend, 'inspect_internet_protection', side_effect=[
                {'supported': True, 'count': 0}, {'supported': True, 'active': True, 'count': 1}]), \
             patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/python3'), \
             patch.object(backend, 'start_process', side_effect=start_helper) as start:
            result = backend.apply_internet_protection(['Example.org'])
        self.assertTrue(result['active'])
        self.assertEqual(start.call_args.args[0], ['/usr/bin/pkexec', '--disable-internal-agent',
                                                 '/usr/bin/python3', '-I', '-c', HOSTS_HELPER])
        self.assertEqual(received, [['example.org']])
        self.assertEqual(process.communicate.call_args.args, ())
        self.assertNotIn('shell', start.call_args.kwargs)

    def test_unsupported_setup_is_not_changed(self):
        from backends.linux import LinuxBackend
        backend = LinuxBackend()
        with patch.object(backend, 'inspect_internet_protection', return_value={
                'supported': False, 'message': 'Unsupported resolver'}), patch.object(backend, 'start_process') as start:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported resolver'):
                backend.apply_internet_protection(['example.org'])
        start.assert_not_called()

    def test_authorization_cancellation_is_reported(self):
        from backends.linux import LinuxBackend
        from core.authorization import AuthorizationError
        backend = LinuxBackend()
        process = Mock(returncode=126)
        process.communicate.return_value = ('cancelled', None)
        with patch.object(backend, 'inspect_internet_protection', return_value={'supported': True}), \
             patch.object(backend, '_require_authorizer', return_value='/usr/bin/pkexec'), \
             patch.object(backend, '_trusted_firewall_executable', return_value='/usr/bin/python3'), \
             patch.object(backend, 'start_process', return_value=process), self.assertRaises(AuthorizationError):
            backend.apply_internet_protection([])


class ResolverConfigurationTests(unittest.TestCase):
    def test_files_and_resolved_orders(self):
        from backends.linux_resolver import nss_hosts_source
        self.assertEqual(nss_hosts_source(' hosts : files dns'), 'files')
        config = 'hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns'
        self.assertIsNone(nss_hosts_source(config))
        self.assertEqual(nss_hosts_source(config, resolved_hosts=True), 'resolve')
        self.assertIsNone(nss_hosts_source('hosts: dns files', resolved_hosts=True))
        self.assertIsNone(nss_hosts_source('hosts: files [SUCCESS=continue] dns'))

    def test_resolved_default_and_drop_in_overrides(self):
        from backends.linux_resolver import resolved_reads_hosts
        self.assertTrue(resolved_reads_hosts('[Resolve]\n#ReadEtcHosts=yes\n'))
        self.assertFalse(resolved_reads_hosts('[Resolve]\nReadEtcHosts=no\n'))
        self.assertTrue(resolved_reads_hosts('[Resolve]\nReadEtcHosts=no\n[Resolve]\nReadEtcHosts=yes\n'))

class LocalDnsTests(unittest.TestCase):
    def test_requires_existing_networkmanager_dnsmasq_without_bypass(self):
        from backends.linux_dns import compatible
        self.assertTrue(compatible('[main]\ndns=dnsmasq', 'hosts: files dns', 'nameserver 127.0.0.1\n'))
        for config, nss, resolv in (
                ('[main]\ndns=systemd-resolved', 'hosts: files dns', 'nameserver 127.0.0.1'),
                ('[main]\ndns=dnsmasq', 'hosts: resolve files dns', 'nameserver 127.0.0.1'),
                ('[main]\ndns=dnsmasq', 'hosts: files dns', 'nameserver 127.0.0.1\nnameserver 1.1.1.1')):
            self.assertFalse(compatible(config, nss, resolv))

    def test_adult_list_optional_and_allow_exception_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DomainLists(directory)
            stream = io.BytesIO(b'adult.example.org\nallowed.example.org\n')
            stream.geturl = lambda: 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt'
            with patch('core.internet.urlopen', return_value=stream) as fetch:
                store.update(['adult'])
            self.assertIn('porn-nl.txt', fetch.call_args.args[0].full_url)
            self.assertEqual(store.compile({'categories': ['adult'], 'allowed': ['allowed.example.org'], 'blocked': []}),
                             ['adult.example.org'])
        self.assertNotIn('adult', preferences({})['categories'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX helper')
    def test_failed_health_check_rolls_back_then_apply_and_pause_migrate_hosts(self):
        from backends.linux_dns import helper
        namespace = {'__name__': 'test_dns_helper'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager'), namespace)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            confdir = root / 'dnsmasq.d'
            confdir.mkdir()
            conf = confdir / '90-libreward.conf'
            domains = root / 'domains.hosts'
            hosts = root / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            replace = namespace['replace_hosts']
            replace(str(hosts), ['old.example.org'])
            original = hosts.read_bytes()
            namespace.update(SETUP_CONF=str(root / 'setup.conf'), LIST=str(domains), CONF=str(conf), CONTENT='addn-hosts=' + str(domains) + '\n')
            namespace['replace_hosts'] = lambda path, values: replace(str(hosts) if path == '/etc/hosts' else path, values)
            namespace['reload_dns'] = Mock()
            namespace['probe'] = Mock(side_effect=RuntimeError('DNS offline'))
            namespace['compatible'] = Mock(return_value=True)
            with patch('subprocess.run', return_value=Mock(stdout='[main]\ndns=dnsmasq')), \
                 patch.object(Path, 'read_text', return_value=''), patch('time.sleep'):
                with self.assertRaisesRegex(RuntimeError, 'DNS offline'):
                    namespace['apply_dns'](['new.example.org'])
                self.assertFalse(conf.exists())
                self.assertFalse(domains.exists())
                self.assertEqual(hosts.read_bytes(), original)
                namespace['probe'] = Mock()
                self.assertEqual(namespace['apply_dns'](['new.example.org'])['count'], 1)
                self.assertIn(b'new.example.org', domains.read_bytes())
                self.assertEqual(hosts.read_bytes(), b'127.0.0.1 localhost\n')
                self.assertEqual(namespace['apply_dns']([])['count'], 0)
                self.assertFalse(conf.exists())
                self.assertFalse(domains.exists())

    def test_large_hosts_fallback_is_refused_before_authorization(self):
        from backends.linux import LinuxBackend
        backend = LinuxBackend()
        with patch.object(backend, 'inspect_internet_protection', return_value={'supported': True, 'engine': 'hosts'}), \
             patch.object(backend, '_require_authorizer') as auth:
            with self.assertRaisesRegex(RuntimeError, 'local DNS backend'):
                backend.apply_internet_protection([f'd{i}.example.org' for i in range(50001)])
            auth.assert_not_called()

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

    def test_setup_helper_installs_owned_snippet_and_pause_restores_previous_mode(self):
        from backends.linux_dns import helper
        namespace = {'__name__': 'test_dns_setup'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager', setup=True), namespace)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            config = root / 'dnsmasq.d' / '90-libreward.conf'
            setup = root / 'conf.d' / '90-libreward-dns.conf'
            domains = root / 'domains.hosts'
            replace = namespace['replace_hosts']
            namespace.update(LIST=str(domains), CONF=str(config), SETUP_CONF=str(setup),
                             CONTENT='addn-hosts=' + str(domains) + '\n')
            namespace['replace_hosts'] = lambda path, values: replace(str(hosts) if path == '/etc/hosts' else path, values)
            namespace['compatible'] = Mock(side_effect=[False, True])
            namespace['setup_supported'] = Mock(return_value=True)
            namespace['probe'] = Mock()
            namespace['reload_dns'] = Mock()
            with patch('subprocess.run', return_value=Mock(stdout='[main]\n')), \
                 patch.object(Path, 'read_text', return_value=''):
                namespace['apply_dns'](['blocked.example.org'])
                self.assertEqual(setup.read_bytes(), b'[main]\ndns=dnsmasq\n')
                namespace['apply_dns']([])
                self.assertFalse(setup.exists())
                self.assertFalse(config.exists())
                self.assertFalse(domains.exists())
                self.assertEqual(namespace['reload_dns'].call_count, 2)
                namespace['compatible'] = Mock(return_value=True)
                namespace['probe'] = Mock(side_effect=RuntimeError('health check failed'))
                with patch('time.sleep'), self.assertRaisesRegex(RuntimeError, 'health check failed'):
                    namespace['apply_dns'](['blocked.example.org'])
                self.assertFalse(setup.exists())
                self.assertFalse(config.exists())
                self.assertFalse(domains.exists())
                namespace['reload_dns'] = Mock(side_effect=[None, RuntimeError('reload failed')])
                with patch('time.sleep'), self.assertRaisesRegex(RuntimeError, 'previous configuration files were restored.*health check failed.*reload failed'):
                    namespace['apply_dns'](['blocked.example.org'])
                self.assertFalse(setup.exists())
                self.assertFalse(config.exists())
                self.assertFalse(domains.exists())

    def test_setup_refuses_changed_network_before_installing_dns_config(self):
        from backends.linux_dns import helper
        namespace = {'__name__': 'test_dns_setup'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager', setup=True), namespace)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            setup = root / 'conf.d' / '90-libreward-dns.conf'
            namespace.update(LIST=str(root / 'domains.hosts'), CONF=str(root / 'dnsmasq.d' / '90-libreward.conf'),
                             SETUP_CONF=str(setup))
            namespace['compatible'] = Mock(return_value=False)
            namespace['setup_supported'] = Mock(return_value=False)
            with patch('subprocess.run', return_value=Mock(stdout='[main]\n')), \
                 patch.object(Path, 'read_text', return_value=''), self.assertRaisesRegex(RuntimeError, 'changed'):
                namespace['apply_dns'](['blocked.example.org'])
            self.assertFalse(setup.exists())

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
            with patch('core.memory_budget.available_memory', return_value=4 * 1024**3):
                self.assertEqual(store.compile({'categories': ['adult'], 'blocked': ['extra.example.org'],
                                               'allowed': ['safe.example.org']}),
                                 ['adult.example.org', 'extra.example.org'])
            with patch('core.memory_budget.available_memory', return_value=0), self.assertRaisesRegex(ValueError, 'memory'):
                store.compile({'categories': ['adult'], 'blocked': [], 'allowed': []})

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

    def test_streaming_status_count_and_digest(self):
        from backends.linux_hosts import inspect_hosts
        from core.internet import domain_digest
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'hosts')
            path.write_text('# BEGIN LIBREWARD DOMAIN PROTECTION\n'
                            '0.0.0.0 a.example.org\n:: a.example.org\n'
                            '0.0.0.0 b.example.org\n:: b.example.org\n'
                            '# END LIBREWARD DOMAIN PROTECTION\n')
            state = inspect_hosts(path)
            self.assertEqual(state['count'], 2)
            self.assertEqual(state['digest'], domain_digest(['a.example.org', 'b.example.org']))
            path.write_text('# BEGIN LIBREWARD DOMAIN PROTECTION\n0.0.0.0 a.example.org\n# END LIBREWARD DOMAIN PROTECTION\n')
            with self.assertRaises(ValueError):
                inspect_hosts(path)


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
