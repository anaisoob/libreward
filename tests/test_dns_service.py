"""Privileged DNS installer tested only against temporary files and fake services."""
import io
import json
import os
import hashlib
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backends.linux_dns_service import helper


@unittest.skipUnless(os.name == 'posix', 'Linux installer uses POSIX locks')
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root
        namespace = {'__name__': 'test_dns_installer'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager', '/usr/bin/systemctl', '/usr/bin/python3'), namespace)
        self.ns = namespace
        # Unmocked copy for testing helpers that the installer tests replace.
        self.ns_real = dict(namespace)
        service_dir = root / 'libreward'
        service_dir.mkdir()
        self.mapping = {
            'ROOT': str(service_dir), 'DATABASE': str(service_dir / 'domains.sqlite3'),
            'STATE': str(service_dir / 'dns-state.json'), 'SERVICE': str(service_dir / 'dns-service.py'),
            'RECOVERY': str(service_dir / 'dns-recovery.py'), 'UNIT': str(root / 'libreward-dns.service'),
            'RECOVERY_UNIT_PATH': str(root / 'libreward-dns-recover.service'),
            'CONF': str(root / 'dnsmasq.d' / '90-libreward.conf'),
            'SETUP_CONF': str(root / 'conf.d' / '90-libreward-dns.conf'),
            'RESOLVED_CONF': str(root / 'resolved.conf.d' / '90-libreward-filter.conf')}
        namespace.update(self.mapping)
        namespace['check_upstream_port'] = Mock()
        namespace['compatible'] = Mock(return_value=True)
        namespace['query_health'] = Mock()
        namespace['probe'] = Mock()
        namespace['reload_dns'] = Mock()
        namespace['wait_for_dns_port'] = Mock()
        namespace['reload_resolved'] = Mock()
        namespace['filter_health'] = Mock()
        namespace['resolved_health'] = Mock()
        namespace['systemctl'] = Mock(side_effect=lambda *args, **kwargs: args[0] not in ('is-active', 'is-enabled'))
        self.run = patch('subprocess.run', return_value=Mock(stdout='[main]\ndns=dnsmasq\n', returncode=0))
        self.run.start()
        self.addCleanup(self.run.stop)

    def apply(self, data=b'a.example.org\nb.example.org\n', count=2, mode='networkmanager', provider=None):
        with patch.object(Path, 'read_text', return_value=''):
            return self.ns['apply_database'](io.BytesIO(data), count, mode, provider)

    def resolved(self, data=b'a.example.org\n', count=1, provider='quad9'):
        with patch.dict(self.ns, network_ready=Mock(return_value=True)):
            return self.apply(data, count, 'resolved', provider)

    def test_resolved_mode_checks_the_filter_before_resolved_points_to_it(self):
        order = []
        resolved_conf = Path(self.mapping['RESOLVED_CONF'])
        self.ns['filter_health'].side_effect = lambda: order.append(('filter checked', resolved_conf.exists()))
        self.ns['reload_resolved'].side_effect = lambda: order.append(('resolved reloaded', resolved_conf.exists()))
        self.ns['resolved_health'].side_effect = lambda allowed: order.append(('lookups checked', allowed))
        self.resolved()
        self.assertEqual(order, [('filter checked', False), ('resolved reloaded', True), ('lookups checked', 'example.org')])
        self.assertEqual(resolved_conf.read_bytes(), self.ns['RESOLVED_CONTENT'])
        unit = Path(self.mapping['UNIT']).read_text()
        self.assertIn('--listen-port 5354 --tls-upstream 9.9.9.9#dns.quad9.net --tls-upstream 149.112.112.112#dns.quad9.net\n', unit)
        state = json.loads(Path(self.mapping['STATE']).read_text())
        self.assertEqual((state['mode'], state['provider'], state['phase']), ('resolved', 'quad9', 'enabled'))
        # NetworkManager is neither changed nor reloaded on a resolved system.
        self.assertFalse(Path(self.mapping['CONF']).exists())
        self.ns['reload_dns'].assert_not_called()

    def test_resolved_pause_and_failure_restore_normal_dns(self):
        resolved_conf = Path(self.mapping['RESOLVED_CONF'])
        self.ns['resolved_health'].side_effect = RuntimeError('Websites could not be reached')
        with self.assertRaisesRegex(RuntimeError, 'could not be reached'):
            self.resolved()
        self.assertFalse(resolved_conf.exists())
        self.assertFalse(Path(self.mapping['STATE']).exists())
        self.assertEqual(self.ns['reload_resolved'].call_count, 2)  # apply and rollback
        self.ns['resolved_health'].side_effect = None
        self.ns['reload_resolved'].reset_mock()
        self.resolved()
        self.apply(b'', 0)
        self.assertFalse(resolved_conf.exists())
        self.assertEqual(self.ns['reload_resolved'].call_count, 2)
        self.ns['reload_dns'].assert_not_called()
        self.assertFalse(json.loads(Path(self.mapping['STATE']).read_text())['active'])

    def test_foreign_resolved_dropin_is_never_replaced(self):
        resolved_conf = Path(self.mapping['RESOLVED_CONF'])
        resolved_conf.parent.mkdir()
        resolved_conf.write_text('[Resolve]\nDNS=192.0.2.1\n')
        with self.assertRaisesRegex(ValueError, 'changed outside'):
            self.resolved()
        self.assertEqual(resolved_conf.read_text(), '[Resolve]\nDNS=192.0.2.1\n')
        self.ns['reload_resolved'].assert_not_called()

    def test_streaming_install_builds_indexed_db_and_pause_removes_dns_overrides(self):
        result = self.apply()
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['digest'], hashlib.sha256(b'a.example.org\nb.example.org\n').hexdigest())
        with closing(sqlite3.connect(self.mapping['DATABASE'])) as db, db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM blocked WHERE domain=?', ('a.example.org',)).fetchone())
        self.assertEqual(Path(self.mapping['CONF']).read_bytes(), b'port=5354\n')
        self.assertIn(b'MemoryMax=128M', Path(self.mapping['UNIT']).read_bytes())
        self.assertNotIn(b'addn-hosts', Path(self.mapping['CONF']).read_bytes())
        self.apply(b'', 0)
        self.assertFalse(Path(self.mapping['CONF']).exists())
        self.assertFalse(Path(self.mapping['SETUP_CONF']).exists())
        self.assertIn(b'false', Path(self.mapping['STATE']).read_bytes())

    def test_health_failure_restores_previous_database_and_configuration(self):
        self.apply()
        db_before = Path(self.mapping['DATABASE']).read_bytes()
        conf_before = Path(self.mapping['CONF']).read_bytes()
        state_before = Path(self.mapping['STATE']).read_bytes()
        self.ns['query_health'].side_effect = RuntimeError('health failure')
        with self.assertRaisesRegex(RuntimeError, 'health failure'):
            self.apply(b'new.example.org\n', 1)
        self.assertEqual(Path(self.mapping['DATABASE']).read_bytes(), db_before)
        self.assertEqual(Path(self.mapping['CONF']).read_bytes(), conf_before)
        self.assertEqual(Path(self.mapping['STATE']).read_bytes(), state_before)
        self.assertFalse(list(Path(self.mapping['ROOT']).glob('.domains-*')))

    def test_filter_starts_only_after_resolver_releases_port(self):
        order = []
        self.ns['reload_dns'].side_effect = lambda: order.append('reload')
        self.ns['wait_for_dns_port'].side_effect = lambda: order.append('port free')
        self.ns['systemctl'].side_effect = lambda *args, **kwargs: (
            order.append(args[0]) if args[:2] == ('start', 'libreward-dns.service') else None,
            args[0] not in ('is-active', 'is-enabled'))[1]
        self.apply()
        self.assertEqual(order[:3], ['reload', 'port free', 'start'])

    def test_waiting_for_port_retries_then_reports_clearly(self):
        import socket
        calls = []
        def bind(self_, address):
            calls.append(address)
            if len(calls) < 3:
                raise OSError('Address already in use')
        with patch.object(socket.socket, 'bind', bind), patch('time.sleep'):
            self.ns_real['wait_for_dns_port']()
        self.assertEqual(calls[-2:], [('127.0.0.1', 53), ('127.0.0.1', 53)])
        with patch.object(socket.socket, 'bind', side_effect=OSError('busy')), patch('time.sleep'):
            with self.assertRaisesRegex(RuntimeError, 'did not release'):
                self.ns_real['wait_for_dns_port'](3)

    def test_unreachable_websites_are_explained_and_rolled_back(self):
        self.ns['probe'].side_effect = RuntimeError('Local DNS health check failed.')
        with self.assertRaisesRegex(RuntimeError, 'internet connection'):
            self.apply()
        for name in ('CONF', 'SETUP_CONF', 'DATABASE', 'STATE'):
            self.assertFalse(Path(self.mapping[name]).exists(), name)

    def test_bad_records_do_not_change_network_configuration(self):
        for data, count in ((b'a.example.org\n', 2), (b'a.example.org\na.example.org\n', 2),
                            (b'127.0.0.1\n', 1), (b'bad.local\n', 1), (b'a.org\nextra.org\n', 1)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.apply(data, count)
        self.ns['reload_dns'].assert_not_called()
        self.assertFalse(Path(self.mapping['CONF']).exists())

    def test_first_install_failure_leaves_no_dns_changes(self):
        self.ns['query_health'].side_effect = RuntimeError('new filter failed')
        with self.assertRaisesRegex(RuntimeError, 'new filter failed'):
            self.apply()
        for name in ('CONF', 'SETUP_CONF', 'DATABASE', 'UNIT', 'STATE'):
            self.assertFalse(Path(self.mapping[name]).exists(), name)

    def test_foreign_dnsmasq_snippet_is_never_replaced(self):
        conf = Path(self.mapping['CONF'])
        conf.parent.mkdir()
        conf.write_text('addn-hosts=/etc/other.hosts\n')
        with self.assertRaisesRegex(ValueError, 'changed outside'):
            self.apply()
        self.assertEqual(conf.read_text(), 'addn-hosts=/etc/other.hosts\n')
        self.ns['reload_dns'].assert_not_called()

@unittest.skipUnless(os.name == 'posix', 'Linux installer uses POSIX locks')
class PreparedDatabaseTests(unittest.TestCase):
    def test_preparing_streams_selected_domains_to_a_single_use_file(self):
        from core.internet import DiskDomainLists
        import json
        with tempfile.TemporaryDirectory() as directory:
            store = DiskDomainLists(directory)
            store.path.parent.mkdir(parents=True)
            with closing(store.connect(store.path)) as db, db:
                db.execute('CREATE TABLE domains(category TEXT, domain TEXT, PRIMARY KEY(category,domain)) WITHOUT ROWID')
                db.execute('CREATE TABLE metadata(value TEXT)')
                db.execute('INSERT INTO metadata VALUES (?)', (json.dumps({'lists': {'adult': 2}}),))
                db.executemany('INSERT INTO domains VALUES (?,?)', [('adult', 'blocked.example.org'), ('adult', 'allowed.example.org')])
            with store.prepare({'categories': ['adult'], 'blocked': ['custom.example.org'], 'allowed': ['allowed.example.org']}) as prepared:
                path = prepared.path
                self.assertEqual(prepared.count, 2)
                with path.open('rb') as stream:
                    header = json.loads(stream.readline())
                    self.assertEqual(header['count'], 2)
                    self.assertEqual(stream.read(), b'blocked.example.org\ncustom.example.org\n')
            self.assertFalse(path.exists())

    def test_recovery_behind_resolved_removes_only_its_dropin(self):
        from backends.linux_dns_service import RECOVERY_SOURCE
        source = RECOVERY_SOURCE.replace('__NMCLI__', repr('/usr/bin/nmcli')).replace('__SYSTEMCTL__', repr('/usr/bin/systemctl'))
        namespace = {'__name__': 'test_dns_recovery'}
        exec(source, namespace)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state.json'
            state.write_text(json.dumps({'active': True, 'count': 10, 'mode': 'resolved'}))
            dropin = root / 'resolved.conf'
            dropin.write_text(namespace['RESOLVED_CONTENT'])
            (root / '.dns-lock').touch()
            namespace.update(ROOT=str(root), STATE=str(state), CONF=str(root / 'none1'), SETUP=str(root / 'none2'),
                             RESOLVED=str(dropin))
            with patch('subprocess.run', return_value=Mock(returncode=1)) as run:
                namespace['recover']()
            commands = [call.args[0] for call in run.call_args_list]
            self.assertFalse(dropin.exists())
            self.assertIn(['/usr/bin/systemctl', 'reload-or-restart', 'systemd-resolved.service'], commands)
            self.assertNotIn(['/usr/bin/nmcli', 'general', 'reload'], commands)
            self.assertFalse(json.loads(state.read_text())['active'])

    def test_failure_recovery_restores_normal_dns_without_replacing_connection_profiles(self):
        from backends.linux_dns_service import RECOVERY_SOURCE
        import json
        source = RECOVERY_SOURCE.replace('__NMCLI__', repr('/usr/bin/nmcli')).replace('__SYSTEMCTL__', repr('/usr/bin/systemctl'))
        namespace = {'__name__': 'test_dns_recovery'}
        exec(source, namespace)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state.json'
            state.write_text(json.dumps({'active': True, 'count': 1000000}))
            conf, setup = root / 'dns.conf', root / 'setup.conf'
            conf.write_text('port=5354\n')
            setup.write_text('[main]\ndns=dnsmasq\n')
            (root / '.dns-lock').touch()
            namespace.update(ROOT=str(root), STATE=str(state), CONF=str(conf), SETUP=str(setup))
            with patch('subprocess.run') as run:
                namespace['recover']()
            self.assertFalse(conf.exists())
            self.assertFalse(setup.exists())
            self.assertFalse(json.loads(state.read_text())['active'])
            self.assertIn(['/usr/bin/nmcli', 'general', 'reload'], [call.args[0] for call in run.call_args_list])
            self.assertNotIn('connection', str(run.call_args_list))
