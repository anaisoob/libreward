"""Privileged DNS installer tested only against temporary files and fake services."""
import io
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
            'SETUP_CONF': str(root / 'conf.d' / '90-libreward-dns.conf')}
        namespace.update(self.mapping)
        namespace['check_upstream_port'] = Mock()
        namespace['compatible'] = Mock(return_value=True)
        namespace['query_health'] = Mock()
        namespace['probe'] = Mock()
        namespace['reload_dns'] = Mock()
        namespace['remove_legacy_hosts'] = Mock()
        namespace['wait_for_dns_port'] = Mock()
        namespace['systemctl'] = Mock(side_effect=lambda *args, **kwargs: args[0] not in ('is-active', 'is-enabled'))
        self.run = patch('subprocess.run', return_value=Mock(stdout='[main]\ndns=dnsmasq\n', returncode=0))
        self.run.start()
        self.addCleanup(self.run.stop)

    def apply(self, data=b'a.example.org\nb.example.org\n', count=2):
        with patch.object(Path, 'read_text', return_value=''):
            return self.ns['apply_database'](io.BytesIO(data), count)

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

    def test_bad_records_do_not_change_network_configuration(self):
        for data, count in ((b'a.example.org\n', 2), (b'a.example.org\na.example.org\n', 2),
                            (b'127.0.0.1\n', 1), (b'bad.local\n', 1), (b'a.org\nextra.org\n', 1)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.apply(data, count)
        self.ns['reload_dns'].assert_not_called()
        self.assertFalse(Path(self.mapping['CONF']).exists())

    def test_first_install_failure_keeps_previous_nm_configuration(self):
        conf = Path(self.mapping['CONF'])
        conf.parent.mkdir()
        conf.write_text(self.ns['CONTENT'])
        self.ns['query_health'].side_effect = RuntimeError('new filter failed')
        with self.assertRaisesRegex(RuntimeError, 'new filter failed'):
            self.apply()
        self.assertEqual(conf.read_text(), self.ns['CONTENT'])
        self.assertFalse(Path(self.mapping['DATABASE']).exists())
        self.assertFalse(Path(self.mapping['UNIT']).exists())

@unittest.skipUnless(os.name == 'posix', 'Linux installer uses POSIX locks')
class PreparedDatabaseTests(unittest.TestCase):
    def test_preparing_and_installing_never_calls_the_in_memory_compiler(self):
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
            with patch.object(store, 'compile', side_effect=AssertionError('List materialized')):
                with store.prepare({'categories': ['adult'], 'blocked': ['custom.example.org'], 'allowed': ['allowed.example.org']}) as prepared:
                    path = prepared.path
                    self.assertEqual(prepared.count, 2)
                    with path.open('rb') as stream:
                        header = json.loads(stream.readline())
                        self.assertEqual(header['count'], 2)
                        self.assertEqual(stream.read(), b'blocked.example.org\ncustom.example.org\n')
                self.assertFalse(path.exists())

    def test_legacy_hosts_removal_preserves_other_entries_and_original_newline(self):
        namespace = {'__name__': 'test_dns_hosts_migration'}
        exec(helper('/usr/bin/nmcli', '/usr/sbin/NetworkManager', '/usr/bin/systemctl', '/usr/bin/python3'), namespace)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'hosts')
            for original in (b'127.0.0.1 localhost', b'127.0.0.1 localhost\n'):
                path.write_bytes(original)
                namespace['replace_hosts'](str(path), ['old.example.org'])
                namespace['remove_legacy_hosts'](str(path))
                self.assertEqual(path.read_bytes(), original)

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
