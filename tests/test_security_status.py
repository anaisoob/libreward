"""Security status: facts read from Linux, and what they mean in plain words."""
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from backends import linux_security as security
from core.security_status import security_items, summary

APP = {'websites_available': True, 'websites_on': True, 'files_on': True, 'scanning_ready': True}


class SecurityFactsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, relative, text, executable=False):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if executable:
            path.chmod(0o755)
        return path

    def test_automatic_updates_and_last_update_on_debian_and_arch(self):
        apt = self.root / 'apt.conf.d'
        self.write('apt.conf.d/20auto-upgrades', 'APT::Periodic::Update-Package-Lists "1";\n')
        self.assertFalse(security.automatic_updates('dpkg', apt_config=apt))
        self.write('apt.conf.d/20auto-upgrades', 'APT::Periodic::Unattended-Upgrade "1";\n')
        self.assertTrue(security.automatic_updates('dpkg', apt_config=apt))
        self.assertIsNone(security.automatic_updates('pacman'))
        dpkg = self.write('dpkg.log', '2026-10-01 09:00:00 install foo:amd64 <none> 1\n'
                                      '2026-10-20 10:30:00 upgrade bar:amd64 1 2\n'
                                      '2026-10-21 08:00:00 status installed bar:amd64 2\n')
        self.assertEqual(time.strftime('%Y-%m-%d %H:%M', time.localtime(security.last_update('dpkg', dpkg_log=dpkg))),
                         '2026-10-20 10:30')
        pacman = self.write('pacman.log', '[2026-10-19T08:00:00+0200] [PACMAN] starting full system upgrade\n'
                                          '[2026-10-19T08:01:00+0200] [ALPM] upgraded linux (1 -> 2)\n')
        self.assertIsNotNone(security.last_update('pacman', pacman_log=pacman))
        self.assertIsNone(security.last_update('dpkg', dpkg_log=self.root / 'missing'))

    def test_only_ports_open_to_other_computers_are_listed(self):
        public, local = socket.socket(), socket.socket()
        self.addCleanup(public.close)
        self.addCleanup(local.close)
        public.bind(('0.0.0.0', 0))
        local.bind(('127.0.0.1', 0))
        public.listen()
        local.listen()
        ports = security.listening_ports()
        self.assertIn(public.getsockname()[1], ports)
        self.assertNotIn(local.getsockname()[1], ports)

    def test_firewall_from_firewalld_or_ufw_settings(self):
        running = self.write('bin/firewall-cmd', '#!/bin/sh\necho running\n', executable=True)
        stopped = self.write('bin/stopped', '#!/bin/sh\necho "not running"; exit 252\n', executable=True)
        self.assertTrue(security.firewall_enabled(ufw_config=self.root / 'none', firewall_cmd=str(running)))
        self.assertFalse(security.firewall_enabled(ufw_config=self.root / 'none', firewall_cmd=str(stopped)))
        ufw = self.write('ufw.conf', '# comment\nENABLED=yes\n')
        self.assertTrue(security.firewall_enabled(ufw_config=ufw, firewall_cmd=''))
        self.write('ufw.conf', 'ENABLED=no\n')
        self.assertFalse(security.firewall_enabled(ufw_config=ufw, firewall_cmd=''))
        self.assertIsNone(security.firewall_enabled(ufw_config=self.root / 'none', firewall_cmd=''))

    def test_disk_encryption_follows_the_device_of_the_home_folder(self):
        tree = {'blockdevices': [{'name': 'nvme0n1', 'type': 'disk', 'mountpoints': [None], 'children': [
            {'name': 'p1', 'type': 'part', 'mountpoints': ['/boot/efi']},
            {'name': 'p2', 'type': 'part', 'mountpoints': [None], 'children': [
                {'name': 'luks-1', 'type': 'crypt', 'mountpoints': ['/', '/home']}]}]}]}
        lsblk = self.write('bin/lsblk', f"#!/bin/sh\ncat <<'END'\n{json.dumps(tree)}\nEND\n", executable=True)
        self.assertTrue(security.disk_encrypted(str(lsblk)))
        tree['blockdevices'][0]['children'][1]['children'][0]['type'] = 'part'
        lsblk = self.write('bin/lsblk', f"#!/bin/sh\ncat <<'END'\n{json.dumps(tree)}\nEND\n", executable=True)
        self.assertFalse(security.disk_encrypted(str(lsblk)))

    def test_administrator_groups_and_gnome_screen_lock(self):
        self.assertTrue(security.administrator_account(['users', 'wheel']))
        self.assertFalse(security.administrator_account(['users']))
        log = self.root / 'gsettings.log'
        self.write('bin/gsettings', f"""#!/bin/sh
echo "$@" >> {log}
case "$2 $3" in
  "org.gnome.desktop.screensaver lock-enabled") echo false ;;
  "org.gnome.desktop.session idle-delay") echo "uint32 0" ;;
esac
""", executable=True)
        with patch.dict(os.environ, {'PATH': f"{self.root / 'bin'}:{os.environ['PATH']}"}):
            self.assertEqual(security.screen_lock('ubuntu:GNOME'), ('gnome', False))
            security.turn_on_screen_lock('gnome')
        changes = [line for line in log.read_text().splitlines() if line.startswith('set')]
        self.assertEqual(changes, ['set org.gnome.desktop.screensaver lock-enabled true',
                                   'set org.gnome.desktop.session idle-delay 300'])
        self.assertEqual(security.screen_lock('XFCE'), (None, None))


class SecurityItemsTests(unittest.TestCase):
    def items(self, facts, **app):
        return {entry['key']: entry for entry in security_items(facts, **dict(APP, **app), now=100 * 86400)}

    def test_everything_on_is_well_protected(self):
        facts = {'automatic_updates': True, 'firewall': True, 'listening_ports': [5355], 'desktop_ports': [5355],
                 'screen_lock': True, 'disk_encrypted': True, 'administrator': False}
        items = security_items(facts, **APP)
        self.assertEqual(summary(items), ('This computer is well protected', 'success'))
        self.assertEqual(self.items(facts)['network']['title'], 'No programs wait for connections from other computers')

    def test_old_updates_need_attention_with_the_way_to_install_them(self):
        facts = {'automatic_updates': False, 'last_update': 70 * 86400, 'pkg_manager': 'dnf'}
        update = self.items(facts)['updates']
        self.assertEqual((update['title'], update['severity'], update['action']),
                         ('System not updated for 30 days', 'warning', None))
        self.assertIn('sudo dnf upgrade', update['detail'])
        facts.update(update_program=['gnome-software'], last_update=99 * 86400)
        update = self.items(facts)['updates']
        self.assertEqual((update['title'], update['severity']), ('System updated yesterday', 'ok'))

    def test_reachable_programs_warn_only_without_a_firewall(self):
        facts = {'listening_ports': [22, 5355], 'desktop_ports': [5355], 'port_names': {22: 'remote login (SSH)'},
                 'firewall': True}
        network = self.items(facts)['network']
        self.assertEqual((network['severity'], network['title']), ('info', '1 program waits for connections from '
                                                                           'other computers'))
        self.assertIn('Remote login (SSH) (port 22)', network['detail'])
        facts['firewall'] = False
        self.assertEqual(self.items(facts)['network']['action'], ('Open Firewall', 'firewall'))

    def test_parts_the_platform_cannot_tell_are_left_out(self):
        items = self.items({}, websites_available=False)
        self.assertNotIn('websites', items)
        self.assertNotIn('screen-lock', items)
        self.assertNotIn('disk', items)
        self.assertEqual(items['firewall']['title'], 'No firewall is installed')


if __name__ == '__main__':
    unittest.main()
