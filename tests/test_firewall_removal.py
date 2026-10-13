import unittest
from core.firewall import FirewallRemoval, FirewallTool, removable_firewall_rules, firewall_rule_columns


class FirewallRemovalTests(unittest.TestCase):
    def test_friendly_rule_columns(self):
        tool = FirewallTool('UFW', 'Inactive', '', '')
        columns = firewall_rule_columns(FirewallRemoval('ufw allow 22/tcp'), tool)
        self.assertEqual(columns[:4], ('Allow', 'To this computer', '22/tcp', 'All networks'))
        self.assertIn('off', columns[4])
        columns = firewall_rule_columns(FirewallRemoval('ufw deny out proto tcp from any to 192.168.1.0/24 port 80'), tool)
        self.assertEqual(columns[:4], ('Block', 'From this computer', '80 TCP', '192.168.1.0/24'))

    def test_ufw_uses_exact_rule_instead_of_unstable_number(self):
        tool = FirewallTool('UFW', 'Inactive', 'Status: inactive\nufw allow 22/tcp\nufw deny out 80/tcp', '')
        entries = removable_firewall_rules(tool)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].arguments('UFW'), ('ufw', ['--force', 'delete', 'allow', '22/tcp']))

    def test_global_commands_are_rejected(self):
        for text in ('ufw reset', 'ufw --force reset', 'ufw allow --force', 'ufw allow 22\nufw reset'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                FirewallRemoval(text).arguments('UFW')

    def test_firewalld_distinguishes_runtime_and_saved(self):
        text = ('Runtime zones and rules\npublic (active)\n  services: ssh\n  ports: 8080/tcp\n'
                '  rich rules:\n    rule family="ipv4" port port="22" protocol="tcp" accept\n'
                'Permanent zones and rules\npublic\n  services: ssh\n')
        entries = removable_firewall_rules(FirewallTool('firewalld', 'Running', text, ''))
        self.assertEqual(len(entries), 4)
        self.assertFalse(entries[0].permanent)
        self.assertTrue(entries[-1].permanent)
        self.assertIn('--remove-service=ssh', entries[-1].arguments('firewalld')[1])
        self.assertIn('--permanent', entries[-1].arguments('firewalld')[1])
