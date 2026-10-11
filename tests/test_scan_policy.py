import unittest
from unittest.mock import patch

from core.scan_policy import scan_limits


class ScanPolicyTests(unittest.TestCase):
    def test_auto_uses_cpu_count_with_cap_and_fallback(self):
        for cpu, expected in ((1, 1), (8, 8), (32, 16), (None, 1)):
            with self.subTest(cpu=cpu), patch('core.scan_policy.os.cpu_count', return_value=cpu):
                self.assertEqual(scan_limits().workers, expected)

    def test_extended_auto_and_manual(self):
        with patch('core.scan_policy.os.cpu_count', return_value=16):
            self.assertEqual(scan_limits('extended').workers, 2)
            for count in (4, 8, 16):
                self.assertEqual(scan_limits('extended', count).workers, count)
            self.assertEqual(scan_limits('standard', 999).workers, 16)
        self.assertEqual(scan_limits('extended', 8).file_size, '1024M')
