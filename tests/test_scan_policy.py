import unittest
from unittest.mock import patch

from core.scan_policy import scan_limits, worker_choices


class ScanPolicyTests(unittest.TestCase):
    def test_auto_uses_half_of_the_cores_with_bounds(self):
        for cpu, expected in ((1, 1), (2, 1), (8, 4), (12, 6), (64, 16), (None, 1)):
            with self.subTest(cpu=cpu), patch('core.scan_policy.os.cpu_count', return_value=cpu):
                self.assertEqual(scan_limits().workers, expected)
                # Larger-file scanning keeps the same default.
                self.assertEqual(scan_limits('extended').workers, expected)

    def test_manual_choices_fit_the_computer(self):
        with patch('core.scan_policy.os.cpu_count', return_value=6):
            self.assertEqual(worker_choices(), [1, 2, 4])
            self.assertEqual(scan_limits('extended', 4).workers, 4)
            # A saved value this computer cannot run falls back to automatic.
            self.assertEqual(scan_limits('standard', 16).workers, 3)
            self.assertEqual(scan_limits('standard', 999).workers, 3)
        with patch('core.scan_policy.os.cpu_count', return_value=32):
            self.assertEqual(worker_choices(), [1, 2, 4, 8, 16])
        self.assertEqual(scan_limits('extended', 1).file_size, '1024M')
