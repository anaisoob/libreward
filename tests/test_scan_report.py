import unittest
from core.scan_report import format_duration, friendly_report


class ScanReportTests(unittest.TestCase):
    def test_duration(self):
        self.assertEqual(format_duration(196.749), '00:03:16')
        self.assertEqual(format_duration(7423), '02:03:43')
        self.assertEqual(format_duration(None), '00:00:00')

    def test_incomplete_scan_is_not_presented_as_fully_clean(self):
        result = dict(scanned=18812, duration_seconds=196.749, warnings=True,
                      warning_counts={'limits': 3}, warning_details=[
                          dict(path='/folder/example.zip', reason='Heuristics.Limits.Exceeded.MaxFileSize')])
        report = friendly_report(result)
        self.assertIn('could not be fully checked', report)
        self.assertIn('00:03:16', report)
        self.assertIn('/folder/example.zip', report)
        self.assertNotIn('Heuristics.', report)

    def test_stopped_scan_and_detection_require_attention(self):
        self.assertIn('did not finish', friendly_report({'stopped': True}))
        self.assertIn('Potential threats', friendly_report({'infected': [('file', 'signature')]}))
