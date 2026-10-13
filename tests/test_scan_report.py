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


class PlainSummaryTests(unittest.TestCase):
    def test_durations_read_naturally(self):
        from core.scan_report import human_duration
        self.assertEqual([human_duration(s) for s in (9, 412, 7423, None)], ['9 s', '6 min 52 s', '2 h 3 min', '0 s'])

    def test_outcomes(self):
        from core.scan_report import report_summary
        clean = report_summary({'scanned': 18234, 'duration_seconds': 412})
        self.assertEqual((clean['severity'], clean['title']), ('success', 'No threats found'))
        self.assertEqual(clean['subtitle'], '18,234 files checked in 6 min 52 s.')
        self.assertEqual(clean['note'], '')
        warned = report_summary({'scanned': 5, 'warnings': ['a', 'b'], 'warning_counts': {'access': 2}})
        self.assertEqual(warned['title'], 'No threats found')
        self.assertIn('2 files could not be checked', warned['note'])
        self.assertIn('does not mean they are infected', warned['note'])
        infected = report_summary({'scanned': 3, 'infected': [('/home/u/Downloads/eicar.com', 'Eicar-Test-Signature')]})
        self.assertEqual((infected['severity'], infected['title']), ('danger', '1 threat found'))
        self.assertEqual(infected['threats'], [('eicar.com', '/home/u/Downloads', 'Eicar-Test-Signature')])
        failed = report_summary({'scanned': 3, 'errors': ['x']})
        self.assertEqual((failed['severity'], failed['title']), ('warning', 'The scan did not finish'))
        self.assertEqual(report_summary({'stopped': True})['title'], 'Scan stopped')
