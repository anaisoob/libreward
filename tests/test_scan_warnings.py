"""Quarantine isolation, warning explanations and bounded large-file profiles."""
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.clamd import ClamdSession
from core.scan_service import ScanService, scan_outcome
from core.scan_warnings import WarningSummary, alert_warning, warning_report
from scanner import build_clamscan_command


class WarningTests(unittest.TestCase):
    def test_warning_reasons_and_details_are_counted_without_error_suffix(self):
        summary = WarningSummary()
        summary.add('browser', 'No such file or directory. ERROR')
        summary.add('locked', 'Access denied. ERROR')
        summary.add('large', 'Heuristics.Limits.Exceeded.MaxFileSize FOUND')
        summary.add('pdf', 'Heuristics.Encrypted.PDF FOUND')
        self.assertEqual(dict(summary.counts), {'changed': 1, 'access': 1, 'limits': 1, 'encrypted': 1})
        self.assertEqual(summary.details[0]['reason'], 'No such file or directory.')
        text = warning_report({'warning_counts': dict(summary.counts), 'warning_details': summary.details})
        self.assertIn('Close the application', text)
        self.assertIn('Scan limits: 1', text)

    def test_details_are_bounded_but_counts_include_every_warning(self):
        summary = WarningSummary()
        for index in range(300):
            summary.add(str(index), 'Permission denied')
        self.assertEqual(summary.counts['access'], 300)
        self.assertEqual(len(summary.details), 200)

    def test_suspicious_zip_and_signature_detections_remain_detections(self):
        self.assertIsNone(alert_warning('Heuristics.Zip.OverlappingFiles FOUND'))
        self.assertIsNone(alert_warning('Php.Exploit.C99-27 FOUND'))
        service = ScanService()
        with patch('core.scan_service.scan_file', return_value='Heuristics.Zip.OverlappingFiles FOUND'):
            infected, warnings, errors = service._run_parallel(['archive'], None)
        self.assertEqual(len(infected), 1)
        self.assertFalse(warnings)

    def test_encrypted_alert_is_an_incomplete_check_in_both_modes(self):
        service = ScanService()
        with patch('core.scan_service.scan_file', return_value='Heuristics.Encrypted.PDF FOUND'):
            infected, warnings, errors = service._run_parallel(['pdf'], None)
        self.assertEqual(infected, [])
        self.assertTrue(warnings)
        self.assertEqual(service.warning_summary.counts['encrypted'], 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pdf'
            path.write_text('test')
            process = SimpleNamespace(stdout=io.StringIO(
                f'{path}: Heuristics.Encrypted.PDF FOUND\n'
                '----------- SCAN SUMMARY -----------\nInfected files: 1\nScanned files: 1\n'),
                poll=lambda: 1, wait=lambda: 1)
            backend = SimpleNamespace(start_process=lambda *args, **kwargs: process,
                                      scan_may_need_admin=lambda roots: False)
            service = ScanService()
            with patch('core.scan_service.backend', backend), \
                 patch('core.scan_service.build_clamscan_command', return_value=['clamscan']):
                service.run(tmp, [], 'clamscan')
            self.assertFalse(service.result['infected_found'])
            self.assertEqual(service.result['warning_counts'], {'encrypted': 1})
            self.assertIn('could not be fully checked', scan_outcome(service.result))

    def test_encrypted_zip_is_not_a_detection_in_both_modes(self):
        service = ScanService()
        with patch('core.scan_service.scan_file', return_value='Heuristics.Encrypted.Zip FOUND'):
            infected, warnings, errors = service._run_parallel(['archive.zip'], None)
        self.assertEqual(infected, [])
        self.assertTrue(warnings)
        self.assertEqual(service.warning_summary.counts['encrypted'], 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'archive.zip'
            path.write_text('test')
            process = SimpleNamespace(stdout=io.StringIO(
                f'{path}: Heuristics.Encrypted.Zip FOUND\n'
                '----------- SCAN SUMMARY -----------\nInfected files: 1\nScanned files: 1\n'),
                poll=lambda: 1, wait=lambda: 1)
            backend = SimpleNamespace(start_process=lambda *args, **kwargs: process,
                                      scan_may_need_admin=lambda roots: False)
            service = ScanService()
            with patch('core.scan_service.backend', backend), \
                 patch('core.scan_service.build_clamscan_command', return_value=['clamscan']):
                service.run(tmp, [], 'clamscan')
            self.assertFalse(service.result['infected_found'])
            self.assertEqual(service.result['warning_counts'], {'encrypted': 1})
            self.assertIn('could not be fully checked', scan_outcome(service.result))

    def test_quarantine_is_excluded_even_without_user_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            quarantine = root / 'quarantine'
            quarantine.mkdir()
            (quarantine / 'test-virus').write_text('test')
            safe = root / 'safe'
            safe.write_text('test')
            backend = Mock()
            backend.scan_may_need_admin.return_value = False
            session = SimpleNamespace(acquire=lambda *args: None, reused=False, close=lambda: None)
            with patch('excludes.backend', SimpleNamespace(quarantine_dir=lambda: quarantine)), \
                 patch('core.scan_service.backend', backend), \
                 patch('core.scan_service.ClamdSession', return_value=session), \
                 patch('core.scan_service._first_database_dir', return_value=None), \
                 patch('core.scan_service.scan_file', return_value='OK') as scan:
                service = ScanService()
                service.run(tmp, [], 'clamscan', parallel=True)
                self.assertEqual([call.args[1] for call in scan.call_args_list], [str(safe)])
                self.assertEqual(service.result['total'], 1)

    def test_extended_limits_apply_to_cli_and_owned_daemon(self):
        args = build_clamscan_command('.', [], clamscan_path='clamscan', scan_profile='extended')
        self.assertIn('--max-filesize=1024M', args)
        self.assertIn('--max-scansize=2048M', args)
        self.assertIn('--alert-exceeds-max=yes', args)
        backend = Mock()
        backend.clamd_endpoints.return_value = []
        backend.find_clamd.return_value = 'clamd'
        backend.clamd_listen_config.return_value = (('tcp', ('127.0.0.1', 3310)), ['TCPAddr 127.0.0.1', 'TCPSocket 3310'])
        backend.start_process.return_value.poll.return_value = None
        with patch('core.scan_policy.os.cpu_count', return_value=8):
            session = ClamdSession(backend, 'extended')
        try:
            with patch('core.clamd.ping', return_value=True):
                session.acquire('clamscan', Path('/db'), lambda: False)
            config = Path(backend.start_process.call_args.args[0][-1]).read_text()
            self.assertIn('MaxFileSize 1024M', config)
            self.assertIn('MaxScanSize 2048M', config)
            self.assertIn('MaxThreads 4', config)  # half of 8 cores, also for larger files
        finally:
            session.close()


class RealResultReportTests(unittest.TestCase):
    """The report must accept the exact result a scan produces (flags, not lists)."""
    def scan_result(self, output):
        with tempfile.TemporaryDirectory() as tmp:
            process = SimpleNamespace(stdout=io.StringIO(output.format(root=tmp)), poll=lambda: 1, wait=lambda: 1)
            backend = SimpleNamespace(start_process=lambda *args, **kwargs: process,
                                      scan_may_need_admin=lambda roots: False)
            service = ScanService()
            with patch('core.scan_service.backend', backend), \
                 patch('core.scan_service.build_clamscan_command', return_value=['clamscan']):
                service.run(tmp, [], 'clamscan')
            return service.result

    def test_locked_files_and_threats_reach_the_plain_report(self):
        from core.scan_report import friendly_report, report_summary
        result = self.scan_result(
            '{root}/locked.db: Can\'t open file or directory ERROR\n'
            '{root}/eicar.com: Eicar-Test-Signature FOUND\n'
            '----------- SCAN SUMMARY -----------\nInfected files: 1\nScanned files: 2\n')
        self.assertIs(result['warnings'], True)
        summary = report_summary(result)
        self.assertEqual(summary['title'], '1 threat found')
        self.assertEqual(summary['threats'][0][0], 'eicar.com')
        self.assertIn('could not be checked', summary['note'])
        friendly_report(result)
        warning_report(result)

    def test_clean_scan_reaches_the_plain_report(self):
        from core.scan_report import report_summary
        result = self.scan_result('----------- SCAN SUMMARY -----------\nInfected files: 0\nScanned files: 0\n')
        self.assertEqual(report_summary(result)['title'], 'No threats found')
