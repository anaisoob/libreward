"""Qt workflow regressions. Run with QT_QPA_PLATFORM=offscreen and PySide6 installed."""
import os
import threading
import tempfile
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
try:
    from PySide6.QtCore import QEvent
    from PySide6.QtWidgets import QApplication, QDialog, QTableWidgetItem
    from ui.main_window import QtMainWindow
    from ui.dialogs import UpdateProgressDialog
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False

from backends.base import RuntimeInfo
from core.runtime import StartupStatus


@unittest.skipUnless(QT_AVAILABLE, 'PySide6 and its system libraries are required')
class QtFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.ready = StartupStatus(
            RuntimeInfo('system-path', 'clamscan', 'freshclam', 'ClamAV 1.5.2', '1.5.2'),
            True, True, False, True,
        )
        self.patchers = []
        self.patch('ui.main_window.check_startup', return_value=self.ready)
        self.patch('ui.main_window.load_config', return_value={'unrelated_setting': 'preserved'})
        self.patch('ui.main_window.save_config')
        self.patch('ui.main_window.database_summary', return_value='Database ready')
        self.patch('ui.main_window.list_quarantined_files', return_value=[])
        self.warning = self.patch('ui.main_window.QMessageBox.warning')
        self.patch('ui.main_window.QMessageBox.information')
        self.window = QtMainWindow()
        self.wait_idle()

    def patch(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        self.patchers.append(patcher)
        return patcher.start()

    def tearDown(self):
        if self.window.worker:
            self.window.worker.join(timeout=3)
        self.window.poll_events()
        self.window.close()
        self.window.deleteLater()
        self.app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.app.processEvents()
        for patcher in reversed(self.patchers):
            patcher.stop()

    def wait_idle(self):
        deadline = time.monotonic() + 3
        while self.window.operation is not None and time.monotonic() < deadline:
            self.app.processEvents()
            self.window.poll_events()
            time.sleep(.005)
        self.assertIsNone(self.window.operation)

    def findings(self):
        self.window.results.setRowCount(1)
        self.window.results.setItem(0, 0, QTableWidgetItem('/sample'))
        self.window.results.setItem(0, 1, QTableWidgetItem('Test FOUND'))
        self.window.results.selectRow(0)

    def test_startup_populates_sidebar_pages_and_readiness(self):
        self.assertEqual(self.window.pages.count(), 6)
        self.assertTrue(self.window.scan_button.isEnabled())
        self.assertTrue(self.window.database_button.isEnabled())
        self.assertIn('Database ready', self.window.runtime_info.toPlainText())

    def test_navigation_keeps_operation_locked(self):
        release = threading.Event()
        self.addCleanup(release.set)
        self.window.start_task('scan', lambda: release.wait(2))
        self.window.nav_buttons['settings'].click()
        self.assertEqual(self.window.pages.currentIndex(), self.window.page_indices['settings'])
        self.assertFalse(self.window.runtime_button.isEnabled())
        self.assertTrue(self.window.stop_button.isEnabled())
        release.set()
        self.wait_idle()

    def test_update_cannot_be_closed_mid_operation(self):
        from PySide6.QtGui import QCloseEvent
        release = threading.Event()
        self.addCleanup(release.set)
        self.window.start_task('database', lambda: release.wait(2))
        event = QCloseEvent()
        self.window.closeEvent(event)
        self.assertFalse(event.isAccepted())
        release.set()
        self.wait_idle()

    def test_settings_preserve_unknown_keys_and_update_excludes(self):
        save = self.patch('ui.main_window.save_config')
        self.window.path.setText('/scan')
        label, check = next(iter(self.window.exclude_checks.items()))
        check.setChecked(True)
        self.window.excluded_paths.addItem('/skip')
        self.window.suppress_setup.setChecked(True)
        self.assertTrue(self.window.save_settings())
        config = save.call_args.args[0]
        self.assertEqual(config['unrelated_setting'], 'preserved')
        self.assertIn(label, config['enabled_common_excludes'])
        self.assertEqual(config['user_excludes'], ['/skip'])
        self.assertTrue(config['suppress_clamav_setup_prompt'])

    def test_missing_database_disables_scanning(self):
        self.window.startup_status.db_found = False
        self.window.set_busy(None)
        self.assertFalse(self.window.scan_button.isEnabled())
        self.assertTrue(self.window.database_button.isEnabled())

    def test_concurrent_operation_cannot_start(self):
        release = threading.Event()
        self.addCleanup(release.set)
        self.assertTrue(self.window.start_task('database', lambda: release.wait(2)))
        self.assertFalse(self.window.start_task('runtime-install', lambda: self.fail('parallel update')))
        self.assertFalse(self.window.runtime_button.isEnabled())
        self.assertFalse(self.window.scan_button.isEnabled())
        release.set()
        self.wait_idle()
        self.assertTrue(self.window.scan_button.isEnabled())

    def test_cancelled_quarantine_does_not_move_file(self):
        self.findings()
        move = self.patch('ui.main_window.quarantine_file')
        with patch.object(self.window, 'confirm', return_value=False):
            self.window.handle_findings('quarantine')
        move.assert_not_called()
        self.assertEqual(self.window.results.rowCount(), 1)

    def test_failed_quarantine_keeps_finding_for_retry(self):
        self.findings()
        self.patch('ui.main_window.quarantine_file', return_value='Cannot quarantine: locked')
        with patch.object(self.window, 'confirm', return_value=True):
            self.window.handle_findings('quarantine')
            self.wait_idle()
        self.assertEqual(self.window.results.rowCount(), 1)
        self.warning.assert_called_once()

    def test_successful_quarantine_removes_only_handled_finding(self):
        self.findings()
        self.patch('ui.main_window.quarantine_file', return_value='Quarantined: /sample')
        with patch.object(self.window, 'confirm', return_value=True):
            self.window.handle_findings('quarantine')
            self.wait_idle()
        self.assertEqual(self.window.results.rowCount(), 0)

    def test_restoration_never_overwrites_existing_file(self):
        self.window.show_quarantine([{'quarantine_name': 'abc_sample', 'original_path': '/sample'}])
        self.window.quarantine_table.selectRow(0)
        restore = self.patch('ui.main_window.restore_file', return_value='Original file already exists: /sample')
        with patch.object(self.window, 'confirm', return_value=True):
            self.window.restore_selected()
            self.wait_idle()
        restore.assert_called_once_with('abc_sample')
        self.warning.assert_called_once()

    def test_refused_first_run_does_not_fetch_manifest(self):
        self.window.startup_status.runtime_ok = False
        self.patch('ui.main_window.backend.manages_own_runtime', return_value=True)
        self.patch('ui.main_window.ClamAVConsentDialog.exec', return_value=QDialog.DialogCode.Rejected)
        self.patch('ui.main_window.save_config')
        fetch = self.patch('ui.main_window.check_for_updates')
        install = self.patch('ui.main_window.perform_update')
        self.window.update_runtime()
        fetch.assert_not_called()
        install.assert_not_called()

    def test_declined_runtime_confirmation_never_installs(self):
        install = self.patch('ui.main_window.perform_update')
        with patch.object(self.window, 'confirm', return_value=False):
            self.window.confirm_runtime_update({'latest_version': '1.5.2'})
        install.assert_not_called()

    def test_successful_runtime_install_starts_database_flow(self):
        install = self.patch('ui.main_window.perform_update', return_value=None)
        with patch.object(self.window, 'confirm', return_value=True), \
             patch.object(self.window, 'update_database') as update_db:
            self.window.confirm_runtime_update({'latest_version': '1.5.2'})
            self.wait_idle()
        install.assert_called_once()
        update_db.assert_called_once_with(confirm=False)

    def test_quarantine_and_restore_round_trip_through_qt(self):
        import core.quarantine as quarantine_core
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / 'sample.txt'
            original.write_text('harmless test payload')
            with patch.object(quarantine_core, 'backend', SimpleNamespace(quarantine_dir=lambda: root / 'quarantine')), \
                 patch('ui.main_window.list_quarantined_files', side_effect=quarantine_core.list_quarantined_files), \
                 patch.object(self.window, 'confirm', return_value=True):
                self.findings()
                self.window.results.item(0, 0).setText(str(original))
                self.window.handle_findings('quarantine')
                self.wait_idle()
                self.assertFalse(original.exists())
                self.assertEqual(self.window.results.rowCount(), 0)
                self.assertEqual(self.window.quarantine_table.rowCount(), 1)
                self.window.quarantine_table.selectRow(0)
                self.window.restore_selected()
                self.wait_idle()
                self.assertEqual(original.read_text(), 'harmless test payload')
                self.assertEqual(self.window.quarantine_table.rowCount(), 0)

    def test_database_button_click_requires_confirmation(self):
        update = self.patch('ui.main_window.run_freshclam_update')
        with patch.object(self.window, 'confirm', return_value=False) as confirm:
            self.window.database_button.click()
        confirm.assert_called_once()
        update.assert_not_called()

    def test_progress_and_unknown_detection_cannot_show_clean_result(self):
        self.window.events.put(('__PROGRESS__', 5, 4, False))
        self.window.events.put(('__SCAN_DONE__', {
            'infected': [], 'infected_found': True, 'scanned': 5, 'total': 4,
        }))
        self.window.poll_events()
        self.assertEqual(self.window.progress.value(), 99)
        self.assertEqual(self.window.status.text(), 'Infected files found!')

    def test_active_progress_dialog_cannot_be_dismissed(self):
        dialog = UpdateProgressDialog(self.window, 'Update')
        dialog.show()
        dialog.reject()
        self.assertTrue(dialog.isVisible())
        dialog.finish(False)
        dialog.reject()
        self.assertFalse(dialog.isVisible())

    def test_setup_refusal_never_downloads_or_installs(self):
        from unittest.mock import Mock
        dialog = Mock()
        dialog.exec.return_value = QDialog.DialogCode.Rejected
        dialog.suppress.isChecked.return_value = True
        with patch('ui.main_window.AntivirusSetupDialog', return_value=dialog), \
             patch('ui.main_window.save_config'), \
             patch.object(self.window, 'update_runtime') as install, \
             patch.object(self.window, 'update_database') as database:
            self.window.open_antivirus_setup()
        install.assert_not_called()
        database.assert_not_called()
        self.assertTrue(self.window.config['suppress_clamav_setup_prompt'])

    def test_linux_setup_offers_recheck_after_manual_install(self):
        from dataclasses import replace
        from ui.dialogs import AntivirusSetupDialog
        status = replace(self.ready, runtime_ok=False)
        dialog = AntivirusSetupDialog(self.window, status, instructions='Install using your package manager.')
        self.assertEqual(dialog.action, 'check')
        self.assertIn('check again', dialog.action_button.text())
        dialog.deleteLater()

    def test_worker_failure_releases_busy_state(self):
        def fail():
            raise RuntimeError('simulated failure')
        self.window.start_task('check', fail)
        self.wait_idle()
        self.assertTrue(self.window.scan_button.isEnabled())
        self.assertIn('simulated failure', self.window.log.toPlainText())
        self.warning.assert_called_once()


if __name__ == '__main__':
    unittest.main()
