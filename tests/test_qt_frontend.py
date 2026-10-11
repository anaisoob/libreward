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
    from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QTableWidgetItem
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
        from core.authorization import AuthorizationStatus
        self.patch('ui.main_window.backend.authorization_status', return_value=AuthorizationStatus(True, 'System dialog available'))
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

    def test_firewall_refresh_prefers_active_tool_and_switches_rules(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        snapshot = FirewallSnapshot(True, [
            FirewallTool('UFW', 'Inactive', 'saved UFW rules', 'sudo ufw status verbose'),
            FirewallTool('firewalld', 'Running', 'runtime zones', 'sudo firewall-cmd --list-all-zones'),
        ], 'Read-only inspection')
        query = self.patch('ui.main_window.backend.inspect_firewall', return_value=snapshot)
        self.window.switch_page('firewall')
        self.wait_idle()
        query.assert_called_once()
        self.assertEqual(self.window.firewall_tools.currentText(), 'firewalld')
        self.assertIn('runtime zones', self.window.firewall_rules.toPlainText())
        self.window.firewall_tools.setCurrentIndex(0)
        self.assertEqual('Protection is off', self.window.firewall_status.text())
        self.assertEqual(self.window.firewall_status.property('severity'), 'danger')
        self.assertIn('saved UFW rules', self.window.firewall_rules.toPlainText())
        self.assertIn('before turning protection on', self.window.firewall_management_hint.text())

    def test_firewall_auto_check_is_cached_and_refresh_button_is_removed(self):
        from core.firewall import FirewallSnapshot
        query = self.patch('ui.main_window.backend.inspect_firewall', return_value=FirewallSnapshot(True))
        self.window.switch_page('firewall')
        self.wait_idle()
        self.window.switch_page('scan')
        self.window.switch_page('firewall')
        self.window.poll_events()
        query.assert_called_once()
        from PySide6.QtWidgets import QPushButton
        page = self.window.pages.widget(self.window.page_indices['firewall'])
        self.assertNotIn('Refresh', [button.text() for button in page.findChildren(QPushButton)])

    def test_firewall_auto_check_waits_for_running_operation(self):
        from core.firewall import FirewallSnapshot
        release = threading.Event()
        self.addCleanup(release.set)
        query = self.patch('ui.main_window.backend.inspect_firewall', return_value=FirewallSnapshot(True))
        self.window.start_task('scan', lambda: release.wait(2))
        self.window.switch_page('firewall')
        query.assert_not_called()
        self.assertTrue(self.window.firewall_refresh_pending)
        release.set()
        self.wait_idle()
        query.assert_called_once()
        self.assertIsNotNone(self.window.firewall_snapshot)

    def test_deferred_firewall_check_does_not_run_after_leaving_page(self):
        from core.firewall import FirewallSnapshot
        release = threading.Event()
        self.addCleanup(release.set)
        query = self.patch('ui.main_window.backend.inspect_firewall', return_value=FirewallSnapshot(True))
        self.window.start_task('scan', lambda: release.wait(2))
        self.window.switch_page('firewall')
        self.window.switch_page('scan')
        release.set()
        self.wait_idle()
        query.assert_not_called()
        self.window.switch_page('firewall')
        self.wait_idle()
        query.assert_called_once()

    def test_firewall_authorization_updates_only_selected_tool(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        original = FirewallSnapshot(True, [
            FirewallTool('UFW', 'Inactive', 'ufw rules', 'sudo ufw status verbose'),
            FirewallTool('nftables', 'Unknown', 'denied', 'sudo nft list ruleset'),
        ], 'Read only')
        self.window.apply_firewall_snapshot(original)
        self.window.firewall_tools.setCurrentIndex(1)
        result = FirewallSnapshot(True, [FirewallTool('nftables', 'Rules present', 'nft rules', 'sudo nft list ruleset')], 'Read only')
        query = self.patch('ui.main_window.backend.inspect_firewall', return_value=result)
        self.window.authorize_firewall()
        self.wait_idle()
        query.assert_called_once_with(privileged=True, tool_name='nftables')
        self.assertEqual(self.window.firewall_tools.count(), 2)
        self.assertEqual(self.window.firewall_tools.currentText(), 'nftables')
        self.assertIn('nft rules', self.window.firewall_rules.toPlainText())

    def test_firewall_enable_cancel_does_not_run_command(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', '', '')]))
        self.assertTrue(self.window.firewall_enable_button.isEnabled())
        change = self.patch('ui.main_window.backend.change_firewall')
        self.patch('ui.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.No)
        self.window.enable_firewall()
        change.assert_not_called()

    def test_firewall_enable_confirmed_refreshes_state_and_toggle(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', 'old rules', '')]))
        from core.firewall import FirewallChangeResult
        refreshed = FirewallSnapshot(True, [FirewallTool('UFW', 'Active', 'new rules', '')])
        change = self.patch('ui.main_window.backend.change_firewall', return_value=FirewallChangeResult(True, 'Firewall is active', refreshed))
        self.patch('ui.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.Yes)
        self.window.enable_firewall()
        self.wait_idle()
        change.assert_called_once_with('UFW', rule=None, enabled=True)
        self.assertIn('Change completed', self.window.firewall_change_result.text())
        self.assertEqual('Protection is on', self.window.firewall_status.text())
        self.assertIn('take effect immediately', self.window.firewall_management_hint.text())
        self.assertIn('new rules', self.window.firewall_rules.toPlainText())
        self.assertEqual(self.window.firewall_enable_button.text(), 'Disable firewall')
        self.assertTrue(self.window.firewall_enable_button.isEnabled())

    def test_firewall_disable_refreshes_state_and_toggle(self):
        from core.firewall import FirewallChangeResult, FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Active', '', '')]))
        result = FirewallChangeResult(True, 'Firewall stopped', FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', 'Status: inactive', '')]))
        change = self.patch('ui.main_window.backend.change_firewall', return_value=result)
        self.patch('ui.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.Yes)
        self.window.enable_firewall()
        self.wait_idle()
        change.assert_called_once_with('UFW', rule=None, enabled=False)
        self.assertEqual(self.window.firewall_enable_button.text(), 'Enable firewall')
        self.assertEqual(self.window.firewall_status.property('severity'), 'danger')

    def test_unverified_firewall_change_does_not_show_old_state_as_current(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', 'old rules', '')]))
        self.patch('ui.main_window.backend.change_firewall', side_effect=RuntimeError('Timed out'))
        self.window.run_firewall_change('UFW')
        self.wait_idle()
        self.assertEqual('Protection status needs checking', self.window.firewall_status.text())
        self.assertFalse(self.window.firewall_enable_button.isEnabled())
        self.assertIn('Previous snapshot', self.window.firewall_rules.toPlainText())

    def test_firewall_rule_dialog_prefills_and_switches_detected_network(self):
        from ui.firewall_dialog import FirewallRuleDialog
        dialog = FirewallRuleDialog(self.window, 'UFW', networks=[('eth0', '192.168.8.0/23'), ('wlan0', '10.0.0.0/24')])
        self.assertEqual(dialog.subnet.text(), '192.168.8.0/23')
        dialog.detected_networks.setCurrentIndex(1)
        self.assertEqual(dialog.subnet.text(), '10.0.0.0/24')
        dialog.direction.setCurrentIndex(dialog.direction.findData('both'))
        dialog.port.setText('443')
        self.assertEqual(dialog.rule().direction, 'both')
        dialog.deleteLater()

    def test_raw_firewall_tool_cannot_be_changed_and_busy_disables_actions(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('nftables', 'Rules present', '', '')]))
        self.assertFalse(self.window.firewall_add_button.isEnabled())
        self.assertFalse(self.window.firewall_enable_button.isEnabled())
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', '', '')]))
        self.window.set_busy('firewall-change')
        self.assertFalse(self.window.firewall_add_button.isEnabled())
        self.assertFalse(self.window.firewall_tools.isEnabled())
        self.window.set_busy(None)
        self.assertTrue(self.window.firewall_add_button.isEnabled())

    def test_firewall_rule_dialog_lan_and_internet_are_distinct(self):
        from ui.firewall_dialog import FirewallRuleDialog
        dialog = FirewallRuleDialog(self.window, 'UFW')
        dialog.port.setText('22')
        with self.assertRaises(ValueError):
            dialog.rule()
        dialog.subnet.setText('192.168.5.42/24')
        self.assertEqual(dialog.rule().subnet, '192.168.5.0/24')
        dialog.scope.setCurrentIndex(1)
        self.assertFalse(dialog.subnet.isEnabled())
        self.assertEqual(dialog.rule().subnet, '')
        self.assertIn('your local network and the Internet', dialog.hint.text())
        dialog.deleteLater()

    def test_missing_pkexec_shows_help_and_does_not_change_firewall(self):
        from core.authorization import AuthorizationStatus
        from core.firewall import FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', '', 'sudo ufw status verbose')]))
        self.patch('ui.main_window.backend.authorization_status', return_value=AuthorizationStatus(False, 'pkexec missing', 'sudo apt install pkexec'))
        change = self.patch('ui.main_window.backend.change_firewall')
        with patch.object(self.window, 'show_authorization_help') as help_dialog:
            self.window.run_firewall_change('UFW')
        help_dialog.assert_called_once()
        change.assert_not_called()
        self.assertIn('sudo ufw --force enable', self.window.privileged_terminal_commands)

    def test_authorization_agent_failure_keeps_commands_for_terminal(self):
        from core.authorization import AuthorizationError
        from core.firewall import FirewallSnapshot, FirewallTool
        self.window.apply_firewall_snapshot(FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', '', 'sudo ufw status verbose')]))
        self.patch('ui.main_window.backend.change_firewall', side_effect=AuthorizationError('unavailable', 'Check desktop authentication agent'))
        with patch.object(self.window, 'show_authorization_help') as help_dialog:
            self.window.run_firewall_change('UFW')
            self.wait_idle()
        help_dialog.assert_called_once_with('Check desktop authentication agent')
        self.assertIn('sudo ufw status verbose', self.window.privileged_terminal_commands)

    def test_clamav_install_refusal_never_runs_package_manager(self):
        from core.authorization import PackageInstallPlan
        plan = PackageInstallPlan('apt', 'sudo apt-get install clamav', ('clamav',), 'Install from distro repositories')
        self.patch('ui.main_window.backend.clamav_install_plan', return_value=plan)
        install = self.patch('ui.main_window.backend.install_clamav')
        with patch.object(self.window, 'confirm', return_value=False):
            self.window.install_clamav_packages()
        install.assert_not_called()

    def test_confirmed_clamav_install_rechecks_and_waits_for_report_close(self):
        from core.authorization import PackageInstallPlan
        plan = PackageInstallPlan('apt', 'sudo apt-get install clamav', ('clamav',), 'Install from distro repositories')
        self.patch('ui.main_window.backend.clamav_install_plan', return_value=plan)
        install = self.patch('ui.main_window.backend.install_clamav')
        with patch.object(self.window, 'confirm', return_value=True), patch.object(self.window, 'after_clamav_package_install') as after:
            self.window.install_clamav_packages()
            dialog = self.window.update_dialog
            self.wait_idle()
            install.assert_called_once()
            after.assert_not_called()
            self.assertTrue(dialog.isVisible())
            dialog.close()
            self.app.processEvents()
            after.assert_called_once_with(self.ready)

    def test_folder_choosers_use_themed_qt_dialog(self):
        from PySide6.QtWidgets import QFileDialog
        with patch('ui.main_window.QFileDialog.getExistingDirectory', return_value='') as choose:
            self.window.choose_folder()
            self.window.add_exclude()
        self.assertEqual(choose.call_count, 2)
        for call in choose.call_args_list:
            self.assertTrue(call.kwargs['options'] & QFileDialog.Option.DontUseNativeDialog)
            self.assertTrue(call.kwargs['options'] & QFileDialog.Option.ShowDirsOnly)

    def test_folder_views_have_dark_and_light_text_background_contrast(self):
        from PySide6.QtGui import QPalette
        from PySide6.QtWidgets import QFileDialog, QTreeView
        for mode in ('dark', 'light'):
            self.window.apply_theme(mode)
            dialog = QFileDialog(self.window)
            dialog.setOption(QFileDialog.Option.DontUseNativeDialog)
            dialog.ensurePolished()
            view = dialog.findChild(QTreeView)
            view.ensurePolished()
            text = view.palette().color(QPalette.ColorRole.Text)
            background = view.palette().color(QPalette.ColorRole.Base)
            self.assertNotEqual(text, background)
            if mode == 'dark':
                self.assertGreater(text.lightness(), background.lightness())
            else:
                self.assertLess(text.lightness(), background.lightness())
            dialog.deleteLater()

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

    def test_background_database_update_monitors_until_available(self):
        from core.database_update import DatabaseUpdateResult
        missing = StartupStatus(self.ready.runtime, True, False, True, True)
        self.patch('ui.main_window.check_startup', return_value=missing)
        self.patch('ui.main_window.run_freshclam_update',
                   return_value=DatabaseUpdateResult(False, 'System updater active', pending=True))
        self.window.update_database(confirm=False)
        dialog = self.window.update_dialog
        self.wait_idle()
        self.assertEqual(dialog.progress.maximum(), 0)
        self.assertIn('not confirmed', dialog.status.text())
        dialog.accept()
        self.app.processEvents()
        self.assertTrue(self.window.database_watch_timer.isActive())
        self.window.system_database_checked(self.ready)
        self.assertFalse(self.window.database_watch_timer.isActive())
        self.warning.assert_not_called()

    def test_parallel_workers_setting_is_saved(self):
        self.window.scan_workers.setCurrentIndex(self.window.scan_workers.findData(8))
        self.assertTrue(self.window.save_settings())
        self.assertEqual(self.window.config['scan_workers'], 8)
        self.window.parallel_scan.setChecked(False)
        self.assertFalse(self.window.scan_workers.isEnabled())

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
            update_db.assert_not_called()
            dialog = self.window.findChildren(UpdateProgressDialog)[-1]
            self.assertTrue(dialog.isVisible())
            self.assertFalse(dialog.active)
            dialog.accept()
        install.assert_called_once()
        update_db.assert_called_once_with(confirm=False)

    def test_successful_update_remains_open_until_acknowledged(self):
        from unittest.mock import Mock
        callback = Mock()
        self.window.start_task('database', lambda: 'result', on_done=callback,
                               title='Update virus database')
        self.wait_idle()
        dialog = self.window.findChildren(UpdateProgressDialog)[-1]
        self.assertTrue(dialog.isVisible())
        self.assertTrue(dialog.close_button.isEnabled())
        self.assertIn('successfully', dialog.status.text())
        callback.assert_not_called()
        dialog.close()
        callback.assert_called_once_with('result')

    def test_failed_update_remains_open_with_error(self):
        def fail():
            raise RuntimeError('Download failed')
        self.window.start_task('database', fail, title='Update virus database')
        self.wait_idle()
        dialog = self.window.findChildren(UpdateProgressDialog)[-1]
        self.assertTrue(dialog.isVisible())
        self.assertIn('failed', dialog.status.text())
        self.assertIn('Download failed', dialog.log.toPlainText())
        dialog.accept()

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

    def test_discovery_shows_counts_then_switches_to_percentage(self):
        self.window.events.put(('__DISCOVERY__', 2000, 500, False, 6))
        self.window.poll_events()
        self.assertEqual(self.window.progress.maximum(), 0)
        self.assertEqual(self.window.percent.text(), 'Scanning…')
        self.assertIn('2,000', self.window.summary.text())
        self.assertIn('Scanning files as they are found', self.window.status.text())
        self.window.events.put(('__DISCOVERY__', 2000, 500, True, 7))
        self.window.poll_events()
        self.assertEqual(self.window.progress.maximum(), 100)
        self.assertEqual(self.window.percent.text(), '25%')

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

    def test_linux_setup_offers_install_and_manual_recheck(self):
        from dataclasses import replace
        from core.authorization import PackageInstallPlan
        from ui.dialogs import AntivirusSetupDialog
        status = replace(self.ready, runtime_ok=False)
        plan = PackageInstallPlan('apt', 'sudo apt-get install clamav', ('clamav',), 'Install packages')
        dialog = AntivirusSetupDialog(self.window, status, instructions='Install using apt.', install_plan=plan)
        self.assertEqual(dialog.action, 'package-install')
        dialog.recheck()
        self.assertEqual(dialog.action, 'check')
        dialog.deleteLater()

    def test_package_authorization_failure_shows_help_after_report_close(self):
        from core.authorization import AuthorizationError, PackageInstallPlan
        plan = PackageInstallPlan('apt', 'sudo apt-get install clamav', ('clamav',), 'Install packages')
        self.patch('ui.main_window.backend.clamav_install_plan', return_value=plan)
        self.patch('ui.main_window.backend.install_clamav', side_effect=AuthorizationError('unavailable', 'No desktop agent'))
        with patch.object(self.window, 'confirm', return_value=True), patch.object(self.window, 'show_authorization_help') as help_dialog:
            self.window.install_clamav_packages()
            dialog = self.window.update_dialog
            self.wait_idle()
            help_dialog.assert_not_called()
            self.assertIn('No desktop agent', dialog.log.toPlainText())
            dialog.close()
            self.app.processEvents()
            help_dialog.assert_called_once_with('No desktop agent')

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
