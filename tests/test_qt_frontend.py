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
    from PySide6.QtWidgets import QApplication, QDialog, QLabel, QMessageBox, QTableWidgetItem
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
        self.patch('ui.internet_page.save_config')
        self.patch('ui.file_protection.save_config')
        # Never touch the developer's login autostart.
        self.autostart = self.patch('ui.main_window.backend.remove_autostart')
        self.online = self.patch('ui.internet_page.internet_available', return_value=True)
        from core.authorization import AuthorizationStatus
        self.patch('ui.main_window.backend.authorization_status', return_value=AuthorizationStatus(True, 'System dialog available'))
        self.patch('ui.main_window.database_summary', return_value='Database ready')
        self.patch('ui.main_window.list_quarantined_files', return_value=[])
        self.warning = self.patch('ui.main_window.QMessageBox.warning')
        self.patch('ui.main_window.QMessageBox.information')
        # Never install, start or stop the developer's background service.
        self.monitor_service = self.patch('ui.main_window.backend.set_monitor_service')
        self.agent_running = self.patch('ui.main_window.backend.monitor_agent_running', return_value=False)
        self.service_installed = self.patch('ui.main_window.backend.monitor_service_installed', return_value=True)
        self.monitor_state = self.patch('ui.main_window.read_state', return_value={})
        self.patch('ui.file_protection.read_state', new=self.monitor_state)
        self.monitor_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.monitor_directory.cleanup)
        self.patch('ui.file_protection.monitor_dir', return_value=Path(self.monitor_directory.name))
        self.patch('ui.internet_page.backend.internet_protection_state_directory', return_value=None)
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

    def wait_for(self, condition):
        deadline = time.monotonic() + 3
        while not condition() and time.monotonic() < deadline:
            self.app.processEvents()
            self.window.poll_events()
            time.sleep(.005)
        self.assertTrue(condition())

    def enable_monitoring(self, folder='/selected/folder'):
        section = self.window.file_protection
        with patch('ui.file_protection.default_folders', return_value=[folder]):
            section.toggle()
            self.wait_for(lambda: not section.busy)
        self.assertTrue(self.window.config.get('watch_folders_enabled'))
        return section

    def test_live_protection_replaces_the_internet_page_entry(self):
        self.assertEqual(self.window.nav_buttons['internet'].text(), 'Live protection')
        self.assertFalse(hasattr(self.window, 'watch_enabled'))  # no longer hidden in Settings

    def test_navigation_order_and_quarantine_only_when_needed(self):
        order = [self.window.nav_buttons[key] for key in ('scan', 'internet', 'quarantine', 'firewall', 'settings')]
        positions = [button.mapTo(self.window, button.rect().topLeft()).y() for button in order]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue(self.window.nav_buttons['quarantine'].isHidden())
        self.window.show_quarantine([])
        self.assertTrue(self.window.nav_buttons['quarantine'].isHidden())

    def test_protection_badge_counts_parts_that_are_on(self):
        button = self.window.nav_buttons['internet']
        page = self.window.internet_page
        section = self.window.file_protection
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup'})
        self.assertEqual((button.on, button.total, button.level()), (0, 2, 'none'))
        page.show_state({'supported': True, 'active': True, 'count': 0, 'engine': 'sqlite-dns', 'upstream': 'quad9'})
        self.assertEqual((button.on, button.total, button.level()), (1, 2, 'some'))
        self.agent_running.return_value = True
        self.monitor_state.return_value = {'status': 'watching'}
        self.enable_monitoring()
        section.refresh()
        self.assertEqual((button.on, button.total, button.level()), (2, 2, 'all'))
        self.assertIn('Websites: on', button.toolTip())
        # Where website protection is unavailable, only new files count.
        page.show_state({'supported': False, 'active': False, 'count': 0})
        self.assertEqual((button.on, button.total), (1, 1))

    def test_turning_on_protects_downloads_and_starts_the_service_off_the_gui_thread(self):
        section = self.window.file_protection
        self.wait_for(lambda: self.monitor_service.call_count == 1)
        self.monitor_service.assert_called_with(False)  # startup matches the saved settings
        self.assertEqual(section.status.text(), 'Off')
        main_thread = threading.get_ident()
        threads = []
        self.monitor_service.side_effect = lambda _enabled: threads.append(threading.get_ident())
        self.enable_monitoring(str(Path.home() / 'Downloads'))
        self.monitor_service.assert_called_with(True)
        self.assertNotIn(main_thread, threads)
        self.assertEqual(self.window.config['watched_folders'], [str(Path.home() / 'Downloads')])
        self.assertEqual(self.window.config['unrelated_setting'], 'preserved')
        self.assertIn('~/Downloads', section.folders_label.text())
        self.assertEqual(section.toggle_button.text(), 'Turn off')
        section.toggle()
        self.wait_for(lambda: self.monitor_service.call_count == 3)
        self.monitor_service.assert_called_with(False)
        self.assertFalse(self.window.config['watch_folders_enabled'])
        self.assertEqual(self.window.config['watched_folders'], [str(Path.home() / 'Downloads')])

    def test_removed_service_is_not_turned_back_on_after_reinstalling(self):
        from ui.file_protection import FileProtectionSection
        from PySide6.QtWidgets import QVBoxLayout, QWidget
        self.window.config = dict(self.window.config, watch_folders_enabled=True,
                                  watched_folders=['/home/user/Downloads'])
        self.service_installed.return_value = False  # uninstall deleted it
        self.monitor_service.reset_mock()
        holder = QWidget()
        self.addCleanup(holder.deleteLater)
        section = FileProtectionSection(self.window, QVBoxLayout(holder))
        self.wait_for(lambda: self.monitor_service.called)
        self.monitor_service.assert_called_once_with(False)
        self.assertFalse(self.window.config['watch_folders_enabled'])
        self.assertEqual(self.window.config['watched_folders'], ['/home/user/Downloads'])
        self.assertEqual(section.status.text(), 'Off')
        section.stop()

    def test_folders_are_only_called_protected_while_protection_is_on(self):
        section = self.enable_monitoring(str(Path.home() / 'Downloads'))
        self.agent_running.return_value = True
        self.monitor_state.return_value = {'status': 'watching'}
        section.refresh()
        self.assertEqual(section.folders_label.text(), 'Protected folders: ~/Downloads')
        section.toggle()
        self.wait_for(lambda: section.status.text() == 'Off')
        self.assertEqual(section.folders_label.text(), 'Folders to protect: ~/Downloads')

    def test_scan_activity_bar_appears_only_once_files_are_checked(self):
        release = threading.Event()
        try:
            self.window.start_task('scan', lambda: release.wait(3))
            self.app.processEvents()
            self.assertTrue(self.window.activity.isHidden())  # preparing: one bar is enough
            self.window.events.put(('__CURRENT_FILE__', '/home/user/big.iso'))
            self.window.poll_events()
            self.assertFalse(self.window.activity.isHidden())
        finally:
            release.set()
        self.wait_idle()
        self.assertTrue(self.window.activity.isHidden())

    def test_service_failure_needs_attention_and_settings_save_retries(self):
        self.monitor_service.side_effect = OSError('Background folder monitoring needs systemd (systemctl --user).')
        section = self.enable_monitoring()
        self.wait_for(lambda: 'needs systemd' in section.info.text())
        self.assertEqual(section.status.text(), 'Needs attention')
        self.monitor_service.side_effect = None
        calls = self.monitor_service.call_count
        self.assertTrue(self.window.save_settings())
        self.wait_for(lambda: self.monitor_service.call_count == calls + 1)

    def test_missing_watchdog_is_explained_and_service_not_started(self):
        with patch('ui.file_protection.missing_components', return_value={'watchdog': 'No module'}), \
                patch('core.dependencies.backend.dependency_install_commands',
                      return_value=['sudo dnf install python3-watchdog']):
            section = self.enable_monitoring()
        self.app.processEvents()
        self.assertNotIn(((True,),), [call[:1] for call in self.monitor_service.call_args_list])
        self.assertEqual(section.status.text(), 'Needs attention')
        self.assertIn('needs watchdog', section.info.text())
        self.assertIn('sudo dnf install python3-watchdog', section.info.text())

    def test_agent_state_is_shown_in_plain_words(self):
        section = self.enable_monitoring()
        self.monitor_state.return_value = {'status': 'error', 'message': 'Folder monitoring needs watchdog.'}
        section.started_at = float('-inf')
        section.refresh()
        self.assertEqual(section.status.text(), 'Needs attention')
        self.assertIn('needs watchdog', section.info.text())
        self.agent_running.return_value = True
        self.monitor_state.return_value = {'status': 'watching', 'notifications': False, 'updated': 1,
                                           'last_scan': {'time': 0, 'outcome': 'No threats found',
                                                         'names': 'report.pdf'}}
        with patch('ui.file_protection.backend.notifications_available', return_value=False), \
                patch('core.dependencies.backend.dependency_install_commands',
                      return_value=['sudo dnf install libnotify']):
            section.refresh()
        self.assertEqual(section.status.text(), 'On')
        self.assertIn('No threats found (report.pdf)', section.info.text())
        self.assertIn('sudo dnf install libnotify', section.info.text())

    def background_threat(self, folder, *, found=10):
        infected = Path(folder) / 'eicar.com'
        infected.write_text('sample')
        self.monitor_state.return_value = {'updated': found, 'threats': [
            {'path': str(infected), 'threat': 'Eicar-Signature FOUND', 'time': found},
            {'path': str(Path(folder) / 'already-gone.exe'), 'threat': 'Other FOUND', 'time': found}]}
        return infected

    def test_new_background_threat_asks_once_and_quarantines_without_second_question(self):
        from ui.dialogs import ThreatsFoundDialog
        with tempfile.TemporaryDirectory() as folder:
            infected = self.background_threat(folder)
            question = self.patch('ui.main_window.QMessageBox.question')
            with patch.object(ThreatsFoundDialog, 'exec', return_value=ThreatsFoundDialog.QUARANTINE) as asked, \
                    patch('ui.main_window.quarantine_file', return_value='Quarantined: eicar.com') as quarantine:
                self.window.file_protection.refresh()
                self.wait_idle()
                asked.assert_called_once()
                quarantine.assert_called_once_with(str(infected), 'Eicar-Signature FOUND')
                question.assert_not_called()
                self.assertEqual(self.window.pages.currentIndex(), self.window.page_indices['scan'])
                self.assertEqual(self.window.config['threats_reviewed_at'], 10)
                self.window.monitor_state_mtime = None
                self.window.file_protection.refresh()
                asked.assert_called_once()

    def test_closing_the_threat_question_asks_again_and_keep_does_not(self):
        from ui.dialogs import ThreatsFoundDialog
        with tempfile.TemporaryDirectory() as folder:
            self.background_threat(folder)
            with patch.object(ThreatsFoundDialog, 'exec', return_value=QDialog.DialogCode.Rejected) as asked:
                self.window.open_background_threats()
                self.window.open_background_threats()
            self.assertEqual(asked.call_count, 2)
            self.assertNotIn('threats_reviewed_at', self.window.config)
            with patch.object(ThreatsFoundDialog, 'exec', return_value=ThreatsFoundDialog.KEEP), \
                    patch('ui.main_window.quarantine_file') as quarantine:
                self.window.open_background_threats()
            quarantine.assert_not_called()
            self.assertEqual(self.window.config['threats_reviewed_at'], 10)
            self.assertEqual(self.window.results.rowCount(), 0)  # rows come from the page poll

    def test_delete_from_threat_question_still_confirms(self):
        from ui.dialogs import ThreatsFoundDialog
        with tempfile.TemporaryDirectory() as folder:
            self.background_threat(folder)
            self.patch('ui.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.No)
            with patch.object(ThreatsFoundDialog, 'exec', return_value=ThreatsFoundDialog.DELETE), \
                    patch('ui.main_window.delete_file') as delete:
                self.window.open_background_threats()
            delete.assert_not_called()
            self.assertNotIn('threats_reviewed_at', self.window.config)

    def test_closing_explains_once_that_live_protection_keeps_working(self):
        from PySide6.QtGui import QCloseEvent
        info = self.patch('ui.internet_page.QMessageBox.information')
        self.patch('ui.main_window.backend.internet_protection_enabled', return_value=False)
        self.enable_monitoring()
        self.agent_running.return_value = True
        event = QCloseEvent()
        self.window.closeEvent(event)
        self.assertTrue(event.isAccepted())
        self.assertFalse(self.window.file_protection.timer.isActive())
        self.assertEqual(info.call_count, 1)
        self.assertIn('still checked for viruses', info.call_args.args[2])
        self.window.closeEvent(QCloseEvent())
        self.assertEqual(info.call_count, 1)

    def test_gui_leaves_database_refresh_to_the_running_agent(self):
        self.patch('ui.main_window.own_database_needs_refresh', return_value=True)
        self.window.startup_status = self.ready
        self.agent_running.return_value = True
        self.assertFalse(self.window.maybe_auto_update_database())

    def test_test_notification_reports_delivery_with_install_hint(self):
        section = self.window.file_protection
        with patch('ui.file_protection.backend.send_desktop_notification', return_value=False) as send, \
                patch('ui.file_protection.backend.notifications_available', return_value=False), \
                patch('core.dependencies.backend.dependency_install_commands',
                      return_value=['sudo dnf install libnotify']):
            section.test_notification()
            self.wait_for(lambda: 'unavailable' in section.notification_status.text())
        send.assert_called_once_with('LibreWard — notification test', 'Desktop notifications are working.')
        self.assertIn('sudo dnf install libnotify', section.notification_status.text())

    def test_second_launch_brings_window_forward_with_the_activation_token(self):
        from PySide6.QtNetwork import QLocalServer
        from ui.main_window import listen_for_instances, show_running_instance
        name = f'libreward-test-{os.getpid()}'
        server = listen_for_instances(self.window, name)
        try:
            self.window.hide()
            with patch.dict(os.environ, {}), \
                    patch.object(self.window, 'open_background_threats') as threats:
                self.assertTrue(show_running_instance(name, 'threats token-123'))
                self.wait_for(lambda: threats.called)
                self.assertEqual(os.environ.get('XDG_ACTIVATION_TOKEN'), 'token-123')
            threats.assert_called_once_with(activated=True)
            self.assertTrue(self.window.isVisible())
        finally:
            server.close()
            QLocalServer.removeServer(name)
        self.assertFalse(show_running_instance(name, 'show'))

    def test_instance_request_carries_the_token(self):
        from ui.main_window import instance_request
        with patch.dict(os.environ, {'XDG_ACTIVATION_TOKEN': 'abc'}):
            self.assertEqual(instance_request(threats=True), 'threats abc')
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(instance_request(), 'show')

    def test_protected_folders_dialog_finds_downloads_off_the_gui_thread(self):
        from ui.dialogs import ProtectedFoldersDialog
        main_thread = threading.get_ident()
        observed = []

        def discover():
            observed.append(threading.get_ident())
            return ['/home/user/Downloads', '/home/user/Downloads']

        dialog = ProtectedFoldersDialog(self.window, ['/home/user/Documents'], discover=discover)
        dialog.find()
        self.wait_for(lambda: dialog.find_button.isEnabled())
        self.assertEqual(dialog.folders(), ['/home/user/Documents', '/home/user/Downloads'])
        self.assertNotEqual(observed, [main_thread])
        dialog.deleteLater()

    def test_startup_populates_sidebar_pages_and_readiness(self):
        self.assertEqual(self.window.pages.count(), 6)
        self.assertTrue(self.window.scan_button.isEnabled())
        self.assertTrue(self.window.database_button.isEnabled())
        self.assertIn('Database ready', self.window.runtime_info.toPlainText())

    def test_internet_page_has_safe_defaults_and_read_only_detection(self):
        page = self.window.internet_page
        self.assertTrue(page.categories['dangerous'].isChecked())
        self.assertFalse(page.categories['tracking'].isChecked())
        self.assertFalse(page.categories['ads'].isChecked())
        inspect = self.patch('ui.internet_page.backend.inspect_internet_protection', return_value={
            'supported': True, 'active': False, 'count': 0, 'message': 'Ready'})
        apply = self.patch('ui.internet_page.backend.apply_internet_protection')
        self.window.switch_page('internet')
        self.wait_idle()
        inspect.assert_called_once()
        apply.assert_not_called()
        self.assertTrue(page.toggle_button.isEnabled())
        self.assertEqual(page.toggle_button.text(), 'Turn on')
        self.assertTrue(page.pending_bar.isHidden())

    def test_internet_status_check_keeps_scroll_position(self):
        self.patch('ui.internet_page.backend.inspect_internet_protection', return_value={
            'supported': True, 'active': False, 'count': 0, 'message': 'Ready'})
        self.window.resize(980, 740)
        self.window.show()
        self.window.switch_page('internet')
        self.wait_idle()
        page = self.window.internet_page
        self.app.processEvents()
        page.scroll.verticalScrollBar().setValue(0)
        page.toggle_button.setFocus()
        page.refresh()
        self.wait_idle()
        self.app.processEvents()
        self.assertEqual(page.scroll.verticalScrollBar().value(), 0)

    def test_internet_exceptions_are_exact_and_can_move_between_lists(self):
        page = self.window.internet_page
        field = page.domain_fields[1]
        field.setText('Example.org')
        page.add_domain('blocked', field)
        field.setText('example.org')
        page.add_domain('allowed', field)
        self.assertEqual(page.settings()['allowed'], ['example.org'])
        self.assertEqual(page.settings()['blocked'], [])
        field.setText('https://example.org/path')
        page.add_domain('blocked', field)
        self.warning.assert_called_once()
        self.assertEqual(page.settings()['blocked'], [])

    def test_advanced_applies_lists_with_a_neutral_dns_service(self):
        from core.internet import DiskDomainLists, PreparedDomains
        page = self.window.internet_page
        with tempfile.TemporaryDirectory() as directory:
            page.store = DiskDomainLists(directory)
            self.assertTrue(page.advanced_section.isHidden())  # new users start with Simple
            page.levels['advanced'].setChecked(True)
            self.assertFalse(page.advanced_section.isHidden())
            self.assertTrue(page.simple_card.isHidden())
            for checkbox in page.categories.values():
                checkbox.setChecked(False)
            page.domain_lists['blocked'].addItem('blocked.example.org')
            page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup',
                             'mode': 'resolved', 'setup_available': True, 'needs_dns_install': False})
            self.assertEqual(page.upstream.currentData(), 'quad9-unfiltered')
            self.assertEqual(page.upstream.findData('network'), -1)
            page.upstream.setCurrentIndex(page.upstream.findData('cloudflare'))
            calls = []

            def apply(prepared, upstream=None):
                self.assertIsInstance(prepared, PreparedDomains)
                calls.append((upstream, len(prepared)))
                return {'supported': True, 'active': True, 'count': 1, 'engine': 'sqlite-dns',
                        'mode': 'resolved', 'upstream': upstream}
            with patch('ui.internet_page.backend.apply_internet_protection', side_effect=apply), \
                 patch.object(self.window, 'confirm', return_value=False) as confirm:
                page.apply()
            consent = confirm.call_args.args[1]
            for text in ('sends their names to Cloudflare', 'not part of LibreWard', 'no warranty',
                         'even when LibreWard is closed'):
                self.assertIn(text, consent)
            self.assertEqual(calls, [])
            with patch('ui.internet_page.backend.apply_internet_protection', side_effect=apply), \
                 patch.object(self.window, 'confirm', return_value=True):
                page.apply()
                dialog = self.window.update_dialog
                self.wait_idle()
            self.assertEqual(calls, [('cloudflare', 1)])
            dialog.accept()
            self.app.processEvents()
            self.assertTrue(page.state['active'])
            self.assertEqual(page.info.text(), 'Blocking 1 website from your lists.')
            saved = self.window.config['internet_protection']
            self.assertEqual((saved['level'], saved['upstream']), ('advanced', 'cloudflare'))

    def test_simple_protection_needs_no_lists_and_uses_the_chosen_service(self):
        from core.internet import DiskDomainLists
        page = self.window.internet_page
        with tempfile.TemporaryDirectory() as directory:
            page.store = DiskDomainLists(directory)
            page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup',
                             'mode': 'resolved', 'setup_available': True, 'needs_dns_install': False})
            self.assertFalse(page.simple_card.isHidden())
            self.assertTrue(page.simple_choices['quad9'].isChecked())
            page.simple_choices['adguard-family'].setChecked(True)
            calls = []

            def apply(prepared, upstream=None):
                calls.append((upstream, len(prepared)))
                return {'supported': True, 'active': True, 'count': 0, 'engine': 'sqlite-dns',
                        'mode': 'resolved', 'upstream': upstream}
            with patch('ui.internet_page.backend.apply_internet_protection', side_effect=apply), \
                    patch.object(page.store, 'update', side_effect=AssertionError('no list download')), \
                    patch.object(self.window, 'confirm', return_value=True) as confirm:
                page.apply()
                dialog = self.window.update_dialog
                self.wait_idle()
            consent = confirm.call_args.args[1]
            self.assertIn('sends their names to AdGuard DNS Family', consent)
            self.assertIn('blocks dangerous and adult websites and ads', consent)
            self.assertEqual(calls, [('adguard-family', 0)])
            dialog.accept()
            self.app.processEvents()
            self.assertEqual(page.info.text(), 'AdGuard DNS Family blocks dangerous and adult websites and ads.')
            self.assertTrue(page.pending_bar.isHidden())

    def test_offline_apply_explains_and_changes_nothing(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup', 'mode': 'networkmanager'})
        self.online.return_value = False
        apply = self.patch('ui.internet_page.backend.apply_internet_protection')
        with patch.object(self.window, 'confirm', return_value=True):
            page.apply()
            dialog = self.window.update_dialog
            self.wait_idle()
        apply.assert_not_called()
        self.assertIn('not connected to the internet', dialog.log.toPlainText())
        dialog.accept()

    def test_cancel_before_the_system_change_stops_the_operation(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': True, 'count': 1, 'engine': 'sqlite-dns', 'mode': 'networkmanager'})
        release = threading.Event()
        self.addCleanup(release.set)
        apply = self.patch('ui.internet_page.backend.apply_internet_protection')
        self.patch('ui.internet_page.backend.reset_cancellation')
        original = page.start_system_change
        def slow_checkpoint():
            release.wait(3)
            original()
        with patch.object(page, 'start_system_change', side_effect=slow_checkpoint), \
                patch.object(self.window, 'confirm', return_value=True):
            page.pause()
            dialog = self.window.update_dialog
            self.assertFalse(dialog.cancel_button.isHidden())
            dialog.cancel_button.click()
            self.assertEqual(dialog.status.text(), 'Cancelling…')
            release.set()
            self.wait_idle()
        apply.assert_not_called()
        self.assertIn('Cancelled', dialog.log.toPlainText())
        self.assertTrue(dialog.cancel_button.isHidden())
        # A cancelled change keeps the known state instead of "needs checking".
        self.assertTrue(page.state['active'])
        dialog.accept()

    def test_cancel_after_authorization_explains_that_the_change_finishes(self):
        page = self.window.internet_page
        page.reset_cancel()
        page.start_system_change()
        dialog = UpdateProgressDialog(self.window, 'Apply')
        self.window.update_dialog = dialog
        self.patch('ui.internet_page.backend.cancel_authorization', return_value=False)
        page.offer_cancel()
        dialog.cancel_button.click()
        self.assertIn('finishing the change safely', dialog.status.text())
        self.assertFalse(dialog.cancel_button.isEnabled())
        self.window.update_dialog = None
        dialog.deleteLater()

    def test_recovered_notice_is_shown_once(self):
        page = self.window.internet_page
        recovered = {'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup', 'recovered': True}
        page.show_state(recovered)
        self.assertIn('filter stopped', page.notice.text())
        page.notice.setText('Other notice')
        page.show_state(recovered)
        self.assertEqual(page.notice.text(), 'Other notice')

    def test_websites_section_avoids_technical_words(self):
        from PySide6.QtWidgets import QAbstractButton, QComboBox, QLabel
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup',
                         'mode': 'networkmanager'})
        technical = {page.advanced, page.method_info}  # under "Show how protection works"
        texts = [label.text() for label in page.page.findChildren(QLabel) if label not in technical]
        texts += [button.text() for button in page.page.findChildren(QAbstractButton)]
        texts += [combo.itemText(i) for combo in page.page.findChildren(QComboBox) for i in range(combo.count())]
        for level in ('simple', 'advanced'):
            page.levels[level].setChecked(True)
            texts.append(page.upstream_info.text())
        joined = ' '.join(texts).lower()
        for word in ('blocks nothing', 'no blocking', 'domain', 'lookup', 'upstream', 'dns service', 'resolver'):
            self.assertNotIn(word, joined)

    def test_apply_bar_stays_in_view_below_the_scrolling_content(self):
        page = self.window.internet_page
        self.assertFalse(page.scroll.widget().isAncestorOf(page.pending_bar))
        self.assertTrue(page.page.isAncestorOf(page.pending_bar))

    def test_pages_react_to_state_changes_instead_of_polling(self):
        section = self.window.file_protection
        self.assertIn(self.monitor_directory.name, section.watcher.directories())
        self.assertGreaterEqual(section.timer.interval(), 30000)
        section.watcher.directoryChanged.emit(self.monitor_directory.name)
        self.assertTrue(section.changed.isActive())  # one refresh shortly after, for a burst of changes
        page = self.window.internet_page
        self.assertFalse(hasattr(page, 'health_timer'))
        with tempfile.TemporaryDirectory() as directory, \
                patch('ui.internet_page.backend.internet_protection_state_directory', return_value=Path(directory)):
            page.watch_state()
            self.assertIn(directory, page.state_watcher.directories())
            page.state_watcher.directoryChanged.emit(directory)
            self.assertTrue(page.state_changed.isActive())

    def test_status_checks_never_undo_unapplied_choices(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': True, 'count': 0, 'engine': 'sqlite-dns',
                         'mode': 'resolved', 'upstream': 'quad9'})
        self.assertTrue(page.pending_bar.isHidden())
        page.simple_choices['adguard-family'].setChecked(True)
        # Saved at once, and shown as waiting to be applied.
        self.assertEqual(self.window.config['internet_protection']['simple'], 'adguard-family')
        self.assertFalse(page.pending_bar.isHidden())
        # The periodic status check reports the active service; the choice stays.
        page.show_state({'supported': True, 'active': True, 'count': 0, 'engine': 'sqlite-dns',
                         'mode': 'resolved', 'upstream': 'quad9'})
        self.assertTrue(page.simple_choices['adguard-family'].isChecked())
        self.assertFalse(page.pending_bar.isHidden())
        page.applied({'supported': True, 'active': True, 'count': 0, 'engine': 'sqlite-dns',
                      'mode': 'resolved', 'upstream': 'adguard-family'})
        self.assertTrue(page.pending_bar.isHidden())

    def test_changes_while_off_need_no_apply_and_leaving_with_changes_asks(self):
        page = self.window.internet_page
        page.levels['advanced'].setChecked(True)
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup', 'mode': 'networkmanager'})
        page.categories['ads'].setChecked(True)
        self.assertTrue(page.pending_bar.isHidden())
        self.assertIn('ads', self.window.config['internet_protection']['categories'])
        page.show_state({'supported': True, 'active': True, 'count': 5, 'engine': 'sqlite-dns', 'mode': 'networkmanager'})
        page.categories['tracking'].setChecked(True)
        self.window.pages.setCurrentIndex(self.window.page_indices['internet'])
        self.patch('ui.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.Yes)
        with patch.object(page, 'apply') as apply:
            self.window.switch_page('settings')
        apply.assert_called_once_with(changes=True)
        self.assertEqual(self.window.pages.currentIndex(), self.window.page_indices['internet'])

    def test_network_dns_is_offered_only_with_networkmanager(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup', 'mode': 'networkmanager'})
        index = page.upstream.findData('network')
        self.assertGreaterEqual(index, 0)
        page.upstream.setCurrentIndex(index)
        self.assertEqual(self.window.config['internet_protection']['upstream'], 'network')
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup', 'mode': 'resolved'})
        self.assertEqual(page.upstream.findData('network'), -1)
        self.assertEqual(page.upstream.currentData(), 'quad9-unfiltered')

    def test_debian_dns_setup_is_offered_with_installation_consent(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': False, 'count': 0,
                         'engine': 'sqlite-setup', 'setup_available': True, 'needs_dns_install': True,
                         'dns_package': 'dnsmasq-base'})
        apply = self.patch('ui.internet_page.backend.apply_internet_protection')
        with patch.object(self.window, 'confirm', return_value=False) as confirm:
            page.apply()
        self.assertIn('dnsmasq-base', confirm.call_args.args[1])
        apply.assert_not_called()
        self.assertTrue(page.apply_button.isEnabled())

    def test_database_filter_uses_a_disk_payload_and_cleans_it_after_application(self):
        from core.internet import DiskDomainLists, PreparedDomains
        page = self.window.internet_page
        with tempfile.TemporaryDirectory() as directory:
            page.store = DiskDomainLists(directory)
            page.levels['advanced'].setChecked(True)
            for checkbox in page.categories.values():
                checkbox.setChecked(False)
            page.domain_lists['blocked'].addItem('blocked.example.org')
            page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup',
                             'setup_available': True, 'needs_dns_install': False})
            payloads = []
            def apply(prepared, upstream=None):
                self.assertEqual(upstream, 'quad9-unfiltered')
                self.assertIsInstance(prepared, PreparedDomains)
                self.assertTrue(prepared.path.exists())
                payloads.append(prepared.path)
                return {'supported': True, 'active': True, 'count': 1, 'engine': 'sqlite-dns'}
            with patch('ui.internet_page.backend.apply_internet_protection', side_effect=apply), \
                 patch.object(self.window, 'confirm', return_value=True):
                page.apply()
                dialog = self.window.update_dialog
                self.wait_idle()
            self.assertEqual(len(payloads), 1)
            self.assertFalse(payloads[0].exists())
            dialog.accept()
            self.app.processEvents()
            self.assertTrue(page.state['active'])
            self.assertEqual(page.info.text(), 'Blocking 1 website from your lists.')
            self.assertEqual(page.toggle_button.text(), 'Turn off')

    def test_internet_pause_only_removes_libreward_blocks(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': True, 'count': 1})
        apply = self.patch('ui.internet_page.backend.apply_internet_protection', return_value={
            'supported': True, 'active': False, 'count': 0})
        with patch.object(self.window, 'confirm', return_value=True):
            page.pause()
            dialog = self.window.update_dialog
            self.wait_idle()
        apply.assert_called_once_with([])
        dialog.accept()
        self.app.processEvents()
        self.assertFalse(page.state['active'])
        self.assertEqual(page.toggle_button.text(), 'Turn on')

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

    def test_firewall_rules_visible_and_deletion_requires_confirmation(self):
        from core.firewall import FirewallSnapshot, FirewallTool
        snapshot = FirewallSnapshot(True, [FirewallTool('UFW', 'Inactive', 'ufw allow 22/tcp', '')])
        self.window.apply_firewall_snapshot(snapshot)
        self.assertFalse(self.window.firewall_details_toggle.isChecked())
        self.assertEqual(self.window.firewall_rule_list.rowCount(), 1)
        self.assertEqual(self.window.firewall_rule_list.item(0, 0).text(), 'Allow')
        self.window.firewall_rule_list.selectRow(0)
        self.assertTrue(self.window.firewall_delete_button.isEnabled())
        with patch('ui.main_window.QMessageBox.question', return_value=QMessageBox.StandardButton.No), \
             patch('ui.main_window.backend.change_firewall') as change:
            self.window.delete_firewall_rule()
        change.assert_not_called()

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
        self.assertEqual(dialog.status.text(), 'Done.')
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
                self.assertFalse(self.window.nav_buttons['quarantine'].isHidden())
                self.window.switch_page('quarantine')
                self.window.quarantine_table.selectRow(0)
                self.window.restore_selected()
                self.wait_idle()
                self.assertEqual(original.read_text(), 'harmless test payload')
                self.assertEqual(self.window.quarantine_table.rowCount(), 0)
                # Still visible while open; hidden once the empty quarantine is left.
                self.assertFalse(self.window.nav_buttons['quarantine'].isHidden())
                self.window.switch_page('scan')
                self.assertTrue(self.window.nav_buttons['quarantine'].isHidden())

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
        self.assertEqual(dialog.action_button.text(), 'Check again')
        # Manual installation needs the command, so details start open.
        self.assertFalse(dialog.details.isHidden())
        dialog.deleteLater()

    def test_linux_setup_offers_install_and_manual_recheck(self):
        from dataclasses import replace
        from core.authorization import PackageInstallPlan
        from ui.dialogs import AntivirusSetupDialog
        status = replace(self.ready, runtime_ok=False)
        plan = PackageInstallPlan('apt', 'sudo apt-get install clamav', ('clamav',), 'Install packages')
        dialog = AntivirusSetupDialog(self.window, status, instructions='Install using apt.', install_plan=plan)
        self.assertEqual(dialog.action, 'package-install')
        self.assertEqual(dialog.action_button.text(), 'Install')
        self.assertTrue(dialog.details.isHidden())
        dialog.toggle_details()
        self.assertFalse(dialog.details.isHidden())
        dialog.recheck()
        self.assertEqual(dialog.action, 'check')
        dialog.deleteLater()

    def test_setup_dialog_states_are_short_and_optional_parts_are_optional(self):
        from dataclasses import replace
        from ui.dialogs import AntivirusSetupDialog
        cases = {
            'Download the virus database': replace(self.ready, db_found=False),
            'Faster scanning (optional)': replace(self.ready, clamd_path=None, clamd_running=False),
            'Virus protection is ready': replace(self.ready, clamd_path='/usr/sbin/clamd'),
        }
        for heading, status in cases.items():
            dialog = AntivirusSetupDialog(self.window, status, instructions='Install using dnf.')
            self.assertIn(heading, [label.text() for label in dialog.findChildren(QLabel)])
            dialog.deleteLater()

    def test_install_from_setup_dialog_does_not_ask_twice(self):
        from unittest.mock import Mock
        dialog = Mock()
        dialog.exec.return_value = QDialog.DialogCode.Accepted
        dialog.action = 'package-install'
        dialog.suppress.isChecked.return_value = False
        with patch('ui.main_window.AntivirusSetupDialog', return_value=dialog), \
             patch.object(self.window, 'install_clamav_packages') as install:
            self.window.open_antivirus_setup(self.ready)
        install.assert_called_once_with(confirmed=True)
        from core.authorization import PackageInstallPlan
        self.patch('ui.main_window.backend.clamav_install_plan',
                   return_value=PackageInstallPlan('dnf', 'sudo dnf install clamav', ('clamav',), 'Install'))
        self.patch('ui.main_window.backend.install_clamav')
        with patch.object(self.window, 'confirm') as confirm, patch.object(self.window, 'start_task') as start:
            self.window.install_clamav_packages(confirmed=True)
        confirm.assert_not_called()
        start.assert_called_once()

    def test_automatic_database_update_runs_quietly_when_due(self):
        self.window.startup_status = self.ready
        self.patch('ui.main_window.own_database_needs_refresh', return_value=True)
        run = self.patch('ui.main_window.run_freshclam_update', return_value=(True, 'updated'))
        save = self.patch('ui.main_window.save_config')
        self.assertTrue(self.window.maybe_auto_update_database())
        self.window.auto_database_thread.join(3)
        self.assertEqual(run.call_args.kwargs, {'wait': False})
        self.window.poll_events()
        self.assertTrue(self.window.config['database_auto_update_ok'])
        self.assertIn('database_auto_update_at', save.call_args.args[0])
        self.assertIn('updated automatically', self.window.log.toPlainText())
        # Just updated: not due again.
        self.assertFalse(self.window.maybe_auto_update_database())
        self.assertIsNone(self.window.update_dialog)

    def test_automatic_database_update_respects_the_setting_and_pending_runs(self):
        self.window.startup_status = self.ready
        self.patch('ui.main_window.own_database_needs_refresh', return_value=True)
        run = self.patch('ui.main_window.run_freshclam_update')
        self.window.config['auto_update_database'] = False
        self.assertFalse(self.window.maybe_auto_update_database())
        run.assert_not_called()
        self.window.config['auto_update_database'] = True
        self.window.auto_database_update_finished(False, True)
        self.assertNotIn('database_auto_update_at', self.window.config)
        self.assertTrue(self.window.auto_update_database.isChecked())

    def test_scan_report_opens_for_a_result_with_warnings(self):
        from ui.dialogs import ScanReportDialog
        # As produced by ScanService: flags plus separate counts (Fedora quick scan).
        result = {'infected': [], 'infected_found': False, 'total': 900, 'scanned': 880, 'stopped': False,
                  'errors': False, 'warnings': True, 'summary_lines': [], 'parallel': True,
                  'warning_counts': {'access': 20}, 'warning_count': 20,
                  'warning_details': [{'path': '/home/u/.cache/a', 'reason': 'Permission denied', 'category': 'access'}],
                  'scan_profile': 'standard', 'duration_seconds': 42.0, 'workers': 4, 'uses_system_daemon': False}
        dialog = ScanReportDialog(self.window, result)
        texts = [label.text() for label in dialog.findChildren(QLabel)]
        self.assertIn('No threats found', texts)
        self.assertTrue(any('20 files could not be checked' in text for text in texts))
        dialog.deleteLater()

    def test_a_broken_report_still_shows_the_outcome(self):
        self.window.last_result = {'infected': [], 'warnings': False, 'errors': False, 'scanned': 1}
        info = self.patch('ui.main_window.QMessageBox.information')
        with patch('ui.main_window.ScanReportDialog', side_effect=TypeError('broken')):
            self.window.show_scan_report()
        self.assertEqual(info.call_args.args[2], 'No threats found.')
        self.assertIn('TypeError: broken', self.window.log.toPlainText())

    def test_closing_never_touches_internet_protection(self):
        from PySide6.QtGui import QCloseEvent
        inspect = self.patch('ui.main_window.backend.inspect_internet_protection')
        apply = self.patch('ui.main_window.backend.apply_internet_protection')
        event = QCloseEvent()
        self.window.closeEvent(event)
        self.assertTrue(event.isAccepted())
        inspect.assert_not_called()
        apply.assert_not_called()

    def test_old_autostart_entry_is_removed_and_shows_nothing(self):
        from ui.main_window import run
        self.autostart.reset_mock()
        with patch('ui.main_window.QApplication') as application:
            self.assertEqual(run(autostart=True), 0)
        self.autostart.assert_called_once()
        application.assert_not_called()

    def test_first_turn_on_and_first_close_explain_that_protection_keeps_working(self):
        from PySide6.QtGui import QCloseEvent
        info = self.patch('ui.internet_page.QMessageBox.information')
        page = self.window.internet_page
        on = {'supported': True, 'active': True, 'count': 3, 'engine': 'sqlite-dns', 'mode': 'networkmanager'}
        page.applied(on)
        page.applied(on)
        self.assertEqual(info.call_count, 1)
        self.assertIn('keeps working when LibreWard is closed', info.call_args.args[2])
        info.reset_mock()
        self.patch('ui.main_window.backend.internet_protection_enabled', return_value=True)
        for _ in range(2):
            event = QCloseEvent()
            self.window.closeEvent(event)
            self.assertTrue(event.isAccepted())
        self.assertEqual(info.call_count, 1)
        self.assertIn('keeps blocking websites', info.call_args.args[2])

    def test_social_media_can_be_blocked(self):
        from core.internet import CATEGORIES
        self.assertEqual(CATEGORIES['social'][1], ('facebook', 'whatsapp', 'tiktok', 'twitter'))
        checkbox = self.window.internet_page.categories['social']
        self.assertFalse(checkbox.isChecked())
        self.assertIn('Instagram', checkbox.text())

    def test_consent_explains_protection_is_a_system_setting(self):
        page = self.window.internet_page
        page.show_state({'supported': True, 'active': False, 'count': 0, 'engine': 'sqlite-setup', 'mode': 'networkmanager'})
        text = page.consent_text(page.settings(), changes=False)
        self.assertIn('system setting, like the firewall', text)
        self.assertIn('even when LibreWard is closed', text)

    def test_scan_report_leads_with_the_outcome_and_offers_quarantine(self):
        from ui.dialogs import ScanReportDialog
        result = {'scanned': 2, 'duration_seconds': 3,
                  'infected': [('/tmp/a/eicar.com', 'Eicar-Test-Signature'), ('/tmp/b<i>.zip', 'Win.Trojan.X')]}
        dialog = ScanReportDialog(self.window, result)
        texts = [label.text() for label in dialog.findChildren(QLabel)]
        self.assertIn('2 threats found', texts)
        self.assertEqual(len(dialog.threat_labels), 2)
        self.assertIn('b&lt;i&gt;.zip', dialog.threat_labels[1].text())  # file names are escaped
        self.assertTrue(dialog.details.isHidden())
        dialog.deleteLater()
        self.window.last_result = result
        with patch('ui.main_window.ScanReportDialog') as report, \
                patch.object(self.window, 'handle_findings') as handle:
            report.QUARANTINE_ALL = ScanReportDialog.QUARANTINE_ALL
            report.return_value.exec.return_value = ScanReportDialog.QUARANTINE_ALL
            self.window.show_scan_report()
        handle.assert_called_once_with('quarantine')

    def test_progress_window_shows_progress_not_the_log(self):
        dialog = UpdateProgressDialog(self.window, 'Update virus database')
        self.assertTrue(dialog.log.isHidden())
        dialog.append('Downloading daily.cvd [=====>    ] 42%\n')
        self.assertEqual(dialog.progress.value(), 42)
        dialog.toggle_details()
        self.assertFalse(dialog.log.isHidden())
        self.assertIn('daily.cvd', dialog.log.toPlainText())
        dialog.finish(False, 'The virus database could not be downloaded.\nTraceback details')
        self.assertEqual(dialog.status.text(), 'This did not finish. The virus database could not be downloaded.')
        dialog.deleteLater()

    def test_dark_theme_covers_context_menus(self):
        from PySide6.QtGui import QPalette
        self.window.apply_theme('dark')
        app = QApplication.instance()
        self.assertIn('QMenu {', app.styleSheet())
        self.assertEqual(app.palette().color(QPalette.ColorRole.Window).name(), '#101713')
        self.assertTrue(self.window.log.isHidden())
        self.window.log_toggle.click()
        self.assertFalse(self.window.log.isHidden())

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
