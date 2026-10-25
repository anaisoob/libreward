"""Live protection for new files: one switch; the background agent does the work."""
import os
import threading
import time

from PySide6.QtCore import QFileSystemWatcher, Qt, QTimer
from PySide6.QtWidgets import QHBoxLayout

from backends import backend
from config import save_config
from core.dependencies import install_hint, missing_components, missing_message
from core.download_folders import discover_download_folders
from core.monitor_agent import monitor_dir, monitor_settings, read_state

from .dialogs import ProtectedFoldersDialog


def folder_name(path):
    """Short, familiar form: ~/Downloads instead of /home/name/Downloads."""
    home = os.path.expanduser('~')
    return '~' + path[len(home):] if path == home or path.startswith(home + os.sep) else path


def default_folders():
    """Downloads folders of the system and browsers; the user can change them later."""
    folders = [folder.path for folder in discover_download_folders()]
    if not folders:
        fallback = backend.downloads_directory()
        folders = [str(fallback)] if fallback and os.path.isdir(fallback) else []
    return folders


class FileProtectionSection:
    def __init__(self, window, layout):
        self.window = window
        self.service_error = None
        self.started_at = float('-inf')
        self.busy = False
        card, box = window.card()
        box.addWidget(window.label('NEW FILES AND DOWNLOADS', 'eyebrow'))
        self.status = window.label('Checking…', 'statusValue')
        box.addWidget(self.status)
        self.info = window.label('', 'muted')
        self.info.setWordWrap(True)
        # Install commands can be copied.
        self.info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.addWidget(self.info)
        row = QHBoxLayout()
        self.toggle_button = window.button('Turn on', self.toggle, variant='primary')
        row.addWidget(self.toggle_button)
        row.addStretch()
        self.folders_button = window.button('Choose folders…', self.choose_folders)
        row.addWidget(self.folders_button)
        test = window.button('Send a test notification', self.test_notification)
        test.setFlat(True)
        row.addWidget(test)
        box.addLayout(row)
        self.folders_label = window.label('', 'muted')
        self.folders_label.setWordWrap(True)
        box.addWidget(self.folders_label)
        self.notification_status = window.label('', 'muted')
        self.notification_status.setWordWrap(True)
        self.notification_status.hide()
        box.addWidget(self.notification_status)
        layout.addWidget(card)
        # The agent replaces its state file on every change; react to that instead
        # of polling. A slow check notices an agent that stopped without writing.
        self.watcher = QFileSystemWatcher(card)
        self.changed = QTimer(card)
        self.changed.setSingleShot(True)
        self.changed.setInterval(200)
        self.changed.timeout.connect(self.refresh)
        self.watcher.directoryChanged.connect(lambda _path: self.changed.start())
        self.timer = QTimer(card)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(30000)
        self.apply_service()

    # ── settings ────────────────────────────────────────────────────

    @property
    def enabled(self):
        return monitor_settings(self.window.config) is not None

    def folders(self):
        return [path for path in self.window.config.get('watched_folders', []) if isinstance(path, str) and path]

    def save(self, **changes):
        updated = dict(self.window.config, **changes)
        try:
            save_config(updated)
        except OSError as exc:
            self.service_error = f'Cannot save the setting: {exc}'
            self.refresh()
            return False
        self.window.config = updated
        return True

    def toggle(self):
        if self.enabled:
            if self.save(watch_folders_enabled=False):
                self.apply_service()
            return
        if self.folders():
            if self.save(watch_folders_enabled=True):
                self.apply_service()
            return
        # First use: protect the Downloads folders without asking where they are.
        self.busy = True
        self.refresh()
        self.in_background(default_folders, self.folders_found)

    def folders_found(self, folders):
        self.busy = False
        if not folders:
            self.service_error = 'No Downloads folder was found. Choose folders to protect.'
            self.refresh()
            self.choose_folders()
            return
        if self.save(watch_folders_enabled=True, watched_folders=folders):
            self.apply_service()

    def choose_folders(self):
        dialog = ProtectedFoldersDialog(self.window, self.folders(), discover=default_folders)
        if dialog.exec() == ProtectedFoldersDialog.DialogCode.Accepted:
            folders = dialog.folders()
            was_enabled = self.enabled
            if self.save(watched_folders=folders, watch_folders_enabled=bool(folders) and (
                    was_enabled or not self.folders())):
                # A running agent follows the saved folders by itself.
                if self.enabled != was_enabled or not backend.monitor_agent_running():
                    self.apply_service()
                self.refresh()
        dialog.deleteLater()

    def in_background(self, work, done):
        def run():
            try:
                result = work()
            except OSError:
                result = []
            self.window.events.put(('__CALL__', done, result))
        threading.Thread(target=run, name='file-protection', daemon=True).start()

    # ── background service ─────────────────────────────────────────

    def apply_service(self):
        """Start or remove the background agent to match the saved settings.

        Starting also repairs a service that points to an older installation.
        systemctl can take a moment, so this never runs on the GUI thread.
        """
        enabled = self.enabled
        self.service_error = None
        missing = missing_components(['watchdog']) if enabled else {}
        if missing:
            # The service runs this interpreter: it would fail the same way.
            self.service_error = missing_message(missing, 'Protection for new files')
            self.refresh()
            return
        self.busy = enabled
        self.refresh()

        def work():
            try:
                backend.set_monitor_service(enabled)
                return None
            except OSError as exc:
                return str(exc) or 'The background service could not be changed.'

        self.in_background(work, lambda error: self.service_changed(enabled, error))

    def service_changed(self, enabled, error):
        if enabled != self.enabled:
            return  # switched again meanwhile; the newer request decides
        self.busy = False
        self.service_error = error
        if enabled and not error:
            self.started_at = time.monotonic()
            # Shows a failed start once "Turning on…" is over.
            QTimer.singleShot(16000, self.refresh)
        if error:
            self.window.log.appendPlainText(f'Live protection: {error}')
        self.refresh()

    def ensure_running(self):
        """After settings changes elsewhere: start the agent again if it stopped."""
        if self.service_error or (self.enabled and not backend.monitor_agent_running()):
            self.apply_service()

    # ── status ──────────────────────────────────────────────────────

    def watch(self):
        # The agent creates its directory when it first runs.
        path = str(monitor_dir())
        if path not in self.watcher.directories() and os.path.isdir(path):
            self.watcher.addPath(path)

    def refresh(self):
        self.watch()
        enabled = self.enabled
        state = read_state()
        running = enabled and backend.monitor_agent_running()
        folders = self.folders()
        if self.busy:
            status, severity, info = 'Turning on…', 'normal', 'Finding your Downloads folders and starting protection.'
        elif self.service_error:
            status, severity, info = 'Needs attention', 'warning', self.service_error
        elif not enabled:
            status, severity = 'Off', 'warning'
            info = ('Turn on to check new downloads and other new files for viruses as soon as they arrive. '
                    'It keeps working when LibreWard is closed.')
        elif not running and state.get('status') == 'error' and state.get('message'):
            status, severity, info = 'Needs attention', 'warning', state['message']
        elif not running and time.monotonic() - self.started_at < 15:
            status, severity, info = 'Turning on…', 'normal', 'Starting protection.'
        elif not running:
            status, severity = 'Needs attention', 'warning'
            info = 'Protection for new files stopped. Turn it off and on again to restart it.'
        elif state.get('status') == 'needs-setup':
            status, severity = 'Needs attention', 'warning'
            info = 'Waiting for the antivirus engine and virus database. Set them up in Settings.'
        elif state.get('status') in ('error', 'paused') and state.get('message'):
            status, severity, info = 'Needs attention', 'warning', state['message']
        else:
            status, severity = 'On', 'success'
            info = ('New files are checked as soon as they arrive, also when LibreWard is closed. '
                    'You get a notification for each check, and LibreWard opens if a file is dangerous.')
            last = state.get('last_scan')
            if isinstance(last, dict) and last.get('outcome'):
                checked = time.strftime('%H:%M', time.localtime(last.get('time', 0)))
                info += f"\nLast check at {checked}: {last['outcome']} ({last.get('names', '')})."
            if state.get('notifications') is False:
                info += '\n' + self.notifications_unavailable_text()
        self.status.setText(status)
        self.status.setProperty('severity', severity)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.info.setText(info)
        self.toggle_button.setText('Turn off' if enabled else 'Turn on')
        self.toggle_button.setObjectName('secondaryButton' if enabled else 'primaryButton')
        self.toggle_button.style().unpolish(self.toggle_button)
        self.toggle_button.style().polish(self.toggle_button)
        self.toggle_button.setEnabled(not self.busy)
        self.folders_label.setText('Protected folders: ' + ', '.join(folder_name(path) for path in folders)
                                   if folders else '')
        self.window.show_monitor_threats(state)

    @staticmethod
    def notifications_unavailable_text():
        text = 'Desktop notifications are unavailable, so results are only shown here.'
        if not backend.notifications_available():
            text += ' ' + install_hint(['notify-send'])
        return text

    def test_notification(self):
        def send():
            return backend.send_desktop_notification('LibreWard — notification test',
                                                     'Desktop notifications are working.')

        def done(delivered):
            self.notification_status.setText(
                'Notification sent. If no message appears, check the notification settings of your desktop '
                'and Do Not Disturb.' if delivered else self.notifications_unavailable_text())
            self.notification_status.show()

        self.in_background(send, done)

    def stop(self):
        self.timer.stop()
        self.changed.stop()
        self.watcher.removePaths(self.watcher.directories())
