"""Security status page: the most important protection at a glance, with a button to fix each part."""
import threading

from PySide6.QtWidgets import QHBoxLayout, QScrollArea, QVBoxLayout, QWidget

from backends import backend
from core.monitor_agent import monitoring_enabled
from core.security_status import security_items, summary

SYMBOLS = {'ok': '✓', 'warning': '!', 'info': 'i'}
SEVERITIES = {'ok': 'success', 'warning': 'warning', 'info': 'normal'}


class SecurityStatusPage:
    def __init__(self, window):
        self.window = window
        self.checking = False
        self.facts = None
        self.items = []
        self.page, outer = window.page('Security status',
                                       'The most important protection of this computer at a glance.')
        header = QHBoxLayout()
        self.summary = window.label('Checking…', 'statusValue')
        self.summary.setWordWrap(True)
        header.addWidget(self.summary, 1)
        self.check_button = window.button('Check again', self.refresh)
        header.addWidget(self.check_button)
        outer.addLayout(header)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName('settingsContent')
        self.rows = QVBoxLayout(content)
        self.rows.setContentsMargins(0, 0, 0, 0)
        self.rows.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

    def refresh(self):
        """Read the facts off the GUI thread; called when the page opens."""
        if self.checking:
            return
        self.checking = True
        self.check_button.setEnabled(False)

        def work():
            try:
                facts = backend.security_facts()
            except Exception:  # noqa: BLE001 - shown as unavailable, never a crash
                facts = None
            self.window.events.put(('__CALL__', self.show, facts))

        threading.Thread(target=work, name='security-status', daemon=True).start()

    def show(self, facts):
        self.facts = facts
        self.checking = False
        self.check_button.setEnabled(True)
        window = self.window
        while self.rows.count() > 1:
            widget = self.rows.takeAt(0).widget()
            if widget is not None:
                widget.hide()  # deleted later; never shown under the new rows
                widget.setParent(None)
                widget.deleteLater()
        if facts is None:
            self.items = []
            self.set_summary('Security status is available on Linux.', 'normal')
            return
        status = window.startup_status
        self.items = security_items(
            facts, websites_available=backend.internet_protection_available(),
            websites_on=backend.internet_protection_enabled(),
            files_on=monitoring_enabled(window.config) and backend.monitor_agent_running(),
            scanning_ready=bool(status and status.can_scan))
        title, severity = summary(self.items)
        self.set_summary(title, severity)
        for position, entry in enumerate(self.items):
            self.rows.insertWidget(position, self.row(entry))

    def row(self, entry):
        window = self.window
        card, box = window.card()
        line = QHBoxLayout()
        texts = QVBoxLayout()
        title = window.label(f"{SYMBOLS[entry['severity']]}  {entry['title']}", 'statusValue')
        title.setProperty('severity', SEVERITIES[entry['severity']])
        title.setWordWrap(True)
        texts.addWidget(title)
        detail = window.label(entry['detail'], 'muted')
        detail.setWordWrap(True)
        texts.addWidget(detail)
        line.addLayout(texts, 1)
        if entry['action']:
            text, key = entry['action']
            button = window.button(text, lambda _checked=False, k=key: self.act(k),
                                   variant='primary' if entry['severity'] == 'warning' else 'secondary',
                                   track=False)
            line.addWidget(button)
        box.addLayout(line)
        return card

    def set_summary(self, text, severity):
        self.summary.setText(text)
        self.summary.setProperty('severity', severity)
        self.summary.style().unpolish(self.summary)
        self.summary.style().polish(self.summary)

    def act(self, key):
        window = self.window
        if key in ('firewall', 'internet'):
            window.switch_page(key)
        elif key == 'setup':
            window.open_antivirus_setup(window.startup_status)
        elif key == 'updates':
            try:
                backend.open_software_updates(self.facts['update_program'])
            except OSError as exc:
                window.log.appendPlainText(f'Security status: cannot open software updates: {exc}')
        elif key == 'screen-lock':
            self.turn_on_screen_lock()

    def turn_on_screen_lock(self):
        desktop = self.facts.get('desktop')

        def work():
            try:
                backend.turn_on_screen_lock(desktop)
                error = None
            except OSError as exc:
                error = str(exc)
            self.window.events.put(('__CALL__', self.screen_lock_changed, error))

        threading.Thread(target=work, name='screen-lock', daemon=True).start()

    def screen_lock_changed(self, error):
        if error:
            self.window.log.appendPlainText(f'Security status: {error}')
        self.refresh()
