"""Scheduled Quick scans: one choice; the background agent runs them."""
import time

from PySide6.QtWidgets import QComboBox, QHBoxLayout

from backends import backend
from core.monitor_agent import agent_needed, last_scheduled_scan, read_state, scheduled_interval

CHOICES = [('off', 'Off'), ('daily', 'Every day'), ('weekly', 'Every week')]


def day_and_time(moment):
    return time.strftime('%A %d %B at %H:%M', time.localtime(moment))


class ScheduledScanSection:
    def __init__(self, window, layout):
        self.window = window
        self.changed_at = float('-inf')
        card, box = window.card()
        box.addWidget(window.label('SCHEDULED SCAN', 'eyebrow'))
        self.status = window.label('Off', 'statusValue')
        box.addWidget(self.status)
        self.info = window.label('', 'muted')
        self.info.setWordWrap(True)
        box.addWidget(self.info)
        row = QHBoxLayout()
        self.choice = QComboBox()
        for key, text in CHOICES:
            self.choice.addItem(text, key)
        self.choice.setCurrentIndex(self.choice.findData(self.schedule))
        self.choice.currentIndexChanged.connect(self.chosen)
        row.addWidget(self.choice)
        row.addStretch()
        box.addLayout(row)
        layout.addWidget(card)
        self.refresh()

    @property
    def schedule(self):
        return self.window.config.get('scheduled_scan') if scheduled_interval(self.window.config) else 'off'

    def chosen(self, _index):
        key = self.choice.currentData()
        was_needed = agent_needed(self.window.config)
        protection = self.window.file_protection
        if not protection.save(scheduled_scan=key):
            self.choice.setCurrentIndex(self.choice.findData(self.schedule))
            return
        self.changed_at = time.monotonic()
        # A running agent reads the saved choice within seconds.
        if agent_needed(self.window.config) != was_needed or not backend.monitor_agent_running():
            protection.apply_service()
        self.refresh()

    def refresh(self, state=None):
        state = read_state() if state is None else state
        self.choice.blockSignals(True)
        self.choice.setCurrentIndex(self.choice.findData(self.schedule))
        self.choice.blockSignals(False)
        interval = scheduled_interval(self.window.config)
        error = self.window.file_protection.service_error
        last = last_scheduled_scan(state)
        if interval is None:
            status, severity = 'Off', 'warning'
            info = ('LibreWard can check the places where threats usually arrive, such as Downloads, the Desktop '
                    'and temporary files, every day or every week. It also works when LibreWard is closed.')
        elif error:
            status, severity, info = 'Needs attention', 'warning', error
        elif not backend.monitor_agent_running():
            if time.monotonic() - self.changed_at < 15:
                status, severity, info = 'Turning on…', 'normal', 'Starting the background service.'
            else:
                status, severity = 'Needs attention', 'warning'
                info = 'The background service is not running. Choose Off and then the schedule again to restart it.'
        elif state.get('scheduled_scan_running'):
            status, severity = 'Scanning now…', 'normal'
            info = ('A Quick scan is running in the background. You can keep working; '
                    'you get a notification when it has finished.')
        else:
            status, severity = dict(CHOICES)[self.schedule], 'success'
            info = ('A Quick scan runs in the background, also when LibreWard is closed. '
                    'If the computer was off at that time, it runs soon after you log in.')
            if state.get('scheduled_scan_waiting'):
                status, severity = 'Needs attention', 'warning'
                info += '\n' + state['scheduled_scan_waiting']
            elif state.get('scheduled_scan_error'):
                info += '\nThe last scan did not finish. LibreWard tries again in an hour.'
            if last.get('outcome'):
                info += (f"\nLast scan on {day_and_time(last.get('time', 0))}: {last['outcome']} "
                         f"({last.get('files', 0)} files checked).")
            started = last.get('started')
            if isinstance(started, (int, float)) and 0 <= time.time() - started < interval:
                info += f'\nNext scan: {day_and_time(started + interval)}.'
            else:
                info += '\nThe first scan starts in a few minutes.' if not last else '\nThe next scan starts soon.'
        self.status.setText(status)
        self.status.setProperty('severity', severity)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.info.setText(info)
