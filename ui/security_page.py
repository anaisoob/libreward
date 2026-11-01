"""Security status page: how protected the computer is, what to do about it, and everything else in brief."""
import html
import threading

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from backends import backend
from core.db_manager import database_time
from core.monitor_agent import last_scheduled_scan, monitoring_enabled, read_state
from core.security_status import (
    activity,
    attention,
    security_items,
    summary,
    upkeep_items,
)

from .theme import shield_pixmap

TILE_COLUMNS = 3
QUICK_SCAN = ('Scan now', 'scan')


class SecurityStatusPage:
    def __init__(self, window):
        self.window = window
        self.checking = False
        self.facts = None
        self.items = []
        self.primary_action = None
        self.page = QWidget()
        self.page.setObjectName('contentPage')
        outer = QVBoxLayout(self.page)
        outer.setContentsMargins(28, 26, 28, 24)
        outer.setSpacing(16)
        outer.addWidget(self.build_hero())
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName('settingsContent')
        self.rows = QVBoxLayout(content)
        self.rows.setContentsMargins(0, 0, 0, 0)
        self.rows.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

    def build_hero(self):
        window = self.window
        self.hero = QFrame()
        self.hero.setObjectName('hero')
        line = QHBoxLayout(self.hero)
        line.setContentsMargins(24, 20, 24, 20)
        line.setSpacing(20)
        self.shield = window.label('')
        self.shield.setPixmap(shield_pixmap(None))
        line.addWidget(self.shield)
        texts = QVBoxLayout()
        texts.setSpacing(6)
        texts.addStretch()
        self.summary = window.label('Checking…', 'heroTitle')
        self.summary.setWordWrap(True)
        texts.addWidget(self.summary)
        self.activity = window.label('', 'muted')
        self.activity.setWordWrap(True)
        texts.addWidget(self.activity)
        texts.addStretch()
        line.addLayout(texts, 1)
        buttons = QVBoxLayout()
        buttons.addStretch()
        # Not tracked: what it does changes, and a scan or fix guards itself while busy.
        self.primary = window.button('', self.run_primary, variant='primary', track=False)
        self.primary.hide()
        buttons.addWidget(self.primary)
        self.check_button = window.button('Check again', self.refresh)
        buttons.addWidget(self.check_button)
        buttons.addStretch()
        line.addLayout(buttons)
        return self.hero

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
            self.window.events.put(('__CALL__', self.show, (facts, self.recent_times())))

        threading.Thread(target=work, name='security-status', daemon=True).start()

    def recent_times(self):
        """(virus database, last scan) as time.time() values or None."""
        scans = [self.window.config.get('last_scan_at'), last_scheduled_scan(read_state()).get('time')]
        return (database_time(),
                max((scan for scan in scans if isinstance(scan, (int, float))), default=None))

    def show(self, result):
        facts, times = result
        self.facts = facts
        self.checking = False
        self.check_button.setEnabled(True)
        window = self.window
        self.clear_rows()
        status = window.startup_status
        scanning_ready = bool(status and status.can_scan)
        self.activity.setText(activity(*times, window.quarantine_items))
        if facts is None:
            self.items = []
            self.set_summary('Security status is available on Linux.', 'normal')
            self.set_primary([], scanning_ready)
            return
        self.items = security_items(
            facts, websites_available=backend.internet_protection_available(),
            websites_on=backend.internet_protection_enabled(),
            files_on=monitoring_enabled(window.config) and backend.monitor_agent_running(),
            scanning_ready=scanning_ready)
        self.items += upkeep_items(*times, scanning_ready=scanning_ready,
                                   can_update_database=bool(status and status.can_update_db))
        self.set_summary(*summary(self.items))
        fixes = attention(self.items)
        self.set_primary(fixes, scanning_ready)
        if fixes:
            self.add_row(self.heading('Needs your attention'))
            for entry in fixes:
                self.add_row(self.row(entry))
        tiles = [entry for entry in self.items if entry['severity'] != 'warning']
        if tiles:
            self.add_row(self.heading('Protection'))
            self.add_row(self.tile_grid(tiles))

    def clear_rows(self):
        while self.rows.count() > 1:
            widget = self.rows.takeAt(0).widget()
            if widget is not None:
                widget.hide()  # deleted later; never shown under the new rows
                widget.setParent(None)
                widget.deleteLater()

    def heading(self, text):
        label = self.window.label(text, 'sectionTitle')
        label.setContentsMargins(0, 8, 0, 2)
        return label

    def add_row(self, widget):
        self.rows.insertWidget(self.rows.count() - 1, widget)

    def set_primary(self, fixes, scanning_ready):
        """The hero button: the most important fix, otherwise a scan."""
        actions = [entry['action'] for entry in fixes if entry['action']]
        self.primary_action = actions[0] if actions else QUICK_SCAN if scanning_ready else None
        self.primary.setVisible(self.primary_action is not None)
        if self.primary_action:
            self.primary.setText(self.primary_action[0])

    def run_primary(self):
        if self.primary_action:
            self.act(self.primary_action[1])

    def row(self, entry):
        window = self.window
        card, box = window.card()
        line = QHBoxLayout()
        texts = QVBoxLayout()
        title = window.label(f"!  {entry['title']}", 'statusValue')
        title.setProperty('severity', 'warning')
        title.setWordWrap(True)
        texts.addWidget(title)
        detail = window.label(entry['detail'], 'muted')
        detail.setWordWrap(True)
        texts.addWidget(detail)
        line.addLayout(texts, 1)
        if entry['action']:
            text, key = entry['action']
            line.addWidget(window.button(text, lambda _checked=False, k=key: self.act(k), track=False))
        box.addLayout(line)
        return card

    def tile_grid(self, entries):
        grid_widget = QWidget()
        grid_widget.setObjectName('settingsContent')
        grid = QGridLayout(grid_widget)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)
        for column in range(TILE_COLUMNS):
            grid.setColumnStretch(column, 1)
        for position, entry in enumerate(entries):
            grid.addWidget(self.tile(entry), position // TILE_COLUMNS, position % TILE_COLUMNS)
        return grid_widget

    def tile(self, entry):
        window = self.window
        tile = QFrame()
        tile.setObjectName('tile')
        tile.setToolTip(f"<p>{html.escape(entry['title'])}</p><p>{html.escape(entry['detail'])}</p>")
        line = QHBoxLayout(tile)
        line.setContentsMargins(14, 12, 14, 12)
        line.setSpacing(10)
        mark = window.label('✓' if entry['severity'] == 'ok' else 'i', 'tileMark')
        mark.setProperty('severity', 'success' if entry['severity'] == 'ok' else 'normal')
        mark.setAlignment(Qt.AlignmentFlag.AlignTop)
        line.addWidget(mark)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        texts.addWidget(window.label(entry['label'], 'tileName'))
        state = window.label(entry['state'], 'muted')
        state.setWordWrap(True)
        texts.addWidget(state)
        line.addLayout(texts, 1)
        return tile

    def set_summary(self, text, severity):
        self.summary.setText(text)
        self.shield.setPixmap(shield_pixmap(severity))
        for widget in (self.summary, self.hero):
            widget.setProperty('severity', severity)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def act(self, key):
        window = self.window
        if key in ('firewall', 'internet'):
            window.switch_page(key)
        elif key == 'scan':
            window.switch_page('scan')
            window.start_quick_scan()
        elif key == 'database':
            window.update_database()
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
