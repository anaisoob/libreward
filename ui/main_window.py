"""PySide6 frontend using shared core services and platform backends."""
import os
import queue
import threading

from PySide6.QtCore import Qt, QTimer, QSize, QByteArray
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QStackedWidget, QVBoxLayout, QWidget,
    QFrame, QHeaderView, QSizePolicy, QSplitter,
)

from backends import backend
from config import load_config, save_config
from core.authorization import AuthorizationError
from core.constants import APP_NAME, APP_VERSION, CLAMAV_HOMEPAGE, CLAMAV_SOURCE
from core.db_manager import database_summary, run_freshclam_update
from core.quarantine import (
    delete_file, delete_quarantined_file, list_quarantined_files,
    open_file_location, quarantine_file, restore_file,
)
from core.runtime import check_startup, setup_components
from core.scan_service import ScanService, scan_outcome
from core.updater import check_for_updates, perform_update
from excludes import get_active_exclude_patterns, get_common_excludes
from .dialogs import ClamAVConsentDialog, UpdateProgressDialog, ScanReportDialog, AntivirusSetupDialog, AuthorizationHelpDialog
from .firewall_dialog import FirewallRuleDialog
from .theme import stylesheet, navigation_icon
from .widgets import ElidedPathLabel, BusyNavigationButton


class QtMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1180, 860)
        self.setMinimumSize(980, 740)
        self.events = queue.Queue()
        self.worker = None
        self.service = None
        self.operation = None
        self.startup_status = None
        self.update_dialog = None
        self.completion = None
        self.on_done = None
        self.pending_setup = False
        self.privileged_terminal_commands = ''
        config = load_config()
        self.config = config if isinstance(config, dict) else {}
        self.idle_buttons = []
        self.scan_actions = []
        self.last_result = None
        self.build_shell()
        self.apply_theme(self.config.get("qt_theme", "dark"))
        geometry = self.config.get('window_geometry')
        if isinstance(geometry, str) and len(geometry) <= 8192:
            try:
                self.restoreGeometry(QByteArray(bytes.fromhex(geometry)))
                self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized)
            except ValueError:
                pass
        QApplication.instance().styleHints().colorSchemeChanged.connect(self.system_theme_changed)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_events)
        self.timer.start(100)
        self.database_watch_checks = 0
        self.database_watch_timer = QTimer(self)
        self.database_watch_timer.setInterval(10000)
        self.database_watch_timer.timeout.connect(self.poll_system_database)
        self.start_task("check", self.check_runtime, on_done=self.offer_setup)

    def build_shell(self):
        shell = QWidget()
        shell.setObjectName("appShell")
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(18, 26, 18, 22)
        side.setSpacing(8)
        brand = QHBoxLayout()
        logo = self.label("LW", "logo")
        logo.setFixedSize(40, 40)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand.addWidget(logo)
        brand.addWidget(self.label(APP_NAME, "brand"))
        brand.addStretch()
        side.addLayout(brand)
        side.addSpacing(28)
        side.addWidget(self.label("WORKSPACE", "eyebrow"))
        side.addSpacing(6)
        self.pages = QStackedWidget()
        self.nav_buttons = {}
        self.page_indices = {}
        definitions = [
            ("scan", "Virus scan", self.build_scan_page),
            ("quarantine", "Quarantine", self.build_quarantine_page),
            ("firewall", "Firewall", self.build_firewall_page),
            ("internet", "Internet Watcher", lambda: self.build_planned_page("Internet Watcher", "Understand your network activity", "Internet traffic monitoring is planned for a future release.")),
            ("settings", "Settings", self.build_settings_page),
            ("about", "About", self.build_about_page),
        ]
        for key, text, builder in definitions:
            self.page_indices[key] = self.pages.addWidget(builder())
            nav = BusyNavigationButton(text) if key == "scan" else QPushButton(text)
            nav.setObjectName("navButton")
            nav.setCheckable(True)
            nav.setMinimumHeight(46)
            nav.setIconSize(QSize(20, 20))
            nav.clicked.connect(lambda checked=False, k=key: self.switch_page(k))
            self.nav_buttons[key] = nav
            if key == "about":
                side.addStretch()
                self.sidebar_status = self.label("Checking engine…", "sidebarStatus")
                side.addWidget(self.sidebar_status)
                side.addSpacing(12)
            side.addWidget(nav)
        side.addWidget(self.label(f"Version {APP_VERSION}", "muted"))
        layout.addWidget(sidebar)
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(shell)
        self.switch_page("scan")
        self.update_exclude_summary()

    def switch_page(self, key):
        self.pages.setCurrentIndex(self.page_indices[key])
        for name, button in self.nav_buttons.items():
            button.setChecked(name == key)
        self.update_scan_indicator()
        if key == 'firewall' and self.firewall_snapshot is None:
            self.firewall_refresh_pending = True
            if self.operation:
                self.firewall_status.setText('Waiting for the current operation before checking firewall…')
            self.maybe_refresh_firewall()

    def update_scan_indicator(self):
        away = self.pages.currentIndex() != self.page_indices["scan"]
        self.nav_buttons["scan"].set_busy(self.operation == "scan" and away)

    @staticmethod
    def label(text, role=""):
        label = QLabel(text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        if role:
            label.setObjectName(role)
        return label

    def page(self, title, subtitle):
        page = QWidget()
        page.setObjectName("contentPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 26, 28, 24)
        layout.setSpacing(16)
        layout.addWidget(self.label(title, "pageTitle"))
        description = self.label(subtitle, "muted")
        description.setWordWrap(True)
        layout.addWidget(description)
        return page, layout

    @staticmethod
    def card():
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        return frame, layout

    def button(self, text, callback, *, scan_action=False, variant="secondary"):
        button = QPushButton(text)
        button.setObjectName(variant + "Button")
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setMinimumHeight(38)
        button.clicked.connect(callback)
        (self.scan_actions if scan_action else self.idle_buttons).append(button)
        return button

    @staticmethod
    def table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(42)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        return table

    def build_firewall_page(self):
        page, layout = self.page("Firewall", "Control which network connections this computer allows.")
        self.firewall_snapshot = None
        self.firewall_refresh_pending = False
        overview, box = self.card()
        box.addWidget(self.label("NETWORK PROTECTION", "eyebrow"))
        self.firewall_status = self.label("Not checked", "statusValue")
        box.addWidget(self.firewall_status)
        self.firewall_info = self.label("Checking which firewall is available on your computer…", "muted")
        self.firewall_info.setWordWrap(True)
        box.addWidget(self.firewall_info)
        row = QHBoxLayout()
        self.firewall_tools = QComboBox()
        self.firewall_tools.setMinimumHeight(38)
        self.firewall_tools.currentIndexChanged.connect(self.show_firewall_tool)
        row.addWidget(self.firewall_tools, 1)
        row.addWidget(self.button("Check protection status", self.authorize_firewall, variant="primary"))
        box.addLayout(row)
        actions = QHBoxLayout()
        self.firewall_enable_button = self.button("Enable firewall", self.enable_firewall, variant="primary")
        self.firewall_add_button = self.button("Add rule", self.add_firewall_rule)
        actions.addWidget(self.firewall_enable_button)
        actions.addWidget(self.firewall_add_button)
        actions.addStretch()
        box.addLayout(actions)
        self.firewall_management_hint = self.label("Firewall actions will appear after automatic detection.", "muted")
        self.firewall_management_hint.setWordWrap(True)
        box.addWidget(self.firewall_management_hint)
        self.firewall_change_result = self.label("", "muted")
        self.firewall_change_result.setWordWrap(True)
        box.addWidget(self.firewall_change_result)
        self.update_firewall_controls()
        layout.addWidget(overview)
        rules, box = self.card()
        box.addWidget(self.label("CONNECTION RULES", "eyebrow"))
        self.firewall_rules_help = self.label('Rules decide which connections are allowed or blocked. Checking status does not change your settings.', 'muted')
        self.firewall_rules_help.setWordWrap(True)
        box.addWidget(self.firewall_rules_help)
        self.firewall_details_toggle = QCheckBox('Show technical rule details')
        box.addWidget(self.firewall_details_toggle)
        self.firewall_rules = QPlainTextEdit()
        self.firewall_rules.setReadOnly(True)
        self.firewall_rules.setPlaceholderText("Existing rules and installation instructions will appear here.")
        self.firewall_rules.hide()
        self.firewall_details_toggle.toggled.connect(self.firewall_rules.setVisible)
        box.addWidget(self.firewall_rules, 1)
        box.addStretch()  # keep text at the top while rule details are hidden
        layout.addWidget(rules, 1)
        return page

    def maybe_refresh_firewall(self):
        if (self.firewall_refresh_pending and self.operation is None
                and self.pages.currentIndex() == self.page_indices['firewall']
                and QApplication.activeModalWidget() is None):
            self.refresh_firewall()

    def refresh_firewall(self):
        if self.start_task("firewall", backend.inspect_firewall, on_done=self.apply_firewall_snapshot):
            self.firewall_refresh_pending = False
            self.firewall_status.setText("Checking firewall…")

    def authorize_firewall(self):
        name = self.firewall_tools.currentText()
        if not name:
            self.firewall_refresh_pending = True
            self.maybe_refresh_firewall()
            return
        self.privileged_terminal_commands = self.selected_firewall_tool().command
        if not self.ensure_system_authorization():
            return
        if self.start_task("firewall", lambda: backend.inspect_firewall(privileged=True, tool_name=name),
                           on_done=self.apply_privileged_firewall_snapshot):
            self.firewall_status.setText("Waiting for system authorization and reading rules…")

    def show_authorization_help(self, message=None):
        status = backend.authorization_status()
        dialog = AuthorizationHelpDialog(self, status, self.privileged_terminal_commands, issue=message)
        dialog.exec()
        dialog.deleteLater()

    def ensure_system_authorization(self):
        if backend.authorization_status().available:
            return True
        self.show_authorization_help()
        return False

    def apply_privileged_firewall_snapshot(self, snapshot):
        if self.firewall_snapshot:
            updated = {tool.name: tool for tool in snapshot.tools}
            snapshot.tools = [updated.get(tool.name, tool) for tool in self.firewall_snapshot.tools]
        selected = self.firewall_tools.currentText()
        self.apply_firewall_snapshot(snapshot)
        index = self.firewall_tools.findText(selected)
        if index >= 0:
            self.firewall_tools.setCurrentIndex(index)

    def apply_firewall_snapshot(self, snapshot):
        self.firewall_refresh_pending = False
        self.firewall_snapshot = snapshot
        self.firewall_info.setText(snapshot.instructions if not snapshot.tools else
                                  'A firewall controls network access to and from your computer. '
                                  'Checking or changing protected settings may ask for your system password.')
        self.firewall_tools.blockSignals(True)
        self.firewall_tools.clear()
        self.firewall_tools.addItems([tool.name for tool in snapshot.tools])
        preferred = next((i for i, tool in enumerate(snapshot.tools) if tool.state in ("Active", "Running")), 0)
        self.firewall_tools.setCurrentIndex(preferred if snapshot.tools else -1)
        self.firewall_tools.blockSignals(False)
        self.show_firewall_tool(self.firewall_tools.currentIndex())

    def show_firewall_tool(self, index):
        self.update_firewall_controls()
        snapshot = self.firewall_snapshot
        if snapshot is None:
            return
        if index < 0 or index >= len(snapshot.tools):
            self.firewall_status.setText("No supported firewall found" if snapshot.supported else "Firewall management is not available on this system")
            self.firewall_rules.setPlainText(snapshot.instructions)
            self.firewall_rules_help.setText(snapshot.instructions)
            return
        tool = snapshot.tools[index]
        self.firewall_status.setProperty('severity',
            'danger' if tool.state in ('Inactive', 'Not running') else
            'success' if tool.state in ('Active', 'Running') else 'unknown')
        self.firewall_status.style().unpolish(self.firewall_status)
        self.firewall_status.style().polish(self.firewall_status)
        active = tool.state in ('Active', 'Running')
        inactive = tool.state in ('Inactive', 'Not running')
        self.firewall_status.setText('Protection is on' if active else
                                     'Protection is off' if inactive else 'Protection status needs checking')
        self.firewall_rules_help.setText(
            ('This firewall is applying its connection rules. Use “Add rule” to allow or block a specific connection.' if active else
             'This firewall is not applying its rules. Turn it on to use its network protection.' if inactive else
             'We could not confirm whether this firewall is protecting your computer. Select “Check protection status”; your system may ask for authorization.')
            + '\nIncoming means connections to this computer. Outgoing means connections from this computer. '
            'Home / local network means devices on the selected network. All networks also includes the Internet.')
        self.firewall_rules.setPlainText(tool.rules)

    def selected_firewall_tool(self):
        snapshot = self.firewall_snapshot
        index = self.firewall_tools.currentIndex()
        return snapshot.tools[index] if snapshot and 0 <= index < len(snapshot.tools) else None

    def update_firewall_controls(self):
        tool = self.selected_firewall_tool()
        idle = self.operation is None
        managed = tool is not None and tool.name in ('UFW', 'firewalld')
        self.firewall_enable_button.setEnabled(idle and managed and tool.state in ('Inactive', 'Not running', 'Active', 'Running'))
        self.firewall_enable_button.setText('Disable firewall' if tool and tool.state in ('Active', 'Running') else 'Enable firewall')
        self.firewall_add_button.setEnabled(idle and managed and (tool.name == 'UFW' or tool.state == 'Running'))
        self.firewall_tools.setEnabled(idle)
        if not tool:
            hint = 'Firewall detection starts automatically when this page is opened.'
        elif not managed:
            hint = 'This tool supports inspection here. Use UFW or firewalld to enable protection and add rules.'
        elif tool.name == 'firewalld':
            hint = 'Turn on this firewall before adding rules. Rules apply to the selected connection group (zone). Turning it on here does not enable automatic startup.'
        else:
            hint = 'You can add rules before turning protection on. Saved rules take effect when the firewall is on.'
        self.firewall_management_hint.setText(hint)

    def enable_firewall(self):
        tool = self.selected_firewall_tool()
        if self.operation or not tool or tool.name not in ('UFW', 'firewalld') or tool.state not in ('Inactive', 'Not running', 'Active', 'Running'):
            return
        enabled = tool.state in ('Inactive', 'Not running')
        try:
            preview = backend.firewall_change_preview(tool.name, enabled=enabled)
        except (ValueError, NotImplementedError) as exc:
            QMessageBox.warning(self, 'Firewall', str(exc))
            return
        if enabled:
            persistence = ('UFW will be enabled now and at startup, using its existing rules and default policies.'
                           if tool.name == 'UFW' else 'firewalld will start now with its saved zones and rules. Its boot setting is unchanged.')
            explanation = persistence + '\n\nThis may interrupt incoming connections, including SSH or remote desktop. Add required access rules before continuing.'
        else:
            explanation = ('UFW will be disabled now and at startup. Saved rules are kept.' if tool.name == 'UFW' else
                           'firewalld will stop now. Saved rules and its boot setting are kept.')
            explanation += '\n\nThis removes protection provided by this firewall. Existing network services may become reachable.'
        action = 'Enable' if enabled else 'Disable'
        text = explanation + f'\n\n{action} this firewall?'
        if QMessageBox.question(self, f'{action} firewall', text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self.run_firewall_change(tool.name, enabled=enabled)

    def add_firewall_rule(self):
        tool = self.selected_firewall_tool()
        if self.operation or not tool or tool.name not in ('UFW', 'firewalld'):
            return
        if tool.name == 'firewalld' and tool.state != 'Running':
            return
        import re
        zones = re.findall(r'^([A-Za-z0-9_][A-Za-z0-9_-]*)(?: \(.*\))?$', tool.rules, re.MULTILINE) if tool.name == 'firewalld' else ()
        self.start_task('firewall-networks', backend.firewall_networks,
                        on_done=lambda networks: self.open_firewall_rule_editor(tool.name, zones, networks))

    def open_firewall_rule_editor(self, name, zones, networks):
        dialog = FirewallRuleDialog(self, name, zones, networks)
        while dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                rule = dialog.rule()
                preview = backend.firewall_change_preview(name, rule=rule)
            except (ValueError, NotImplementedError) as exc:
                QMessageBox.warning(self, 'Invalid firewall rule', str(exc))
                continue
            text = rule.description(name) + '\n\nApply this change?'
            if QMessageBox.question(self, 'Review firewall rule', text,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                self.run_firewall_change(name, rule=rule)
            break
        dialog.deleteLater()

    def run_firewall_change(self, name, *, rule=None, enabled=True):
        preview = backend.firewall_change_preview(name, rule=rule, enabled=enabled)
        tool = self.selected_firewall_tool()
        self.privileged_terminal_commands = '\n'.join('sudo ' + line for line in preview.splitlines())
        if tool:
            self.privileged_terminal_commands += '\n' + tool.command
        if not self.ensure_system_authorization():
            return
        if self.start_task('firewall-change', lambda: backend.change_firewall(name, rule=rule, enabled=enabled),
                           on_done=self.firewall_change_finished):
            self.firewall_change_result.setText('Waiting for system authorization…')

    def firewall_change_finished(self, result):
        self.apply_privileged_firewall_snapshot(result.snapshot)
        heading = 'Change completed. Status and rules refreshed.' if result.success else 'Change did not fully complete. Current status and rules refreshed.'
        self.firewall_change_result.setText(heading + '\n' + result.message + ('\n' + result.refresh_error if result.refresh_error else ''))
        if not result.success or result.refresh_error:
            QMessageBox.warning(self, 'Firewall operation', result.message + '\n' + result.refresh_error)

    def build_scan_page(self):
        page, layout = self.page("Virus scan", "Run ClamAV scans, monitor progress and review detected files.")
        folder, box = self.card()
        box.addWidget(self.label("SCAN FOLDER", "eyebrow"))
        row = QHBoxLayout()
        row.setSpacing(10)
        self.path = QLineEdit(str(self.config.get("scan_path", "")))
        self.path.setPlaceholderText("Choose a folder to scan…")
        self.path.setMinimumWidth(0)
        row.addWidget(self.path, 1)
        row.addWidget(self.button("Choose", self.choose_folder))
        row.addWidget(self.button("Excludes", lambda: self.switch_page("settings")))
        box.addLayout(row)
        self.exclude_summary = self.label("Excludes: none", "muted")
        box.addWidget(self.exclude_summary)
        layout.addWidget(folder)
        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.scan_button = self.button("Start scan", lambda: self.start_scan([self.path.text().strip()]), scan_action=True, variant="primary")
        self.quick_button = self.button("Quick system scan", lambda: self.start_scan(backend.quick_scan_paths()), scan_action=True)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("dangerButton")
        self.stop_button.setMinimumHeight(38)
        self.stop_button.clicked.connect(self.stop_scan)
        actions.addWidget(self.scan_button)
        actions.addWidget(self.quick_button)
        actions.addWidget(self.stop_button)
        actions.addStretch()
        actions.addWidget(self.button("Clear log", self.log_clear))
        layout.addLayout(actions)
        cards = QHBoxLayout()
        status_card, status_box = self.card()
        status_box.addWidget(self.label("STATUS", "eyebrow"))
        self.status = self.label("Checking ClamAV…", "statusValue")
        self.status.setWordWrap(True)
        status_box.addWidget(self.status)
        current_card, current_box = self.card()
        current_box.addWidget(self.label("CURRENT FILE", "eyebrow"))
        self.current_file = ElidedPathLabel("No scan running")
        self.current_file.setObjectName("currentFile")
        current_box.addWidget(self.current_file)
        cards.addWidget(status_card, 1)
        cards.addWidget(current_card, 2)
        layout.addLayout(cards)
        progress_card, progress_box = self.card()
        row = QHBoxLayout()
        row.addWidget(self.label("Scan progress", "sectionTitle"))
        row.addStretch()
        self.percent = self.label("0%", "accent")
        row.addWidget(self.percent)
        progress_box.addLayout(row)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        progress_box.addWidget(self.progress)
        self.summary = self.label("Choose a folder or run a quick scan.", "muted")
        self.summary.setWordWrap(True)
        progress_box.addWidget(self.summary)
        self.activity = QProgressBar()
        self.activity.setObjectName("activityBar")
        self.activity.setRange(0, 0)
        self.activity.setTextVisible(False)
        self.activity.setFixedHeight(3)
        self.activity.hide()
        progress_box.addWidget(self.activity)
        layout.addWidget(progress_card)
        self.scan_panels = QSplitter(Qt.Orientation.Vertical)
        self.findings_card, findings = self.card()
        findings.addWidget(self.label("Detected files", "sectionTitle"))
        self.results = self.table(["File", "Threat"])
        self.results.setMinimumHeight(130)
        self.findings_card.setMinimumHeight(230)
        findings.addWidget(self.results)
        row = QHBoxLayout()
        row.addWidget(self.button("Quarantine selected", lambda: self.handle_findings("quarantine"), variant="primary"))
        row.addWidget(self.button("Delete selected", lambda: self.handle_findings("delete"), variant="danger"))
        row.addWidget(self.button("Open location", self.open_finding_location))
        findings.addLayout(row)
        self.scan_panels.addWidget(self.findings_card)
        self.findings_card.hide()
        log_card, log_box = self.card()
        log_card.setMinimumHeight(200)
        row = QHBoxLayout()
        row.addWidget(self.label("Event log", "sectionTitle"))
        row.addStretch()
        self.report_button = QPushButton("View scan report")
        self.report_button.setObjectName("secondaryButton")
        self.report_button.setEnabled(False)
        self.report_button.clicked.connect(self.show_scan_report)
        row.addWidget(self.report_button)
        log_box.addLayout(row)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(10000)
        self.log.setPlaceholderText("Scan events and update messages will appear here.")
        log_box.addWidget(self.log)
        self.scan_panels.addWidget(log_card)
        self.scan_panels.setChildrenCollapsible(False)
        layout.addWidget(self.scan_panels, 1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        return scroll

    def log_clear(self):
        self.log.clear()

    def show_scan_report(self):
        if self.last_result is not None:
            ScanReportDialog(self, self.last_result).exec()

    def build_quarantine_page(self):
        page, layout = self.page("Quarantine", "Review isolated files and restore trusted items to their original locations.")
        card, box = self.card()
        self.quarantine_count = self.label("No quarantined files", "sectionTitle")
        box.addWidget(self.quarantine_count)
        self.quarantine_table = self.table(["Original file", "Threat", "Quarantined at", "Size"])
        box.addWidget(self.quarantine_table, 1)
        row = QHBoxLayout()
        row.addWidget(self.button("Restore selected", self.restore_selected, variant="primary"))
        row.addWidget(self.button("Delete selected", self.delete_quarantine_selected, variant="danger"))
        row.addStretch()
        row.addWidget(self.button("Refresh", self.refresh_state))
        box.addLayout(row)
        layout.addWidget(card, 1)
        layout.addWidget(self.label("Restoring never overwrites an existing file. Permanent deletion requires confirmation.", "muted"))
        return page

    def build_settings_page(self):
        page, layout = self.page("Settings", "Configure ClamAV, scan exclusions and the appearance of your workspace.")
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content.setObjectName("settingsContent")
        form = QVBoxLayout(content)
        form.setContentsMargins(0, 0, 8, 0)
        form.setSpacing(16)
        card, box = self.card()
        box.addWidget(self.label("ClamAV runtime & database", "sectionTitle"))
        self.runtime_info = QPlainTextEdit()
        self.runtime_info.setReadOnly(True)
        self.runtime_info.setMinimumHeight(145)
        self.runtime_info.setMaximumHeight(180)
        box.addWidget(self.runtime_info)
        box.addWidget(self.button('Enable antivirus protection / setup', self.open_antivirus_setup, variant='primary'))
        row = QHBoxLayout()
        self.runtime_button = self.button("Install / update ClamAV", self.update_runtime)
        self.database_button = self.button("Update virus database", self.update_database, variant="primary")
        row.addWidget(self.runtime_button)
        row.addWidget(self.database_button)
        row.addWidget(self.button("Check status", self.refresh_state))
        box.addLayout(row)
        self.parallel_scan = QCheckBox("Parallel scanning (use clamd when available)")
        self.parallel_scan.setChecked(self.config.get("parallel_scanning", True))
        box.addWidget(self.parallel_scan)
        box.addWidget(self.label('Parallel file checks', 'muted'))
        self.scan_workers = QComboBox()
        self.scan_workers.addItem('Automatic (CPU count, up to 16)', 'auto')
        for count in (4, 8, 16):
            self.scan_workers.addItem(str(count), count)
        index = self.scan_workers.findData(self.config.get('scan_workers', 'auto'))
        self.scan_workers.setCurrentIndex(max(0, index))
        self.scan_workers.setEnabled(self.parallel_scan.isChecked())
        self.parallel_scan.toggled.connect(self.scan_workers.setEnabled)
        self.scan_workers.setToolTip('Automatic uses up to two checks for larger files. '
                                    'Manual settings may use substantially more memory. '
                                    'Existing system clamd may enforce a lower limit.')
        box.addWidget(self.scan_workers)
        self.large_file_scan = QCheckBox('Check larger files (slower, uses more memory)')
        self.large_file_scan.setChecked(self.config.get('scan_profile') == 'extended')
        self.large_file_scan.setToolTip('Raises the file limit to 1 GiB and the total contents limit to 2 GiB. '
                                        'Automatic uses at most two parallel checks. Manual parallel settings use more memory. '
                                        'Existing system clamd settings are unchanged.')
        box.addWidget(self.large_file_scan)
        quarantine_note = self.label('LibreWard quarantine is always excluded from scans.', 'muted')
        quarantine_note.setWordWrap(True)
        box.addWidget(quarantine_note)
        form.addWidget(card)
        card, box = self.card()
        box.addWidget(self.label("Common excludes", "sectionTitle"))
        box.addWidget(self.label("Only selected exclusions are applied to scans.", "muted"))
        self.exclude_checks = {}
        enabled = self.config.get("enabled_common_excludes", [])
        for label in get_common_excludes():
            check = QCheckBox(label)
            check.setChecked(label in enabled)
            box.addWidget(check)
            self.exclude_checks[label] = check
        form.addWidget(card)
        card, box = self.card()
        box.addWidget(self.label("Custom excluded folders", "sectionTitle"))
        self.excluded_paths = QListWidget()
        self.excluded_paths.setMinimumHeight(100)
        self.excluded_paths.setMaximumHeight(150)
        self.excluded_paths.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        for path in self.config.get("user_excludes", []):
            if isinstance(path, str):
                self.excluded_paths.addItem(path)
        box.addWidget(self.excluded_paths)
        row = QHBoxLayout()
        row.addWidget(self.button("Add folder", self.add_exclude))
        row.addWidget(self.button("Remove selected", self.remove_excludes))
        row.addStretch()
        box.addLayout(row)
        form.addWidget(card)
        card, box = self.card()
        box.addWidget(self.label("Preferences", "sectionTitle"))
        self.suppress_setup = QCheckBox("Don't show ClamAV setup automatically")
        self.suppress_setup.setChecked(bool(self.config.get("suppress_clamav_setup_prompt", False)))
        box.addWidget(self.suppress_setup)
        box.addWidget(self.label("Uncheck to show the setup prompt again on the next launch.", "muted"))
        row = QHBoxLayout()
        row.addWidget(self.label("Color theme", "sectionTitle"))
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light", "system"])
        self.theme.setCurrentText(self.config.get("qt_theme", "dark"))
        self.theme.currentTextChanged.connect(self.apply_theme)
        row.addWidget(self.theme)
        row.addStretch()
        box.addLayout(row)
        form.addWidget(card)
        form.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)
        row = QHBoxLayout()
        self.settings_feedback = self.label("", "muted")
        row.addWidget(self.settings_feedback, 1)
        row.addWidget(self.button("Save settings", self.save_settings, variant="primary"))
        layout.addLayout(row)
        return page

    def build_planned_page(self, title, subtitle, message):
        page, layout = self.page(title, subtitle)
        card, box = self.card()
        box.addWidget(self.label("PLANNED FEATURE", "eyebrow"))
        box.addWidget(self.label(message, "sectionTitle"))
        box.addWidget(self.label("This module is not active in this release.", "muted"))
        layout.addWidget(card)
        layout.addStretch()
        return page

    def build_about_page(self):
        page, layout = self.page("About LibreWard", "An open-source workspace for security and privacy.")
        card, box = self.card()
        box.addWidget(self.label(f"{APP_NAME}  /  {APP_VERSION}", "sectionTitle"))
        text = self.label(
            "LibreWard is licensed under GPL-2.0-or-later.\n\n"
            "LibreWard executes external ClamAV tools (clamscan and freshclam) "
            "for antivirus scans and virus database updates. ClamAV is developed "
            "by the ClamAV project/Cisco Talos and licensed separately under "
            "the GNU General Public License version 2.\n\n"
            "PySide6 / Qt is used under the applicable open-source LGPLv3 license.\n\n"
            f"ClamAV homepage: {CLAMAV_HOMEPAGE}\nClamAV source: {CLAMAV_SOURCE}\n\n"
            "LibreWard and ClamAV are provided with no warranty, to the extent permitted by law."
        )
        text.setWordWrap(True)
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.addWidget(text)
        layout.addWidget(card)
        layout.addStretch()
        return page

    def apply_theme(self, theme):
        dark = theme == "dark" or (theme == "system" and QApplication.instance().styleHints().colorScheme() == Qt.ColorScheme.Dark)
        self.setStyleSheet(stylesheet(dark))
        for key, button in self.nav_buttons.items():
            button.setIcon(navigation_icon(key, "#92b6a3" if dark else "#4e685a"))
        self.update()

    def set_status(self, text, severity="normal"):
        self.status.setText(text)
        self.status.setProperty("severity", severity)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    def system_theme_changed(self, scheme):
        if self.theme.currentText() == "system":
            self.apply_theme("system")

    def update_exclude_summary(self):
        common = sum(check.isChecked() for check in self.exclude_checks.values())
        custom = self.excluded_paths.count()
        self.exclude_summary.setText(f"Excludes: {common} common groups · {custom} custom folders")

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose scan folder", self.path.text(),
            options=QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog)
        if folder:
            self.path.setText(folder)

    def add_exclude(self):
        folder = QFileDialog.getExistingDirectory(self, "Exclude folder",
            options=QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog)
        paths = [self.excluded_paths.item(i).text() for i in range(self.excluded_paths.count())]
        if folder and folder not in paths:
            self.excluded_paths.addItem(folder)

    def remove_excludes(self):
        for item in self.excluded_paths.selectedItems():
            self.excluded_paths.takeItem(self.excluded_paths.row(item))

    def save_settings(self):
        updated = dict(self.config)
        updated.update(
            scan_path=self.path.text().strip(),
            enabled_common_excludes=[label for label, check in self.exclude_checks.items() if check.isChecked()],
            user_excludes=[self.excluded_paths.item(i).text() for i in range(self.excluded_paths.count())],
            suppress_clamav_setup_prompt=self.suppress_setup.isChecked(),
            qt_theme=self.theme.currentText(),
            parallel_scanning=self.parallel_scan.isChecked(),
            scan_workers=self.scan_workers.currentData(),
            scan_profile='extended' if self.large_file_scan.isChecked() else 'standard',
        )
        try:
            save_config(updated)
        except OSError as exc:
            QMessageBox.warning(self, "Settings", f"Cannot save settings: {exc}")
            return False
        self.config = updated
        self.update_exclude_summary()
        self.settings_feedback.setText("Settings saved")
        return True

    def set_busy(self, operation):
        self.operation = operation
        if operation == 'scan':
            self.summary.setText('Preparing scan — checking the antivirus engine and database…')
        self.update_scan_indicator()
        for button in self.idle_buttons:
            button.setEnabled(operation is None)
        for button in self.scan_actions:
            button.setEnabled(operation is None and self.startup_status is not None and self.startup_status.can_scan)
        self.update_firewall_controls()
        self.stop_button.setEnabled(operation == "scan")
        self.activity.setVisible(operation is not None)
        if operation:
            self.percent.setText("Working…")
        else:
            self.percent.setText(f"{max(0, self.progress.value())}%")
        self.database_button.setEnabled(operation is None and self.startup_status is not None and self.startup_status.can_update_db)
        if operation:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, 100)

    def start_task(self, operation, target, *, on_done=None, title=None):
        if self.operation is not None or (self.worker and self.worker.is_alive()):
            return False
        self.on_done = on_done
        self.completion = None
        self.set_busy(operation)
        if title:
            self.update_dialog = UpdateProgressDialog(self, title)
            self.update_dialog.show()

        def run_worker():
            try:
                payload = target()
                self.events.put(("__TASK_DONE__", True, payload))
            except Exception as exc:
                self.events.put(("__TASK_DONE__", False, exc if isinstance(exc, AuthorizationError) else str(exc)))

        self.worker = threading.Thread(target=run_worker, daemon=False)
        self.worker.start()
        return True

    def check_runtime(self, *, quiet=False):
        status = check_startup(log=None if quiet else self.events.put)
        state = {"status": status, "database": database_summary(), "quarantine": list_quarantined_files()}
        self.events.put(("__STATE__", state))
        return status

    def refresh_state(self):
        self.start_task("check", self.check_runtime)

    def offer_setup(self, status):
        if (not status.can_scan or not status.freshclam_ok) and not self.config.get("suppress_clamav_setup_prompt", False):
            self.open_antivirus_setup(status)

    def open_antivirus_setup(self, status=None):
        if self.operation is not None:
            return
        # clicked(bool) may supply False instead of a StartupStatus.
        status = status if hasattr(status, 'runtime_ok') else self.startup_status
        if status is None:
            self.start_task('check', self.check_runtime, on_done=self.open_antivirus_setup)
            return
        instructions = '' if backend.manages_own_runtime() else backend.runtime_install_instructions()
        dialog = AntivirusSetupDialog(self, status, instructions=instructions,
                                      install_plan=backend.clamav_install_plan(),
                                      suppressed=self.config.get('suppress_clamav_setup_prompt', False))
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        self.suppress_setup.setChecked(dialog.suppress.isChecked())
        if not self.save_settings() or not accepted:
            return
        if dialog.action == 'runtime':
            self.update_runtime()
        elif dialog.action == 'package-install':
            self.install_clamav_packages()
        elif dialog.action == 'database':
            self.update_database()
        elif dialog.action == 'check':
            self.start_task('check', self.check_runtime, on_done=self.open_antivirus_setup)

    def offer_database_update(self):
        if self.startup_status and self.startup_status.can_update_db:
            self.update_database()
        else:
            QMessageBox.warning(self, "Virus database missing", "Scanning is blocked until the virus database is available. Install a working ClamAV runtime first.")

    def start_scan(self, roots):
        if self.operation is not None:
            return
        if not roots or any(not root or not os.path.isdir(root) for root in roots):
            QMessageBox.information(self, "Scan folder", "Choose an existing folder to scan.")
            return
        if not self.save_settings():
            return
        self.results.setRowCount(0)
        self.findings_card.hide()
        self.progress.setValue(0)
        self.percent.setText("0%")
        self.last_result = None
        self.report_button.setEnabled(False)
        self.pending_setup = False
        self.service = ScanService(self.events, scan_profile=self.config.get('scan_profile', 'standard'),
                                   workers=self.config.get('scan_workers', 'auto'))
        patterns = get_active_exclude_patterns(set(self.config.get("enabled_common_excludes", [])), self.config.get("user_excludes", []))

        def run_scan():
            status = self.check_runtime()
            if not status.can_scan:
                self.events.put(("__NEEDS_SETUP__",))
                return
            self.service.run(roots, patterns, status.runtime.clamscan,
                             parallel=self.config.get("parallel_scanning", True))

        def after_scan(_):
            if self.pending_setup:
                self.offer_setup(self.startup_status)
            elif self.last_result is not None:
                self.show_scan_report()

        self.start_task("scan", run_scan, on_done=after_scan)

    def stop_scan(self):
        if self.service and self.operation == "scan":
            try:
                self.service.stop()
                self.set_status("Stopping scan…")
                self.summary.setText('Stopping scan — waiting for active file checks to finish…')
            except OSError as exc:
                self.log.appendPlainText(f"Cannot stop scan: {exc}")

    def update_database(self, *, confirm=True):
        if self.operation is not None:
            return
        if confirm and not self.confirm("Update virus database", "Download the latest ClamAV virus database? On Linux this may request system authorization."):
            return

        def run_update():
            status = check_startup()
            if not status.can_update_db:
                raise RuntimeError("freshclam is unavailable. Install ClamAV before updating the database.")
            result = run_freshclam_update(status.runtime.freshclam, log_callback=self.events.put)
            success, _ = result
            pending = getattr(result, 'pending', False)
            if not success and not pending:
                raise RuntimeError("Database update failed. See the log.")
            return {'status': self.check_runtime(), 'pending': pending}

        self.start_task("database", run_update, title="Update virus database", on_done=self.database_update_finished)

    def database_update_finished(self, result):
        if result['pending'] and not result['status'].db_found:
            self.database_watch_checks = 0
            self.database_watch_timer.start()
            self.set_status('System updater is working — waiting for the virus database')
        else:
            self.database_watch_timer.stop()

    def poll_system_database(self):
        if self.operation is not None or QApplication.activeModalWidget() is not None:
            return
        self.start_task('database-check', lambda: self.check_runtime(quiet=True),
                        on_done=self.system_database_checked)

    def system_database_checked(self, status):
        self.database_watch_checks += 1
        if status.db_found:
            self.database_watch_timer.stop()
            self.set_status('Virus database is available. The system updater continues managing updates.')
        elif self.database_watch_checks >= 60:
            self.database_watch_timer.stop()
            self.set_status('Virus database is still unavailable. Check the system FreshClam service log.', 'warning')

    def update_runtime(self):
        if self.operation is not None:
            return
        if not backend.manages_own_runtime():
            self.install_clamav_packages()
            return
        setup = self.startup_status is None or not self.startup_status.runtime_ok
        if setup:
            consent = ClamAVConsentDialog(self)
            accepted = consent.exec() == QDialog.DialogCode.Accepted
            self.suppress_setup.setChecked(consent.suppress.isChecked())
            if not self.save_settings() or not accepted:
                return
        status = self.startup_status
        repair = bool(status and (not status.freshclam_ok or not (status.clamd_path or status.clamd_running)))
        self.start_task(
            "runtime-check", lambda: check_for_updates(log=self.events.put, repair=repair),
            on_done=self.confirm_runtime_update, title="Check ClamAV runtime",
        )

    def install_clamav_packages(self):
        if self.operation is not None:
            return
        plan = backend.clamav_install_plan()
        if plan is None:
            QMessageBox.information(self, 'Install ClamAV', backend.runtime_install_instructions())
            return
        self.privileged_terminal_commands = plan.command
        if not self.confirm('Install ClamAV packages', plan.explanation + '\n\n' + plan.command + '\n\nInstall these packages?'):
            return
        if not self.ensure_system_authorization():
            return

        def install():
            backend.install_clamav(log=self.events.put)
            status = self.check_runtime()
            if not status.runtime_ok or not status.freshclam_ok:
                raise RuntimeError('The package manager finished, but ClamAV or freshclam is still unavailable. Review the installation log and check components again.')
            return status

        self.start_task('package-install', install, title='Install ClamAV', on_done=self.after_clamav_package_install)

    def after_clamav_package_install(self, status):
        if not status.db_found:
            self.offer_database_update()
        else:
            self.open_antivirus_setup(status)

    def confirm_runtime_update(self, entry):
        if entry is None:
            QMessageBox.information(self, "ClamAV", "No compatible runtime update is available. See the log for details.")
            return
        if not self.confirm("Install ClamAV", f"Download and install ClamAV {entry.get('latest_version', '?')} from its official upstream release?"):
            return

        def run_install():
            error = perform_update(
                entry, log=self.events.put,
                progress=lambda phase, done, total: self.events.put(("__DOWNLOAD_PROGRESS__", done, total)),
            )
            if error:
                raise error
            return self.check_runtime()

        def after_install(status):
            if not status.runtime_ok:
                QMessageBox.warning(self, "ClamAV", "The installed runtime could not be started. See the log.")
                return
            # Setup acceptance covers downloading the runtime and its databases.
            self.update_database(confirm=False)

        self.start_task("runtime-install", run_install, on_done=after_install, title="Install ClamAV runtime")

    def confirm(self, title, message):
        return QMessageBox.question(
            self, title, message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes

    @staticmethod
    def selected_rows(table):
        return sorted({index.row() for index in table.selectionModel().selectedRows()})

    def handle_findings(self, action):
        if self.operation is not None:
            return
        rows = self.selected_rows(self.results)
        if not rows:
            return
        files = [(self.results.item(row, 0).text(), self.results.item(row, 1).text()) for row in rows]
        message = f"Move {len(files)} selected file(s) into quarantine?" if action == "quarantine" else f"Permanently delete {len(files)} selected file(s)? This cannot be undone."
        if not self.confirm("Confirm file action", message):
            return

        def apply():
            results = []
            for path, threat in files:
                try:
                    msg = quarantine_file(path, threat) if action == "quarantine" else delete_file(path)
                except OSError as exc:
                    msg = str(exc)
                success = msg.startswith("Quarantined:") if action == "quarantine" else msg.startswith("Deleted:")
                self.events.put(msg)
                results.append((path, success))
            self.events.put(("__QUARANTINE__", list_quarantined_files()))
            return results

        def finished(results):
            successful = {path for path, success in results if success}
            for row in reversed(range(self.results.rowCount())):
                if self.results.item(row, 0).text() in successful:
                    self.results.removeRow(row)
            self.findings_card.setVisible(self.results.rowCount() > 0)
            self.report_batch(results)

        self.start_task("file-action", apply, on_done=finished)

    def open_finding_location(self):
        rows = self.selected_rows(self.results)
        if rows:
            path = self.results.item(rows[0], 0).text()
            def open_location():
                message = open_file_location(path)
                if message:
                    raise RuntimeError(message)
            self.start_task("open-location", open_location)

    def selected_quarantine_items(self):
        return [self.quarantine_table.item(row, 0).data(Qt.ItemDataRole.UserRole) for row in self.selected_rows(self.quarantine_table)]

    def restore_selected(self):
        if self.operation is not None:
            return
        items = self.selected_quarantine_items()
        if not items or not self.confirm("Restore files", f"Restore {len(items)} selected file(s) to their original locations? Restore only files you trust. Existing files will not be overwritten."):
            return
        self.quarantine_action(items, restore_file, "Restored:")

    def delete_quarantine_selected(self):
        if self.operation is not None:
            return
        items = self.selected_quarantine_items()
        if not items or not self.confirm("Delete quarantined files", f"Permanently delete {len(items)} selected quarantined file(s)? This cannot be undone."):
            return
        self.quarantine_action(items, delete_quarantined_file, "Permanently deleted:")

    def quarantine_action(self, items, action, success_prefix):
        def apply():
            results = []
            for item in items:
                try:
                    msg = action(item["quarantine_name"])
                except OSError as exc:
                    msg = str(exc)
                self.events.put(msg)
                results.append((item["quarantine_name"], msg.startswith(success_prefix)))
            self.events.put(("__QUARANTINE__", list_quarantined_files()))
            return results
        self.start_task("quarantine-action", apply, on_done=self.report_batch)

    def report_batch(self, results):
        failures = sum(not success for _, success in results)
        self.set_status(f"Completed {len(results) - failures} of {len(results)} file action(s).")
        if failures:
            QMessageBox.warning(self, "File actions", f"{failures} action(s) failed. See the log; failed files remain available for retry.")

    def show_quarantine(self, items):
        self.quarantine_table.setRowCount(0)
        self.quarantine_count.setText(f"{len(items)} quarantined file(s)" if items else "No quarantined files")
        self.nav_buttons["quarantine"].setText(f"Quarantine  ({len(items)})" if items else "Quarantine")
        for item in items:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            for col, value in enumerate((item.get("original_path", ""), item.get("threat_name", ""), item.get("quarantined_at", ""), item.get("original_size", 0))):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.ItemDataRole.UserRole, item)
                self.quarantine_table.setItem(row, col, cell)

    def poll_events(self):
        for _ in range(200):
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            if isinstance(event, str):
                self.log.appendPlainText(event.rstrip())
                if self.update_dialog:
                    self.update_dialog.append(event)
                continue
            kind, *values = event
            if kind == "__STATE__":
                state = values[0]
                self.startup_status = state["status"]
                runtime = self.startup_status.runtime
                self.runtime_info.setPlainText(
                    '\n'.join(f'{name}: {value}' for name, value in setup_components(self.startup_status)) + '\n\n' +
                    f"ClamAV: {runtime.version or 'unavailable'}\nSource: {runtime.source}\n"
                    f"clamscan: {runtime.clamscan or 'not found'}\nfreshclam: {runtime.freshclam or 'not found'}\n\n{state['database']}"
                )
                self.show_quarantine(state["quarantine"])
                self.sidebar_status.setText("●  Engine ready" if self.startup_status.can_scan else "●  Setup needed")
                self.sidebar_status.setProperty("ready", self.startup_status.can_scan)
                self.sidebar_status.style().unpolish(self.sidebar_status)
                self.sidebar_status.style().polish(self.sidebar_status)
                self.set_status("Ready" if self.startup_status.can_scan else "ClamAV runtime or database needs setup")
            elif kind == "__QUARANTINE__":
                self.show_quarantine(values[0])
            elif kind == "__NEEDS_SETUP__":
                self.pending_setup = True
                self.summary.setText('Set up ClamAV and a virus database before scanning.')
            elif kind == "__STATUS__":
                if not (self.operation == 'scan' and self.service and self.service.stop_requested):
                    self.set_status(values[0])
                    if self.operation == 'scan':
                        self.summary.setText(values[0].capitalize())
            elif kind == "__CURRENT_FILE__":
                self.current_file.setText(values[0])
            elif kind == '__DISCOVERY__':
                discovered, processed, done, elapsed = values
                if self.service and self.service.stop_requested:
                    continue
                self.summary.setText(f'Scanning · Processed: {processed:,} · Found so far: {discovered:,}'
                                     if not done else
                                     f'Scanning · Processed: {processed:,} / {discovered:,} files')
                if not done:
                    self.progress.setRange(0, 0)
                    self.percent.setText('Scanning…')
                    self.set_status('Scanning files as they are found. Percentage will appear when the total is known.')
                elif not self.service or not self.service.stop_requested:
                    self.progress.setRange(0, 100)
                    self.progress.setValue(min(99, int(100 * processed / discovered) if discovered else 0))
                    self.percent.setText(f'{self.progress.value()}%')
                    self.set_status('Scanning')
            elif kind == "__PROGRESS__":
                current, total, finished = values
                self.progress.setRange(0, 100)
                self.progress.setValue(100 if finished else min(99, int(100 * current / total) if total else 0))
                self.percent.setText(f"{self.progress.value()}%")
                if not (self.service and self.service.stop_requested):
                    self.summary.setText('File checks finished — preparing the scan report…' if finished else
                                         f'Scanning · Processed: {current:,} / estimated {total:,} files')
            elif kind == "__DOWNLOAD_PROGRESS__":
                if self.update_dialog:
                    self.update_dialog.set_progress(*values)
            elif kind == "__SCAN_DONE__":
                result = values[0]
                self.last_result = result
                self.report_button.setEnabled(True)
                self.findings_card.setVisible(bool(result["infected"]))
                severity = "danger" if result.get("infected") or result.get("infected_found") or result.get("errors") else "warning" if result.get("warnings") else "normal"
                self.set_status(scan_outcome(result), severity)
                self.current_file.setText("—")
                count_label = "Processed" if result.get("parallel") else "Scanned"
                self.summary.setText(f"{scan_outcome(result)}. {count_label}: {result['scanned']:,} / estimated {result['total']:,}. "
                                     "Counts may differ when files change or cannot be accessed.")
                if result.get("warnings") and result.get("admin_hint"):
                    self.summary.setText(self.summary.text() + " For a deeper scan of protected locations, you can run LibreWard as Administrator.")
                for path, threat in result["infected"]:
                    row = self.results.rowCount()
                    self.results.insertRow(row)
                    self.results.setItem(row, 0, QTableWidgetItem(path))
                    self.results.setItem(row, 1, QTableWidgetItem(threat))
            elif kind == "__TASK_DONE__":
                self.completion = values
        # The completion event can arrive just before the worker returns. Wait
        # for its actual exit before enabling a subsequent operation.
        if self.completion is not None and not self.worker.is_alive():
            completed_operation = self.operation
            success, payload = self.completion
            callback = self.on_done
            self.completion = None
            self.on_done = None
            dialog = self.update_dialog
            self.update_dialog = None
            self.set_busy(None)
            if dialog:
                # Keep the outcome visible. Follow-up steps (confirmation or
                # database update) start after the user dismisses this report.
                if success and callback:
                    dialog.finished.connect(lambda _result, cb=callback, value=payload: cb(value))
                if not success and isinstance(payload, AuthorizationError) and payload.kind != 'cancelled':
                    dialog.finished.connect(lambda _result, issue=str(payload): self.show_authorization_help(issue))
                dialog.finish(success, '' if success else str(payload))
                if (success and completed_operation == 'database'
                        and isinstance(payload, dict) and payload.get('pending')):
                    dialog.status.setText('System updater is running — latest update completion is not confirmed. Close this report to continue.')
                    dialog.progress.setRange(0, 0)
            if success:
                if callback and not dialog:
                    callback(payload)
            else:
                self.set_status("Operation failed", "danger")
                if completed_operation == 'firewall-change':
                    tool = self.selected_firewall_tool()
                    if tool:
                        tool.state = 'Unknown — refresh required after unverified change'
                        tool.rules = 'Previous snapshot — refresh to verify current rules.\n\n' + tool.rules
                        self.show_firewall_tool(self.firewall_tools.currentIndex())
                    self.firewall_change_result.setText('Change was not confirmed. Read current rules before retrying.\n' + str(payload))
                if completed_operation == 'scan':
                    self.summary.setText('Scan could not finish. See the event log for details.')
                if completed_operation not in ('firewall', 'firewall-change', 'firewall-networks'):
                    self.log.appendPlainText(str(payload))
                if not dialog:
                    if isinstance(payload, AuthorizationError) and payload.kind != 'cancelled':
                        self.show_authorization_help(str(payload))
                    else:
                        QMessageBox.warning(self, "LibreWard", str(payload))

        self.maybe_refresh_firewall()

    def closeEvent(self, event):
        if self.operation is not None or (self.worker and self.worker.is_alive()):
            if self.operation == "scan":
                self.stop_scan()
                self.set_status("Stopping scan. Close again when it finishes.")
            else:
                self.set_status("Wait for the current operation before closing.")
            event.ignore()
            return
        self.timer.stop()
        self.database_watch_timer.stop()
        updated = dict(self.config)
        updated['window_geometry'] = bytes(self.saveGeometry()).hex()
        try:
            save_config(updated)
            self.config = updated
        except OSError as exc:
            self.log.appendPlainText(f'Cannot save window size and position: {exc}')
        event.accept()


def run():
    app = QApplication([])
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)
    app.setStyle("Fusion")
    window = QtMainWindow()
    window.show()
    return app.exec()
