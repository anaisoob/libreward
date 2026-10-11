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
from .dialogs import ClamAVConsentDialog, UpdateProgressDialog, ScanReportDialog, AntivirusSetupDialog
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
            ("firewall", "Firewall", lambda: self.build_planned_page("Firewall", "Manage network access", "Firewall controls are planned for a future release.")),
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
        folder = QFileDialog.getExistingDirectory(self, "Choose scan folder", self.path.text())
        if folder:
            self.path.setText(folder)

    def add_exclude(self):
        folder = QFileDialog.getExistingDirectory(self, "Exclude folder")
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
        self.update_scan_indicator()
        for button in self.idle_buttons:
            button.setEnabled(operation is None)
        for button in self.scan_actions:
            button.setEnabled(operation is None and self.startup_status is not None and self.startup_status.can_scan)
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
                self.events.put(("__TASK_DONE__", False, str(exc)))

        self.worker = threading.Thread(target=run_worker, daemon=False)
        self.worker.start()
        return True

    def check_runtime(self):
        status = check_startup(log=self.events.put)
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
                                      suppressed=self.config.get('suppress_clamav_setup_prompt', False))
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        self.suppress_setup.setChecked(dialog.suppress.isChecked())
        if not self.save_settings() or not accepted:
            return
        if dialog.action == 'runtime':
            self.update_runtime()
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
        self.service = ScanService(self.events)
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
            success, _ = run_freshclam_update(status.runtime.freshclam, log_callback=self.events.put)
            if not success:
                raise RuntimeError("Database update failed. See the log.")
            return self.check_runtime()

        self.start_task("database", run_update, title="Update virus database")

    def update_runtime(self):
        if self.operation is not None:
            return
        if not backend.manages_own_runtime():
            QMessageBox.information(self, "ClamAV installation and updates", backend.runtime_install_instructions())
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
            elif kind == "__STATUS__":
                self.set_status(values[0])
            elif kind == "__CURRENT_FILE__":
                self.current_file.setText(values[0])
            elif kind == "__PROGRESS__":
                current, total, finished = values
                self.progress.setRange(0, 100)
                self.progress.setValue(100 if finished else min(99, int(100 * current / total) if total else 0))
                self.percent.setText(f"{self.progress.value()}%")
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
                self.summary.setText(f"{count_label}: {result['scanned']} / estimated {result['total']}. "
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
            success, payload = self.completion
            callback = self.on_done
            self.completion = None
            self.on_done = None
            dialog = self.update_dialog
            self.update_dialog = None
            self.set_busy(None)
            if dialog:
                dialog.finish(success)
                if success:
                    dialog.accept()
                else:
                    dialog.append(payload)
            if success:
                if callback:
                    callback(payload)
            else:
                self.set_status("Operation failed", "danger")
                self.log.appendPlainText(payload)
                if not dialog:
                    QMessageBox.warning(self, "LibreWard", payload)

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
