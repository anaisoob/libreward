"""Qt dialogs shared by setup and background update flows."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QLabel, QPlainTextEdit,
    QProgressBar, QPushButton, QVBoxLayout,
)


class ClamAVConsentDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Enable antivirus features")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        explanation = QLabel(
            "LibreWard uses ClamAV, a separate third-party open-source antivirus "
            "runtime developed by the ClamAV project/Cisco Talos.\n\n"
            "Antivirus features require downloading and running the official "
            "ClamAV tools and downloading ClamAV virus databases.\n\n"
            "LibreWard and ClamAV are provided with no warranty, to the extent "
            "permitted by law. You may refuse this setup."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.suppress = QCheckBox("Don't show the setup prompt again")
        layout.addWidget(self.suppress)
        buttons = QDialogButtonBox()
        buttons.addButton("Accept and continue", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton("Not now", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class AntivirusSetupDialog(QDialog):
    """Show installed components and one concrete next setup action."""
    def __init__(self, parent, status, *, instructions='', suppressed=False):
        from core.runtime import setup_components, setup_next_action
        super().__init__(parent)
        self.setWindowTitle('Enable antivirus protection')
        self.resize(620, 470)
        self.action, action_label = setup_next_action(status)
        layout = QVBoxLayout(self)
        title = QLabel('Antivirus setup')
        title.setObjectName('pageTitle')
        layout.addWidget(title)
        explanation = QLabel('LibreWard uses ClamAV to check files for threats. '
                             'Parallel scanning is optional; standard scanning works without it.')
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        for name, state in setup_components(status):
            label = QLabel(f'{name}: {state}')
            label.setWordWrap(True)
            layout.addWidget(label)
        if instructions and self.action == 'runtime':
            text = QPlainTextEdit()
            text.setReadOnly(True)
            text.setPlainText(instructions)
            layout.addWidget(text)
            if self.action == 'runtime':
                action_label = 'I have installed it — check again'
                self.action = 'check'
        self.suppress = QCheckBox("Don't show setup automatically")
        self.suppress.setChecked(suppressed)
        layout.addWidget(self.suppress)
        buttons = QDialogButtonBox()
        self.action_button = buttons.addButton(action_label, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton('Later', QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class UpdateProgressDialog(QDialog):
    """Application-modal progress display; callers update it on the GUI thread."""
    def __init__(self, parent, title):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.resize(640, 400)
        self.active = True
        layout = QVBoxLayout(self)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        layout.addWidget(self.log)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        layout.addWidget(self.progress)
        self.close_button = QPushButton("Close")
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.accept)
        layout.addWidget(self.close_button)

    def append(self, message):
        self.log.appendPlainText(message.rstrip())

    def set_progress(self, done, total):
        if total:
            self.progress.setRange(0, 100)
            self.progress.setValue(min(99, int(100 * done / total)))
        else:
            self.progress.setRange(0, 0)

    def finish(self, success):
        self.active = False
        self.progress.setRange(0, 100)
        if success:
            self.progress.setValue(100)
        self.close_button.setEnabled(True)

    def reject(self):
        if not self.active:
            super().reject()

    def closeEvent(self, event):
        if self.active:
            event.ignore()
        else:
            event.accept()


class ScanReportDialog(QDialog):
    """Complete scan report, including warnings and ClamAV summary output."""
    def __init__(self, parent, result):
        from core.scan_service import scan_outcome
        super().__init__(parent)
        self.setWindowTitle("Scan report")
        self.resize(680, 460)
        layout = QVBoxLayout(self)
        title = QLabel(scan_outcome(result))
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        count_label = 'Processed' if result.get('parallel') else 'Scanned'
        summary = QLabel(
            f"{count_label}: {result.get('scanned', 0)} / estimated {result.get('total', 0)}\n"
            f"Detected files: {len(result.get('infected', []))}\n"
            f"Warnings: {'yes' if result.get('warnings') else 'none'}\n"
            f"Errors: {'yes' if result.get('errors') else 'none'}"
        )
        layout.addWidget(summary)
        report = QPlainTextEdit()
        report.setReadOnly(True)
        lines = result.get('summary_lines', [])
        report.setPlainText(''.join(lines) if lines else 'No ClamAV summary is available for this scan.')
        layout.addWidget(report)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
