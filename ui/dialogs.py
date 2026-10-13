"""Qt dialogs shared by setup and background update flows."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPlainTextEdit,
    QProgressBar, QPushButton, QVBoxLayout, QWidget,
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
    """One plain sentence and one next step; component details stay folded away."""
    def __init__(self, parent, status, *, instructions='', install_plan=None, suppressed=False):
        from core.runtime import setup_components, setup_next_action
        super().__init__(parent)
        self.setWindowTitle('Virus protection')
        self.setMinimumWidth(480)
        self.action, _ = setup_next_action(status)
        parallel_only = self.action == 'runtime' and status.runtime_ok and status.freshclam_ok
        manual = self.action == 'runtime' and instructions and install_plan is None
        if self.action == 'runtime' and install_plan is not None:
            self.action = 'package-install'
        elif manual:
            self.action = 'check'
        if parallel_only:
            heading, text, label = ('Faster scanning (optional)',
                                    'Virus protection is ready. Installing the ClamAV scan service makes '
                                    'scanning many files faster.', 'Install')
        elif self.action in ('runtime', 'package-install', 'check'):
            heading = 'Install virus protection'
            text = ('LibreWard scans files with ClamAV, a free antivirus program. '
                    + ('It is installed from your system’s software sources, then LibreWard downloads its '
                       'virus database. Your password may be requested.' if self.action != 'check' else
                       'Install it with your system’s software manager or the command below, then check again.'))
            label = 'Check again' if self.action == 'check' else 'Install'
        elif self.action == 'database':
            heading, text, label = ('Download the virus database',
                                    'ClamAV is installed. LibreWard needs its virus database before it can scan. '
                                    'The download can take a few minutes.', 'Download')
        else:
            heading, text, label = 'Virus protection is ready', 'Files can be scanned now.', 'OK'
        layout = QVBoxLayout(self)
        title = QLabel(heading)
        title.setObjectName('pageTitle')
        layout.addWidget(title)
        explanation = QLabel(text)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        # Details: component states, terminal command and a manual re-check.
        self.details = QWidget()
        details = QVBoxLayout(self.details)
        details.setContentsMargins(0, 0, 0, 0)
        for name, state in setup_components(status):
            label_widget = QLabel(f'{name}: {state}')
            label_widget.setWordWrap(True)
            details.addWidget(label_widget)
        if instructions and self.action in ('package-install', 'check'):
            commands = QPlainTextEdit()
            commands.setReadOnly(True)
            commands.setPlainText(install_plan.command if install_plan is not None else instructions)
            commands.setMaximumHeight(140 if install_plan is None else 60)
            details.addWidget(commands)
        row = QHBoxLayout()
        if install_plan is not None and self.action == 'package-install':
            copy = QPushButton('Copy install command')
            copy.clicked.connect(lambda: QApplication.clipboard().setText(install_plan.command))
            row.addWidget(copy)
        if self.action != 'check':
            check = QPushButton('Check again')
            check.clicked.connect(self.recheck)
            row.addWidget(check)
        row.addStretch()
        details.addLayout(row)
        self.suppress = QCheckBox("Don't show this automatically")
        self.suppress.setChecked(suppressed)
        details.addWidget(self.suppress)
        # Manual installation needs the command, so it starts unfolded.
        self.details.setVisible(bool(manual))
        self.details_button = QPushButton('Hide details' if manual else 'Show details')
        self.details_button.setFlat(True)
        self.details_button.clicked.connect(self.toggle_details)
        layout.addWidget(self.details_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.details)
        buttons = QDialogButtonBox()
        self.action_button = buttons.addButton(label, QDialogButtonBox.ButtonRole.AcceptRole)
        self.action_button.setDefault(True)
        self.action_button.setObjectName('primaryButton')  # the app's green main-action style
        if self.action != 'ready':
            buttons.addButton('Not now', QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def toggle_details(self):
        self.details.setVisible(not self.details.isVisible())
        self.details_button.setText('Hide details' if self.details.isVisible() else 'Show details')
        self.adjustSize()

    def recheck(self):
        self.action = 'check'
        self.accept()


class AuthorizationHelpDialog(QDialog):
    def __init__(self, parent, status, commands='', *, issue=None):
        super().__init__(parent)
        self.setWindowTitle('Administrator authorization')
        self.resize(650, 450)
        layout = QVBoxLayout(self)
        explanation = QLabel(issue or status.message)
        explanation.setTextFormat(Qt.TextFormat.PlainText)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        if status.install_command:
            install = QLabel('Install pkexec/polkit in a terminal:\n' + status.install_command)
            install.setTextFormat(Qt.TextFormat.PlainText)
            install.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(install)
            copy_install = QPushButton('Copy authorization install command')
            copy_install.clicked.connect(lambda: QApplication.clipboard().setText(status.install_command))
            layout.addWidget(copy_install)
        hint = QLabel(('Alternatively, run the commands below using sudo in a terminal. ' if commands else
                       'Set up system authorization, then retry the requested action. ')
                      +
                      'Your password stays with the system tools. Afterward, check component status or use Check protection status in the Firewall page to reload the relevant information.')
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.commands = QPlainTextEdit()
        self.commands.setReadOnly(True)
        self.commands.setPlainText(commands)
        self.commands.setVisible(bool(commands))
        layout.addWidget(self.commands, 1)
        copy = QPushButton('Copy sudo commands')
        copy.setEnabled(bool(commands))
        copy.setVisible(bool(commands))
        copy.clicked.connect(lambda: QApplication.clipboard().setText(commands))
        layout.addWidget(copy)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
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
        self.status = QLabel('Operation in progress…')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        layout.addWidget(self.log)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        layout.addWidget(self.progress)
        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.hide()
        layout.addWidget(self.cancel_button)
        self.close_button = QPushButton("Close")
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.accept)
        layout.addWidget(self.close_button)

    def enable_cancel(self, callback):
        """Offer cancelling while the operation can still stop safely."""
        self.cancel_button.clicked.connect(callback)
        self.cancel_button.show()

    def append(self, message):
        self.log.appendPlainText(message.rstrip())

    def set_progress(self, done, total):
        if total:
            self.progress.setRange(0, 100)
            self.progress.setValue(min(99, int(100 * done / total)))
        else:
            self.progress.setRange(0, 0)

    def finish(self, success, message=''):
        self.active = False
        self.cancel_button.hide()
        self.status.setText('Completed successfully. Review the details below.' if success else
                            'Operation failed. Review the error below.')
        if message:
            self.append(message)
        self.progress.setRange(0, 100)
        if success:
            self.progress.setValue(100)
        self.close_button.setEnabled(True)
        self.close_button.setFocus()

    def accept(self):
        if not self.active:
            super().accept()

    def reject(self):
        if not self.active:
            super().reject()

    def closeEvent(self, event):
        if self.active:
            event.ignore()
        else:
            super().closeEvent(event)


class ScanReportDialog(QDialog):
    """Complete scan report, including warnings and ClamAV summary output."""
    def __init__(self, parent, result):
        from core.scan_service import scan_outcome
        from core.scan_warnings import warning_report
        from core.scan_report import friendly_report
        super().__init__(parent)
        self.setWindowTitle("Scan report")
        self.resize(680, 460)
        layout = QVBoxLayout(self)
        title = QLabel(scan_outcome(result))
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        report = QPlainTextEdit()
        report.setReadOnly(True)
        lines = result.get('summary_lines', [])
        engine_report = ''.join(lines) if lines else 'No ClamAV summary is available for this scan.'
        report.setPlainText(friendly_report(result))
        layout.addWidget(report)
        details = QCheckBox('Show technical details')
        layout.addWidget(details)
        technical = QPlainTextEdit()
        technical.setReadOnly(True)
        technical.setPlainText(warning_report(result) + '\n' + engine_report)
        technical.hide()
        details.toggled.connect(technical.setVisible)
        layout.addWidget(technical)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
