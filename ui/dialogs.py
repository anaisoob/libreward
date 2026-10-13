"""Qt dialogs shared by setup and background update flows."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QLabel, QPlainTextEdit,
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
    def __init__(self, parent, status, *, instructions='', install_plan=None, suppressed=False):
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
            if install_plan is not None:
                action_label = 'Install ClamAV with system package manager'
                self.action = 'package-install'
            else:
                action_label = 'I have installed it — check again'
                self.action = 'check'
        self.suppress = QCheckBox("Don't show setup automatically")
        self.suppress.setChecked(suppressed)
        layout.addWidget(self.suppress)
        buttons = QDialogButtonBox()
        self.action_button = buttons.addButton(action_label, QDialogButtonBox.ButtonRole.AcceptRole)
        if self.action == 'package-install':
            copy = buttons.addButton('Copy install command', QDialogButtonBox.ButtonRole.ActionRole)
            copy.clicked.connect(lambda: QApplication.clipboard().setText(install_plan.command))
            check = buttons.addButton('Check again', QDialogButtonBox.ButtonRole.ActionRole)
            check.clicked.connect(self.recheck)
        buttons.addButton('Later', QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

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

    def finish(self, success, message=''):
        self.active = False
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
