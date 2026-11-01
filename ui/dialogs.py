"""Qt dialogs shared by setup and background update flows."""
from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel,
    QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout, QWidget, QListWidget, QListWidgetItem,
)


class _Relay(QObject):
    """Delivers a worker thread's result on the GUI thread."""
    done = Signal(object)


class LogDialog(QDialog):
    """The technical messages. Reopened, not rebuilt: `log` keeps collecting while it is closed."""
    def __init__(self, parent, log):
        super().__init__(parent)
        self.setWindowTitle('Event log')
        self.setModal(True)
        self.resize(760, 480)
        layout = QVBoxLayout(self)
        layout.addWidget(log, 1)
        row = QHBoxLayout()
        clear = QPushButton('Clear log')
        clear.clicked.connect(log.clear)
        row.addWidget(clear)
        row.addStretch()
        close = QPushButton('Close')
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)


class ExcludesDialog(QDialog):
    """What scans skip: common groups and the user's own folders."""
    def __init__(self, parent, common, enabled, folders):
        super().__init__(parent)
        self.setWindowTitle('Excludes')
        self.resize(560, 520)
        layout = QVBoxLayout(self)
        heading = QLabel('Common excludes')
        heading.setObjectName('sectionTitle')
        layout.addWidget(heading)
        note = QLabel('Only selected exclusions are applied to scans.')
        note.setObjectName('muted')
        layout.addWidget(note)
        self.checks = {}
        for label in common:
            check = QCheckBox(label)
            check.setChecked(label in enabled)
            layout.addWidget(check)
            self.checks[label] = check
        heading = QLabel('Custom excluded folders')
        heading.setObjectName('sectionTitle')
        layout.addWidget(heading)
        self.paths = QListWidget()
        self.paths.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.paths.addItems(folders)
        layout.addWidget(self.paths, 1)
        row = QHBoxLayout()
        add = QPushButton('Add folder')
        add.clicked.connect(self.add_folder)
        row.addWidget(add)
        remove = QPushButton('Remove selected')
        remove.clicked.connect(self.remove_selected)
        row.addWidget(remove)
        row.addStretch()
        layout.addLayout(row)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def folders(self):
        return [self.paths.item(index).text() for index in range(self.paths.count())]

    def enabled_common(self):
        return [label for label, check in self.checks.items() if check.isChecked()]

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, 'Exclude folder', options=QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog)
        if folder and folder not in self.folders():
            self.paths.addItem(folder)

    def remove_selected(self):
        for item in self.paths.selectedItems():
            self.paths.takeItem(self.paths.row(item))


class ProtectedFoldersDialog(QDialog):
    """Folders checked by Live protection; Downloads folders are found automatically."""
    def __init__(self, parent, folders, *, discover, follow=True):
        super().__init__(parent)
        self.discover = discover
        self.setWindowTitle('Protected folders')
        self.resize(620, 420)
        layout = QVBoxLayout(self)
        note = QLabel('LibreWard checks new files in these folders and their subfolders. '
                      'Downloads folders of the system and of web browsers are usually enough.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.listing = QListWidget()
        self.listing.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        for folder in folders:
            self.add(folder)
        layout.addWidget(self.listing, 1)
        row = QHBoxLayout()
        self.find_button = QPushButton('Add Downloads folders')
        self.find_button.clicked.connect(self.find)
        row.addWidget(self.find_button)
        add = QPushButton('Add folder…')
        add.clicked.connect(self.choose)
        row.addWidget(add)
        remove = QPushButton('Remove')
        remove.clicked.connect(self.remove)
        row.addWidget(remove)
        row.addStretch()
        layout.addLayout(row)
        self.follow_browsers = QCheckBox('Also protect everything my web browsers download, '
                                         'wherever I save it')
        self.follow_browsers.setChecked(follow)
        layout.addWidget(self.follow_browsers)
        privacy = QLabel('LibreWard follows the download folders set in your browsers and reads their lists of '
                         'finished downloads. It does not read which websites you visit, and nothing leaves '
                         'this computer.')
        privacy.setObjectName('muted')
        privacy.setWordWrap(True)
        layout.addWidget(privacy)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setObjectName('primaryButton')
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.relay = _Relay(self)
        self.relay.done.connect(self.found)

    def add(self, folder):
        import os
        key = os.path.normcase(os.path.realpath(folder))
        if any(os.path.normcase(os.path.realpath(path)) == key for path in self.folders()):
            return
        self.listing.addItem(folder)

    def folders(self):
        return [self.listing.item(i).text() for i in range(self.listing.count())]

    def follow(self):
        return self.follow_browsers.isChecked()

    def choose(self):
        from PySide6.QtWidgets import QFileDialog
        folder = QFileDialog.getExistingDirectory(self, 'Choose a folder to protect')
        if folder:
            self.add(folder)

    def remove(self):
        for item in self.listing.selectedItems():
            self.listing.takeItem(self.listing.row(item))

    def find(self):
        import threading
        self.find_button.setEnabled(False)

        def run():
            try:
                folders = self.discover()
            except OSError:
                folders = []
            self.relay.done.emit(folders)

        threading.Thread(target=run, name='download-folders', daemon=True).start()

    def found(self, folders):
        for folder in folders:
            self.add(folder)
        self.find_button.setEnabled(True)


def danger_icon(size=48, on_red=False):
    """A circle with an exclamation mark, the same in every theme; white on a red background."""
    from PySide6.QtGui import QColor, QPainter, QPen, QPixmap
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    circle, mark = ('#ffffff', '#c62f2f') if on_red else ('#d93636', '#ffffff')
    painter.setPen(QPen(QColor('#ffffff'), max(2, size / 16)))
    painter.setBrush(QColor(circle))
    painter.drawEllipse(2, 2, size - 4, size - 4)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(mark))
    bar = size * .12
    painter.drawRoundedRect(int((size - bar) / 2), int(size * .22), int(bar), int(size * .36), bar / 2, bar / 2)
    painter.drawEllipse(int((size - bar * 1.25) / 2), int(size * .66), int(bar * 1.25), int(bar * 1.25))
    painter.end()
    return pixmap


class ThreatsFoundDialog(QDialog):
    """One clear decision for files found by Live protection; looks unlike other dialogs."""
    QUARANTINE = 2
    DELETE = 3
    KEEP = 4

    def __init__(self, parent, threats, *, keep=True):
        """keep=False: an administrator decided that dangerous files are never kept."""
        super().__init__(parent)
        self.threats = []
        self.setObjectName('dangerDialog')
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 16)
        layout.setSpacing(12)
        # A red band with the warning sign: clearly not an ordinary dialog.
        header = QWidget()
        header.setObjectName('dangerHeader')
        header.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        band = QHBoxLayout(header)
        band.setContentsMargins(20, 18, 20, 18)
        band.setSpacing(16)
        icon = QLabel()
        icon.setPixmap(danger_icon(52, on_red=True))
        band.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        heading = QVBoxLayout()
        heading.setSpacing(4)
        self.title = QLabel()
        self.title.setObjectName('dangerTitle')
        self.title.setWordWrap(True)
        heading.addWidget(self.title)
        text = QLabel('It contains a virus or other harmful software. Do not open it.')
        text.setObjectName('dangerSubtitle')
        text.setWordWrap(True)
        heading.addWidget(text)
        band.addLayout(heading, 1)
        layout.addWidget(header)
        body = QVBoxLayout()
        body.setContentsMargins(20, 4, 20, 0)
        body.setSpacing(10)
        self.files = QVBoxLayout()
        self.files.setSpacing(8)
        body.addLayout(self.files)
        note = QLabel('Quarantine moves it to a safe place where it cannot do harm. '
                      + ('If it was a mistake, you can restore it later from Quarantine.' if keep else
                         'Your administrator decided that dangerous files are not kept.'))
        note.setObjectName('muted')
        note.setWordWrap(True)
        body.addWidget(note)
        buttons = QDialogButtonBox()
        self.keep_button = None
        if keep:
            self.keep_button = buttons.addButton('Keep file', QDialogButtonBox.ButtonRole.RejectRole)
            self.keep_button.clicked.connect(lambda: self.done(self.KEEP))
        delete = buttons.addButton('Delete', QDialogButtonBox.ButtonRole.DestructiveRole)
        delete.setObjectName('dangerButton')
        delete.clicked.connect(lambda: self.done(self.DELETE))
        quarantine = buttons.addButton('Move to quarantine', QDialogButtonBox.ButtonRole.AcceptRole)
        quarantine.setObjectName('primaryButton')
        quarantine.setDefault(True)
        quarantine.clicked.connect(lambda: self.done(self.QUARANTINE))
        body.addSpacing(4)
        body.addWidget(buttons)
        layout.addLayout(body)
        self.add_threats(threats)

    def add_threats(self, threats):
        """Add files found while the question is open; one decision covers them all."""
        import os
        from html import escape
        known = {path for path, _threat in self.threats}
        self.threats += [(path, threat) for path, threat in threats if path not in known]
        count = len(self.threats)
        self.setWindowTitle('Dangerous file found' if count == 1 else 'Dangerous files found')
        self.title.setText('LibreWard found a dangerous file' if count == 1 else
                           f'LibreWard found {count} dangerous files')
        while self.files.count():
            self.files.takeAt(0).widget().deleteLater()
        for path, threat in self.threats[:8]:
            folder = os.path.dirname(path)
            folder = folder if len(folder) <= 70 else '…' + folder[-69:]
            # No word wrap: wrapped rich text makes Qt size the dialog too small.
            row = QLabel(f'<b>{escape(os.path.basename(path))}</b> &nbsp;·&nbsp; {escape(threat.removesuffix(" FOUND"))}<br>'
                         f'<span style="font-size: 11px;">{escape(folder)}</span>')
            row.setObjectName('dangerFile')
            row.setTextFormat(Qt.TextFormat.RichText)
            row.setToolTip(path)
            # Its full size is the minimum, so the window grows for it (also when a file
            # is added while it is shown) instead of cutting the folder off.
            row.setMinimumSize(row.sizeHint())
            self.files.addWidget(row)
        if count > 8:
            self.files.addWidget(QLabel(f'…and {count - 8} more, listed on the Virus scan page.'))
        # Grow for the new rows once the layout has measured them (the wrapped note
        # below makes the height depend on the width).
        layout = self.layout()
        layout.activate()
        width = max(self.width(), self.sizeHint().width())
        height = layout.totalHeightForWidth(width) if layout.hasHeightForWidth() else self.sizeHint().height()
        self.resize(width, max(height, self.minimumSizeHint().height()))


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
    """Title, one status line and progress; the technical log stays under Show details."""
    def __init__(self, parent, title):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setMinimumWidth(460)
        self.active = True
        layout = QVBoxLayout(self)
        heading = QLabel(title)
        heading.setObjectName('sectionTitle')
        layout.addWidget(heading)
        self.status = QLabel('Please wait. This can take a few minutes.')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        self.details_button = QPushButton('Show details')
        self.details_button.setFlat(True)
        self.details_button.clicked.connect(self.toggle_details)
        layout.addWidget(self.details_button, 0, Qt.AlignmentFlag.AlignLeft)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setMinimumHeight(220)
        self.log.hide()
        layout.addWidget(self.log, 1)
        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.hide()
        layout.addWidget(self.cancel_button)
        self.close_button = QPushButton("Close")
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.accept)
        layout.addWidget(self.close_button)

    def toggle_details(self):
        self.log.setVisible(not self.log.isVisible())
        self.details_button.setText('Hide details' if self.log.isVisible() else 'Show details')
        self.adjustSize()

    def enable_cancel(self, callback):
        """Offer cancelling while the operation can still stop safely."""
        self.cancel_button.clicked.connect(callback)
        self.cancel_button.show()

    def append(self, message):
        self.log.appendPlainText(message.rstrip())
        # Tools such as freshclam report percentages; use them when present.
        import re
        match = re.search(r'(\d{1,3})(?:\.\d+)?%', message)
        if self.active and match and int(match.group(1)) <= 100:
            self.set_progress(int(match.group(1)), 100)

    def set_progress(self, done, total):
        if total:
            self.progress.setRange(0, 100)
            self.progress.setValue(min(99, int(100 * done / total)))
        else:
            self.progress.setRange(0, 0)

    def finish(self, success, message=''):
        self.active = False
        self.cancel_button.hide()
        # One plain line; the full output stays under Show details.
        summary = (message or '').strip().splitlines()[0] if (message or '').strip() else ''
        self.status.setText('Done.' if success else
                            'This did not finish. ' + (summary or 'Show details for more information.'))
        if message:
            self.log.appendPlainText(message.rstrip())
        self.progress.setRange(0, 100)
        self.progress.setValue(100 if success else 0)
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
    """Outcome first in plain words; file lists and engine output under Show details."""
    QUARANTINE_ALL = 2

    def __init__(self, parent, result):
        from html import escape
        from core.scan_report import friendly_report, report_summary
        from core.scan_warnings import warning_report
        super().__init__(parent)
        self.setWindowTitle("Scan report")
        self.setMinimumWidth(520)
        summary = report_summary(result)
        layout = QVBoxLayout(self)
        title = QLabel(summary['title'])
        title.setObjectName('statusValue')
        title.setProperty('severity', summary['severity'])
        title.setStyleSheet('font-size: 24px;')
        layout.addWidget(title)
        subtitle = QLabel(summary['subtitle'])
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        self.threat_labels = []
        for name, folder, threat in summary['threats'][:8]:
            row = QLabel(f'<b>{escape(name)}</b> &nbsp;·&nbsp; {escape(threat)}<br>'
                         f'<span style="font-size: 11px;">{escape(folder)}</span>')
            row.setTextFormat(Qt.TextFormat.RichText)
            row.setWordWrap(True)
            layout.addWidget(row)
            self.threat_labels.append(row)
        if len(summary['threats']) > 8:
            layout.addWidget(QLabel(f"…and {len(summary['threats']) - 8} more, listed on the scan page."))
        if summary['note']:
            note = QLabel(summary['note'])
            note.setObjectName('muted')
            note.setWordWrap(True)
            layout.addWidget(note)
        self.details_button = QPushButton('Show details')
        self.details_button.setFlat(True)
        self.details_button.clicked.connect(self.toggle_details)
        layout.addWidget(self.details_button, 0, Qt.AlignmentFlag.AlignLeft)
        lines = result.get('summary_lines', [])
        engine_report = ''.join(lines) if lines else 'No ClamAV summary is available for this scan.'
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlainText(friendly_report(result) + '\n\n' + warning_report(result) + '\n' + engine_report)
        self.details.setMinimumHeight(240)
        self.details.hide()
        layout.addWidget(self.details, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        if summary['threats']:
            quarantine = buttons.addButton('Move all to quarantine', QDialogButtonBox.ButtonRole.ActionRole)
            quarantine.setObjectName('primaryButton')
            quarantine.clicked.connect(lambda: self.done(self.QUARANTINE_ALL))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def toggle_details(self):
        self.details.setVisible(not self.details.isVisible())
        self.details_button.setText('Hide details' if self.details.isVisible() else 'Show details')
        self.adjustSize()


class SystemCheckDialog(QDialog):
    """Findings of the system check in plain words; suspicious, so nothing to quarantine."""
    DEEPER = 2

    def __init__(self, parent, result, *, deeper=False):
        from html import escape
        from core.system_check import DEEP_NOTE, NOTE, summary
        super().__init__(parent)
        self.setWindowTitle('System check')
        self.setMinimumWidth(560)
        title_text, severity = summary(result)
        layout = QVBoxLayout(self)
        title = QLabel(title_text)
        title.setObjectName('statusValue')
        title.setProperty('severity', severity)
        title.setStyleSheet('font-size: 24px;')
        layout.addWidget(title)
        if result['findings']:
            intro = QLabel('These are signs that a program may be hiding on this computer. They are not proof: '
                           'some programs do these things on purpose. If you do not recognise one, ask someone '
                           'you trust to check the computer. LibreWard does not change anything.')
        else:
            intro = QLabel('No signs of hidden programs were found.')
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.finding_labels = []
        for entry in result['findings']:
            label = QLabel(f"<b>{escape(entry['title'])}</b><br>{escape(entry['detail'])}")
            label.setTextFormat(Qt.TextFormat.RichText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(label)
            self.finding_labels.append(label)
        checked = QLabel('Checked: ' + '; '.join(result['checks']) + '.')
        checked.setObjectName('muted')
        checked.setWordWrap(True)
        layout.addWidget(checked)
        note = QLabel(DEEP_NOTE if result.get('deep') else NOTE)
        note.setObjectName('muted')
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.deeper_button = None
        if deeper and not result.get('deep'):
            # Takes a few minutes: every system program is compared with its package.
            self.deeper_button = buttons.addButton('Check deeper…', QDialogButtonBox.ButtonRole.ActionRole)
            self.deeper_button.setToolTip('Asks for the administrator password and takes a few minutes')
            self.deeper_button.clicked.connect(lambda: self.done(self.DEEPER))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
