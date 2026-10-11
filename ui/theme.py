"""Shared Qt colors, widget styling and small code-drawn navigation icons."""
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


def stylesheet(dark):
    colors = dict(
        bg='#101713', sidebar='#151f19', surface='#1b2820', field='#142019',
        border='#2c3c32', text='#edf5ef', muted='#91a99a', accent='#4bd396',
        selected='#243f30', hover='#26382d', alternate='#19251e',
    ) if dark else dict(
        bg='#f3f7f4', sidebar='#e8f0ea', surface='#ffffff', field='#f7faf8',
        border='#d9e4dc', text='#182d20', muted='#657d6d', accent='#237c53',
        selected='#d6ebde', hover='#e3eee7', alternate='#f5f9f6',
    )
    c = colors
    return f'''
    QWidget {{ color: {c['text']}; font-family: "Segoe UI", "DejaVu Sans", sans-serif; font-size: 13px; }}
    QMainWindow, QWidget#appShell, QWidget#contentPage, QWidget#settingsContent {{ background: {c['bg']}; }}
    QDialog, QMessageBox {{ background: {c['surface']}; }}
    QFrame#sidebar {{ background: {c['sidebar']}; border-right: 1px solid {c['border']}; }}
    QFrame#card {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 12px; }}
    QLabel {{ background: transparent; border: none; }}
    QLabel#brand {{ font-size: 21px; font-weight: 700; }}
    QLabel#logo {{ background: #278359; color: white; border-radius: 11px; font-weight: 700; font-size: 14px; }}
    QLabel#pageTitle {{ font-size: 27px; font-weight: 700; }}
    QLabel#sectionTitle {{ font-size: 14px; font-weight: 600; }}
    QLabel#eyebrow {{ font-size: 10px; font-weight: 600; letter-spacing: 1px; color: {c['muted']}; }}
    QLabel#muted {{ color: {c['muted']}; font-size: 12px; }}
    QLabel#statusValue {{ font-size: 16px; font-weight: 600; }}
    QLabel#statusValue[severity="danger"] {{ color: {'#f0a5a5' if dark else '#a33232'}; }}
    QLabel#statusValue[severity="success"] {{ color: {c['accent']}; }}
    QLabel#statusValue[severity="warning"] {{ color: {'#dfbf79' if dark else '#856311'}; }}
    QLabel#sidebarStatus[ready="false"] {{ color: {'#dfbf79' if dark else '#856311'}; }}
    QLabel#currentFile {{ font-size: 12px; }}
    QLabel#accent {{ color: {c['accent']}; font-size: 14px; font-weight: 600; }}
    QLabel#sidebarStatus {{ background: {c['selected']}; color: {c['accent']}; padding: 11px; border-radius: 8px; font-size: 12px; }}
    QPushButton {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 8px; padding: 0 14px; font-weight: 600; min-height: 34px; }}
    QPushButton:hover {{ background: {c['hover']}; border-color: {c['muted']}; }}
    QPushButton:focus, QLineEdit:focus, QComboBox:focus {{ border: 1px solid {c['accent']}; }}
    QPushButton:disabled {{ background: {c['field']}; color: {c['muted']}; border-color: {c['border']}; }}
    QPushButton#primaryButton {{ background: #278359; color: white; border: 1px solid #278359; }}
    QPushButton#primaryButton:hover {{ background: #31966a; }}
    QPushButton#primaryButton:disabled {{ background: {c['field']}; color: {c['muted']}; border-color: {c['border']}; }}
    QPushButton#dangerButton {{ background: transparent; border: 1px solid #8c4b4b; color: {'#f0a5a5' if dark else '#a33232'}; }}
    QPushButton#dangerButton:hover {{ background: {'#462b2b' if dark else '#fbe9e9'}; }}
    QPushButton#dangerButton:disabled {{ color: {c['muted']}; border-color: {c['border']}; }}
    QPushButton#navButton {{ text-align: left; padding: 0 12px; background: transparent; border: 1px solid transparent; color: {c['muted']}; }}
    QPushButton#navButton:hover {{ background: {c['hover']}; color: {c['text']}; }}
    QPushButton#navButton:checked {{ background: {c['selected']}; color: {c['accent']}; border: 1px solid {c['border']}; }}
    QLineEdit, QComboBox {{ background: {c['field']}; border: 1px solid {c['border']}; border-radius: 7px; padding: 9px 11px; selection-background-color: #278359; }}
    QComboBox::drop-down {{ border: none; width: 24px; }}
    QComboBox QAbstractItemView {{ background: {c['surface']}; color: {c['text']}; selection-background-color: {c['selected']}; }}
    QPlainTextEdit, QListWidget, QTableWidget, QListView, QTreeView {{ background: {c['field']}; alternate-background-color: {c['alternate']}; border: 1px solid {c['border']}; border-radius: 7px; padding: 6px; selection-background-color: {c['selected']}; selection-color: {c['text']}; }}
    QPlainTextEdit {{ font-family: "Cascadia Mono", "DejaVu Sans Mono", monospace; font-size: 11px; }}
    QTableWidget::item {{ padding: 5px 9px; border-bottom: 1px solid {c['border']}; }}
    QHeaderView::section {{ background: {c['surface']}; color: {c['muted']}; padding: 10px; border: none; border-bottom: 1px solid {c['border']}; font-size: 11px; font-weight: 600; }}
    QTableCornerButton::section {{ background: {c['surface']}; border: none; }}
    QProgressBar {{ background: {c['border']}; border: none; border-radius: 4px; height: 8px; max-height: 8px; }}
    QProgressBar::chunk {{ background: {c['accent']}; border-radius: 4px; }}
    QProgressBar#activityBar {{ max-height: 3px; border-radius: 1px; }}
    QCheckBox {{ spacing: 9px; padding: 6px 0; background: transparent; }}
    QCheckBox::indicator {{ width: 17px; height: 17px; border: 1px solid {c['muted']}; border-radius: 4px; background: {c['field']}; }}
    QCheckBox::indicator:checked {{ background: #278359; border-color: {c['accent']}; }}
    QScrollArea {{ background: transparent; border: none; }}
    QScrollBar:vertical {{ background: transparent; width: 9px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 3px; min-height: 28px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
    QSplitter::handle {{ background: transparent; height: 10px; }}
    QToolTip {{ background: {c['surface']}; color: {c['text']}; border: 1px solid {c['border']}; padding: 6px; }}
    '''


def navigation_icon(name, color):
    pixmap = QPixmap(48, 48)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.scale(2, 2)
    painter.setPen(QPen(QColor(color), 1.7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    if name in ('scan', 'firewall'):
        path = QPainterPath(QPointF(12, 3))
        path.lineTo(20, 6)
        path.lineTo(19, 13)
        path.quadTo(18, 18, 12, 21)
        path.quadTo(6, 18, 5, 13)
        path.lineTo(4, 6)
        path.closeSubpath()
        painter.drawPath(path)
        if name == 'scan':
            painter.drawLine(8, 12, 11, 15)
            painter.drawLine(11, 15, 16, 9)
        else:
            painter.drawLine(8, 10, 16, 10)
            painter.drawLine(8, 14, 16, 14)
            painter.drawLine(12, 10, 12, 14)
    elif name == 'quarantine':
        painter.drawRoundedRect(4, 7, 16, 14, 2, 2)
        painter.drawRoundedRect(3, 3, 18, 4, 1, 1)
        painter.drawLine(9, 12, 15, 12)
    elif name == 'internet':
        painter.drawEllipse(3, 3, 18, 18)
        painter.drawEllipse(8, 3, 8, 18)
        painter.drawLine(3, 12, 21, 12)
    elif name == 'settings':
        for y, knob in ((6, 9), (12, 15), (18, 8)):
            painter.drawLine(3, y, knob - 3, y)
            painter.drawEllipse(knob - 2, y - 2, 4, 4)
            painter.drawLine(knob + 3, y, 21, y)
    else:
        painter.drawEllipse(3, 3, 18, 18)
        painter.drawLine(12, 10, 12, 17)
        painter.drawPoint(12, 7)
    painter.end()
    return QIcon(pixmap)
