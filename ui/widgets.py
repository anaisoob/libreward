"""Small reusable Qt widgets."""
from PySide6.QtCore import Qt, QTimer, QRectF, QPointF
from PySide6.QtGui import QPainter, QPainterPath, QPen, QColor
from PySide6.QtWidgets import QLabel, QSizePolicy, QPushButton


class BusyNavigationButton(QPushButton):
    """Navigation button with a trailing activity indicator."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.busy = False
        self.angle = 0
        self.animation = QTimer(self)
        self.animation.setInterval(80)
        self.animation.timeout.connect(self._animate)

    def set_busy(self, busy):
        self.busy = busy
        self.setToolTip('Scan in progress' if busy else '')
        if busy:
            self.animation.start()
        else:
            self.animation.stop()
        self.update()

    def _animate(self):
        self.angle = (self.angle + 30) % 360
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.busy:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(QPen(QColor('#47b985'), 2, Qt.PenStyle.SolidLine,
                                Qt.PenCapStyle.RoundCap))
            painter.drawArc(QRectF(self.width() - 30, (self.height() - 16) / 2,
                                   16, 16), -self.angle * 16, 250 * 16)
            painter.end()


class ProtectionNavigationButton(QPushButton):
    """Navigation button with a trailing badge: how many protections are on.

    All on: a green circle with a check mark. Otherwise "1/2" in an amber
    circle, or "0/2" in a red one when nothing is on.
    """
    COLORS = {'all': '#47b985', 'some': '#d9a441', 'none': '#e06c6c'}

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.on = self.total = 0

    def set_protection(self, on, total, tooltip=''):
        self.on, self.total = on, total
        self.setToolTip(tooltip)
        self.update()

    def level(self):
        return 'all' if self.total and self.on == self.total else 'some' if self.on else 'none'

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self.total:
            return
        color = QColor(self.COLORS[self.level()])
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        size = 26
        box = QRectF(self.width() - size - 12, (self.height() - size) / 2, size, size)
        painter.setPen(QPen(color, 1.6))
        painter.drawEllipse(box.adjusted(1, 1, -1, -1))
        if self.level() == 'all':
            check = QPainterPath(QPointF(box.left() + 7, box.center().y() + 0.5))
            check.lineTo(box.left() + 10.5, box.center().y() + 4)
            check.lineTo(box.right() - 6.5, box.center().y() - 3.5)
            painter.setPen(QPen(color, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(check)
        else:
            font = painter.font()
            font.setPointSizeF(max(7, font.pointSizeF() * 0.78))
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(box, Qt.AlignmentFlag.AlignCenter, f'{self.on}/{self.total}')
        painter.end()


class ElidedPathLabel(QLabel):
    """Keep a full path in the tooltip and shorten its middle to fit one line."""
    def __init__(self, text='', parent=None):
        super().__init__(parent)
        self.full_text = ''
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setWordWrap(False)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text):
        self.full_text = str(text)
        self.setToolTip(self.full_text)
        self._update_text()

    def _update_text(self):
        available = max(0, self.contentsRect().width() - 2 * self.margin())
        text = self.fontMetrics().elidedText(
            self.full_text.replace('\n', ' ').replace('\r', ' '),
            Qt.TextElideMode.ElideMiddle, available)
        super().setText(text)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_text()
