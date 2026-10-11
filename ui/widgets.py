"""Small reusable Qt widgets."""
from PySide6.QtCore import Qt, QTimer, QRectF
from PySide6.QtGui import QPainter, QPen, QColor
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
