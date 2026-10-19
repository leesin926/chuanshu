"""Frameless window chrome: custom title bar, edge resizing, Win11 rounded corners.

Everything the OS title bar used to give us has to be rebuilt here:
- dragging: handed to the platform window via QWindow.startSystemMove(), so Windows
  still runs its native move loop (and Aero Snap keeps working);
- resizing: QWindow.startSystemResize() with edges derived from a border band;
- maximizing: Qt's native showMaximized()/isMaximized(). Verified against the taskbar:
  the maximized window stops at the work area, so no manual availableGeometry maths.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys

from PySide6.QtCore import QObject, QEvent, QPoint, QSize, Qt, Signal
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app import icons
from app.i18n import _

RESIZE_MARGIN = 6
CAPTION_SIZE = 30
#: Cursors for the eight resize directions, keyed by Qt edge combinations.
_EDGE_CURSORS = {
    Qt.LeftEdge: Qt.SizeHorCursor,
    Qt.RightEdge: Qt.SizeHorCursor,
    Qt.TopEdge: Qt.SizeVerCursor,
    Qt.BottomEdge: Qt.SizeVerCursor,
    Qt.LeftEdge | Qt.TopEdge: Qt.SizeFDiagCursor,
    Qt.RightEdge | Qt.BottomEdge: Qt.SizeFDiagCursor,
    Qt.RightEdge | Qt.TopEdge: Qt.SizeBDiagCursor,
    Qt.LeftEdge | Qt.BottomEdge: Qt.SizeBDiagCursor,
}

DWMWA_WINDOW_CORNER_PREFERENCE = 33
DWMWCP_ROUND = 2


def apply_rounded_corners(hwnd: int) -> None:
    """Ask DWM for rounded corners. No-op on Windows 10 and older, where the attribute
    does not exist; DWM keeps square frameless windows there."""
    if sys.platform != "win32" or sys.getwindowsversion().build < 22000:
        return
    preference = ctypes.c_int(DWMWCP_ROUND)
    try:
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            wintypes.HWND(int(hwnd)),
            ctypes.c_int(DWMWA_WINDOW_CORNER_PREFERENCE),
            ctypes.byref(preference),
            ctypes.c_uint(ctypes.sizeof(preference)),
        )
    except OSError:
        pass


class TitleBar(QWidget):
    minimize_requested = Signal()
    toggle_maximize_requested = Signal()
    close_requested = Signal()

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setFixedHeight(44)

        self.title_label = QLabel(self)
        self.title_label.setObjectName("TitleLabel")
        self.title_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)

        # No menu bar at all: the app menu hangs off the logo, language and theme are
        # their own icon buttons, and each one pops a QMenu under itself.
        # Which glyph each button shows, and how big, comes from assets/icons/icons.json.
        self.app_button = self._icon_button("AppButton", "app", _("应用菜单"))
        self.lang_button = self._icon_button("LangButton", "lang", _("语言"))
        self.theme_button = self._icon_button("ThemeButton", "theme", _("外观"))

        self.min_button = self._icon_button("MinButton", "min", _("最小化"))
        self.max_button = self._icon_button("MaxButton", "max", _("最大化"))
        self.close_button = self._icon_button("CloseButton", "close", _("关闭"))
        self.min_button.clicked.connect(self.minimize_requested)
        self.max_button.clicked.connect(self.toggle_maximize_requested)
        self.close_button.clicked.connect(self.close_requested)

        row = QWidget(self)
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(8, 0, 8, 0)
        row_layout.setSpacing(2)
        row_layout.addWidget(self.app_button)
        row_layout.addSpacing(6)
        row_layout.addWidget(self.title_label)
        row_layout.addStretch(1)
        row_layout.addWidget(self.lang_button)
        row_layout.addWidget(self.theme_button)
        row_layout.addSpacing(6)
        row_layout.addWidget(self.min_button)
        row_layout.addWidget(self.max_button)
        row_layout.addWidget(self.close_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(row, 1)

    def _icon_button(self, object_name: str, role: str, accessible: str) -> QToolButton:
        button = QToolButton(self)
        button.setObjectName(object_name)
        button.setFixedSize(CAPTION_SIZE, CAPTION_SIZE)
        side = icons.button_icon_size(role)
        button.setIconSize(QSize(side, side))
        button.setAutoRaise(True)
        button.setToolTip(accessible)
        button.setAccessibleName(accessible)
        #: read back by _apply_glyph() so a theme/state change can rebuild the icon
        button.setProperty("icon_role", role)
        return button

    def popup_below(self, button: QToolButton, menu) -> None:
        """Open `menu` with its top-left at the button's bottom-left corner."""
        def show() -> None:
            menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

        button.clicked.connect(show)

    def restyle(self, color: str, dark: bool) -> None:
        """Rebuild the glyph icons in the current palette color (called on theme switch)."""
        self.theme_button.setProperty("icon_variant", "dark" if dark else "default")
        for button in (self.app_button, self.lang_button, self.theme_button,
                       self.min_button, self.max_button, self.close_button):
            self._apply_glyph(button, color)

    def _apply_glyph(self, button: QToolButton, color: str) -> None:
        role = str(button.property("icon_role"))
        variant = str(button.property("icon_variant") or "")
        button.setIcon(icons.button_icon(role, color, variant or None))

    def set_maximized(self, maximized: bool, color: str) -> None:
        self.max_button.setProperty("icon_variant", "maximized" if maximized else "default")
        self.max_button.setToolTip(_("还原") if maximized else _("最大化"))
        self._apply_glyph(self.max_button, color)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            window = self.window()
            handle = window.windowHandle()
            if handle is not None:
                if window.is_maximized:
                    # Restore under the cursor first, then let the OS move it.
                    window.restore_for_drag(event.globalPosition().toPoint())
                    handle = window.windowHandle()
                if handle is not None and handle.startSystemMove():
                    event.accept()
                    return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self.toggle_maximize_requested.emit()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)


class EdgeResizeFilter(QObject):
    """Consume presses inside the window border band and start a native resize.

    Lives on the window rather than the title bar because the resize band wraps the
    whole frame, including the content area's edges.
    """

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.window = window
        window.setMouseTracking(True)
        self._edges = Qt.Edge(0)

    def edges_at(self, local_to_window: QPoint) -> Qt.Edge:
        if self.window.is_maximized:
            return Qt.Edge(0)
        rect = self.window.rect()
        edges = Qt.Edge(0)
        if local_to_window.x() <= RESIZE_MARGIN:
            edges |= Qt.LeftEdge
        if local_to_window.x() >= rect.width() - RESIZE_MARGIN:
            edges |= Qt.RightEdge
        if local_to_window.y() <= RESIZE_MARGIN:
            edges |= Qt.TopEdge
        if local_to_window.y() >= rect.height() - RESIZE_MARGIN:
            edges |= Qt.BottomEdge
        return edges

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        # Installed on the window and its central widget: the border band is usually
        # covered by children, which swallow the press before the window sees it.
        if not isinstance(watched, QWidget):
            return False
        if event.type() == QEvent.MouseButtonPress and event.button() == Qt.LeftButton:
            edges = self.edges_at(watched.mapTo(self.window, event.position().toPoint()))
            if edges:
                handle = self.window.windowHandle()
                if handle is not None and handle.startSystemResize(edges):
                    return True
        elif event.type() == QEvent.MouseMove:
            edges = self.edges_at(watched.mapTo(self.window, event.position().toPoint()))
            if edges != self._edges:
                self._edges = edges
                cursor = _EDGE_CURSORS.get(edges)
                if cursor is None:
                    self.window.unsetCursor()
                else:
                    self.window.setCursor(Qt.CursorShape(cursor))
        return False
