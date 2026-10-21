"""Main window: frameless chrome, tray, close behaviour and theming."""

from __future__ import annotations

import logging

from PySide6.QtCore import QEvent, QPoint, QRect, Qt, qVersion
from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QMainWindow,
    QMessageBox,
    QSystemTrayIcon,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
)

from app import autostart, icons
from app.config import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings
from app.i18n import LanguageManager, N, _
from app.logging_setup import log_file
from app.meta import COPYRIGHT, VERSION, display_name
from app.ui import theme
from app.ui.settings_dialog import SettingsPage
from app.ui.title_bar import EdgeResizeFilter, TitleBar, apply_rounded_corners
from app.ui.transfer import TransferPanel
from app.ui.tray import TrayIcon

log = logging.getLogger(__name__)

#: Rail order, and the msgid each button carries. The four pages are the whole window; the
#: gear on the caption is only ever a shortcut to the last one. N() because Babel only reads
#: literals out of a call, and these reach _() as the tuple's second element.
NAV_ITEMS = (("transfer", N("传输")), ("devices", N("设备")), ("files", N("文件")), ("settings", N("设置")))
#: Which entry of NAV_ITEMS is the settings page, and so which stack index it occupies.
PAGE_SETTINGS = 3


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings, languages: LanguageManager) -> None:
        super().__init__()
        self.settings = settings
        self.languages = languages
        #: False while the window is only hidden to the tray; the real quit sets it.
        self._quitting = False
        self._restore_rect = None
        #: Built on the first click of the gear button or the rail, then kept as a page.
        self.settings_page: SettingsPage | None = None
        #: Property read by TitleBar/EdgeResizeFilter; kept in sync with Qt's state.
        self.is_maximized = False

        # Frameless: everything the OS caption used to provide is drawn by TitleBar.
        self.setWindowFlags(
            Qt.Window
            | Qt.FramelessWindowHint
            | Qt.WindowMinimizeButtonHint
            | Qt.WindowMaximizeButtonHint
            | Qt.WindowCloseButtonHint
        )

        self.title_bar = TitleBar(self)
        self.title_bar.minimize_requested.connect(self.showMinimized)
        self.title_bar.toggle_maximize_requested.connect(self.toggle_maximized)
        self.title_bar.close_requested.connect(self.request_close)
        self.title_bar.settings_requested.connect(self.open_settings)

        central = QWidget(self)
        central.setObjectName("Central")
        central.setMouseTracking(True)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.title_bar)
        layout.addLayout(self._build_body())
        self.setCentralWidget(central)

        self.status = self.statusBar()

        self._resize_filter = EdgeResizeFilter(self)
        self.installEventFilter(self._resize_filter)
        central.installEventFilter(self._resize_filter)

        self._build_popups()
        self._build_tray()

        self.languages.changed.connect(self.retranslate)
        # No fixed floor here on purpose. An explicit minimum overrides the layout's own,
        # so the window could be made narrower than the widest control in a language and
        # Qt then clipped that control instead of refusing the size. The layout decides.
        size = self.settings.get("window", {})
        self.resize(
            max(int(size.get("width", 1080)), self.minimumWidth()),
            max(int(size.get("height", 680)), self.minimumHeight()),
        )
        self.apply_theme(self.settings.get("theme", "auto"), save=False)
        self.retranslate()

    def _build_body(self) -> QHBoxLayout:
        """The rail and the page it selects, side by side inside the window's margins.

        设置 became a page rather than a window because everything on it already took effect the
        moment it was typed; a second frame would promise a cancel button that cannot exist.
        """
        body = QHBoxLayout()
        body.setContentsMargins(18, 14, 18, 12)
        body.setSpacing(12)
        self.panel = TransferPanel(self.settings, self)
        body.addWidget(self._build_nav())
        body.addWidget(self.panel, 1)
        return body

    def _build_nav(self) -> QWidget:
        nav = QWidget(self)
        nav.setObjectName("Nav")
        self.nav = nav
        layout = QVBoxLayout(nav)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        group = QButtonGroup(self)
        group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        for page, (key, msgid) in enumerate(NAV_ITEMS):
            button = QPushButton(nav)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            # Text arrives with the first retranslate(); the accessible name is set now so the
            # very first picture of the window already answers "what is this button".
            button.setAccessibleName(_(msgid))
            button.clicked.connect(lambda _checked=False, target=page: self.show_page(target))
            group.addButton(button)
            layout.addWidget(button)
            self.nav_buttons[key] = button
        self.nav_buttons["transfer"].setChecked(True)
        layout.addStretch(1)
        return nav

    def _fit_nav(self) -> None:
        """Give the rail the width its widest caption needs; no language may lose a tail."""
        need = max(button.sizeHint().width() for button in self.nav_buttons.values())
        self.nav.setFixedWidth(max(76, need + 4))

    def show_page(self, page: int) -> None:
        """One place that knows a rail position is a stack index."""
        if page == PAGE_SETTINGS and self.settings_page is None:
            self.open_settings()
            return
        self.panel.show_page(page)
        self._sync_nav(page)

    def _sync_nav(self, page: int) -> None:
        for index, (key, _msgid) in enumerate(NAV_ITEMS):
            self.nav_buttons[key].setChecked(index == page)

    def _build_popups(self) -> None:
        """Three icon buttons on the title bar, each popping its own menu."""
        bar = self.title_bar
        # Titles are assigned in retranslate() so a language switch can rewrite them.
        self.menu_app = QMenu(self)
        self.menu_language = QMenu(self)
        self.menu_theme = QMenu(self)

        self.action_tray = QAction(self)
        self.action_tray.setShortcut("Ctrl+H")
        self.action_tray.triggered.connect(self.hide_to_tray)
        self.menu_app.addAction(self.action_tray)

        self.action_about = QAction(self)
        self.action_about.triggered.connect(self.show_about)
        self.menu_app.addAction(self.action_about)

        self.menu_app.addSeparator()

        self.action_quit = QAction(self)
        self.action_quit.setShortcut("Ctrl+Q")
        self.action_quit.triggered.connect(self.quit_app)
        self.menu_app.addAction(self.action_quit)

        self.theme_group = QActionGroup(self)
        self.theme_group.setExclusive(True)
        for value in ("auto", "light", "dark"):
            action = QAction(self)
            action.setCheckable(True)
            action.setData(value)
            action.triggered.connect(lambda _c=False, v=value: self.apply_theme(v))
            self.theme_group.addAction(action)
            self.menu_theme.addAction(action)

        self.language_group = QActionGroup(self)
        self.language_group.setExclusive(True)
        for code in self.languages.available():
            action = QAction(self.languages.display_name(code), self)
            action.setCheckable(True)
            action.setData(code)
            action.triggered.connect(lambda _c=False, c=code: self.switch_language(c))
            self.language_group.addAction(action)
            self.menu_language.addAction(action)

        bar.popup_below(bar.app_button, self.menu_app)
        bar.popup_below(bar.lang_button, self.menu_language)
        bar.popup_below(bar.theme_button, self.menu_theme)

        # With no menu bar widget, shortcuts have to hang off the window itself.
        self.addAction(self.action_tray)
        self.addAction(self.action_quit)

    def _build_tray(self) -> None:
        color = theme.palette_for(self.settings.get("theme", "auto")).text
        self.tray = TrayIcon(self, color)
        self.tray.restore_requested.connect(self.show_from_tray)
        self.tray.quit_requested.connect(self.quit_app)
        self.tray.autostart_toggled.connect(self.on_autostart_toggled)
        self.tray.retranslate(self.brand())
        # The registry is the truth about autostart, not the last saved preference.
        self.tray.action_autostart.setChecked(autostart.is_enabled())
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()
        else:
            log.warning("system tray unavailable, run-in-background is disabled")

    def brand(self) -> str:
        """The product name in the language currently on screen."""
        return display_name(self.languages.current)

    # ---------------------------------------------------------------- theme

    @property
    def palette(self) -> theme.Palette:
        return theme.palette_for(self.settings.get("theme", "auto"))

    @staticmethod
    def theme_labels() -> dict:
        return {"auto": _("跟随系统"), "light": _("浅色"), "dark": _("深色")}

    def apply_theme(self, preference: str, save: bool = True) -> None:
        """Swap the global stylesheet and repaint the vector caption glyphs."""
        if save:
            self.settings.set("theme", preference)
            log.info("theme set to %s", preference)
        p = theme.palette_for(preference)
        app = QApplication.instance()
        if app is not None:
            theme.apply_theme(app, p)
            # The shared logo is recoloured with the palette, so every window that
            # inherits QApplication's icon (plus QMessageBox.about) follows the theme.
            app.setWindowIcon(icons.window_icon(p.text))
        self.title_bar.restyle(p.text, p.name == "dark")
        self.title_bar.set_maximized(self.is_maximized, p.text)
        tip = _("外观：{name}").format(name=self.theme_labels()[preference])
        self.title_bar.theme_button.setToolTip(tip)
        self.title_bar.theme_button.setAccessibleName(tip)
        self.tray.restyle(p.text)
        for action in self.theme_group.actions():
            action.setChecked(action.data() == preference)

    # ------------------------------------------------------------- captions

    def toggle_maximized(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self._restore_rect = self.geometry()
            self.showMaximized()

    def restore_for_drag(self, global_pos: QPoint) -> None:
        """Un-maximize while dragging, keeping the cursor inside the caption."""
        rect = self._restore_rect or self._default_normal_rect()
        self.showNormal()
        # Keep the same point under the cursor so the bar doesn't jump away from it.
        ratio = max(0.0, min(1.0, (global_pos.x() - self.x()) / max(1, self.width())))
        self.move(QRect(global_pos.x() - int(ratio * rect.width()), rect.y(), rect.width(), rect.height()))

    def _default_normal_rect(self) -> QRect:
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry()
        width = max(720, available.width() // 2)
        height = max(480, available.height() // 2)
        return QRect(available.center().x() - width // 2, available.center().y() - height // 2, width, height)

    def changeEvent(self, event) -> None:
        if event.type() == QEvent.WindowStateChange:
            self.is_maximized = self.isMaximized()
            self.title_bar.set_maximized(self.is_maximized, self.palette.text)
        super().changeEvent(event)

    # ------------------------------------------------------------ tray flow

    def show_from_tray(self) -> None:
        if self.isHidden():
            self.show()
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()

    def hide_to_tray(self) -> None:
        self.hide()
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.notify_background(self.brand())

    def open_settings(self) -> None:
        """The gear button and the rail's 设置, which land on the same page.

        Non-modal on purpose, as the window used to be: receiving keeps working while the user
        is on this page, and nothing here waits for an OK that would never arrive.
        """
        if self.settings_page is None:
            self.settings_page = SettingsPage(self, self.settings, self.languages, self.panel)
            index = self.panel.add_page(self.settings_page)
            if index != PAGE_SETTINGS:
                log.error("the settings page landed at index %s instead of %s", index, PAGE_SETTINGS)
            self.panel.fit_pages()
        self.settings_page.reload()
        self.panel.show_page(PAGE_SETTINGS)
        self._sync_nav(PAGE_SETTINGS)

    def on_autostart_toggled(self, checked: bool) -> None:
        applied = autostart.set_enabled(checked)
        self.settings.set("autostart", applied)
        self.tray.sync_autostart(applied, checked)

    # ------------------------------------------------------------- closing

    def request_close(self) -> None:
        """Close button / Alt+F4 entry point: ask, or honour the remembered choice."""
        choice = self.settings.get("on_close", CLOSE_ASK)
        if choice == CLOSE_TRAY:
            self.hide_to_tray()
            return
        if choice == CLOSE_QUIT:
            self.quit_app()
            return
        self._ask_close()

    def _ask_close(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle(_("关闭 {app}").format(app=self.brand()))
        box.setText(_("窗口关闭后，希望退出程序还是留在托盘后台运行？"))
        box.setStandardButtons(QMessageBox.NoButton)
        # Carry the decision on the button: PySide6 may hand out a different wrapper
        # for the same native button, so `clickedButton() is to_tray` is not reliable.
        to_tray = box.addButton(_("最小化到托盘"), QMessageBox.ActionRole)
        to_tray.setProperty("choice", CLOSE_TRAY)
        quit_ = box.addButton(_("退出程序"), QMessageBox.AcceptRole)
        quit_.setProperty("choice", CLOSE_QUIT)
        quit_.setDefault(True)
        cancel = box.addButton(_("取消"), QMessageBox.RejectRole)
        cancel.setProperty("choice", "")
        remember = QCheckBox(_("记住我的选择"))
        box.setCheckBox(remember)

        box.exec()
        clicked = box.clickedButton()
        chosen = str(clicked.property("choice")) if clicked is not None else ""
        if chosen not in (CLOSE_TRAY, CLOSE_QUIT):
            return
        if remember.isChecked():
            self.settings.set("on_close", chosen)
            log.info("close behaviour remembered: %s", chosen)
        if chosen == CLOSE_TRAY:
            self.hide_to_tray()
        else:
            self.quit_app()

    def quit_app(self) -> None:
        self._quitting = True
        # Releases the ports and answers any offer still waiting on the user as a decline.
        self.panel.shutdown()
        self.tray.hide()
        self.close()

    # ------------------------------------------------------------- i18n glue

    def switch_language(self, code: str) -> None:
        if code == self.languages.current:
            return
        log.info("user switched language to %s", code)
        self.settings.set("language", code)
        self.languages.set_language(code)

    def retranslate(self, *_args) -> None:
        """Re-apply every visible string; also runs right after a language switch."""
        brand = self.brand()
        self.setWindowTitle(brand)
        self.title_bar.title_label.setText(brand)
        bar = self.title_bar
        # Tooltips double as accessible names, and both are set here so a language
        # switch rewrites them; the constructor values only cover the startup locale.
        for button, tip in (
            (bar.app_button, _("应用菜单")),
            (bar.lang_button, _("语言")),
            (bar.settings_button, _("设置")),
            (bar.theme_button, _("外观：{name}").format(name=self.theme_labels()[self.settings.get("theme", "auto")])),
            (bar.min_button, _("最小化")),
            (bar.close_button, _("关闭")),
        ):
            button.setToolTip(tip)
            button.setAccessibleName(tip)
        self.action_tray.setText(_("隐藏到托盘"))
        self.action_quit.setText(_("退出 {app}").format(app=brand))
        self.action_about.setText(_("关于 {app}").format(app=brand))
        labels = self.theme_labels()
        for action in self.theme_group.actions():
            action.setText(labels[action.data()])
        self.panel.retranslate()
        for key, msgid in NAV_ITEMS:
            caption = _(msgid)
            button = self.nav_buttons[key]
            button.setText(caption)
            button.setAccessibleName(caption)
            button.setToolTip(caption)
        self._fit_nav()
        if self.settings_page is not None:
            self.settings_page.retranslate()
        # After the last caption is written: a page's height demand is a function of the words
        # in it, so this is the moment the number is finally true for this language.
        self.panel.fit_pages()
        self.status.showMessage(
            _("当前语言：{lang}    日志：{path}").format(
                lang=self.languages.display_name(self.languages.current), path=log_file()
            )
        )
        for action in self.language_group.actions():
            action.setChecked(action.data() == self.languages.current)
        self.tray.retranslate(self.brand())
        if self.isVisible():
            self.apply_theme(self.settings.get("theme", "auto"), save=False)

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            _("关于 {app}").format(app=self.brand()),
            f"{self.brand()} {VERSION}\n{COPYRIGHT}\n{_('Qt')} {qVersion()}",
        )

    def showEvent(self, event) -> None:
        super().showEvent(event)
        apply_rounded_corners(int(self.winId()))

    def closeEvent(self, event) -> None:
        if not self._quitting:
            # Alt+F4 and taskbar close land here; route them through the same question.
            event.ignore()
            self.request_close()
            return
        self.settings.set("window", {"width": self.width(), "height": self.height()})
        app = QApplication.instance()
        if app is not None:
            app.quit()
        super().closeEvent(event)
