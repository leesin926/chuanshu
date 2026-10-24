"""Main window: frameless chrome, tray, close behaviour and theming."""

from __future__ import annotations

import logging

from PySide6.QtCore import QEvent, QPoint, QRect, Qt, qVersion
from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QLabel,
    QMainWindow,
    QMessageBox,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
)

from app import autostart, icons
from app.config import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings
from app.i18n import N, _
from app.meta import COPYRIGHT, VERSION, display_name
from app.ui import theme, transfer
from app.ui.language_manager import LanguageManager
from app.ui.settings_dialog import SettingsPage
from app.ui.title_bar import EdgeResizeFilter, TitleBar, apply_rounded_corners
from app.ui.transfer import TransferPanel
from app.ui.tray import TrayIcon, available as tray_available

log = logging.getLogger(__name__)

#: Rail order, the caption each button carries, and the glyph in front of it. The mockups put
#: an icon on every rail item, so a language with long captions still reads at a glance.
#: N() because Babel only reads literals out of a call, and these reach _() as the tuple's
#: second element.
#: key, caption, glyph, and the stack page it opens. The page is named rather than counted:
#: 传输记录 sits between 文件 and 设置 in the stack but is not a rail entry, so a rail button's
#: position and its page are two different numbers.
NAV_ITEMS = (
    ("transfer", N("传输"), "nav-transfer", transfer.PAGE_TRANSFER),
    ("send", N("发送"), "nav-send", transfer.PAGE_SEND),
    ("receive", N("接收"), "nav-receive", transfer.PAGE_RECEIVE),
    ("files", N("文件"), "nav-files", transfer.PAGE_FILES),
    ("settings", N("设置"), "settings", transfer.PAGE_SETTINGS),
)
#: Which entry of NAV_ITEMS is the settings page, and so which stack index it occupies.
PAGE_SETTINGS = transfer.PAGE_SETTINGS
#: Which rail entry each page lights up, by key rather than by count - 传输记录 is reached from
#: the dashboard's own card and leaves 传输 lit, and 设置 is a page the rail opens last.
RAIL_FOR_PAGE = {
    transfer.PAGE_TRANSFER: "transfer",
    transfer.PAGE_SEND: "send",
    transfer.PAGE_RECEIVE: "receive",
    transfer.PAGE_FILES: "files",
    transfer.PAGE_HISTORY: "transfer",
    transfer.PAGE_SETTINGS: "settings",
}


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

        # No status strip. Every mockup ends the window at the last card, and a bar of permanent
        # diagnostics is the one piece of chrome all six pages would have to make room for; the
        # log path it used to carry now sits on 设置 › 关于, where it is a fact you go and read.
        self.status = self.statusBar()
        self.status.hide()

        self._resize_filter = EdgeResizeFilter(self)
        self.installEventFilter(self._resize_filter)
        central.installEventFilter(self._resize_filter)

        self._build_popups()
        self._build_tray()
        self.panel.arrived.connect(self._notify_arrival)
        # The chip is the rail's one piece of machine-owned text, and a rename reaches it only
        # through retranslate(); without this the rail keeps showing the name the machine used to
        # have while every page has already moved on.
        self.panel.device_name_changed.connect(lambda _name: self.retranslate())

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
        """The rail and the page it selects.

        设置 became a page rather than a window because everything on it already took effect the
        moment it was typed; a second frame would promise a cancel button that cannot exist.

        The rail goes flush to the window's left, top and bottom, because in the mockups the dark
        column *is* the edge of the app - a margin around it reads as a widget floating on paper.
        That also pushes the caption bar into the content column, so it only ever sits over the
        light part.
        """
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        self.panel = TransferPanel(self.settings, self)
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self.title_bar)
        content = QHBoxLayout()
        content.setContentsMargins(24, 18, 24, 16)
        content.addWidget(self.panel, 1)
        right.addLayout(content, 1)
        body.addWidget(self._build_nav())
        body.addLayout(right, 1)
        return body

    def _build_nav(self) -> QWidget:
        nav = QWidget(self)
        nav.setObjectName("Nav")
        self.nav = nav
        layout = QVBoxLayout(nav)
        # The mockups pad the rail by about a fifth of its width. A tighter margin makes the
        # pills touch the navy edge, which is the one thing that turns a rail into a list.
        layout.setContentsMargins(18, 20, 18, 16)
        layout.setSpacing(12)

        brand = QHBoxLayout()
        brand.setSpacing(9)
        self.brand_icon = QLabel(nav)
        self.brand_icon.setObjectName("BrandIcon")
        self.brand_icon.setFixedSize(30, 30)
        self.brand_icon.setAlignment(Qt.AlignCenter)
        brand.addWidget(self.brand_icon)
        self.brand_label = QLabel(nav)
        self.brand_label.setObjectName("Brand")
        brand.addWidget(self.brand_label)
        brand.addStretch(1)
        layout.addLayout(brand)
        layout.addSpacing(26)

        group = QButtonGroup(self)
        group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        for key, msgid, _glyph, page in NAV_ITEMS:
            button = QPushButton(nav)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            # Text arrives with the first retranslate(); the accessible name is set now so the
            # very first picture of the window already answers "what is this button".
            button.setAccessibleName(_(msgid))
            button.clicked.connect(lambda _checked=False, target=page: self.show_page(target))
            button.toggled.connect(lambda _on=False, b=button: self._restyle_nav_icon(b))
            group.addButton(button)
            layout.addWidget(button)
            self.nav_buttons[key] = button
        self.nav_buttons["transfer"].setChecked(True)
        layout.addStretch(1)

        # The mockups close the rail with a face rather than a footer: it is the account the
        # pairing code belongs to, and clicking it is the shortest route to changing that name.
        self.nav_user = QPushButton(nav)
        self.nav_user.setObjectName("NavUser")
        self.nav_user.setIcon(icons.icon("user", self.palette.nav_text))
        self.nav_user.clicked.connect(lambda: self.show_page(PAGE_SETTINGS))
        layout.addWidget(self.nav_user)
        return nav

    def _restyle_nav_icon(self, button: QPushButton) -> None:
        """A QIcon cannot follow a stylesheet, so the checked state repaints the glyph itself."""
        p = self.palette
        name = next((k for k, b in self.nav_buttons.items() if b is button), "")
        glyph = dict((k, g) for k, _m, g, _p in NAV_ITEMS).get(name, "")
        if glyph:
            button.setIcon(icons.icon(glyph, p.nav_sel_text if button.isChecked() else p.nav_text))

    def _fit_nav(self) -> None:
        """Give the rail the width its widest caption needs; no language may lose a tail."""
        need = max(button.sizeHint().width() for button in self.nav_buttons.values())
        # The rail's captions come out of a catalog and get their width above; the account chip's
        # text comes out of the machine, so it is bounded instead: a long hostname widens the rail
        # up to a ceiling, and past that the chip spells out that it is abbreviating. Left to Qt a
        # QPushButton just clips with no mark - the first real Linux desktop read "DESKTOP-58TSA7"
        # for a machine named "DESKTOP-58TSA70". The tooltip and accessible name, written by
        # retranslate(), always carry the whole name.
        name = self.panel.device_name
        # Measured from the whole name, never from what a previous pass left in the button: an
        # elided tail would read as a smaller demand and shrink the rail again on the next call.
        self.nav_user.setText(name)
        fm = self.nav_user.fontMetrics()
        # Everything the chip needs around the words - padding, the face icon, their spacing - is
        # what its own size hint asks for beyond the advance width of those words.
        chrome = max(0, self.nav_user.sizeHint().width() - fm.horizontalAdvance(name))
        pad = 36  # the rail's own left and right margins
        # The two pixels are Qt's: elidedText() abbreviates when the advance width equals the room
        # it was given, so a rail fitted to the letter would still show the ellipsis.
        room = fm.horizontalAdvance(name) + 2
        width = max(180, need + 34, min(248, room + chrome + pad))
        self.nav.setFixedWidth(width)
        self.nav_user.setText(fm.elidedText(name, Qt.ElideRight, max(24, width - pad - chrome)))

    def show_page(self, page: int) -> None:
        """One place that knows a rail position is a stack index."""
        if page == PAGE_SETTINGS and self.settings_page is None:
            self.open_settings()
            return
        self.panel.show_page(page)
        self._sync_nav(page)

    def _sync_nav(self, page: int) -> None:
        lit = RAIL_FOR_PAGE.get(page, "transfer")
        for key, button in self.nav_buttons.items():
            button.setChecked(key == lit)

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
        self.tray = TrayIcon(self, color, self.brand())
        self.tray.restore_requested.connect(self.show_from_tray)
        self.tray.quit_requested.connect(self.quit_app)
        self.tray.autostart_toggled.connect(self.on_autostart_toggled)
        self.tray.retranslate(self.brand())
        # The registration is the truth about autostart, not the last saved preference.
        self.tray.action_autostart.setChecked(autostart.is_enabled())
        if tray_available():
            self.tray.show()
        else:
            log.warning("system tray unavailable, run-in-background is disabled")
            # Greyed rather than fatal: the menu item is the only place a user would look for
            # this, and hide_to_tray() refuses on the same condition so the shortcut cannot
            # strand the window behind a tray that does not exist.
            self.action_tray.setEnabled(False)

    def brand(self) -> str:
        """The product name in the language currently on screen."""
        return display_name(self.languages.current)

    def _notify_arrival(self, who: str, count: int, size: str) -> None:
        """The 通知 switch, honoured: a transfer that lands says so outside the window."""
        if bool(self.settings.get("notify", True)) and self.tray.isVisible():
            self.tray.notify_arrival(self.brand(), who, count, size)

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
        # The rail's glyphs are QIcons, and a stylesheet cannot reach inside one, so the theme
        # switch has to hand each button a freshly rasterised glyph in the colour it now wears.
        self.brand_icon.setPixmap(icons.pixmap("logo", "#ffffff", 18))
        for button in self.nav_buttons.values():
            self._restyle_nav_icon(button)
        self.nav_user.setIcon(icons.icon("user", p.nav_text))
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
        if not tray_available():
            # The transport keeps running either way, so refusing to hide costs nothing the
            # user is relying on - and hiding would cost them the only way back.
            log.info("no tray on this desktop, staying visible instead of hiding")
            return
        self.hide()
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
        if choice == CLOSE_TRAY and not tray_available():
            # Remembered on a desktop that had a tray, and the tray is gone (GNOME lost its
            # AppIndicator extension, the session is headless): asking beats hiding forever.
            log.info("close choice is tray but no tray is available, asking instead")
            self._ask_close()
            return
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
        box.setWindowTitle(_("关闭{app}").format(app=self.brand()))
        has_tray = tray_available()
        box.setText(
            _("窗口关闭后，希望退出程序还是留在托盘后台运行？")
            if has_tray
            else _("这个桌面没有可用的托盘图标，关闭窗口就是退出程序。")
        )
        box.setStandardButtons(QMessageBox.NoButton)
        # Carry the decision on the button: PySide6 may hand out a different wrapper
        # for the same native button, so `clickedButton() is to_tray` is not reliable.
        if has_tray:
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
        self.action_quit.setText(_("退出{app}").format(app=brand))
        self.action_about.setText(_("关于{app}").format(app=brand))
        labels = self.theme_labels()
        for action in self.theme_group.actions():
            action.setText(labels[action.data()])
        self.panel.retranslate()
        self.brand_label.setText(brand)
        user_tip = _("本机：{name}").format(name=self.panel.device_name)
        self.nav_user.setToolTip(user_tip)
        self.nav_user.setAccessibleName(user_tip)
        # The chip's own text is written by _fit_nav() at the end of this method, because that is
        # the only place it can be measured against the font the theme pass has just polished.
        for key, msgid, _glyph, _page in NAV_ITEMS:
            caption = _(msgid)
            button = self.nav_buttons[key]
            button.setText(caption)
            button.setAccessibleName(caption)
            button.setToolTip(caption)
        if self.settings_page is not None:
            self.settings_page.retranslate()
        for action in self.language_group.actions():
            action.setChecked(action.data() == self.languages.current)
        self.tray.retranslate(self.brand())
        if self.isVisible():
            self.apply_theme(self.settings.get("theme", "auto"), save=False)
        # After the last caption is written *and* after the theme pass, which is what re-polishes
        # every widget: a page asked for its minimum before that still answers with the previous
        # language's number, and pinning the stack to it leaves the new captions with less room
        # than their own words need.
        self._fit_nav()
        self.panel.fit_pages()

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            _("关于{app}").format(app=self.brand()),
            f"{self.brand()} {VERSION}\n{COPYRIGHT}\n{_('Qt')} {qVersion()}",
        )

    def showEvent(self, event) -> None:
        super().showEvent(event)
        apply_rounded_corners(int(self.winId()))
        # The rail is fitted again here because the first mapping is when every widget gets
        # polished for real: the constructor's pass measured the chip against a font the platform
        # had not resolved yet, and on the Linux desktop that number was small enough to hide a
        # character.
        self._fit_nav()

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
