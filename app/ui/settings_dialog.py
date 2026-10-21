"""Settings window: a list of sections on the left, the chosen section on the right.

There is deliberately no OK button. Each control writes the value the rest of the app
already reads and takes effect on the spot - a dialog you could "cancel" after the
receiving port had already moved would be lying about one of the two states.

Anything shown here has to be something the app can actually do, so the protocol numbers
(port, chunk size, code lifetime) are read-only facts: they come from the frozen contract
both ends check each other against, and changing them here would only break pairing.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import PySide6

from PySide6.QtCore import QSize, Qt, QUrl, qVersion
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app import autostart
from app.config import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings
from app.i18n import LanguageManager, N, _
from app.meta import COPYRIGHT, VERSION
from app.paths import logs_dir, receive_root, user_data_dir
from app.ui.transfer import TransferPanel

if TYPE_CHECKING:
    from app.ui.main_window import MainWindow

log = logging.getLogger(__name__)

#: Left-hand menu, in the order the stack holds them. Each one is also a msgid.
SECTIONS = ("常规", "传输", "已配对设备", "关于")

#: Width an explanation keeps at the smallest window the user can drag this to.
#: Qt counts a single line of a word-wrapped label when it works out a layout's minimum, so
#: a page full of sentences asked to be 211 px tall and then cut the tail off three of them,
#: squeezing the radio groups next door. Pin the width and the height becomes calculable,
#: which lets the window's own minimum tell the truth.
NOTE_WIDTH = 340


class SettingsDialog(QDialog):
    def __init__(self, window: MainWindow, settings: Settings, languages: LanguageManager, panel: TransferPanel) -> None:
        super().__init__(window)
        self.host = window
        self.settings = settings
        self.languages = languages
        self.panel = panel
        #: (widget, msgid, setter) replayed by retranslate() so a language switch is enough.
        self._bound: list[tuple[object, str, object]] = []
        #: Labels allowed to break into several lines; remeasured whenever their text changes.
        self._wrapping: list[QLabel] = []

        self.setObjectName("SettingsDialog")
        # No explicit minimum: it would override the layout's own, and the window could then
        # be sized narrower than the longest caption on a page, which clips the control
        # instead of refusing the size. The layout floor moves with the language.
        self.resize(760, 500)

        self.menu = QListWidget(self)
        self.menu.setObjectName("SettingsMenu")
        self._fit_menu()

        self.stack = QStackedWidget(self)
        for page in (self._general_page(), self._transfer_page(), self._peers_page(), self._about_page()):
            self.menu.addItem(QListWidgetItem())
            self.stack.addWidget(page)
        self.menu.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.menu.setCurrentRow(0)

        close_box = QDialogButtonBox(QDialogButtonBox.Close, self)
        close_box.rejected.connect(self.close)
        close_box.accepted.connect(self.close)
        self._bind(close_box.button(QDialogButtonBox.Close), "关闭")

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        row.addWidget(self.menu)
        row.addWidget(self.stack, 1)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.addLayout(row, 1)
        outer.addWidget(close_box)

        # The name is edited here and inline on the panel, so both have to follow it.
        self.panel.device_name_changed.connect(lambda _name: self.reload())
        self.retranslate()

    # ------------------------------------------------------------------ widgets

    def _bind(self, widget: QWidget, msgid: str, setter=None) -> QWidget:
        """Remember where a translatable string lives so retranslate() can rewrite it."""
        self._bound.append((widget, msgid, setter or widget.setText))
        return widget

    def _label(self, msgid: str, *, muted: bool = False) -> QLabel:
        label = QLabel(self)
        if muted:
            label.setObjectName("Muted")
            self._wrap(label)
        return self._bind(label, msgid)

    def _wrap(self, label: QLabel) -> QLabel:
        """Mark a label as one that may need several lines; see NOTE_WIDTH."""
        label.setWordWrap(True)
        self._wrapping.append(label)
        return label

    def _fit_menu(self) -> None:
        """Give the section list the width its longest name needs in the current language.

        A fixed column truncated "Dispositivos emparejados" on screen, and this list is the
        only place that says what the other pages are.
        """
        need = self.menu.sizeHintForColumn(0) + 2 * self.menu.frameWidth()
        self.menu.setFixedWidth(max(150, need))

    def _form(self, title: str) -> tuple[QWidget, QFormLayout]:
        """A page with its heading. Rows are added by the caller, so every caption literal
        stays visible to the message extractor instead of hiding inside a tuple."""
        page = QWidget(self)
        form = QFormLayout(page)
        form.setContentsMargins(6, 6, 6, 6)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(10)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        heading = QLabel(self)
        heading.setObjectName("SectionTitle")
        form.addRow(self._bind(heading, title))
        return page, form

    def _radios(self, values: dict[str, str], chosen: str, on_change) -> tuple[QWidget, dict]:
        box = QWidget(self)
        # Vertical: three captions side by side are wider than the page at its minimum, and
        # a radio that has to share a row is the one that gets cut off.
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        buttons: dict[str, QRadioButton] = {}
        for value, msgid in values.items():
            radio = QRadioButton(box)  # one parent widget is what makes them mutually exclusive
            self._bind(radio, msgid)
            radio.setChecked(value == chosen)
            radio.toggled.connect(lambda on, name=value: on and on_change(name))
            layout.addWidget(radio)
            buttons[value] = radio
        return box, buttons

    def _row(self, *widgets: QWidget) -> QWidget:
        box = QWidget(self)
        layout = QHBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        for widget in widgets:
            layout.addWidget(widget)
        layout.addStretch(1)
        return box

    def _general_page(self) -> QWidget:
        self.name_edit = QLineEdit(self)
        self.name_edit.setMaxLength(40)
        self.name_edit.setClearButtonEnabled(True)
        self.name_edit.editingFinished.connect(self._apply_name)

        self.language_box = QComboBox(self)
        for code in self.languages.available():
            self.language_box.addItem(self.languages.display_name(code), code)
        self.language_box.currentIndexChanged.connect(self._apply_language)

        self.theme_box, self.theme_buttons = self._radios(
            {"auto": N("跟随系统"), "light": N("浅色"), "dark": N("深色")},
            str(self.settings.get("theme", "auto")),
            self._apply_theme,
        )
        self.autostart_check = QCheckBox(self)
        self._bind(self.autostart_check, "开机时自动启动")
        self.autostart_check.toggled.connect(self._apply_autostart)
        self.close_box, self.close_buttons = self._radios(
            {CLOSE_ASK: N("每次询问"), CLOSE_TRAY: N("最小化到托盘"), CLOSE_QUIT: N("直接退出")},
            str(self.settings.get("on_close", CLOSE_ASK)),
            self._apply_close,
        )
        page, form = self._form("常规")
        form.addRow(self._label("设备名"), self.name_edit)
        form.addRow(QLabel(self), self._label("这个名称会出现在附近设备的名单里，改完立即生效。", muted=True))
        form.addRow(self._label("界面语言"), self.language_box)
        form.addRow(self._label("外观"), self.theme_box)
        form.addRow(QLabel(self), self.autostart_check)
        form.addRow(self._label("关闭窗口时"), self.close_box)
        return page

    def _transfer_page(self) -> QWidget:
        self.dir_edit = QLineEdit(self)
        self.dir_edit.setReadOnly(True)
        self.browse_button = QPushButton(self)
        self._bind(self.browse_button, "浏览…")
        self.browse_button.clicked.connect(self._choose_dir)
        self.reset_dir_button = QPushButton(self)
        self._bind(self.reset_dir_button, "恢复默认")
        self.reset_dir_button.clicked.connect(self._reset_dir)
        dir_box = QWidget(self)
        dir_layout = QHBoxLayout(dir_box)
        dir_layout.setContentsMargins(0, 0, 0, 0)
        dir_layout.addWidget(self.dir_edit, 1)
        dir_layout.addWidget(self.browse_button)
        dir_layout.addWidget(self.reset_dir_button)

        self.port_label = self._wrap(QLabel(self))
        self.chunk_label = self._wrap(QLabel(self))
        self.code_life_label = self._wrap(QLabel(self))
        # These three quote the contract in one sentence each, which is wider than the page
        # in some languages; wrapping keeps the numbers readable instead of clipped.
        self.open_dir_button = QPushButton(self)
        self._bind(self.open_dir_button, "打开接收目录")
        self.open_dir_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(receive_root()))))
        page, form = self._form("传输")
        form.addRow(self._label("接收目录"), dir_box)
        form.addRow(QLabel(self), self._label("对方发来的文件按每一次传输建一个子文件夹。", muted=True))
        form.addRow(QLabel(self), self._row(self.open_dir_button))
        form.addRow(self._label("端口"), self.port_label)
        form.addRow(self._label("分块"), self.chunk_label)
        form.addRow(self._label("配对码"), self.code_life_label)
        form.addRow(QLabel(self), self._label(
            "上面这几项由 protocol/protocol.json 冻结，手机端按同一份契约校验，改了就配不上对。",
            muted=True,
        ))
        return page

    def _peers_page(self) -> QWidget:
        self.pin_list = QListWidget(self)
        self.pin_list.itemSelectionChanged.connect(self._sync_unpin)
        self.unpin_button = QPushButton(self)
        self._bind(self.unpin_button, "撤销这台设备")
        self.unpin_button.clicked.connect(self._unpin_selected)
        page, form = self._form("已配对设备")
        form.addRow(QLabel(self), self._label(
            "配对成功过的设备记在这里，下次传文件不再问配对码。怀疑对方换过密钥就撤销它。",
            muted=True,
        ))
        form.addRow(QLabel(self), self.pin_list)
        form.addRow(QLabel(self), self._row(self.unpin_button))
        return page

    def _about_page(self) -> QWidget:
        self.version_label = QLabel(self)
        self.copyright_label = QLabel(self)
        self.copyright_label.setObjectName("Muted")
        self.qt_label = QLabel(self)
        self.protocol_label = QLabel(self)
        self.data_label = self._wrap(QLabel(self))
        self.data_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.open_log_button = QPushButton(self)
        self._bind(self.open_log_button, "打开日志目录")
        self.open_log_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(logs_dir()))))
        page, form = self._form("关于")
        form.addRow(self._label("版本"), self.version_label)
        form.addRow(QLabel(self), self.copyright_label)
        form.addRow(self._label("界面库"), self.qt_label)
        form.addRow(self._label("协议"), self.protocol_label)
        form.addRow(self._label("数据目录"), self.data_label)
        form.addRow(self._label("日志"), self._row(self.open_log_button))
        return page

    # ------------------------------------------------------------------ state in

    def reload(self) -> None:
        """Re-read every control from the settings, the panel and the registry."""
        for widget, value in ((self.name_edit, self.panel.device_name), (self.dir_edit, str(receive_root()))):
            widget.blockSignals(True)
            widget.setText(value)
            widget.blockSignals(False)

        self.language_box.blockSignals(True)
        self.language_box.setCurrentIndex(max(0, self.language_box.findData(self.languages.current)))
        self.language_box.blockSignals(False)

        self._check(self.theme_buttons, str(self.settings.get("theme", "auto")))
        self._check(self.close_buttons, str(self.settings.get("on_close", CLOSE_ASK)))

        self.autostart_check.blockSignals(True)
        self.autostart_check.setEnabled(autostart.is_supported())
        self.autostart_check.setChecked(autostart.is_supported() and autostart.is_enabled())
        self.autostart_check.blockSignals(False)

        proto = self.panel.proto
        self.port_label.setText(
            _("局域网端口 {port}，发现端口 {discovery}").format(port=proto.transport_port, discovery=proto.discovery_port)
        )
        self.chunk_label.setText(
            _("每块 {size} 字节，最多 {n} 块并行").format(size=f"{proto.chunk_size:,}", n=proto.max_parallel_chunks)
        )
        self.code_life_label.setText(
            # The contract freezes whether a code lapses, so the page quotes whichever of the
            # two promises this build actually keeps.
            _("{digits} 位数字，固定不换；只有点主页面的「更换配对码和密码」才会换一组").format(digits=proto.pair_code_digits)
            if proto.pair_code_static
            else _("{digits} 位数字，{ttl} 秒后换一个").format(digits=proto.pair_code_digits, ttl=proto.pair_code_ttl_s)
        )
        self.version_label.setText(f"{self.host.brand()} {VERSION}")
        self.copyright_label.setText(COPYRIGHT)
        self.qt_label.setText(f"Qt {qVersion()} / PySide6 {PySide6.__version__}")
        self.protocol_label.setText(_("契约版本 v{version}（{name}）").format(version=proto.version, name=proto.technical_name))
        self.data_label.setText(str(user_data_dir()))
        self._refresh_pins()
        self._remeasure()

    def _remeasure(self) -> None:
        """Tell the layout how tall each wrapping label really is at NOTE_WIDTH.

        Qt's own minimum for a word-wrapped label is one line, and a page of hints would
        otherwise ask for 211 px, get 211 px, and lose the end of three sentences.
        """
        for label in self._wrapping:
            label.setMinimumSize(QSize(NOTE_WIDTH, label.heightForWidth(NOTE_WIDTH)))

    @staticmethod
    def _check(buttons: dict, value: str) -> None:
        for name, button in buttons.items():
            button.blockSignals(True)
            button.setChecked(name == value)
            button.blockSignals(False)

    def _refresh_pins(self) -> None:
        """Rebuild the pinned list straight from identity/trusted.json."""
        # Hold the fingerprint, not the item: clear() destroys the C++ object under us.
        keep = self.pin_list.currentItem()
        selected = "" if keep is None else str(keep.data(Qt.UserRole))
        pinned = self.panel.identity.pinned_fingerprints()
        self.pin_list.clear()
        for fingerprint in pinned:
            entry = self.panel.identity.trusted_entry(fingerprint) or {}
            item = QListWidgetItem(f"{entry.get('name') or _('未知设备')}    {fingerprint[: self.panel.proto.prefix_chars]}")
            item.setData(Qt.UserRole, fingerprint)
            item.setToolTip(_("指纹 {fp}").format(fp=fingerprint))
            self.pin_list.addItem(item)
            if fingerprint == selected:
                self.pin_list.setCurrentItem(item)
        self._sync_unpin()

    def _sync_unpin(self) -> None:
        """The button only makes sense once a row is actually selected."""
        self.unpin_button.setEnabled(self.pin_list.currentItem() is not None)

    # ---------------------------------------------------------------- apply out

    def _apply_name(self) -> None:
        if not self.panel.set_device_name(self.name_edit.text()):
            self.name_edit.setText(self.panel.device_name)
            return
        self.host.status.showMessage(_("设备名已改成 {name}").format(name=self.panel.device_name), 8000)

    def _apply_language(self, index: int) -> None:
        code = self.language_box.itemData(index)
        if code and code != self.languages.current:
            self.host.switch_language(str(code))

    def _apply_theme(self, value: str) -> None:
        self.host.apply_theme(value)

    def _apply_autostart(self, checked: bool) -> None:
        self.host.on_autostart_toggled(checked)
        # The registry, not the checkbox, decides what is now true.
        self.reload()

    def _apply_close(self, value: str) -> None:
        self.settings.set("on_close", value)
        log.info("close behaviour set to %s", value)

    def _choose_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, _("选择接收目录"), str(receive_root()))
        if chosen:
            self._set_receive_dir(chosen)

    def _reset_dir(self) -> None:
        self._set_receive_dir("")

    def _set_receive_dir(self, path: str) -> None:
        if str(path) == str(self.settings.get("receive_dir", "")):
            return
        self.settings.set("receive_dir", str(path))
        # The folder is read when the receiver is built, so a running one has to move too.
        self.panel.restart_services()
        self.reload()
        log.info("receive directory set to %s", receive_root())

    def _unpin_selected(self) -> None:
        item = self.pin_list.currentItem()
        if item is None:
            return
        # The row shows a prefix of the fingerprint, so take the full one from its data.
        name = item.text().split("    ")[0]
        fingerprint = str(item.data(Qt.UserRole))
        if not self.panel.identity.untrust(fingerprint):
            self.host.status.showMessage(_("这台设备已经不在名单里了。"), 8000)
            self._refresh_pins()
            return
        # The main card lists paired devices by fingerprint, and a session would otherwise stay
        # alive holding exactly the key this button just threw away.
        self.panel.forget(fingerprint)
        self._refresh_pins()
        self.host.status.showMessage(_("已撤销 {name}，它已从已连接的设备里移出，下次传文件要重新配对。").format(name=name), 8000)

    # ------------------------------------------------------------------- strings

    def retranslate(self) -> None:
        """Re-apply every string; also runs right after a language switch."""
        for widget, msgid, setter in self._bound:
            setter(_(msgid))
        self.setWindowTitle(_("设置"))
        for row, title in enumerate(SECTIONS):
            self.menu.item(row).setText(_(title))
        self._fit_menu()
        self.name_edit.setPlaceholderText(self.panel.device_name)
        self.name_edit.setToolTip(_("这台设备对别人显示的名字"))
        self.language_box.setToolTip(_("只改这个程序的界面文字"))
        self.autostart_check.setToolTip(
            _("只有打包好的 Windows 版本能改开机自启。")
            if not self.autostart_check.isEnabled()
            else _("登录 Windows 后自动运行，并留在托盘")
        )
        self.browse_button.setToolTip(_("换一个存放收到文件的文件夹"))
        self.reset_dir_button.setToolTip(_("回到应用数据目录下的 received"))
        self.unpin_button.setToolTip(_("忘记这台设备的密钥，下次传文件要重新输配对码"))
        self.reload()
