"""The settings page: one sheet of rows, the caption on the left, the control on the right.

It is a page in the window's rail rather than a dialog, because there is deliberately no OK
button. Each control writes the value the rest of the app already reads and takes effect on
the spot - a window you could "cancel" after the receiving port had already moved would be
lying about one of the two states.

Anything shown here has to be something the app can actually do, so the protocol numbers
(port, chunk size, code lifetime) are read-only facts: they come from the frozen contract
both ends check each other against, and changing them here would only break pairing.

The mockup draws the sheet as six rows; this build has more that is worth changing than the
drawing has room for, so the sheet scrolls instead of stretching the window. Row order keeps
the mockup's: the folder, then the two bandwidth/notice switches, then the look.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

import PySide6

from PySide6.QtCore import QRect, QSize, Qt, QUrl, qVersion
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractButton,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from app import autostart
from app.ui import theme, tray
from app.config import CLOSE_ASK, CLOSE_QUIT, CLOSE_TRAY, Settings
from app.i18n import N, _
from app.meta import COPYRIGHT, VERSION
from app.paths import logs_dir, receive_root, user_data_dir
from app.ui.language_manager import LanguageManager
from app.ui.transfer import TransferPanel

if TYPE_CHECKING:
    from app.ui.main_window import MainWindow

log = logging.getLogger(__name__)

#: Width a caption keeps at the smallest window the user can drag this to.
#: Qt counts a single line of a word-wrapped label when it works out a layout's minimum, so
#: a page full of sentences asked to be 211 px tall and then cut the tail off three of them.
#: Pin the width and the height becomes calculable, which lets the window's floor tell the truth.
#: 260 is not a taste number: the sheet adds 56 px of padding, the scroll area 17 of bar and the
#: page 12 of margin, and the four content pages already hold the stack at 594. A caption column
#: wider than this moves the floor for the whole window, not just for the page that asked.
ROW_TEXT_WIDTH = 260

#: The same arithmetic on the right-hand side, where the facts are paths and version strings.
#: 40 px narrower than the caption column because a value has no button next to it to make room
#: for; the widest thing this sheet holds is the 主题 pill row, and that is what sets the floor.
ROW_VALUE_WIDTH = 220

#: A fact too long for the right-hand slot goes under its own caption, across the sheet.
#: 500 keeps the whole page inside the 594 px the four content pages already ask the window for.
ROW_BLOCK_WIDTH = 500

THEME_CHOICES = (("auto", N("跟随系统")), ("light", N("浅色")), ("dark", N("深色")))
#: The label for each close behaviour. 最小化到托盘 is only offered on a desktop that has a
#: tray to come back from - see tray.available().
CLOSE_CHOICE_LABELS = {CLOSE_ASK: N("每次询问"), CLOSE_TRAY: N("最小化到托盘"), CLOSE_QUIT: N("直接退出")}


class SwitchButton(QAbstractButton):
    """The pill toggle from the mockups.

    Qt's checkbox cannot be made into one by stylesheet - the indicator is a sub-control the
    platform style paints, and QSS only resizes it. Drawing it here also means the switch is
    still a button: space bar and click both work, and it is the same widget in both themes.
    """

    SIZE = QSize(52, 30)
    KNOB = 24

    def __init__(self, palette: Callable[[], theme.Palette], label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        # The only thing saying what this switch is, since it carries no text of its own.
        self.setAccessibleName(label)
        self.setFixedSize(self.SIZE)
        self.toggled.connect(self.update)

    def hitButton(self, pos) -> bool:
        return self.rect().contains(pos)

    def paintEvent(self, _event) -> None:
        p = self._palette()
        on = self.isChecked()
        live = self.isEnabled()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        # Off is grey-on-grey against the card if the track borrows the card's own recessed
        # fill, and a switch nobody can see is a switch nobody can read. The mockup draws the
        # off track a full step darker than the sheet, so it does too.
        track = QColor(p.accent if on else p.pressed)
        if not live:
            track.setAlpha(120)
        painter.setPen(QPen(QColor(p.hairline), 1) if not on else Qt.NoPen)
        painter.setBrush(track)
        painter.drawRoundedRect(QRect(1, 1, self.width() - 3, self.height() - 3), 14, 14)
        knob = QRect(3, (self.height() - self.KNOB) // 2, self.KNOB, self.KNOB)
        if on:
            knob.moveLeft(self.width() - 3 - self.KNOB)
        painter.setPen(QPen(QColor(p.hairline), 1))
        painter.setBrush(QColor(p.card) if live else QColor(p.hover))
        painter.drawEllipse(knob)


class SettingsPage(QWidget):
    def __init__(self, window: MainWindow, settings: Settings, languages: LanguageManager, panel: TransferPanel) -> None:
        super().__init__(window)
        self.host = window
        self.settings = settings
        self.languages = languages
        self.panel = panel
        #: (widget, msgid, setter) replayed by retranslate() so a language switch is enough.
        self._bound: list[tuple[object, str, object]] = []
        #: Labels allowed to break into several lines, with the width each one keeps.
        self._wrapping: list[tuple[QLabel, int]] = []

        self.setObjectName("SettingsPage")
        # No explicit minimum: it would override the layout's own, and the window could then
        # be sized narrower than the longest caption on the sheet, which clips the control
        # instead of refusing the size. The layout floor moves with the language.

        outer = QVBoxLayout(self)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(14)
        outer.addWidget(self._bind(QLabel(self), "设置", None, "PageTitle"))

        self.scroll = QScrollArea(self)
        self.scroll.setObjectName("Page")
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setWidgetResizable(True)
        # The sheet is as wide as the page, so a vertical bar is the only one that can appear -
        # and a horizontal one would mean a row had outgrown the window it is sitting in.
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.sheet = QFrame(self.scroll)
        self.sheet.setObjectName("Card")
        self.rows = QVBoxLayout(self.sheet)
        self.rows.setContentsMargins(28, 6, 28, 6)
        self.rows.setSpacing(0)
        self._build_rows()

        self.scroll.setWidget(self.sheet)
        outer.addWidget(self.scroll, 1)

        # The name is edited here and inline on the panel, so both have to follow it.
        self.panel.device_name_changed.connect(lambda _name: self.reload())
        self.retranslate()

    # ------------------------------------------------------------------ widgets

    def _bind(
        self,
        widget: QWidget,
        msgid: str,
        setter=None,
        object_name: str | None = None,
        values: dict | None = None,
    ) -> QWidget:
        """Remember where a translatable string lives so retranslate() can rewrite it.

        `values` is for the captions that carry the product name: the msgid stays a literal
        the extractor can see, and the name is substituted every time the strings are replayed,
        because 传书 in one language is ChuanShu in another. A value that is callable is called
        then, so it follows the language instead of freezing the one this row was built in.
        """
        if object_name is not None:
            widget.setObjectName(object_name)
        write = setter or widget.setText
        if values:
            # `sink=write` binds the setter as it is now: closing over the name would make the
            # lambda call itself.
            write = lambda text, captured=values, sink=write: sink(
                text.format(**{k: v() if callable(v) else v for k, v in captured.items()})
            )
        self._bound.append((widget, msgid, write))
        return widget

    def _wrap(self, label: QLabel, width: int) -> QLabel:
        """Mark a label as one that may need several lines; see ROW_TEXT_WIDTH."""
        label.setWordWrap(True)
        self._wrapping.append((label, width))
        return label

    def _words(self, title: str, note: str, extra: QWidget | None = None, values: dict | None = None) -> QWidget:
        """The left half of a row: what it is called, and in plain terms what it does."""
        box = QWidget(self)
        box.setObjectName("SettingRow")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self._bind(QLabel(box), title, None, "RowTitle", values))
        layout.addWidget(
            self._wrap(self._bind(QLabel(box), note, None, "RowNote", values), ROW_TEXT_WIDTH)
        )
        if extra is not None:
            # The actions that are not worth a button on the right - reset this one, open that
            # folder - sit under the sentence they belong to, so the row keeps one clear control.
            layout.addSpacing(2)
            layout.addWidget(extra)
        return box

    def _links(self, *buttons: QPushButton) -> QWidget:
        box = QWidget(self)
        box.setObjectName("SettingRow")
        layout = QHBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        for button in buttons:
            layout.addWidget(button)
        return box

    def _hairline(self) -> QFrame:
        line = QFrame(self)
        line.setObjectName("Hairline")
        line.setFixedHeight(1)
        self.rows.addWidget(line)
        return line

    def _row(
        self,
        title: str,
        note: str,
        *controls: QWidget,
        expand: QWidget | None = None,
        extra: QWidget | None = None,
        values: dict | None = None,
    ) -> QWidget:
        line = QWidget(self)
        line.setObjectName("SettingRow")
        layout = QHBoxLayout(line)
        layout.setContentsMargins(0, 18, 0, 18)
        layout.setSpacing(16)
        if self.rows.count():
            self._hairline()
        layout.addWidget(self._words(title, note, extra, values))
        if expand is None:
            # The caption is the fixed half; everything else keeps to the right edge.
            layout.addStretch(1)
        for widget in controls:
            layout.addWidget(widget, 1 if widget is expand else 0)
        self.rows.addWidget(line)
        return line

    def _block_row(self, title: str, note: str, block: QWidget, *buttons: QWidget) -> QWidget:
        """A row whose control is too wide for the right-hand slot and goes under the caption."""
        if self.rows.count():
            self._hairline()
        line = QWidget(self)
        line.setObjectName("SettingRow")
        layout = QVBoxLayout(line)
        layout.setContentsMargins(0, 18, 0, 18)
        layout.setSpacing(12)
        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(16)
        top.addWidget(self._words(title, note))
        top.addStretch(1)
        for button in buttons:
            top.addWidget(button)
        layout.addLayout(top)
        layout.addWidget(block)
        self.rows.addWidget(line)
        return line

    def _field(self, *buttons: QWidget) -> tuple[QFrame, QLineEdit]:
        """One outlined box holding a path and the buttons that act on it, as the mockup draws it."""
        box = QFrame(self)
        box.setObjectName("FieldGroup")
        layout = QHBoxLayout(box)
        layout.setContentsMargins(10, 5, 8, 5)
        layout.setSpacing(8)
        edit = QLineEdit(box)
        edit.setObjectName("FieldBare")
        edit.setReadOnly(True)
        layout.addWidget(edit, 1)
        for button in buttons:
            layout.addWidget(button)
        return box, edit

    def _switch(self, msgid: str, on_change) -> SwitchButton:
        switch = SwitchButton(lambda: self.host.palette, "", self)
        # A painted pill carries no text, so the caption is all a screen reader has to say.
        self._bound.append((switch, msgid, switch.setAccessibleName))
        switch.toggled.connect(on_change)
        return switch

    def _pills(self, options: tuple, on_change) -> tuple[QWidget, dict]:
        """A choice drawn as the mockups do it: a row of outlined buttons, the picked one accented."""
        box = QWidget(self)
        box.setObjectName("SettingRow")
        layout = QHBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        buttons: dict = {}
        for value, msgid in options:
            button = QPushButton(box)
            button.setObjectName("Choice")
            button.setCheckable(True)
            self._bind(button, msgid)
            button.clicked.connect(lambda _checked, name=value: on_change(name))
            layout.addWidget(button)
            buttons[value] = button
        return box, buttons

    def _value(self, selectable: bool = False, width: int = ROW_VALUE_WIDTH) -> QLabel:
        """A fact you read here and change somewhere else - or nowhere.

        The narrow ones sit at the right edge of their row, under the control column. A `width`
        of ROW_BLOCK_WIDTH means the value goes under its caption instead, where a path or three
        sentences have the sheet's whole width to be legible in.
        """
        across = width == ROW_BLOCK_WIDTH
        label = QLabel(self)
        label.setObjectName("RowValue")
        label.setAlignment((Qt.AlignLeft if across else Qt.AlignRight) | Qt.AlignTop)
        if selectable:
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return self._wrap(label, width)

    def _build_rows(self) -> None:
        self.browse_button = self._bind(QPushButton(self), "浏览", None, "Ghost")
        self.browse_button.clicked.connect(self._choose_dir)
        self.reset_dir_button = self._bind(QPushButton(self), "恢复默认", None, "Inline")
        self.reset_dir_button.clicked.connect(self._reset_dir)
        self.open_dir_button = self._bind(QPushButton(self), "打开接收目录", None, "Inline")
        self.open_dir_button.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(receive_root())))
        )
        field, self.dir_edit = self._field(self.browse_button)
        field.setMinimumWidth(ROW_VALUE_WIDTH)
        self._row(
            N("保存路径"),
            N("接收文件保存位置"),
            field,
            expand=field,
            extra=self._links(self.reset_dir_button, self.open_dir_button),
        )

        self.limit_spin = QSpinBox(self)
        self.limit_spin.setRange(1, 1000)
        self.limit_spin.setSingleStep(1)
        self.limit_spin.setFixedWidth(120)
        self.limit_spin.valueChanged.connect(self._apply_limit_rate)
        self.limit_switch = self._switch("传输限速", self._apply_limit)
        self._row(N("传输限速"), N("限制本机发出文件的速度，给同一网络里的别的程序省带宽"), self.limit_spin, self.limit_switch)

        self.autostart_switch = self._switch("开机自启", self._apply_autostart)
        self._row(N("开机自启"), N("开机时自动启动{app}"), self.autostart_switch, values={"app": self.host.brand})

        self.notify_switch = self._switch("通知", self._apply_notify)
        self._row(N("通知"), N("接收文件时发送系统通知"), self.notify_switch)

        self.theme_box, self.theme_buttons = self._pills(THEME_CHOICES, self._apply_theme)
        self._row(N("主题"), N("选择界面外观"), self.theme_box)

        self.name_edit = QLineEdit(self)
        self.name_edit.setMaxLength(40)
        self.name_edit.setClearButtonEnabled(True)
        self.name_edit.setFixedWidth(220)
        self.name_edit.editingFinished.connect(self._apply_name)
        self._row(N("设备名"), N("这个名称会出现在附近设备的名单里，改完立即生效。"), self.name_edit)

        self.language_box = QComboBox(self)
        for code in self.languages.available():
            self.language_box.addItem(self.languages.display_name(code), code)
        self.language_box.currentIndexChanged.connect(self._apply_language)
        self._row(N("界面语言"), N("只改这个程序的界面文字"), self.language_box)

        # The mockup gives 主题 a row of pills, so it gets pills. What it never draws is a fourth
        # choice - 跟随系统 - and the app has had one since the first build, so the pill row is
        # three wide, not two. 关闭窗口时 has no drawing to be faithful to, and three captions side
        # by side want more width than the sheet can borrow, because the stack is pinned to its
        # widest page: a combo asks the same question in the width of the one answer it holds.
        self.close_box = QComboBox(self)
        for value in (CLOSE_ASK, CLOSE_TRAY, CLOSE_QUIT):
            if value == CLOSE_TRAY and not tray.available():
                # A desktop with no tray has nowhere to come back from, so 最小化到托盘 is not
                # offered at all rather than offered and then refused. A remembered choice of it
                # falls back to 每次询问 here, and to the ask-dialog in request_close().
                continue
            self.close_box.addItem("", value)
        self.close_box.currentIndexChanged.connect(self._apply_close_index)
        self._row(N("关闭窗口时"), N("点窗口右上角的叉之后怎么办"), self.close_box)

        self.pin_list = QListWidget(self)
        self.pin_list.setObjectName("PinList")
        self.pin_list.setFixedHeight(150)
        self.pin_list.itemSelectionChanged.connect(self._sync_unpin)
        self.unpin_button = self._bind(QPushButton(self), "撤销这台设备", None, "Secondary")
        self.unpin_button.clicked.connect(self._unpin_selected)
        self._block_row(
            N("已配对设备"),
            N("配对成功过的设备记在这里，下次传文件不再问配对码。怀疑对方换过密钥就撤销它。"),
            self.pin_list,
            self.unpin_button,
        )

        self.proto_label = self._value(width=ROW_BLOCK_WIDTH)
        self._block_row(N("协议参数"), N("端口、分块和配对码由 protocol/protocol.json 冻结，手机端按同一份契约校验。"), self.proto_label)

        self.data_label = self._value(selectable=True, width=ROW_BLOCK_WIDTH)
        self._block_row(N("数据目录"), N("设置、已配对设备和收到的文件都存在这里，可以直接复制这个路径。"), self.data_label)

        self.open_log_button = self._bind(QPushButton(self), "打开日志目录", None, "Ghost")
        self.open_log_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(logs_dir()))))
        self._row(N("日志"), N("出问题时把这里发给对方"), self.open_log_button)

        self.version_label = self._value()
        # No spaces around {app} in these Chinese ids. The mockup writes 关于传书, and it is right:
        # the space between Han and Latin is a Chinese typographic convention, but 传书 is Han, so
        # "关于 传书" breaks it. Latin locales keep their own space - it lives in their .po entry,
        # "About ChuanShu", where the msgid cannot reach it.
        self._row(N("关于{app}"), N("{app}版本与版权信息"), self.version_label, values={"app": self.host.brand})

        self.qt_label = self._value()
        self._row(N("界面库"), N("这个程序跑在 Qt 上"), self.qt_label)

        self.protocol_label = self._value()
        self._row(N("契约版本"), N("两端握手时互相核对的那份协议"), self.protocol_label)

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
        self._choose(self.close_box, str(self.settings.get("on_close", CLOSE_ASK)))

        limited = bool(self.settings.get("limit_on", False))
        self.limit_switch.blockSignals(True)
        self.limit_switch.setChecked(limited)
        self.limit_switch.blockSignals(False)
        self.limit_spin.blockSignals(True)
        self.limit_spin.setEnabled(limited)
        self.limit_spin.setValue(max(1, int(self.settings.get("limit_mbps", 10))))
        self.limit_spin.blockSignals(False)

        self.notify_switch.blockSignals(True)
        self.notify_switch.setChecked(bool(self.settings.get("notify", True)))
        self.notify_switch.blockSignals(False)

        self.autostart_switch.blockSignals(True)
        self.autostart_switch.setEnabled(autostart.is_supported())
        self.autostart_switch.setChecked(autostart.is_supported() and autostart.is_enabled())
        self.autostart_switch.blockSignals(False)

        proto = self.panel.proto
        self.proto_label.setText(
            "\n".join(
                (
                    _("局域网端口 {port}，发现端口 {discovery}").format(
                        port=proto.transport_port, discovery=proto.discovery_port
                    ),
                    _("每块 {size} 字节，最多 {n} 块并行").format(
                        size=f"{proto.chunk_size:,}", n=proto.max_parallel_chunks
                    ),
                    # The contract freezes whether a code lapses, so the page quotes whichever of
                    # the two promises this build actually keeps.
                    _("{digits} 位数字，固定不换；只有点主页面的「更换配对码和密码」才会换一组").format(
                        digits=proto.pair_code_digits
                    )
                    if proto.pair_code_static
                    else _("{digits} 位数字，{ttl} 秒后换一个").format(
                        digits=proto.pair_code_digits, ttl=proto.pair_code_ttl_s
                    ),
                )
            )
        )
        self.version_label.setText(f"{self.host.brand()} {VERSION}\n{COPYRIGHT}")
        self.qt_label.setText(f"Qt {qVersion()} / PySide6 {PySide6.__version__}")
        self.protocol_label.setText(_("v{version}（{name}）").format(version=proto.version, name=proto.technical_name))
        self.data_label.setText(str(user_data_dir()))
        self._refresh_pins()
        self._remeasure()

    def _remeasure(self) -> None:
        """Tell the layout how tall each wrapping label really is at the width it keeps.

        Qt's own minimum for a word-wrapped label is one line, and a sheet of hints would
        otherwise ask for one line each, get it, and lose the end of half the sentences.
        """
        for label, width in self._wrapping:
            label.setMinimumSize(QSize(width, label.heightForWidth(width)))
        self.rows.invalidate()
        # The sheet's own width is what the page has to be able to show, bar included: the
        # scroll area is the only thing between a row and the window edge, and it does not
        # shrink the content, it moves it.
        bar = self.scroll.style().pixelMetric(QStyle.PM_ScrollBarExtent)
        self.scroll.setMinimumWidth(
            self.sheet.minimumSizeHint().width() + max(0, bar) + 2 * self.scroll.frameWidth()
        )

    @staticmethod
    def _check(buttons: dict, value: str) -> None:
        for name, button in buttons.items():
            button.blockSignals(True)
            button.setChecked(name == value)
            button.blockSignals(False)

    @staticmethod
    def _choose(box: QComboBox, value: str) -> None:
        """Move a combo to the row that holds this value, without telling it that the user did."""
        box.blockSignals(True)
        box.setCurrentIndex(max(0, box.findData(value)))
        box.blockSignals(False)

    def _refresh_pins(self) -> None:
        """Rebuild the pinned list straight from identity/trusted.json."""
        # Hold the fingerprint, not the item: clear() destroys the C++ object under us.
        keep = self.pin_list.currentItem()
        selected = "" if keep is None else str(keep.data(Qt.UserRole))
        pinned = self.panel.identity.pinned_fingerprints()
        self.pin_list.clear()
        if not pinned:
            # An empty grey box reads as a list that failed to load. Say that it is empty and
            # where the first row would come from. It stays enabled so it paints in a readable
            # grey rather than the style's disabled wash, but it is not selectable: there is
            # nothing here for 撤销 to act on, and currentItem() must stay None.
            blank = QListWidgetItem(_("还没有配对过设备。在「接收」页扫码或输配对码，第一次传完文件就会记在这里。"))
            blank.setFlags(Qt.ItemIsEnabled)
            blank.setForeground(QBrush(QColor(self.host.palette.text_muted)))
            self.pin_list.addItem(blank)
            self._sync_unpin()
            return
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
        # The registry, not the switch, decides what is now true.
        self.reload()

    def _apply_notify(self, checked: bool) -> None:
        self.settings.set("notify", bool(checked))
        log.info("arrival notifications %s", "on" if checked else "off")

    def _apply_limit(self, checked: bool) -> None:
        self.settings.set("limit_on", bool(checked))
        self.limit_spin.setEnabled(checked)
        # The value is read when a transfer starts, so nothing already in flight changes speed.
        self.host.status.showMessage(
            _("发出文件限速 {n} MB/s，下一次传输开始生效。").format(n=self.limit_spin.value())
            if checked
            else _("发出文件不再限速。"),
            8000,
        )
        log.info("send limit %s", "on" if checked else "off")

    def _apply_limit_rate(self, value: int) -> None:
        self.settings.set("limit_mbps", int(value))
        log.info("send limit set to %d MB/s", value)

    def _apply_close_index(self, index: int) -> None:
        self._apply_close(str(self.close_box.itemData(index)))

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
        self.name_edit.setPlaceholderText(self.panel.device_name)
        self.name_edit.setToolTip(_("这台设备对别人显示的名字"))
        self.language_box.setToolTip(_("只改这个程序的界面文字"))
        for i in range(self.close_box.count()):
            self.close_box.setItemText(i, _(CLOSE_CHOICE_LABELS[str(self.close_box.itemData(i))]))
        # A suffix is part of the field's text, not a label beside it, so it has to be replayed
        # like the rest or the number keeps a unit nobody reading this language was offered.
        self.limit_spin.setSuffix(_(" MB/s"))
        self.limit_spin.setToolTip(_("一次传输最多每秒发出这么多兆字节"))
        self.limit_switch.setToolTip(_("限制本机发出的文件速度；收文件不受影响"))
        self.notify_switch.setToolTip(_("文件落地后在托盘冒一条消息，窗口最小化时也看得到"))
        self.autostart_switch.setToolTip(
            _("只有打包好的版本能改开机自启。")
            if not self.autostart_switch.isEnabled()
            else _("登录后自动运行，并留在托盘")
        )
        self.browse_button.setToolTip(_("换一个存放收到文件的文件夹"))
        self.reset_dir_button.setToolTip(_("回到应用数据目录下的 received"))
        self.open_dir_button.setToolTip(_("在文件管理器里打开现在这个文件夹"))
        self.unpin_button.setToolTip(_("忘记这台设备的密钥，下次传文件要重新输配对码"))
        self.reload()
