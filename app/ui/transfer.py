"""The transfer half of the window: pairing, devices, sending, incoming offers.

app/net owns the protocol; this widget only starts those services, turns their thread
callbacks into Qt signals and paints what happened. Two rules keep the GUI responsive:
the receiver's decision callback runs in a server thread and waits on an event, and a
send runs entirely in its own thread, reporting chunk by chunk through signals.

Device names are what a peer said about itself at pairing time. They are stable but not
proof of anything; the fingerprint prefix next to them is the only real anchor.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import threading
import time
from collections import Counter
from pathlib import Path

import qrcode
from qrcode.image.svg import SvgPathImage
from PySide6.QtCore import QPoint, QSize, QUrl, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QDesktopServices,
    QImage,
    QPainter,
    QPalette,
    QPixmap,
    QAction,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app import icons
from app.config import Settings
from app.i18n import _, N
from app.meta import APP_NAME
from app.net import errors as proto_errors
from app.net import firewall
from app.net import spec as protocol_spec
from app.net.discovery import DiscoveryService, Peer, local_ipv4, verify_peer
from app.net.identity import load_or_create
from app.net.receive import ReceiveService
from app.net.send import PairNeeded, PeerConnection, PeerIdentityMismatch, Throttle, TooManyFilesForOffer, WrongPairCode, plan
from app.paths import identity_dir, receive_root, user_data_dir
from app.ui import theme

log = logging.getLogger(__name__)

#: The pair code is fixed until the user rotates it, so this tick only exists to catch the
#: things that do move under a static picture: the LAN address in the QR and the port.
#: Repainting is guarded by the payload string, so a quiet panel draws no QR at all.
CODE_REFRESH_MS = 5_000
#: Side of the pairing picture. Phone cameras need roughly 5 px per module across a desk,
#: and 224 still leaves the window's minimum width free to hold the code beside it.
QR_SIZE = 224
#: How many arrivals to keep on disk. The receive folder is the archive; this list is only
#: the reading list, and a few hundred rows is years of use.
_ARRIVALS_KEPT = 500
#: How many finished task rows the 传输 page remembers from this session.
_TASK_HISTORY_KEPT = 12
#: How many finished arrivals the 传输 page's card shows beside the transfers in flight.
_TASK_CARD_ROWS = 3
#: How wide the 附近设备 row is. The mockup draws three cards across; a fourth would make each
#: one narrower than a device name.
_NEARBY_COLUMNS = 3

#: Stack positions. The rail shows five of these; 传输记录 is the sixth and is reached from the
#: dashboard's own card, because the mockups put the record list behind a "查看全部" rather than
#: in the navigation.
PAGE_TRANSFER = 0
PAGE_SEND = 1
PAGE_RECEIVE = 2
PAGE_FILES = 3
PAGE_HISTORY = 4
PAGE_SETTINGS = 5

#: The four pills the 传输记录 mockup draws, in the order it draws them. N() because the chip
#: text is looked up from the dict and handed to _() at run time: a bare literal here is invisible
#: to Babel, and an absent catalogue entry falls back to the Chinese, so every language would
#: show 全部/进行中 on an English pill.
_HISTORY_FILTER_LABELS = {
    "all": N("全部"),
    "running": N("进行中"),
    "done": N("已完成"),
    "failed": N("失败"),
}


def _human(size: int) -> str:
    """The mockups write 128MB, not 128.0 MB: no space, and no decimal that says "exactly".

    A whole number is dropped to zero decimals, so 456KB does not come out as 456.0KB.
    """
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{value:.0f}{unit}"
            text = f"{value:.1f}"
            if text.endswith(".0"):
                text = text[:-2]
            return f"{text}{unit}"
        value /= 1024
    return f"{size}B"


def refusal_text(error: Exception, proto: protocol_spec.Protocol) -> str:
    """Which of §3's two refusals this is, said in the one place that chooses the words.

    The choice is `isinstance`, not the reply: both faces arrive as `BAD_PAIR_CODE`, and this end is
    the only one that knows whether the code was its own empty one. `spec.pair_refusal` holds the
    sentences, so the gate can read them without importing this module's toolkit.
    """
    return protocol_spec.pair_refusal(not isinstance(error, WrongPairCode), proto)


def _arrivals_file() -> Path:
    """Where verified arrivals are remembered between runs.

    The receive folder is the truth about the bytes; this file is only the reading list that
    makes the 文件 page answer "when did it arrive and from whom", which a folder cannot say.
    """
    return user_data_dir() / "arrivals.json"


def _when(stamp: float) -> str:
    """How long ago, in the words the mockup writes.

    The exact timestamp is the row's tooltip instead: a column that only ever says 上周 cannot be
    reconciled with a calendar, and one that says 2026-10-13 09:41 cannot be scanned. The column
    gets the scannable one, the pointer gets the precise one.
    """
    days = max(0, int((time.time() - stamp) // 86_400))
    if days == 0:
        return _("今天")
    if days == 1:
        return _("昨天")
    if days < 7:
        return _("{n}天前").format(n=days)
    if days < 14:
        return _("上周")
    return _("{n}周前").format(n=days // 7)


def _qr_pixmap(text: str) -> QPixmap:
    """Render the pairing payload as a QR without a native dependency.

    ``qrcode`` draws only the dark modules, so the white border has to be painted here:
    a scanner needs the quiet zone, and a dark theme must not invert it.
    """
    svg = qrcode.make(text, image_factory=SvgPathImage, border=2).to_string()
    renderer = QSvgRenderer(svg)
    image = QImage(QR_SIZE, QR_SIZE, QImage.Format_ARGB32)
    image.fill(Qt.white)
    painter = QPainter(image)
    renderer.render(painter)
    painter.end()
    return QPixmap.fromImage(image)


class _ArrivalRow(QTreeWidgetItem):
    """A file row that sorts by what the column means, not by the words printed in it.

    The display text is a human size and a formatted date, so "9 KB" must not beat "1 MB"
    and "2026-10-19" must not sort against a filename. The comparable value rides in UserRole.
    """

    def __lt__(self, other: QTreeWidgetItem) -> bool:  # noqa: D105 - Qt's sort hook
        tree = self.treeWidget()
        column = 0 if tree is None else tree.sortColumn()
        mine, theirs = self.data(column, Qt.UserRole), other.data(column, Qt.UserRole)
        if type(mine) is type(theirs):
            return bool(mine < theirs)
        return str(mine) < str(theirs)


def _flush_minimum_cache(widget: QWidget) -> None:
    """Tell every layout under a widget that its cached minimum is no longer the one to believe.

    A layout recomputes its minimum only when a queued LayoutRequest event arrives, so a caption
    written moments ago is still worth its old width in the number a parent reads. invalidate()
    clears one layout and no more: the rows inside a card are layouts of their own, so the whole
    tree has to be told before any measurement taken during a language switch means anything.
    """
    for layout in [widget.layout(), *widget.findChildren(QLayout)]:
        if layout is not None:
            layout.invalidate()


#: The width the mockups give the narrow right-hand cards (已连接设备 on 传输, 我的设备 on 接收).
#: It is a floor, not a cap: a language whose longest caption on that card needs more than this
#: takes it, so the layout never pays for the design out of a button's text.
COLUMN = 300

#: QWIDGETSIZE_MAX, which PySide6 does not export. A pinned width is lifted to this so that a
#: layout reports the minimum its content wants rather than the pin it was given.
_ANY_WIDTH = (1 << 24) - 1


class _TightList(QListWidget):
    """A device or task list that never asks for more height than it can shrink to.

    QAbstractScrollArea answers sizeHint with a 192px placeholder when it cannot judge its rows,
    and a layout treats a height-for-width card as worth whatever its children's sizeHints sum to
    - not their minimums. One list in a card therefore cost the window 118px of minimum height,
    three times over the pages, against mockups that fit in a window a third shorter.
    """

    def sizeHint(self) -> QSize:
        return self.minimumSizeHint()


class _TightTree(QTreeWidget):
    """The same deal for the two columned tables, which inherit the same placeholder."""

    def sizeHint(self) -> QSize:
        return self.minimumSizeHint()


class _CandidateDialog(QDialog):
    """Discovery's output, kept behind one button so the main card can promise only real sessions.

    Choosing a row here does not connect: it names the device the pair code on the page belongs
    to, which is why the code field and the 连接 button stay on the panel rather than in here.
    """

    def __init__(self, panel: TransferPanel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.panel = panel
        #: The candidate 连接 was clicked on. None until then, so a cancelled dialog changes nothing.
        self.chosen: Peer | None = None
        self.setWindowTitle(_("连接设备"))
        # The acceptance harness finds this picker by name; nothing in the stylesheet does.
        self.setObjectName("candidates")
        self.resize(430, 360)
        layout = QVBoxLayout(self)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.hint.setObjectName("Muted")
        self.list_ = QListWidget()
        self.list_.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_.itemDoubleClicked.connect(lambda *_: self._accept_row())
        # A stale complaint about the last attempt must not outlive the row it was about.
        self.list_.itemSelectionChanged.connect(lambda *_: self.error_label.setText(""))
        self.error_label = QLabel()
        self.error_label.setObjectName("Muted")
        self.error_label.setWordWrap(True)
        row = QHBoxLayout()
        self.manual_button = QPushButton()
        self.manual_button.setObjectName("Inline")
        self.manual_button.clicked.connect(self._add_manual)
        self.refresh_button = QPushButton()
        self.refresh_button.setObjectName("Inline")
        self.refresh_button.clicked.connect(self.reload)
        row.addWidget(self.manual_button)
        row.addWidget(self.refresh_button)
        row.addStretch(1)
        self.buttons = QDialogButtonBox(self)
        self.buttons.addButton(_("连接"), QDialogButtonBox.AcceptRole)
        self.buttons.addButton(_("取消"), QDialogButtonBox.RejectRole)
        self.buttons.accepted.connect(self._accept_row)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.hint)
        layout.addWidget(self.list_, 1)
        layout.addWidget(self.error_label)
        layout.addLayout(row)
        layout.addWidget(self.buttons)
        # Captions come from the current locale every time the picker opens, so a language
        # switch needs nothing here.
        self.hint.setText(_("下面是广播出来的候选设备。选中一台，回到主界面填它的配对码和密码，再点连接。"))
        self.manual_button.setText(_("手输地址…"))
        self.manual_button.setToolTip(_("没在局域网里广播出来的设备，可以输入它的地址，或粘贴 chuanshu:// 配对串。"))
        self.refresh_button.setText(_("刷新"))
        self.reload()

    def reload(self) -> None:
        current = self.list_.currentItem().data(Qt.UserRole) if self.list_.currentItem() else None
        self.list_.clear()
        peers = self.panel._candidate_peers()
        connected = {peer.fingerprint for peer in self.panel._connected if peer.fingerprint}
        for peer in peers:
            suffix = _("（已连接）") if peer.fingerprint in connected else ""
            item = QListWidgetItem(f"{peer.name or peer.prefix}    {peer.host}:{peer.port}{suffix}")
            item.setData(Qt.UserRole, peer)
            where = _("手动添加") if "manual" in peer.via else "+".join(sorted(peer.via))
            item.setToolTip(_("发现于 {via}；指纹前缀 {fp}").format(via=where or _("手动添加"), fp=peer.prefix))
            self.list_.addItem(item)
            if isinstance(current, Peer) and peer.fingerprint and peer.fingerprint == current.fingerprint:
                self.list_.setCurrentItem(item)
        if not peers:
            self.list_.addItem(QListWidgetItem(_("没找到设备。手输对方地址，或粘贴它的配对串。")))

    def _add_manual(self) -> None:
        example = f"{local_ipv4()}:{self.panel.proto.transport_port}"
        text, ok = QInputDialog.getText(
            self, _("手动添加设备"), _("输入对方地址（{example}）或配对串：").format(example=example)
        )
        if not ok or not text.strip():
            return
        peer, why = self.panel.verify_address(text.strip())
        if peer is None:
            self.error_label.setText(why)
            return
        # The address came from the user, so the fingerprint is the only thing that says this
        # really is that machine. Say it out loud, exactly like a pair code does.
        self.error_label.setText(_("已确认 {name}，指纹前缀 {fp}。选中它点连接。").format(name=peer.name, fp=peer.prefix))
        self.reload()

    def _accept_row(self) -> None:
        item = self.list_.currentItem()
        peer = item.data(Qt.UserRole) if item is not None else None
        if not isinstance(peer, Peer):
            self.error_label.setText(_("先选中一台设备，再点连接。"))
            return
        self.chosen = peer
        self.accept()


class _OfferDialog(QDialog):
    """fig5: the card a phone's files arrive behind.

    Frameless and rounded because the design draws no title bar - the question is one sentence
    and there are two answers. It sits in the middle of the window and does not move; Esc is 拒绝
    and Enter is 接收, which is what a keyboard needs in place of a drag bar.

    浏览 chooses the folder this one transfer is filed under, not the receive root: the root is a
    setting that outlives the offer, and a dialog that quietly changed it would be answering a
    question the user never asked.
    """

    #: Past this many files the card would be taller than the window it is answering for, so the
    #: rest are counted out loud instead of listed.
    SHOWN = 8

    def __init__(self, panel: TransferPanel, manifest: dict, who: str) -> None:
        super().__init__(panel.window())
        self.panel = panel
        self.offer_id = str(manifest.get("offer_id", ""))
        #: The folder the user picked for this transfer; None means this machine's receive root.
        self.parent_dir: Path | None = None
        #: The acceptance harness finds this card by name; nothing in the stylesheet does.
        self.setObjectName("offer")
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        # Without this the 24px radius comes out as four black corners: a translucent top-level
        # is what lets the QSS rounded sheet be the whole window.
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowTitle(_("收到来自 {who} 的文件").format(who=who))
        self.setFixedWidth(677)

        shell = QVBoxLayout(self)
        shell.setContentsMargins(18, 18, 18, 18)
        card = QFrame(self)
        card.setObjectName("OfferCard")
        shell.addWidget(card)
        shadow = QGraphicsDropShadowEffect(card)
        shadow.setBlurRadius(48)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 70))
        card.setGraphicsEffect(shadow)

        box = QVBoxLayout(card)
        box.setContentsMargins(28, 26, 28, 24)
        box.setSpacing(16)

        self.title = QLabel(_("收到来自 {who} 的文件").format(who=who), card)
        self.title.setObjectName("OfferTitle")
        # Wrapping: the name a peer chose for itself is up to 40 characters, and in the wider
        # languages the sentence around it is longer still. A clipped title would hide who is
        # asking - the one word that decides the answer.
        self.title.setWordWrap(True)
        box.addWidget(self.title)

        files = list(manifest.get("files", []))
        #: The names the card lists, for the acceptance harness to read back.
        self.names: list[str] = []
        listing = QFrame(card)
        listing.setObjectName("OfferFiles")
        rows = QVBoxLayout(listing)
        rows.setContentsMargins(18, 0, 18, 0)
        rows.setSpacing(0)
        for index, file in enumerate(files[: self.SHOWN]):
            if index:
                line = QFrame(listing)
                line.setObjectName("Hairline")
                line.setFixedHeight(1)
                rows.addWidget(line)
            name = str(file.get("relpath") or _("（无名文件）"))
            self.names.append(name)
            rows.addWidget(self._file_row(listing, name, int(file.get("size") or 0)))
        box.addWidget(listing)
        if len(files) > self.SHOWN:
            more = QLabel(_("…还有 {n} 个文件没有列出").format(n=len(files) - self.SHOWN), card)
            more.setObjectName("MutedOnCard")
            box.addWidget(more)

        where = QHBoxLayout()
        where.setSpacing(10)
        tag = QLabel(_("保存到"), card)
        tag.setObjectName("Tag")
        self.dir_field = QLineEdit(card)
        self.dir_field.setObjectName("PathField")
        self.dir_field.setReadOnly(True)
        self.browse_button = QPushButton(_("浏览"), card)
        self.browse_button.setObjectName("Ghost")
        self.browse_button.clicked.connect(self._choose_dir)
        where.addWidget(tag)
        where.addWidget(self.dir_field, 1)
        where.addWidget(self.browse_button)
        box.addLayout(where)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.decline_button = QPushButton(_("拒绝"), card)
        self.decline_button.setObjectName("Secondary")
        self.decline_button.clicked.connect(self.reject)
        # One msgid with the rail entry, because the mockup writes 接收 in both places. gettext
        # cannot tell them apart, so the wording has to read as a page name and as a button.
        self.accept_button = QPushButton(_("接收"), card)
        self.accept_button.setDefault(True)
        self.accept_button.clicked.connect(self.accept)
        buttons.addWidget(self.decline_button)
        buttons.addWidget(self.accept_button)
        box.addLayout(buttons)
        self._sync_dir()

    def _file_row(self, parent: QWidget, relpath: str, size: int) -> QWidget:
        row = QWidget(parent)
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 12, 0, 12)
        line.setSpacing(12)
        mark = QLabel(row)
        glyph = self.panel._KIND_GLYPH.get(self.panel._file_kind(relpath), "file-unknown")
        mark.setPixmap(icons.pixmap(glyph, self.panel._p.accent, 22))
        mark.setFixedWidth(24)
        mark.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        name = QLabel(relpath, row)
        name.setWordWrap(True)
        bytes_ = QLabel(_human(size), row)
        bytes_.setObjectName("MutedOnCard")
        bytes_.setAlignment(Qt.AlignRight | Qt.AlignTop)
        line.addWidget(mark)
        line.addWidget(name, 1)
        line.addWidget(bytes_)
        return row

    def landing_dir(self) -> Path:
        """Where these files will be written: one folder per transfer, under the chosen parent."""
        return (self.parent_dir or receive_root()) / self.offer_id

    def _sync_dir(self) -> None:
        self.dir_field.setText(str(self.landing_dir()))

    def _choose_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, _("选择这次存放的文件夹"), str(self.parent_dir or receive_root()))
        if chosen:
            self.parent_dir = Path(chosen)
            self._sync_dir()

    def keyPressEvent(self, event) -> None:
        # A frameless card has no close box, so the two ways out have to be the two keys that
        # mean them. Esc already rejects through the default QDialog behaviour.
        if event.key() in (Qt.Return, Qt.Key_Enter):
            self.accept()
            return
        super().keyPressEvent(event)


class _Cancelled(Exception):
    """Raised inside the send worker when 取消 is pressed on its row."""

class TransferPanel(QWidget):
    _offer_arrived = Signal(dict, str, str)  # manifest, who, token
    #: The server thread gave up waiting. The card is still on screen and the user has not
    #: answered, so it has to go - a 接收 button that can no longer be honoured is a lie.
    _offer_expired = Signal(str)  # token
    #: The sender withdrew this id (§4's DELETE) while the card was still open. Same job as the
    #: expiry above, one second sooner and with a truer sentence: the other end said so on purpose.
    _offer_withdrawn = Signal(str)  # offer id
    _peers_changed = Signal()  # emitted from discovery threads
    #: The idle reclaim took a session back (spec §3). Emitted from the receiver's threads and
    #: from the panel's own tick, so the roster has to stop naming a device it cannot reach.
    _peer_lost = Signal(str)  # fingerprint
    _progressed = Signal(int, int, str)  # chunks done, chunks total, current file
    _finished = Signal(bool, str)
    #: A transfer finished and every byte of it verified. The window turns this into a tray
    #: message, which is the only way a minimized app can say a file arrived.
    arrived = Signal(str, int, str)  # who, count, human size
    #: A finished handshake arrives with its live session: sending to a device the user just
    #: connected to must not spend a second pair on the way.
    _connected_ok = Signal(object, object)  # peer, PeerConnection
    _connect_failed = Signal(str)
    #: Fired on a server thread once finalize has hashed everything; the signal is what makes
    #: it safe to paint from.
    _received_arrived = Signal(str, list)  # who, [{relpath, size, path}]
    #: A peer that dialled us and finished its handshake. Without this the roster could only
    #: ever list devices this machine phoned, and a phone sending files to a PC is the reverse.
    _peer_paired = Signal(str, str, str, str)  # fingerprint, peer_id, name, client ip
    #: The name is shown on the panel and edited in the settings window; both follow it.
    device_name_changed = Signal(str)
    #: What the platform's firewall said about this program. Read on a worker thread because
    #: asking it costs a subprocess, and only a port actually open is a reason to ask.
    _firewall_read = Signal(object)  # firewall.Status

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.proto = protocol_spec.load()
        self.identity = load_or_create(identity_dir())
        self.device_name = str(settings.get("device_name", "") or socket.gethostname())
        self._receiver: ReceiveService | None = None
        self._discovery: DiscoveryService | None = None
        self._decisions: dict[str, dict] = {}
        #: Which card each offer id is asking about. The kernel's withdrawal (§4's DELETE against a
        #: question still open) arrives with only the id, and this is the one place that knows which
        #: token was handed out for it.
        self._offer_ids: dict[str, str] = {}
        #: The offer cards currently on screen, by the token that asked for them. Only the GUI
        #: thread reads or writes this, which is what makes an expiring offer able to find its own
        #: card - the decision holder it lives next to is popped by the server thread the moment it
        #: stops waiting, and a queued close signal arrives after that.
        self._offer_cards: dict[str, _OfferDialog] = {}
        self._ask_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._staged: list[Path] = []
        self._staged_base: Path | None = None
        self._adopted = 0
        #: Devices typed in by hand. They live here rather than in the discovery roster
        #: because that one forgets peers after peer_expiry_s of silence, and a machine
        #: you had to name an address for is by definition not announcing itself.
        self._manual: list[Peer] = []
        #: Peers this machine has paired with since it opened. The card lists these, and only
        #: these: an unpaired broadcast is a candidate, not a device you can send to.
        self._connected: list[Peer] = []
        #: The live session per fingerprint. Sending reuses it so a transfer does not spend
        #: a second pair on the way, and 断开 is what gives it back.
        self._sessions: dict[str, PeerConnection] = {}
        #: The candidate picked from the dialog, waiting for its pair code to be typed.
        self._pending: Peer | None = None
        #: The peer a handshake is in flight for, so the page can say what it is doing.
        self._connecting: Peer | None = None
        self._omit_note = ""
        self._connect_worker: threading.Thread | None = None
        #: The last answer from the platform's firewall, and the thread that asked for it. None
        #: means nobody has asked yet, which the card shows as an empty line rather than as "ok".
        self._firewall: firewall.Status | None = None
        self._firewall_worker: threading.Thread | None = None
        #: Built on the first 连接… click and reused, so it keeps its scroll position.
        self._candidates: _CandidateDialog | None = None
        #: Verified arrivals, newest last. Kept on disk so the 文件 page outlives this run.
        self._received: list[dict] = self._load_arrivals()
        #: Rows in the 传输 page's task list, by task key. Only the send in flight can be
        #: cancelled; finished rows stay so the page can say what happened after it happened.
        self._task_rows: dict[str, dict] = {}
        #: Task keys the user asked to stop. The worker's progress callback reads this.
        self._cancelled: set[str] = set()
        #: Fingerprints that dialled *in*. They are connected but not reachable: an inbound
        #: peer never told us a port we could call back on, so it can receive nothing.
        self._inbound: set[str] = set()
        #: Why receiving is off, when it is off for a reason the user cannot fix by a click.
        self._receive_error = ""
        #: Last pairing string drawn as a picture, so the keep-alive tick does not re-encode
        #: a QR that has not changed.
        self._qr_payload = ""

        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_pairing)
        self._offer_arrived.connect(self._on_offer)
        self._offer_expired.connect(self._close_offer)
        self._offer_withdrawn.connect(self._withdraw_offer)
        self._peers_changed.connect(self._refresh_peers)
        self._peer_lost.connect(self._on_peer_lost)
        self._progressed.connect(self._on_progress)
        self._finished.connect(self._on_finished)
        self._connected_ok.connect(self._on_connected)
        self._connect_failed.connect(self._on_connect_failed)
        self._received_arrived.connect(self._on_received)
        self._peer_paired.connect(self._on_peer_paired)
        self._firewall_read.connect(self._on_firewall_read)
        self.retranslate()
        # Opening the app opens the port: the pairing picture is the first thing the window
        # promises, so it is painted by the launch rather than by a click that asks for it.
        self.start_listening()

    # ------------------------------------------------------------------ widgets

    def _build(self) -> None:
        """Five pages the rail can switch between, plus the record list behind the dashboard.

        Every control keeps its old attribute name: the acceptance script reaches the window
        through these objects, and a rename would turn a passing run into a missing widget.
        """
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.stack = QStackedWidget(self)
        self.page_transfer = self._build_transfer_page()
        self.page_send = self._build_send_page()
        self.page_devices = self._build_receive_page()
        self.page_files = self._build_files_page()
        self.page_history = self._build_history_page()
        for page in (self.page_transfer, self.page_send, self.page_devices,
                     self.page_files, self.page_history):
            self.stack.addWidget(page)
        outer.addWidget(self.stack, 1)

        self.status_label = QLabel()
        self.status_label.setObjectName("Muted")
        self.status_label.setWordWrap(True)
        outer.addWidget(self.status_label)

        self.setAcceptDrops(True)

    def _card(
        self, box_in: QVBoxLayout | QHBoxLayout, heading_id: str = "", stretch: int = 0
    ) -> tuple[QFrame, QLabel | None]:
        """A white sheet laid on the page, with the mockups' 16px corner and 20px padding.

        `heading_id` is a msgid rather than a string because every caption here has to survive
        a language switch, so the label is handed back for retranslate() to write.
        """
        card = QFrame(self)
        card.setObjectName("Card")
        box = QVBoxLayout(card)
        box.setContentsMargins(20, 18, 20, 18)
        box.setSpacing(10)
        heading = None
        if heading_id:
            heading = QLabel(card)
            heading.setObjectName("SectionTitle")
            heading.setProperty("msgid", heading_id)
            box.addWidget(heading)
        box_in.addWidget(card, stretch)
        return card, heading

    #: Protocol v1 carries no device class, so the glyph is guessed from the name the peer
    #: chose for itself - decoration beside a name the user can read, not a claim about it.
    _MOBILE_HINTS = ("手机", "平板", "phone", "iphone", "ipad", "android", "harmony", "hongmeng", "pixel", "mate")

    def _peer_kind(self, peer: Peer) -> str:
        name = (peer.name or peer.prefix or peer.host).lower()
        return "phone" if any(hint in name for hint in self._MOBILE_HINTS) else "desktop"

    def _device_row(self, name: str, status: str, kind: str, online: bool, sub: str = "") -> QFrame:
        """One device, drawn the way the mockups draw it: a tinted tile, a name, a status dot.

        The row is a widget rather than a text item because the list it sits in has to answer
        clicks and keyboard focus, and the picture wants three columns of type inside one row.
        """
        p = self._p
        row = QFrame()
        row.setObjectName("DeviceRow")
        box = QHBoxLayout(row)
        box.setContentsMargins(10, 8, 10, 8)
        box.setSpacing(10)
        tile = QLabel(row)
        tile.setObjectName("DeviceTile")
        tile.setFixedSize(40, 40)
        tile.setAlignment(Qt.AlignCenter)
        tile.setPixmap(icons.pixmap(kind, p.accent, 22))
        box.addWidget(tile)
        words = QVBoxLayout()
        words.setSpacing(1)
        label = QLabel(row)
        label.setObjectName("DeviceName")
        label.setText(name)
        words.addWidget(label)
        if sub:
            detail = QLabel(row)
            detail.setObjectName("MutedOnCard")
            detail.setText(sub)
            words.addWidget(detail)
        box.addLayout(words, 1)
        dot = QLabel(row)
        dot.setText(f'<span style="color:{p.ok_dot if online else p.off_dot}">●</span>'
                    f' <span style="color:{p.ok if online else p.text_muted}">{status}</span>')
        dot.setTextFormat(Qt.RichText)
        box.addWidget(dot)
        row.setAccessibleName(" ".join(part for part in (name, status, sub) if part))
        return row

    def _header(self, box_in: QVBoxLayout, title_id: str, sub_id: str = "") -> tuple[QLabel, QLabel | None]:
        """A page's own title line: the big name, and the quiet sentence beside it."""
        row = QHBoxLayout()
        row.setSpacing(12)
        title = QLabel(self)
        title.setObjectName("PageTitle")
        title.setProperty("msgid", title_id)
        row.addWidget(title)
        sub = None
        if sub_id:
            sub = QLabel(self)
            sub.setObjectName("PageSub")
            sub.setProperty("msgid", sub_id)
            sub.setWordWrap(True)
            row.addWidget(sub, 1)
        else:
            row.addStretch(1)
        box_in.addLayout(row)
        box_in.addSpacing(6)
        return title, sub

    def add_page(self, page: QWidget) -> int:
        """Let the window contribute a rail page. 设置 lives here, not in a second window."""
        return self.stack.addWidget(page)

    def show_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)

    def current_page(self) -> int:
        return self.stack.currentIndex()

    def fit_pages(self) -> None:
        """Ask every page what width it needs and what height its sentences need at that width.

        Called from a language switch, when the window has to re-derive its own floor. The second
        pass is not a belt-and-braces repeat: a stylesheet lands as an event, and until it has, a
        card reports its minimum *without* the padding the theme gives it - a pin 40px too narrow
        for the same words. Because an explicit minimum replaces the stack's own hint for the
        layout above it, that too-low number is exactly what the window then obeys, and the pages
        pay for it out of their buttons' width. So measure now, and measure once more when the
        tick that carries the polish has run.
        """
        self._pin_to_content()
        QTimer.singleShot(0, self._pin_to_content)

    def _pin_to_content(self) -> None:
        # A stacked widget sizes itself on the page that is on screen, so the window's floor would
        # be whatever page happened to be open when the layout was activated - and a page opened
        # later would find itself narrower than its own minimum. Pinning the widest page's floor
        # is what makes the promise below true: the stack can never be narrower than the widest page.
        for index in range(self.stack.count()):
            _flush_minimum_cache(self.stack.widget(index))
        self._fit_columns()
        widest = 0
        for index in range(self.stack.count()):
            page = self.stack.widget(index)
            # A layout caches the minimum it computed last time and only drops the cache when the
            # queued LayoutRequest event is processed, which is after this call: asked during a
            # language switch it answers with the previous language's number, and pinning the
            # stack to that leaves every page narrower than its own words. invalidate() clears one
            # layout and no more - the rows inside a card are layouts of their own - so the whole
            # tree under the page has to be told before any number is read.
            _flush_minimum_cache(page)
            widest = max(widest, page.minimumSizeHint().width())
        if widest:
            self.stack.setMinimumWidth(widest)
        # A minimum hint counts a wrapping label as one line. At the narrowest width the stack
        # can reach a caption needs more lines than that, and the layout paid for the difference
        # out of the buttons' height, so measure the height at the floor the width now has.
        width = self.stack.minimumSizeHint().width()
        need = 0
        for index in range(self.stack.count()):
            page = self.stack.widget(index)
            layout = page.layout()
            height = page.minimumSizeHint().height()
            if width > 0 and layout is not None and layout.hasHeightForWidth():
                height = max(height, layout.totalHeightForWidth(width))
            need = max(need, height)
        if need:
            self.stack.setMinimumHeight(need)

    def _fit_columns(self) -> None:
        """Give the two design-fixed cards the width their own captions need, and no more.

        Chinese keeps the mockup's 300px to the pixel. Russian asks for three more, and a card
        that refuses them takes them out of the button inside it - which is the one way this
        window can render a control narrower than its own text.
        """
        for card in (self.peer_card, self.mine_box):
            _flush_minimum_cache(card)
            # Reading the hint while the width is pinned answers with the pin, not the content,
            # because a layout clamps its own minimum against the widget's fixed size.
            card.setMaximumWidth(_ANY_WIDTH)
            card.setFixedWidth(max(COLUMN, card.minimumSizeHint().width()))

    # ----------------------------------------------------------------- 传输 page

    def _build_transfer_page(self) -> QWidget:
        """The dashboard the mockups call 传输: drop here, who is on the other end, what moved.

        Sending itself lives on 发送. This page only stages, because the picture that matches
        the design is the one where the drop box is the biggest thing on screen.
        """
        page = QWidget(self)
        page.setObjectName("TransferPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        self.page_title_transfer, self.page_sub_transfer = self._header(
            layout, "传书 - 文件互传", "文件放在这里，拖进来就能发给连上的设备。"
        )

        top = QHBoxLayout()
        top.setSpacing(14)
        drop_card, _heading = self._card(top, stretch=1)
        drop_card.setMinimumHeight(240)
        drop_box = drop_card.layout()
        drop_box.setContentsMargins(20, 22, 20, 20)
        drop_box.setSpacing(8)

        # The drop box is the whole left half of the page: dropping is the way anyone actually moves
        # files, and the two pickers are what a keyboard-only user has instead.
        self.drop_box = QFrame(drop_card)
        self.drop_box.setObjectName("DropZone")
        drop_layout = QVBoxLayout(self.drop_box)
        drop_layout.setContentsMargins(18, 26, 18, 26)
        drop_layout.setSpacing(6)
        self.drop_icon = QLabel(self.drop_box)
        self.drop_icon.setObjectName("DropIcon")
        # The mockup's circle is the pale blue of a tile, not a drawn ring: the arrow inside it
        # is what carries the accent, so the disc is painted here and the glyph is stroked there.
        self.drop_icon.setFixedSize(72, 72)
        self.drop_icon.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.drop_big = QLabel()
        self.drop_big.setObjectName("DropBig")
        self.drop_big.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        # Wrapping, not clipping: the mockup's line is short Chinese, but every other language
        # puts a longer sentence here, and a label without word wrap answers that by cutting the
        # tail off the one instruction on the page.
        self.drop_big.setWordWrap(True)
        self.drop_hint = QLabel()
        self.drop_hint.setObjectName("DropHint")
        self.drop_hint.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.drop_hint.setWordWrap(True)
        # The two lines inside the dashed box are the mockup's, and they only say what to drop.
        # That nothing lands until the peer says yes is the one thing about this button a user
        # can be surprised by, so it keeps its own line under the pickers rather than being cut.
        self.drop_note = QLabel()
        self.drop_note.setObjectName("Muted")
        self.drop_note.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.drop_note.setWordWrap(True)
        self.pick_files_button = QPushButton()
        self.pick_files_button.setObjectName("Inline")
        self.pick_files_button.clicked.connect(lambda: self._stage(kind="files"))
        self.pick_dir_button = QPushButton()
        self.pick_dir_button.setObjectName("Inline")
        self.pick_dir_button.clicked.connect(lambda: self._stage(kind="dir"))
        self.clear_stage_button = QPushButton()
        self.clear_stage_button.setObjectName("Inline")
        self.clear_stage_button.clicked.connect(self._clear_stage)
        pickers = QHBoxLayout()
        pickers.addStretch(1)
        pickers.addWidget(self.pick_files_button)
        pickers.addWidget(self.pick_dir_button)
        pickers.addWidget(self.clear_stage_button)
        pickers.addStretch(1)
        drop_layout.addWidget(self.drop_icon)
        # A fixed-size widget in a vertical layout sits at the left unless told otherwise, and
        # the mockup draws the disc on the box's centre line.
        drop_layout.setAlignment(self.drop_icon, Qt.AlignHCenter)
        drop_layout.addWidget(self.drop_big)
        drop_layout.addWidget(self.drop_hint)
        drop_layout.addLayout(pickers)
        drop_layout.addWidget(self.drop_note)
        drop_box.addWidget(self.drop_box, 1)

        # ---- who is on the other end ----
        peer_card, self.peer_card_title = self._card(top, "已连接设备")
        self.peer_card = peer_card
        peer_card.setFixedWidth(COLUMN)
        peer_box = peer_card.layout()
        self.peer_list = _TightList(peer_card)
        self.peer_list.setObjectName("DeviceList")
        # Host:port plus a name is wider than the column; elide it instead of letting the
        # list grow a horizontal scrollbar that hides half of every row behind it.
        self.peer_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.peer_list.currentItemChanged.connect(lambda *_: self._sync_buttons())
        # The empty state reads under the heading, not under the list: an empty list is zero
        # high, so a note placed after it would fall to the bottom of the card and look like a
        # caption for 扫码连接.
        self.peer_note = QLabel()
        self.peer_note.setObjectName("Muted")
        self.peer_note.setWordWrap(True)
        peer_box.addWidget(self.peer_note)
        peer_box.addWidget(self.peer_list, 1)
        # The mockups' one way in is the picture a phone camera reads, so it is the card's
        # primary action; typing an address by hand stays available one page over.
        self.scan_button = QPushButton(peer_card)
        self.scan_button.setObjectName("Pill")
        self.scan_button.clicked.connect(lambda: self.show_page(PAGE_RECEIVE))
        peer_box.addWidget(self.scan_button)
        layout.addLayout(top, 1)

        # Which device this is going to, and what that device asked us to write at, live on
        # 发送: this page only ever stages the files.

        record_card, _heading = self._card(layout, stretch=1)
        head = QHBoxLayout()
        self.task_title = QLabel(record_card)
        self.task_title.setObjectName("SectionTitle")
        head.addWidget(self.task_title)
        head.addStretch(1)
        self.show_history_button = QPushButton(record_card)
        self.show_history_button.setObjectName("Ghost")
        self.show_history_button.clicked.connect(lambda: self.show_page(PAGE_HISTORY))
        head.addWidget(self.show_history_button)
        record_card.layout().addLayout(head)
        # One row per transfer in flight: name, bar, speed, cancel. The protocol only lets one
        # peer hold the slot at a time, so this list holds at most the send under way plus the
        # offer someone else dialled in and we are still deciding about.
        self.task_list = _TightList(record_card)
        self.task_list.setObjectName("TaskList")
        self.task_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        record_card.layout().addWidget(self.task_list)
        # Arrivals that this session did not send sit under the live rows so the card is the
        # same answer on both pages: what moved through 传书, newest first. This one takes the
        # slack - the live list must not, or an idle card pushes yesterday's files off the bottom.
        self.recent_list = _TightList(record_card)
        self.recent_list.setObjectName("RecordList")
        self.recent_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.recent_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        record_card.layout().addWidget(self.recent_list, 1)
        return page

    # ------------------------------------------------------------------ 发送 page

    def _build_send_page(self) -> QWidget:
        """What is staged, where it is going, and the one button that starts it.

        The drop box stays on 传输, where the mockups draw it. This page is the part of the flow
        that needs room to say something: which device holds the slot, and what it asked us to
        write at.
        """
        page = QWidget(self)
        page.setObjectName("SendPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        self.page_title_send, self.page_sub_send = self._header(layout, "发送", "文件在「传输」页拖进来；这一页决定它去哪。")

        # The pace line exists because a paced transfer looks exactly like a slow network here.
        card, self.send_target_title = self._card(layout, "目标设备")
        self.peer_now_box = QGroupBox(card)
        self.peer_now_box.setObjectName("Block")
        self.peer_now_box.setTitle("")
        now_layout = QVBoxLayout(self.peer_now_box)
        self.peer_now_label = QLabel()
        self.peer_now_label.setWordWrap(True)
        self.pace_label = QLabel()
        self.pace_label.setObjectName("Muted")
        self.pace_label.setWordWrap(True)
        now_layout.addWidget(self.peer_now_label)
        now_layout.addWidget(self.pace_label)
        card.layout().addWidget(self.peer_now_box)

        card2, self.send_stage_title = self._card(layout, "这次发什么")
        self.stage_label = QLabel(card2)
        self.stage_label.setObjectName("Muted")
        self.stage_label.setWordWrap(True)
        card2.layout().addWidget(self.stage_label)
        self.progress = QProgressBar(card2)
        self.progress.setObjectName("Slim")
        # The 6px rail is the stylesheet's, but a pinned height is what tells the layout and the
        # selftest that this bar is meant to be thinner than a widget's default floor.
        self.progress.setFixedHeight(6)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.send_button = QPushButton()
        self.send_button.clicked.connect(self._start_send)
        self.send_button.setEnabled(False)
        card2.layout().addWidget(self.progress)
        card2.layout().addWidget(self.send_button)
        layout.addStretch(1)
        return page

    # ----------------------------------------------------------------- 接收 page

    def _build_receive_page(self) -> QWidget:
        """The mockups' 扫码连接手机 page: the picture, this machine's facts beside it, then
        who is out there.

        The QR and 我的设备 share a row on purpose. Stacked, the page's own minimum height went
        past what the window is designed to open at, and the picture - the one thing another
        device has to read from across a desk - is what should be setting that height.
        """
        page = QWidget(self)
        page.setObjectName("DevicesPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        self.page_title_receive, self.page_sub_receive = self._header(
            layout, "扫码连接手机", "请使用传书手机端扫描二维码完成连接"
        )
        top = QHBoxLayout()
        top.setSpacing(14)

        # ---- the picture, with the two secrets it carries beside it ----
        qr_card, _heading = self._card(top, stretch=1)
        self.qr_label = QLabel(qr_card)
        self.qr_label.setObjectName("QrBox")
        self.qr_label.setFixedSize(QR_SIZE + 8, QR_SIZE + 8)
        self.qr_label.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        self.qr_label.setToolTip(_("让对方扫这个码，就能带着配对码和密码连过来。"))
        self.code_label = QLabel(qr_card)
        self.code_label.setObjectName("PairCode")
        self.code_label.setWordWrap(True)
        # Both secrets are read out loud to whoever is on the other side of the desk, so the
        # passphrase gets the same size as the code instead of a footnote.
        self.pass_label = QLabel(qr_card)
        self.pass_label.setObjectName("PairCode")
        self.pass_label.setWordWrap(True)
        self.pass_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        secrets_column = QVBoxLayout()
        secrets_column.setSpacing(4)
        secrets_column.addWidget(self.code_label)
        secrets_column.addWidget(self.pass_label)
        # Under the picture, not beside it. The card has to survive the narrowest window the
        # rail leaves it, and a fixed 232px QR plus a column of text next to it does not.
        pairing = QVBoxLayout()
        pairing.setSpacing(10)
        pairing.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self.qr_label)
        row.addStretch(1)
        pairing.addLayout(row)
        pairing.addLayout(secrets_column)
        pairing.addStretch(1)
        # start_listening() paints this at launch; it stays hidden only if there is no port.
        self.qr_label.hide()
        qr_card.layout().addLayout(pairing, 1)

        # ---- this machine ----
        mine = QGroupBox(page)
        mine.setObjectName("Card")
        self.mine_box = mine
        mine.setFixedWidth(COLUMN)
        mine_layout = QVBoxLayout(mine)
        mine_layout.setContentsMargins(20, 18, 20, 18)
        mine_layout.setSpacing(8)

        # The name is edited right where it is shown, and the two secondary actions are inline
        # text buttons: three real buttons on one row did not fit the minimum window width.
        who = QHBoxLayout()
        self.name_label = QLabel()
        # Wrapping rather than eliding: the name is the one thing on this card the user has to
        # be able to read back, and in the wider languages it does not fit.
        self.name_label.setWordWrap(True)
        self.rename_button = QPushButton()
        self.rename_button.setObjectName("Inline")
        self.rename_button.clicked.connect(self.rename_device)
        who.addWidget(self.name_label, 1)
        who.addWidget(self.rename_button)
        self.listen_label = QLabel()
        self.channel_label = QLabel()
        self.channel_label.setObjectName("Muted")
        self.channel_label.setWordWrap(True)
        #: The inbound half of "am I reachable": discovery says whether this machine can be found,
        #: this says whether anything that found it can actually get in.
        self.firewall_label = QLabel()
        self.firewall_label.setObjectName("Muted")
        self.firewall_label.setWordWrap(True)

        where = QHBoxLayout()
        where.setSpacing(6)
        self.receive_dir_title = QLabel()
        self.receive_dir_title.setObjectName("Muted")
        # A read-only field rather than a label: a Windows path has no space to break at, so as
        # a label its single unbreakable run would set the minimum width of the whole card. The
        # field scrolls instead, and the text stays as selectable as a path needs to be.
        self.receive_dir_field = QLineEdit()
        self.receive_dir_field.setObjectName("PathField")
        self.receive_dir_field.setReadOnly(True)
        self.open_dir_button = QPushButton()
        self.open_dir_button.setObjectName("Inline")
        self.open_dir_button.clicked.connect(self._open_receive_dir)
        where.addWidget(self.receive_dir_title)
        where.addWidget(self.receive_dir_field, 1)
        where.addWidget(self.open_dir_button)

        self.refresh_pair_button = QPushButton()
        self.refresh_pair_button.setObjectName("Inline")
        self.refresh_pair_button.clicked.connect(self.rotate_pairing)

        mine_layout.addLayout(who)
        mine_layout.addWidget(self.listen_label)
        mine_layout.addWidget(self.channel_label)
        mine_layout.addWidget(self.firewall_label)
        mine_layout.addLayout(where)
        rotate = QHBoxLayout()
        rotate.addWidget(self.refresh_pair_button)
        rotate.addStretch(1)
        mine_layout.addLayout(rotate)
        mine_layout.addStretch(1)
        top.addWidget(mine)
        layout.addLayout(top)

        # ---- what discovery can see ----
        # The mockup draws 附近设备 on the page with 刷新 at the right of that heading, then a row
        # of device cards. So the heading is not inside a card and the cards are the chrome. The
        # fields the mockup has no room for - a pairing code typed by hand, an address typed by
        # hand - keep a card of their own under that row.
        near_head = QHBoxLayout()
        near_head.setSpacing(10)
        self.nearby_title = QLabel(page)
        self.nearby_title.setObjectName("SectionTitle")
        near_head.addWidget(self.nearby_title)
        near_head.addStretch(1)
        self.rescan_button = QPushButton(page)
        self.rescan_button.setObjectName("Ghost")
        self.rescan_button.clicked.connect(self._refresh_peers)
        near_head.addWidget(self.rescan_button)
        layout.addLayout(near_head)

        nearby = QWidget(page)
        self.nearby_grid = QGridLayout(nearby)
        self.nearby_grid.setContentsMargins(0, 0, 0, 0)
        self.nearby_grid.setSpacing(14)
        for column in range(_NEARBY_COLUMNS):
            self.nearby_grid.setColumnStretch(column, 1)
        layout.addWidget(nearby)

        peers = QGroupBox(page)
        peers.setObjectName("Card")
        self.peers_box = peers
        peers_layout = QVBoxLayout(peers)
        peers_layout.setContentsMargins(20, 18, 20, 18)
        peers_layout.setSpacing(10)

        self.nearby_label = QLabel()
        self.nearby_label.setObjectName("Muted")
        self.nearby_label.setWordWrap(True)
        peers_layout.addWidget(self.nearby_label)

        # The code is typed here rather than in a modal that appears mid-transfer: which device
        # it belongs to has to be readable while it is being typed.
        self.code_edit = QLineEdit()
        self.code_edit.setMaxLength(self.proto.pair_code_digits)
        self.code_edit.setClearButtonEnabled(True)
        self.code_edit.returnPressed.connect(self._start_connect)
        self.secret_edit = QLineEdit()
        self.secret_edit.setMaxLength(self.proto.passphrase_chars)
        self.secret_edit.setClearButtonEnabled(True)
        # Typed on a keypad across a desk, so it is read back exactly as shown rather than
        # dotted out; a masked field would only hide the typo the user is about to fix.
        self.secret_edit.setEchoMode(QLineEdit.Normal)
        self.secret_edit.returnPressed.connect(self._start_connect)
        self.connect_button = QPushButton()
        self.connect_button.clicked.connect(self._start_connect)
        self.pick_peer_button = QPushButton()
        self.pick_peer_button.setObjectName("Ghost")
        self.pick_peer_button.clicked.connect(self._choose_peer)
        self.disconnect_button = QPushButton()
        self.disconnect_button.setObjectName("Inline")
        self.disconnect_button.clicked.connect(self._disconnect_selected)
        code_row = QHBoxLayout()
        code_row.addWidget(self.code_edit)
        code_row.addWidget(self.secret_edit, 1)
        code_row.addWidget(self.connect_button)
        peers_layout.addLayout(code_row)
        manual = QHBoxLayout()
        manual.addWidget(self.pick_peer_button)
        manual.addWidget(self.disconnect_button)
        manual.addStretch(1)
        peers_layout.addLayout(manual)
        layout.addWidget(peers, 1)
        return page

    # -------------------------------------------------------------- 传输记录 page

    def _build_history_page(self) -> QWidget:
        """Every transfer this machine knows about, newest first, grouped by day.

        Two sources, because the honest answer to "what moved" is two questions: what is in
        flight or finished this session, and what landed on disk and survived a restart.
        """
        page = QWidget(self)
        page.setObjectName("HistoryPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        self.page_title_history, _sub = self._header(layout, "传输记录")

        chips = QHBoxLayout()
        chips.setSpacing(8)
        self.history_chips: list[QPushButton] = []
        self.history_chip_rows: dict[str, QPushButton] = {}
        for value in ("all", "running", "done", "failed"):
            chip = QPushButton(page)
            chip.setObjectName("Chip")
            chip.setCheckable(True)
            chip.setProperty("filter", value)
            chip.clicked.connect(lambda _c=False, picked=chip: self._choose_history_filter(picked))
            chips.addWidget(chip)
            self.history_chips.append(chip)
            self.history_chip_rows[value] = chip
        chips.addStretch(1)
        layout.addLayout(chips)

        card, _heading = self._card(layout, stretch=1)
        # The mockup's record list is a grouped list, not a table: a day heading, then rows that
        # read icon - name - size - status. Columns fight that, so every row is its own widget.
        self.history_list = _TightList(card)
        self.history_list.setObjectName("RecordList")
        self.history_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        card.layout().addWidget(self.history_list, 1)
        self._history_filter = "all"
        return page

    # ----------------------------------------------------------------- 文件 page

    #: The mockups filter 文件管理 by what a file is, not by when it landed. The date column
    #: sorts, so a 今天/近 7 天 pill would only re-ask a question one header click answers.
    #: N() for the same reason as the history pills above: the caption is fetched out of the
    #: dict and translated at run time, so Babel has to be told the literals live here.
    _FILE_KINDS = {
        "all": N("全部"),
        "image": N("图片"),
        "video": N("视频"),
        "doc": N("文档"),
        "archive": N("压缩包"),
    }
    _KIND_SUFFIXES = {
        "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".svg", ".tif", ".tiff"},
        "video": {".mp4", ".mov", ".mkv", ".avi", ".webm", ".flv", ".wmv"},
        "doc": {".pdf", ".doc", ".docx", ".txt", ".md", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".json"},
        "archive": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"},
    }

    @classmethod
    def _file_kind(cls, name: str) -> str:
        suffix = Path(name).suffix.lower()
        return next((kind for kind, group in cls._KIND_SUFFIXES.items() if suffix in group), "")

    def _build_files_page(self) -> QWidget:
        page = QWidget(self)
        page.setObjectName("FilesPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.page_title_files = QLabel()
        self.page_title_files.setObjectName("PageTitle")
        self.received_label = QLabel()
        self.received_label.setObjectName("PageSub")
        self.received_label.setWordWrap(True)
        # The search box shares the title row because that is where the mockup draws it, and
        # because a name is the first thing anyone reaches for once the list has twenty rows.
        self.files_search = QLineEdit()
        self.files_search.setObjectName("Search")
        self.files_search.setFixedWidth(240)
        self.files_search.setClearButtonEnabled(True)
        #: The magnifier is a QAction the line edit owns; holding it lets a theme switch repaint
        #: the same one instead of stacking a second icon in front of the text.
        self._search_action: QAction | None = None
        self.files_search.textChanged.connect(lambda _text: self._refresh_received())
        head = QHBoxLayout()
        head.setSpacing(12)
        head.addWidget(self.page_title_files)
        head.addWidget(self.received_label)
        head.addStretch(1)
        head.addWidget(self.files_search)
        layout.addLayout(head)

        self.chip_row = QHBoxLayout()
        self.chip_row.setSpacing(8)
        self.file_chips: dict[str, QPushButton] = {}
        self._chips: list[QPushButton] = []
        for value, _caption in self._FILE_KINDS.items():
            chip = QPushButton()
            chip.setObjectName("Chip")
            chip.setCheckable(True)
            chip.setProperty("filter", value)
            chip.clicked.connect(lambda _c=False, picked=chip: self._choose_filter(picked))
            self.chip_row.addWidget(chip)
            self._chips.append(chip)
            self.file_chips[value] = chip
        self.chip_row.addStretch(1)
        #: Rows are a reading list; the folder is where the bytes actually are, and the two can
        #: disagree (the user may have moved a file), so the folder gets a button of its own.
        self.open_received_dir_button = QPushButton()
        self.open_received_dir_button.setObjectName("Inline")
        self.open_received_dir_button.clicked.connect(self._open_receive_dir)
        self.chip_row.addWidget(self.open_received_dir_button)
        layout.addLayout(self.chip_row)

        # Columns, because a file list that cannot say which machine it came from or when is
        # a log, not a filing cabinet.
        card, _heading = self._card(layout, stretch=1)
        self.received_list = _TightTree(card)
        self.received_list.setObjectName("ReceivedTable")
        self.received_list.setColumnCount(4)
        self.received_list.setRootIsDecorated(False)
        self.received_list.setAlternatingRowColors(False)
        self.received_list.setSortingEnabled(True)
        self.received_list.sortByColumn(2, Qt.DescendingOrder)
        self.received_list.setSelectionBehavior(QTreeWidget.SelectRows)
        self.received_list.itemDoubleClicked.connect(self._open_received)
        # The name is the only column allowed to shrink; the rest carry numbers that must be
        # readable in full at the narrowest window the layout permits.
        header = self.received_list.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column in (1, 2, 3):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        card.layout().addWidget(self.received_list, 1)
        self._received_filter = "all"
        #: Where an arrival stopped existing on disk, so the table can say so instead of
        #: listing a row that opens nothing.
        self._missing: dict[str, str] = {}
        return page


    def retranslate(self) -> None:
        """Re-apply every visible string, including the ones set from callbacks."""
        self.page_title_transfer.setText(_("传书 - 文件互传"))
        self.page_sub_transfer.setText(_("文件放在这里，拖进来就能发给连上的设备。"))
        self.page_title_send.setText(_("发送"))
        self.page_sub_send.setText(_("文件在「传输」页拖进来；这一页决定它去哪。"))
        self.page_title_receive.setText(_("扫码连接手机"))
        self.page_sub_receive.setText(_("请使用传书手机端扫描二维码完成连接"))
        self.page_title_history.setText(_("传输记录"))
        self.page_title_files.setText(_("文件管理"))
        self.peer_card_title.setText(_("已连接设备"))
        self.peer_note.setText(_("还没有已连接的设备。点下面「扫码连接」，或在「接收」页选一台。"))
        self.scan_button.setText(_("扫码连接"))
        self.show_history_button.setText(_("查看全部"))
        self.send_target_title.setText(_("目标设备"))
        self.send_stage_title.setText(_("这次发什么"))
        self.nearby_title.setText(_("附近设备"))
        self.rescan_button.setText(_("刷新"))
        self.mine_box.setTitle(_("我的设备"))
        # The card below 附近设备 holds the typed code and address, not a list, so it has no
        # heading of its own and no frame title either.
        self.peers_box.setTitle("")
        self.drop_icon.setPixmap(icons.pixmap("arrow-up", self._p.accent, 32))
        # setIcon replaces, so this repaints the same button instead of stacking a second glyph.
        self.rescan_button.setIcon(icons.icon("refresh", self._p.accent))
        self.drop_big.setText(_("拖拽文件到此处，或点击选择"))
        self.drop_hint.setText(_("支持图片 视频 文档 压缩包"))
        self.drop_note.setText(_("对方要先点接受，文件才会落到它的接收目录。"))
        self.task_title.setText(_("传输记录"))
        for value, chip in self.file_chips.items():
            chip.setText(_(self._FILE_KINDS[value]))
        self.files_search.setPlaceholderText(_("搜索文件"))
        # QSS cannot recolour an icon, so the magnifier is re-rasterised with the palette. The
        # QAction itself is made once and only repainted - adding a fresh one per retranslate
        # would stack a leading icon in front of the text every time the theme changed.
        # The line edit sizes its own leading icon from the style, so 16px is what shows.
        if self._search_action is None:
            self._search_action = self.files_search.addAction(
                icons.icon("search", self._p.text_muted), QLineEdit.LeadingPosition
            )
        else:
            self._search_action.setIcon(icons.icon("search", self._p.text_muted))
        self.open_received_dir_button.setText(_("打开接收目录"))
        self.received_list.setHeaderLabels([_("文件名"), _("大小"), _("日期"), _("来源设备")])
        for value, chip in self.history_chip_rows.items():
            chip.setText(_(_HISTORY_FILTER_LABELS[value]))
        self.code_label.setText(self._code_text())
        self.pass_label.setText(self._pass_text())
        self.listen_label.setText(self._listen_text())
        self.channel_label.setText(self._channel_text())
        self._paint_firewall()
        self.receive_dir_title.setText(_("保存到"))
        self.receive_dir_field.setText(str(receive_root()))
        # The field scrolls to the end, which is the end that names the folder; the front of a long
        # path is then off screen with nothing marking it. The tooltip carries the whole thing.
        self.receive_dir_field.setToolTip(str(receive_root()))
        self.refresh_pair_button.setText(_("更换配对码和密码"))
        self.refresh_pair_button.setToolTip(
            _("换一组新的固定配对码和密码，二维码跟着变。已经连上的设备不受影响。")
        )
        self.open_dir_button.setText(_("打开"))
        self.open_dir_button.setToolTip(_("打开接收目录"))
        self.rename_button.setText(_("编辑"))
        self.name_label.setText(_("本机：{name}").format(name=self.device_name))
        self.received_label.setText(_("收到的文件都校验通过、已经落盘。记录存在本机，重启也还在。"))
        self.pick_files_button.setText(_("选择文件…"))
        self.pick_dir_button.setText(_("选择文件夹…"))
        self.clear_stage_button.setText(_("清空"))
        self.pick_peer_button.setText(_("手输地址…"))
        self.pick_peer_button.setToolTip(_("没在附近列表里的设备，可以输入它的地址，或粘贴 chuanshu:// 配对串。"))
        self.disconnect_button.setText(_("断开"))
        self.nearby_label.setText(self._nearby_text())
        self.code_edit.setPlaceholderText(_("{n} 位配对码").format(n=self.proto.pair_code_digits))
        self.code_edit.setToolTip(
            _("输入对方屏幕上显示的 {n} 位配对码。本机存过它的密钥时留空即可，用签名重连。").format(n=self.proto.pair_code_digits)
        )
        self.secret_edit.setPlaceholderText(_("连接密码（可留空）"))
        self.secret_edit.setToolTip(
            _(
                "输入对方屏幕上显示的 {n} 位连接密码。对方是还没有密码的旧版本时留空，"
                "这时只用配对码完成首次配对。"
            ).format(n=self.proto.passphrase_chars)
        )
        self.connect_button.setText(_("连接"))
        self.connect_button.setToolTip(self._connect_tip())
        self.send_button.setText(_("发送给所选设备"))
        self.qr_label.setToolTip(_("让对方扫这个码，就能带着配对码和密码连过来。"))
        self.peer_now_label.setText(self._peer_now_text())
        self.pace_label.setText(self._pace_text())
        self.stage_label.setText(self._stage_text())
        self.status_label.setText(self._status_text())
        for row in self._task_rows.values():
            # A closed row's button is its verdict, not a control: retranslating must not turn
            # 完成 back into 取消 and offer a cancel for bytes that already landed.
            if not row["done"]:
                row["cancel"].setText(_("取消"))
        self._sync_chips()
        self._refresh_peers()
        self._refresh_received()
        self._refresh_history()

    # -------------------------------------------------------------- receiving

    def _new_receiver(self, port: int, root: Path) -> ReceiveService:
        """One construction path, so the retry on an ephemeral port cannot forget a callback.

        ``_received_arrived`` is the thread hop: finalize hashes on a server thread and only
        the signal makes it safe to paint the arrival. ``_peer_paired`` is the same hop for a
        handshake that came in from the outside, which is the only way a device that dialled
        us can reach the roster at all.
        """
        return ReceiveService(
            self.identity,
            self.device_name,
            self._decide,
            port=port,
            root=root,
            on_received=self._received_arrived.emit,
            on_paired=self._peer_paired.emit,
            on_lost=self._peer_lost.emit,
            on_withdrawn=self._offer_withdrawn.emit,
        )

    def _ensure_discovery(self) -> DiscoveryService:
        """The window's one discovery service, in hear-only form until a port is reported to it.

        Spec §2 separates 播 from 听: this object starts with `port=None`, which announces nothing and
        registers nothing (§2's no-listener end - the same shape `ChuanShu-cli peers` runs) while the mDNS
        browse and the 43721 listener still fill 附近设备. Opening the port is then one call, not a rebuild.
        """
        if self._discovery is None:
            self._discovery = DiscoveryService(
                self.identity, self.device_name, None, on_change=self._peers_changed.emit
            )
            self._discovery.start()
        elif self._discovery.device_name != self.device_name:
            # 改名 is a settings write, and this window now keeps one service across 停止接收, so the new
            # name has to be pushed into the beacons instead of arriving with a rebuilt object.
            self._discovery.set_device_name(self.device_name)
        return self._discovery

    def start_listening(self) -> None:
        if self._receiver is not None:
            return
        self._receive_error = ""
        root = receive_root()
        root.mkdir(parents=True, exist_ok=True)
        service: ReceiveService
        try:
            service = self._new_receiver(self.proto.transport_port, root)
        except OSError as error:
            # A second instance on this machine, or something else on the port: the
            # advertised real port comes from mDNS/UDP/QR, so an ephemeral one is fine.
            log.warning("port %d unavailable (%s), binding an ephemeral port", self.proto.transport_port, error)
            try:
                service = self._new_receiver(0, root)
            except OSError as second:
                # Nothing to bind at all - no usable interface, or sockets denied. The window
                # still has to open, and sending from it works, so say what is unavailable.
                log.error("could not bind a receiving port: %s", second)
                self._receive_error = str(second)
                self.status_label.setText(self._status_text())
                return
        self._adopted = service.adopt_interrupted_offers()
        service.start()
        self._receiver = service
        # The port came up, so this end's announcing halves follow it (§2): the beat starts naming this
        # number and the DNS-SD record goes up. 听 was already running - it never waited for this moment.
        self._ensure_discovery().set_port(service.port)
        self._timer.start(CODE_REFRESH_MS)
        # Announcing starts with the port: a machine that is up is a machine worth finding.
        self.qr_label.show()
        self._refresh_pairing()
        self._read_firewall(service.port)
        log.info("receiving enabled with %d interrupted offer(s) adopted", self._adopted)

    def stop_listening(self) -> None:
        self._timer.stop()
        if self._discovery is not None:
            # Only the announcing halves stop: the record comes down and the beat goes quiet, while the
            # browser and the 43721 listener stay - a person who turned receiving off may still want to
            # find someone to send to (spec §2, and the reason 附近设备 used to empty out here).
            self._discovery.set_port(None)
        if self._receiver is not None:
            self._receiver.stop()
            self._receiver = None
        # The answer was about a port that is now closed, and the next listen may well land on a
        # different number - so it is dropped rather than kept on screen as a stale guarantee.
        self._firewall = None
        # Closing the port ended every session accepted through it, so a row that only ever
        # meant "someone dialled us" would be promising a connection that no longer exists.
        self._connected = [peer for peer in self._connected if peer.fingerprint not in self._inbound]
        self._inbound.clear()
        self._qr_payload = ""
        self.qr_label.clear()
        self.qr_label.hide()
        self.listen_label.setText(self._listen_text())
        self.channel_label.setText(self._channel_text())
        self._paint_firewall()

    def rotate_pairing(self) -> None:
        """更换配对码和密码: mint a fresh fixed pair and repaint the picture that carries them.

        Pins survive: this decides what a *stranger* must get right, and a device already
        holding a session proved that once. Revoking those is 断开 plus the pin list.
        """
        self.identity.rotate_pairing(self.proto.pair_code_digits, self.proto.passphrase_chars)
        self._qr_payload = ""
        self._refresh_pairing()
        self.status_label.setText(_("已换成新的配对码和密码，旧二维码作废。已连接的设备不受影响。"))

    def _code_text(self) -> str:
        """The big label beside the QR. Fixed until 更换配对码和密码 is clicked."""
        if self._receiver is None:
            return _("配对码要等接收端口打开才有")
        return _("配对码：{code}").format(code=self._receiver.current_pair_code())

    def _pass_text(self) -> str:
        if self._receiver is None or not self._receiver.passphrase():
            return ""
        return _("密码：{secret}").format(secret=self._receiver.passphrase())

    def _listen_text(self) -> str:
        if self._receive_error:
            return _("本机接收端口没有打开。")
        if self._receiver is None:
            return _("接收已停止，对方连不进来。")
        return _("端口：{port}").format(port=self._receiver.port)

    def _channel_text(self) -> str:
        if self._discovery is None:
            return ""
        states = {name: channel.state for name, channel in self._discovery.channels.items()}
        down = [name for name, state in states.items() if state != "ok"]
        if not down:
            return _("发现通道：mDNS 与 UDP 都可用。")
        labels = {"mdns": _("mDNS"), "udp": _("UDP 广播")}
        reason = "、".join(labels[name] for name in down)
        if len(down) == 2:
            return _("发现通道：{which} 都不可用，只能手输地址或粘贴配对串。").format(which=reason)
        return _("发现通道：{which} 不可用，仍可手输地址或粘贴配对串。").format(which=reason)

    def _firewall_text(self) -> str:
        """One line about whether a device that *found* this machine can also get in.

        The card already says the port is open and that discovery works; those two facts together
        are what a user reads as "ready", and neither of them can see a block rule the platform
        wrote against this exe. So the inbound half is said on its own, in the four states the
        reader can actually tell apart - and never as an all-clear nobody checked.
        """
        status = self._firewall
        if status is None or self._receiver is None:
            return ""
        if status.verdict == "open":
            return _("入站：防火墙放行了，别人连得进来。")
        if status.verdict == "blocked":
            return _("入站：防火墙挡着——本机在听 {port}，但这个程序名下留着阻止入站的规则，对方连不进来。").format(
                port=self._receiver.port
            )
        if status.verdict == "no_allow":
            return _("入站：防火墙没放行——本机在听 {port}，但没有任何规则让对端连进来。").format(port=self._receiver.port)
        return _("入站：读不到防火墙的状态，所以这句话给不了保证。")

    def _paint_firewall(self) -> None:
        """The line plus the facts behind it, so a verdict on screen can always be read back."""
        self.firewall_label.setText(self._firewall_text())
        status = self._firewall
        if status is None:
            self.firewall_label.setToolTip("")
            return
        lines = [f"{status.tool}  {firewall.word(status.profile) or '-'}  {firewall.on_off(status.enabled)}"]
        lines += [
            f"{firewall.word(rule.action)} {firewall.word(rule.direction)} "
            f"{'、'.join(firewall.word(p) for p in rule.profiles) or '-'}  {rule.name}"
            for rule in status.rules
        ]
        lines += list(status.notes) + list(status.failed)
        if status.verdict != "open":
            lines.append(_("要放行，自己提权跑这几条（传书不替你写规则）："))
            lines += firewall.fix_commands(status, APP_NAME)
        self.firewall_label.setToolTip("\n".join(lines))

    def _read_firewall(self, port: int) -> None:
        """Ask the platform on a worker thread - answering costs a subprocess, not a syscall.

        Asked once per listen, not once per tick: a block rule does not appear and disappear between
        repaints, and a reader that polled would put a subprocess on the machine every five seconds
        for the life of the app.
        """
        self._firewall = None
        self._paint_firewall()
        self._firewall_worker = threading.Thread(
            target=self._read_firewall_run, args=(port,), name="chuanshu-firewall", daemon=True
        )
        self._firewall_worker.start()

    def _read_firewall_run(self, port: int) -> None:
        """The worker's body. Nothing here reaches the panel as an exception: an unreadable
        platform is one of the states the card has a sentence for."""
        try:
            status = firewall.inspect(port=port)
        except Exception as error:  # noqa: BLE001 - the reader is where the surprises are
            log.warning("could not ask the firewall: %s", error)
            status = firewall.Status(tool="error", port=port, failed=(f"{type(error).__name__}: {error}",))
        self._firewall_read.emit(status)

    def _on_firewall_read(self, status: firewall.Status) -> None:
        self._firewall = status
        self._paint_firewall()

    def _status_text(self) -> str:
        if self._receive_error:
            return _("这台机器开不了接收端口，但仍能主动发出去：{error}").format(error=self._receive_error)
        if self._adopted and self._receiver is not None:
            return _("上次有 {n} 个传输没传完，对方接着传就会续上。").format(n=self._adopted)
        return ""

    def _refresh_pairing(self) -> None:
        if self._receiver is None or self._discovery is None:
            return
        # The same tick that repaints the pairing picture is what notices a peer going quiet:
        # a stalled connection sends no requests, so nothing else would sweep while it stalls.
        self._receiver.sweep()
        payload = self._discovery.pairing_qr(
            self._receiver.current_pair_code(), host=local_ipv4(), passphrase=self._receiver.passphrase()
        )
        # The secrets are fixed now, so the only thing that moves under the picture is the
        # LAN address, or the port after a collision. Re-encoding a QR that reads the same
        # would be work the screen never asked for.
        if payload != self._qr_payload:
            self._qr_payload = payload
            try:
                self.qr_label.setPixmap(_qr_pixmap(payload))
            except Exception:  # noqa: BLE001 - a missing QR must not stop receiving
                log.exception("could not paint the pairing QR; the code below still works")
                self.qr_label.clear()
        self.code_label.setText(self._code_text())
        self.pass_label.setText(self._pass_text())
        self.listen_label.setText(self._listen_text())
        self.channel_label.setText(self._channel_text())
        self._paint_firewall()

    def _open_receive_dir(self) -> None:
        root = receive_root()
        root.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(root)))

    def rename_device(self) -> None:
        """The inline 编辑 button: ask for a name, then hand it to set_device_name()."""
        name, ok = QInputDialog.getText(self, _("设备名"), _("这台设备对别人显示的名字："), text=self.device_name)
        if ok:
            self.set_device_name(name)

    def set_device_name(self, name: str) -> bool:
        """Adopt a new broadcast name. False when there was nothing to change."""
        name = (name or "").strip()
        if not name or name == self.device_name:
            return False
        self.device_name = name
        self.settings.set("device_name", name)
        self.restart_services()
        self.device_name_changed.emit(name)
        return True

    def restart_services(self) -> None:
        """Re-open everything that carries a setting: the name travels inside the beacons,
        and the receive folder is read when the service is built.

        Peers keep their pins across a restart, so only the session tokens reset.
        """
        was_listening = self._receiver is not None
        self.stop_listening()
        if was_listening:
            self.start_listening()
        self.retranslate()
        if was_listening:
            log.info("services restarted with name=%s", self.device_name)

    # ------------------------------------------------------- incoming decisions

    def _decide(self, manifest: dict, who: str, caller: str) -> bool | Path:
        """Called from a server thread; blocks until the user answers or the offer lapses."""
        token = secrets.token_hex(6)
        holder = {"answer": False, "event": threading.Event(), "withdrawn": False}
        offer_id = str(manifest.get("offer_id") or "")
        with self._ask_lock:
            self._decisions[token] = holder
            if offer_id:
                self._offer_ids[offer_id] = token
        self._offer_arrived.emit(manifest, who or f"{caller[:12]}…", token)
        if not holder["event"].wait(self.proto.offer_wait_timeout_s + 5.0):
            log.warning("nobody answered offer %s", manifest.get("offer_id"))
            # Closing it is a GUI-thread job, and this is not the GUI thread.
            self._offer_expired.emit(token)
        with self._ask_lock:
            self._decisions.pop(token, None)
            if offer_id and self._offer_ids.get(offer_id) == token:
                self._offer_ids.pop(offer_id, None)
        return holder["answer"]

    def _on_offer(self, manifest: dict, who: str, token: str) -> None:
        with self._ask_lock:
            holder = self._decisions.get(token)
            withdrawn = bool((holder or {}).get("withdrawn"))
        if withdrawn:
            # The sender withdrew this id (§4's DELETE) in the moment before the card got up. Asking
            # now would promise a transfer nobody is left to fill - and the kernel answers
            # OFFER_UNKNOWN whatever is tapped, so the honest move is to stop asking out loud.
            log.info("offer %s withdrawn before its card opened", token)
            self.status_label.setText(_("对方撤回了这次发送，确认框已关闭。"))
            self._resolve(token, False)
            return
        dialog = _OfferDialog(self, manifest, who)
        dialog.move(self._center_of(dialog))
        self._offer_cards[token] = dialog
        answer: bool | Path = False
        try:
            if dialog.exec() == QDialog.Accepted:
                # True means "the usual place"; the Path is a parent the user chose for this
                # transfer alone. Either way the receiver files the batch under its own folder.
                answer = dialog.parent_dir or True
        finally:
            self._offer_cards.pop(token, None)
            self._resolve(token, answer)

    def _center_of(self, dialog: QDialog) -> QPoint:
        """Where to put a frameless card: the middle of the window it is asking a question of."""
        host = self.window()
        frame = host.geometry() if host.isMaximized() else host.frameGeometry()
        size = dialog.sizeHint()
        return QPoint(frame.center().x() - size.width() // 2, frame.center().y() - size.height() // 2)

    def _close_offer(self, token: str, withdrawn: bool = False) -> None:
        """Throw away a card whose server thread has already stopped waiting for an answer."""
        dialog = self._offer_cards.get(token)
        if dialog is None:
            return
        log.info("offer card for %s closed unanswered", token)
        self.status_label.setText(
            _("对方撤回了这次发送，确认框已关闭。") if withdrawn
            else _("对方的这次发送已经等不到回答，确认框已关闭。")
        )
        # done() rather than close(): the card is in a nested modal loop, and this is the call that
        # both ends it and says which answer it ended with - 拒绝, the only one still true.
        dialog.done(QDialog.Rejected)

    def _withdraw_offer(self, offer_id: str) -> None:
        """The sender said, on the wire, that this id is dropped (§4's 「中止并清理」) while the card
        is still open. Writing down the fact first is what lets a card that has not reached the
        screen yet refuse to appear, and the server thread waiting on it answer 拒绝 rather than
        allocate a folder for bytes nobody is left to send.
        """
        with self._ask_lock:
            token = self._offer_ids.get(offer_id, "")
            holder = self._decisions.get(token)
            if holder is not None:
                holder["withdrawn"] = True
        if token:
            self._close_offer(token, withdrawn=True)

    def _resolve(self, token: str, answer: bool | Path) -> None:
        with self._ask_lock:
            holder = self._decisions.get(token)
        if holder is not None:
            holder["answer"] = answer
            holder["event"].set()

    # -------------------------------------------------------------- the roster

    def _selected(self) -> Peer | None:
        """The connected peer the row list points at; None while the hint row is current."""
        item = self.peer_list.currentItem()
        if item is None:
            return None
        data = item.data(Qt.UserRole)
        return data if isinstance(data, Peer) else None

    def _candidate_peers(self) -> list[Peer]:
        """What discovery is announcing right now, plus anything typed in by hand.

        These are candidates, never rows in the main list: pairing is what turns one into a
        device you can send to, and the card above only lists the ones that got paired.
        """
        peers = list(self._discovery.candidates()) if self._discovery is not None else []
        seen = {peer.prefix for peer in peers}
        peers += [peer for peer in self._manual if peer.prefix not in seen]
        return sorted(peers, key=lambda peer: (peer.name or peer.prefix, peer.host))

    def _pin_known(self, peer: Peer) -> bool:
        """Whether this machine's pin list already holds the key behind a candidate.

        A candidate carries only the advertised prefix until it is verified, so that prefix is
        all a blank code can be allowed for - the handshake itself proves the rest.
        """
        if peer.verified:
            return self.identity.is_trusted(peer.fingerprint)
        return bool(peer.prefix) and any(fp.startswith(peer.prefix) for fp in self.identity.pinned_fingerprints())

    def _nearby_text(self) -> str:
        """The line under 附近设备 that says what 连接 will act on. The list itself cannot carry
        that: a row is only a broadcast until a code is typed for it."""
        if self._connecting is not None:
            peer = self._connecting
            return _("正在连接 {name}（{host}）…").format(name=peer.name or peer.prefix or peer.host, host=peer.host)
        if self._pending is not None:
            peer = self._pending
            name = peer.name or peer.prefix or peer.host
            if self._pin_known(peer):
                return _("已选择 {name}（{host}）。本机存过它的密钥，留空配对码点连接。").format(name=name, host=peer.host)
            return _("已选择 {name}（{host}）。输入它屏幕上的 {n} 位配对码{extra}，再点连接。").format(
                name=name, host=peer.host, n=self.proto.pair_code_digits, extra=_("和 {m} 位密码").format(m=self.proto.passphrase_chars)
            )
        holder = self._locked_out()
        if holder is not None:
            return _("一次只连一台，现在连着 {name}。要换设备先点「断开」。").format(name=holder.name or holder.prefix)
        if self._discovery is None:
            # Only reachable in the moments before the window finishes building or after it closes: the
            # listener is up for the whole life of the page now, including while 接收 is off, so this says
            # what the list looks like rather than blaming a mode the person could not be in.
            return _("附近暂时没有广播出来的设备。点「手输地址…」填对方地址，或让它扫上面的码。")
        count = len(self._candidate_peers())
        if not count:
            return _("附近暂时没有广播出来的设备。点「手输地址…」填对方地址，或让它扫上面的码。")
        return _("点上面一台设备选中它，再填配对码连接；没广播出来的点「手输地址…」。")

    def _is_inbound(self, peer: Peer) -> bool:
        """True for a peer that dialled us: connected, but with no address to send through."""
        return peer.fingerprint in self._inbound and peer.fingerprint not in self._sessions

    def _device_card(
        self, name: str, status: str, kind: str, online: bool, chosen: bool = False
    ) -> QPushButton:
        """One discovered device, drawn the way the mockup draws it: a round tile, a name, a dot.

        A button rather than a frame because it is the thing you pick a target with, and a
        QPushButton gives the keyboard a stop on the way to the pairing code below it.
        """
        p = self._p
        card = QPushButton()
        card.setObjectName("DeviceCard")
        card.setCheckable(True)
        card.setChecked(chosen)
        # QPushButton sizes itself from its text and icon, and this one has neither. Left alone it
        # reports an empty button's height, the grid row honours that, and the card is a bare bar.
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        box = QVBoxLayout(card)
        box.setContentsMargins(16, 14, 16, 14)
        box.setSpacing(6)
        row = QHBoxLayout()
        row.setSpacing(10)
        tile = QLabel(card)
        tile.setObjectName("DeviceTileRound")
        tile.setFixedSize(40, 40)
        tile.setAlignment(Qt.AlignCenter)
        tile.setPixmap(icons.pixmap(kind, p.accent, 22))
        row.addWidget(tile)
        words = QVBoxLayout()
        words.setSpacing(2)
        label = QLabel(card)
        label.setObjectName("DeviceName")
        label.setText(name)
        label.setWordWrap(True)
        words.addWidget(label)
        dot = QLabel(card)
        dot.setTextFormat(Qt.RichText)
        dot.setText(
            f'<span style="color:{p.ok_dot if online else p.off_dot}">●</span>'
            f' <span style="color:{p.ok if online else p.text_muted}">{status}</span>'
        )
        words.addWidget(dot)
        row.addLayout(words, 1)
        box.addLayout(row)
        card.setAccessibleName(f"{name} {status}")
        return card

    def _clear_nearby(self) -> None:
        """Empty the grid without deleting a card while its own clicked handler is running.

        ``takeAt`` leaves the widget parented, so a card waiting for deleteLater keeps painting
        at its last geometry - which, once the grid has re-flowed, is on top of another card.
        """
        while self.nearby_grid.count():
            widget = self.nearby_grid.takeAt(0).widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _refresh_nearby(self) -> None:
        """The 附近设备 row under the picture: one card per beacon discovery is hearing now.

        A candidate is a broadcast, not a session, so the cards say 在线 rather than promising
        that 连接 will work; the line under them is what names the next step.
        """
        self._clear_nearby()
        connected = {peer.fingerprint for peer in self._connected if peer.fingerprint}
        for index, peer in enumerate(self._candidate_peers()):
            name = peer.name or peer.prefix or peer.host
            linked = peer.fingerprint in connected
            # Choosing a candidate here names whose code belongs in the box below; it does not
            # connect, so the card stays clickable even for a device already paired.
            card = self._device_card(
                name,
                _("已连接") if linked else _("在线"),
                self._peer_kind(peer),
                True,
                chosen=self._pending is not None and self._pending.fingerprint == peer.fingerprint,
            )
            # The mockup's card is two lines, so the address it has no room for goes to the
            # pointer: it is the one number that says which machine this beacon came from.
            card.setToolTip(
                _("{addr}\n指纹前缀 {fp}；发现于 {via}。{state}").format(
                    addr=f"{peer.host}:{peer.port}",
                    fp=peer.prefix or _("未知"),
                    via="+".join(sorted(peer.via)) or _("手动添加"),
                    state=_("已连接") if linked else _("在线"),
                )
            )
            card.clicked.connect(lambda _c=False, picked=peer: self._set_pending(picked))
            self.nearby_grid.addWidget(card, index // _NEARBY_COLUMNS, index % _NEARBY_COLUMNS)

    def _refresh_peers(self) -> None:
        """Paint the connected roster. Discovery callbacks land here too, where they may only
        move the candidate count - a broadcast has no session to send through."""
        current = self._selected()
        self.peer_list.clear()
        for peer in self._connected:
            item = QListWidgetItem()
            # The mockup's row is one line: tile, name, dot. The address it has no room for goes
            # to the pointer - except when the device dialled us, because "you cannot send to
            # this one" is a state, not a detail, and a state has to be on the row.
            inbound = self._is_inbound(peer)
            row = self._device_row(
                peer.name or peer.prefix, _("在线"), self._peer_kind(peer), True,
                sub=_("（对方连进来，只能收）") if inbound else "")
            row.setProperty("chosen", current is not None and peer.fingerprint == current.fingerprint)
            row.setToolTip(
                _("指纹前缀 {fp}。它主动连进来，本机没有可回拨的地址，所以只能收它的文件。"
                  "要发给它，请由它来连本机。").format(fp=peer.prefix)
                if inbound
                else _("指纹前缀 {fp}，地址 {addr}。已配对，会话保留到点断开为止。").format(
                    fp=peer.prefix, addr=f"{peer.host}:{peer.port}")
            )
            item.setData(Qt.UserRole, peer)
            item.setSizeHint(row.sizeHint())
            self.peer_list.addItem(item)
            self.peer_list.setItemWidget(item, row)
            if current is not None and peer.fingerprint == current.fingerprint:
                self.peer_list.setCurrentItem(item)
        self.peer_note.setVisible(not self._connected)
        # The card is the truth about who holds this device's one session, in either direction,
        # so the receiver's door is set from here rather than from each place that moves a row.
        if self._receiver is not None:
            self._receiver.hold_slot_for(self._connected[0].fingerprint if len(self._connected) == 1 else "")
        self.nearby_label.setText(self._nearby_text())
        self._refresh_nearby()
        self._sync_buttons()

    def _on_peer_paired(self, fingerprint: str, peer_id: str, name: str, client_ip: str) -> None:
        """A device finished its handshake against this machine, so the roster has to say so.

        Discovery may already know it, and then the candidate's own address and name win;
        the socket's peer address is the fallback for a peer nobody broadcast.
        """
        if not fingerprint:
            return
        prefix = fingerprint[: self.proto.prefix_chars]
        known = next((peer for peer in (*self._connected, *self._candidate_peers()) if peer.fingerprint == fingerprint), None)
        peer = known or Peer(prefix=prefix, host=client_ip, port=0, via={"inbound"})
        peer.fingerprint = fingerprint
        peer.peer_id = peer.peer_id or peer_id
        peer.name = name or peer.name or peer.prefix
        if known is None:
            peer.host = client_ip
        self._inbound.add(fingerprint)
        # Newest last, and a peer that was already listed moves to the end rather than doubling.
        self._connected = [p for p in self._connected if p.fingerprint != fingerprint] + [peer]
        self._refresh_peers()
        self.status_label.setText(
            _("{name} 已连上本机（{ip}），现在只等它发文件过来。").format(name=peer.name or peer.prefix, ip=client_ip)
        )
        log.info("paired inbound from %s at %s", peer.name, client_ip)

    def _select_row(self, peer: Peer) -> None:
        for row in range(self.peer_list.count()):
            if self.peer_list.item(row).data(Qt.UserRole) is peer:
                self.peer_list.setCurrentItem(self.peer_list.item(row))
                return

    def _choose_peer(self) -> None:
        """The 手输地址… button: the picker, which also re-lists candidates and can verify a
        bare address. The inline 附近设备 list cannot do that second half."""
        box = _CandidateDialog(self, self)
        if box.exec() and box.chosen is not None:
            self._set_pending(box.chosen)

    def _set_pending(self, peer: Peer) -> None:
        """Make a candidate the target of the next handshake - or select it if it is already paired."""
        connected = next((p for p in self._connected if p.fingerprint and p.fingerprint == peer.fingerprint), None)
        if connected is not None:
            self._pending = None
            self._refresh_peers()
            self._select_row(connected)
            self.status_label.setText(_("{name} 已经连着，选文件发送即可。").format(name=connected.name or connected.prefix))
            return
        self._pending = peer
        self._refresh_nearby()
        self.nearby_label.setText(self._nearby_text())
        self.code_edit.setFocus()

    def verify_address(self, text: str) -> tuple[Peer | None, str]:
        """Reach a device discovery never showed, the way the empty roster promises.

        This works with our own receiver off: verifying an address is one outgoing request,
        and a machine that is not listening has no reason not to send files.
        """
        try:
            host, port, prefix = protocol_spec.split_addr(text, self.proto)
            peer = verify_peer(self.proto, Peer(prefix=prefix, host=host, port=port, via={"manual"}))
        except protocol_spec.ProtocolError as error:
            return None, _("{addr} 应答了，但不是能配的版本：{why}").format(addr=text, why=proto_errors.describe(error.code))
        except (OSError, ValueError) as error:
            log.info("manual add of %s failed: %s", text, error)
            return None, _("连不上 {addr}：{error}").format(addr=text, error=getattr(error, "strerror", None) or error)
        peer.prefix = peer.fingerprint[: self.proto.prefix_chars]
        known = {existing.fingerprint for existing in (*self._manual, *self._connected)}
        if peer.fingerprint not in known:
            self._manual.append(peer)
        log.info("added %s (%s) by hand", peer.name, peer.host)
        return peer, ""

    # --------------------------------------------------------------- connect

    def _locked_out(self, peer: Peer | None = None) -> Peer | None:
        """The device holding the one session slot, when it is not the one being connected.

        One peer at a time is what the user asked for and what the receiver enforces, so the
        page has to refuse before the handshake does - otherwise 连接 looks broken rather
        than busy.
        """
        if not self._connected:
            return None
        target = peer or self._pending
        if target is not None and any(held.fingerprint == target.fingerprint for held in self._connected):
            return None
        return self._connected[0]

    def _connect_tip(self) -> str:
        holder = self._locked_out()
        if holder is not None:
            return _("一次只连一台。先断开 {name}，再连新设备。").format(name=holder.name or holder.prefix)
        return _("用上面的配对码和密码连接选中的设备。")

    def _start_connect(self) -> None:
        """连接: verify the candidate and pair with the code and password on the page.

        A blank code is an answer only when the pin list already holds that key - signature-only
        re-pairing is what the contract allows for a pinned peer, and nothing else.
        """
        if self._connect_worker is not None and self._connect_worker.is_alive():
            return
        peer = self._pending
        if peer is None:
            self.status_label.setText(_("先在「附近设备」里点一台，或点「手输地址…」填它的地址。"))
            return
        holder = self._locked_out(peer)
        if holder is not None:
            self.status_label.setText(
                _("本机一次只连一台，现在连着 {name}。要先点「断开」再连它。").format(name=holder.name or holder.prefix)
            )
            return
        code = self.code_edit.text().strip()
        if not code and not self._pin_known(peer):
            self.status_label.setText(_("还差对方屏幕上那 {n} 位配对码。").format(n=self.proto.pair_code_digits))
            return
        secret = self.secret_edit.text().strip()
        why = (protocol_spec.code_reject(code, self.proto) if code else "") or protocol_spec.pass_reject(
            secret, self.proto
        )
        if why:
            self.status_label.setText(why)
            return
        # §3: a blank box puts no `secret` on the wire, and the peer then authenticates this key
        # by the 6-digit code alone. Nothing refuses that, so this end is the only place it is heard.
        self._omit_note = (
            protocol_spec.pass_omitted(secret, self.proto) if code and not self._pin_known(peer) else ""
        )
        if self._omit_note:
            self.status_label.setText(self._omit_note)
        self._connecting = peer
        self.nearby_label.setText(self._nearby_text())
        self._sync_buttons()
        self._connect_worker = threading.Thread(
            target=self._connect_run, args=(peer, code, secret), name="chuanshu-connect", daemon=True
        )
        self._connect_worker.start()

    def _connect_run(self, peer: Peer, code: str, secret: str = "") -> None:
        conn: PeerConnection | None = None
        try:
            target = peer if peer.verified else verify_peer(self.proto, peer)
            conn = PeerConnection(self.identity, self.device_name, target.host, target.port, target.fingerprint)
            conn.hello()
            # The digest is only known after verifying, so the pin check happens here too.
            if self.identity.is_trusted(target.fingerprint):
                conn.pair()
            else:
                conn.pair(code, secret)
        except (PairNeeded, WrongPairCode) as error:
            self._close_quietly(conn)
            self._connect_failed.emit(refusal_text(error, self.proto))
        except PeerIdentityMismatch:
            self._close_quietly(conn)
            self._connect_failed.emit(_("配对应答里的指纹和 hello 不一致，已中止"))
        except protocol_spec.ProtocolError as error:
            self._close_quietly(conn)
            detail = error.detail if isinstance(error.detail, dict) else {}
            if error.code == "PEER_BUSY" and detail.get("reason") == "one peer at a time":
                self._connect_failed.emit(
                    _("它已经连着 {peer}，一次只允许一台。请那边先断开。").format(peer=detail.get("peer") or "?")
                )
            else:
                self._connect_failed.emit(_("对方说：{text}").format(text=proto_errors.describe(error.code)))
        except (OSError, RuntimeError, ValueError) as error:
            log.info("connect to %s failed: %s", peer.host, error)
            self._close_quietly(conn)
            self._connect_failed.emit(_("连不上 {addr}：{error}").format(addr=f"{peer.host}:{peer.port}", error=getattr(error, "strerror", None) or error))
        else:
            self._connected_ok.emit(target, conn)

    @staticmethod
    def _close_quietly(conn: PeerConnection | None) -> None:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass

    def _on_connected(self, peer: Peer, conn: PeerConnection) -> None:
        self._connecting = None
        self._pending = None
        old = self._sessions.get(peer.fingerprint)
        if old is not None and old is not conn:
            self._close_quietly(old)
        self._sessions[peer.fingerprint] = conn
        # This machine dialled it, so the row is no longer the receive-only kind even when the
        # same device had been accepted from the other direction first.
        self._inbound.discard(peer.fingerprint)
        self._connected = [p for p in self._connected if p.fingerprint != peer.fingerprint]
        self._connected.append(peer)
        # Neither secret is spendable twice, so neither stays on screen inviting a second try.
        self.code_edit.clear()
        self.secret_edit.clear()
        self._refresh_peers()
        self._select_row(peer)
        self.status_label.setText(
            _("已连接 {name}，指纹前缀 {fp}。核对无误再发。").format(name=peer.name or peer.prefix, fp=peer.prefix)
            + self._omit_note
        )
        self._omit_note = ""
        log.info("paired with %s at %s:%d", peer.name, peer.host, peer.port)

    def _on_connect_failed(self, reason: str) -> None:
        self._connecting = None
        self._omit_note = ""
        self.nearby_label.setText(self._nearby_text())
        self.status_label.setText(reason)
        self._sync_buttons()

    def _disconnect_selected(self) -> None:
        peer = self._selected()
        if peer is None:
            return
        conn = self._sessions.pop(peer.fingerprint, None)
        if conn is not None:
            conn.close()
        if self._is_inbound(peer) and self._receiver is not None:
            # Revoking the inbound session is the only way 断开 means anything to a peer that
            # dialled us; its socket stays open until the token stops being accepted.
            self._receiver.release(peer.fingerprint)
        self._inbound.discard(peer.fingerprint)
        self._connected = [p for p in self._connected if p.fingerprint != peer.fingerprint]
        if self._pending is peer:
            self._pending = None
        self._refresh_peers()
        self.status_label.setText(
            _("已断开 {name}。它的密钥还留在本机，留空配对码就能重连；要彻底撤销请去设置。").format(name=peer.name or peer.prefix)
        )

    def forget(self, fingerprint: str) -> bool:
        """Drop a device from the roster because its pin is gone.

        A session that outlives the only thing that made the peer trustworthy would let the
        card keep promising a device the pin list no longer knows.
        """
        conn = self._sessions.pop(fingerprint, None)
        before = len(self._connected)
        self._connected = [peer for peer in self._connected if peer.fingerprint != fingerprint]
        self._inbound.discard(fingerprint)
        if self._pending is not None and self._pending.fingerprint == fingerprint:
            self._pending = None
        self._refresh_peers()
        if conn is not None:
            self._close_quietly(conn)
        if self._receiver is not None:
            self._receiver.release(fingerprint)
        return len(self._connected) != before

    def _on_peer_lost(self, fingerprint: str) -> None:
        """The idle reclaim took a session back (spec §3), so the row stops promising it.

        Say it out loud rather than letting the device vanish on the next repaint: the peer is
        still pinned, and a user who wonders what happened needs to know the window that closed
        was this machine's, not the phone's.
        """
        known = next((peer for peer in self._connected if peer.fingerprint == fingerprint), None)
        self.forget(fingerprint)
        if known is not None:
            self.status_label.setText(
                _("{name} 已经 {minutes} 分钟没有动静，本机把会话名额收回了；它的密钥还在，重连不用再报配对码。").format(
                    name=known.name or known.prefix, minutes=self.proto.session_idle_timeout_s // 60
                )
            )

    def _sync_buttons(self) -> None:
        busy = self._worker is not None and self._worker.is_alive()
        connecting = self._connect_worker is not None and self._connect_worker.is_alive()
        selected = self._selected()
        reachable = selected is not None and not self._is_inbound(selected)
        self.send_button.setEnabled(bool(self._staged) and reachable and not busy)
        self.send_button.setToolTip(
            ""
            if selected is None or reachable
            else _("这台设备是连进来的，本机没有可回拨的地址。要发给它，请改由它连接本机。")
        )
        self.clear_stage_button.setEnabled(bool(self._staged))
        self.connect_button.setEnabled(not connecting and self._locked_out() is None)
        self.connect_button.setToolTip(self._connect_tip())
        self.disconnect_button.setEnabled(selected is not None and not busy)
        self._sync_target(selected)

    def _peer_now_text(self, selected: Peer | None = None) -> str:
        selected = self._selected() if selected is None else selected
        if selected is None:
            return _("还没有选定接收设备。到「接收」页连一台，或在附近列表里点一台。")
        who = selected.name or selected.prefix
        return _("当前对端：{name}（{addr}，指纹前缀 {fp}）").format(
            name=who, addr=f"{selected.host}:{selected.port}", fp=selected.prefix
        )

    def _pace_text(self, selected: Peer | None = None) -> str:
        """Why this transfer is slow, when the reason is on the far end rather than the wire.

        The pace line is not decoration: a peer that declared ``chunk_pace_ms`` makes the
        transfer look exactly like a congested network, and only the receiver knows why.
        """
        selected = self._selected() if selected is None else selected
        if selected is None:
            return ""
        conn = self._sessions.get(selected.fingerprint)
        if conn is None:
            return _("这台设备还没有连接会话，点「连接」建立一条。")
        if conn.pace_ms:
            return _(
                "对方要求每 {ms} 毫秒写一条 TLS 记录，所以这台设备比局域网正常水平慢，这不是网络故障。"
            ).format(ms=conn.pace_ms)
        return _("对方没有要求放慢写入，本机按最快速度发。")

    def _sync_target(self, selected: Peer | None) -> None:
        """Repaint the 目标设备 block from whatever selection the roster just settled on."""
        self.peer_now_label.setText(self._peer_now_text(selected))
        self.pace_label.setText(self._pace_text(selected))

    def dragEnterEvent(self, event) -> None:  # noqa: D102 - Qt hook
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_dragging(True)

    def dragLeaveEvent(self, event) -> None:  # noqa: D102 - Qt hook
        self._set_dragging(False)

    def dropEvent(self, event) -> None:  # noqa: D102 - Qt hook
        self._set_dragging(False)
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        if not paths:
            return
        event.acceptProposedAction()
        # Dropping means "send this", so the page follows the intent even when the user
        # dropped onto the file list.
        self.stack.setCurrentIndex(0)
        self._stage_paths(paths)

    def _set_dragging(self, on: bool) -> None:
        """Re-polish the drop frame so it can show that the pointer is carrying something."""
        if bool(self.drop_box.property("dragging")) == on:
            return
        self.drop_box.setProperty("dragging", on)
        style = self.drop_box.style()
        style.unpolish(self.drop_box)
        style.polish(self.drop_box)

    def _stage(self, kind: str) -> None:
        if kind == "dir":
            chosen = QFileDialog.getExistingDirectory(self, _("选择要发送的文件夹"))
            if not chosen:
                return
            base = Path(chosen)
            self._staged_base = base.parent
            self._staged = [base]
            self.stage_label.setText(self._stage_text())
            self._sync_buttons()
        else:
            chosen_list = QFileDialog.getOpenFileNames(self, _("选择要发送的文件"))[0]
            if chosen_list:
                self._stage_paths([Path(p) for p in chosen_list])

    def _stage_paths(self, paths: list[Path]) -> bool:
        """Accept a picked or dropped selection, or refuse it out loud."""
        try:
            # Every relpath in an offer is taken from one shared base, so a selection
            # that spans drives or roots cannot be described - say so instead of
            # flattening names and letting two files fight over one path.
            self._staged_base = Path(os.path.commonpath([str(p.parent) for p in paths]))
        except ValueError:
            self.status_label.setText(_("这些文件不在同一个文件夹下，请分开发送。"))
            return False
        self._staged = paths
        self.stage_label.setText(self._stage_text())
        self._sync_buttons()
        return True

    def _clear_stage(self) -> None:
        self._staged = []
        self._staged_base = None
        self.stage_label.setText(self._stage_text())
        self._sync_buttons()

    def _stage_size(self) -> int:
        """Bytes on disk behind what is staged. The record row needs the number the sentence
        below already contains, and walking a folder twice would let the two disagree."""
        if not self._staged:
            return 0
        if len(self._staged) == 1 and self._staged[0].is_dir():
            return sum(p.stat().st_size for p in self._staged[0].rglob("*") if p.is_file())
        return sum(p.stat().st_size for p in self._staged if p.is_file())

    def _stage_text(self) -> str:
        if not self._staged:
            return _("还没选要发送的内容。")
        total = self._stage_size()
        if len(self._staged) == 1 and self._staged[0].is_dir():
            folder = self._staged[0]
            total = sum(p.stat().st_size for p in folder.rglob("*") if p.is_file())
            return _("已选：{name}（整个文件夹，约 {size}）").format(name=folder.name, size=_human(total))
        return _("已选 {n} 个文件，共 {size}").format(n=len(self._staged), size=_human(total))

    # ---------------------------------------------------------------- sending

    def _start_send(self) -> None:
        peer = self._selected()
        if peer is None or not self._staged or (self._worker is not None and self._worker.is_alive()):
            return
        paths, base = list(self._staged), self._staged_base
        self.progress.setValue(0)
        self.progress.setFormat(_("准备中…"))
        self.send_button.setEnabled(False)
        self._cancelled.discard("send")
        entry = self._add_task_row(
            "send", _("{what} → {who}").format(what=self._stage_text(), who=peer.name or peer.prefix)
        )
        entry["who"] = peer.name or peer.prefix or peer.host
        entry["bytes"] = self._stage_size()
        entry["file"] = paths[0].name if len(paths) == 1 else _("共 {n} 个文件").format(n=len(paths))
        self._worker = threading.Thread(
            target=self._send_worker, args=(peer, paths, base), name="chuanshu-send", daemon=True
        )
        self._worker.start()

    # ---------------------------------------------------------------- task rows

    def _add_task_row(self, key: str, title: str) -> dict:
        """One row per transfer: mark, name, bar, how far, and a way to stop it.

        Rows stay after they finish. A bar that disappears the moment it hits 100% leaves the
        user with no answer to the only question they asked by pressing 发送.
        """
        p = self._p
        row = QWidget(self.task_list)
        row.setObjectName("TaskRow")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(2, 11, 2, 11)
        layout.setSpacing(10)
        # Everything in this card is the same shape, so a live send is marked the way an arrival
        # is: an arrow that says which way the bytes went.
        mark = QLabel(row)
        mark.setPixmap(icons.pixmap("upload-circle", p.text, 20))
        layout.addWidget(mark)
        name = QLabel(title)
        name.setObjectName("RecordName")
        name.setWordWrap(True)
        layout.addWidget(name, 1)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(0)
        bar.setTextVisible(False)
        bar.setFixedHeight(6)
        bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        bar.setMinimumWidth(120)
        layout.addWidget(bar, 2)
        percent = QLabel("0%")
        percent.setObjectName("MutedOnCard")
        layout.addWidget(percent)
        # An elapsed clock rather than a throughput estimate: bytes only become a rate once
        # both ends agree the transfer is over, and a mid-flight guess would be a lie. The row
        # has no column left for it, so the pointer carries it.
        elapsed = QLabel("0:00")
        elapsed.setObjectName("Muted")
        cancel = QPushButton(_("取消"))
        cancel.setObjectName("Inline")
        cancel.setToolTip(_("停下这次传输，并让对方扔掉已经收到的半件。"))
        cancel.clicked.connect(lambda _checked=False, stop=key: self._cancel_task(stop))
        layout.addWidget(cancel)
        item = QListWidgetItem(self.task_list)
        item.setSizeHint(row.sizeHint())
        self.task_list.setItemWidget(item, row)
        self.task_list.setVisible(True)
        entry = {
            "item": item,
            "widget": row,
            "name": name,
            "bar": bar,
            "percent": percent,
            "elapsed": elapsed,
            "cancel": cancel,
            "started": time.time(),
            "title": title,
            "done": False,
            "ok": None,
            #: The 传输记录 page reads these to draw a row the way the mockup does: one file
            #: name, one size, one device. The title above is a sentence, which is not.
            "who": "",
            "bytes": 0,
            "file": title,
        }
        self._task_rows[key] = entry
        self._trim_tasks()
        return entry

    def _trim_tasks(self) -> None:
        """Forget the oldest finished rows so a long session cannot grow the list forever.

        An empty list is hidden: a QListWidget asks for a frame's worth of height even with
        nothing in it, and at launch that blank sits between the card's heading and its rows.
        """
        extra = len(self._task_rows) - _TASK_HISTORY_KEPT
        if extra > 0:
            finished = [key for key, row in self._task_rows.items() if row["done"]]
            for key in finished[:extra]:
                entry = self._task_rows.pop(key)
                self.task_list.takeItem(self.task_list.row(entry["item"]))
        self.task_list.setVisible(self.task_list.count() > 0)

    def _cancel_task(self, key: str) -> None:
        """Ask a running send to stop between chunks.

        The worker only checks this once a chunk is fully written, so 取消 lands within one
        chunk of the request - on a paced peer that is a few seconds, and the row says so
        instead of pretending the bytes already sent came back.
        """
        entry = self._task_rows.get(key)
        if entry is None or entry["cancel"].isEnabled() is False:
            return
        self._cancelled.add(key)
        entry["cancel"].setEnabled(False)
        self._tick_task(key, note=entry["title"] + _("（正在取消…）"))

    def _tick_task(self, key: str, percent: int | None = None, note: str | None = None) -> None:
        entry = self._task_rows.get(key)
        if entry is None:
            return
        seconds = int(time.time() - entry["started"])
        clock = f"{seconds // 60}:{seconds % 60:02d}"
        entry["elapsed"].setText(clock)
        entry["widget"].setToolTip(_("已用 {clock}。").format(clock=clock))
        if percent is not None:
            entry["bar"].setValue(percent)
            entry["percent"].setText(f"{percent}%")
        if note is not None:
            entry["name"].setText(note)

    def _close_task(self, key: str, ok: bool) -> None:
        entry = self._task_rows.get(key)
        if entry is None:
            return
        entry["bar"].setValue(100 if ok else 0)
        # A finished row has nothing left to measure: the mockup's completed lines carry a name,
        # a size and a state, and the bar that said 65% would only keep asking a closed question.
        entry["bar"].setVisible(False)
        entry["percent"].setVisible(False)
        entry["cancel"].setEnabled(False)
        entry["cancel"].setText(_("完成") if ok else _("失败"))
        entry["cancel"].setProperty("state", "ok" if ok else "err")
        # QSS caches a resolved style per widget, so a property set after the first polish
        # needs the widget polished again before the attribute selector is read.
        entry["cancel"].style().polish(entry["cancel"])
        entry["done"] = True
        entry["ok"] = ok
        entry["finished"] = time.time()
        self._tick_task(key, note=entry["title"])

    def _throttle(self) -> Throttle | None:
        """The sender's byte budget, straight from the settings page. None means no limit.

        Read at the start of every transfer instead of cached here, so a switch flipped while a
        session is open is honoured by the next 发送 rather than needing the pair redone.
        """
        if not bool(self.settings.get("limit_on", False)):
            return None
        return Throttle(max(1, int(self.settings.get("limit_mbps", 10))) * 1_000_000)

    def _send_worker(self, peer: Peer, paths: list[Path], base: Path | None) -> None:
        """Push the staged files through the session 连接 made, without closing it afterwards.

        The roster only holds paired peers, so there is no handshake left to spend here and no
        code to interrupt a transfer for. A peer that stopped recognising our key is reported
        instead, because only its fresh pair code can fix that.
        """
        conn = self._sessions.get(peer.fingerprint)
        if conn is None:
            self._finished.emit(False, _("这台设备已经没有连接会话，请重新连接它。"))
            return
        # Read when the transfer starts rather than when the pair finished, so the switch on the
        # settings page applies to the next 发送 without dropping the session it rides on.
        conn.throttle = self._throttle()
        try:
            files = plan(paths, base=base)
            if not files:
                self._finished.emit(False, _("这里没有可发的文件。"))
                return
            # Same counting rule as PeerConnection._chunk_count: an empty file has no
            # chunks at all, so including one here would make progress pass 100%.
            total_chunks = sum((f.size + self.proto.chunk_size - 1) // self.proto.chunk_size if f.size else 0 for f in files)
            total_bytes = sum(f.size for f in files)
            done = [0]

            def progress(relpath: str, _index: int, _total: int) -> None:
                # Cancelled between chunks on purpose: stopping mid-chunk would leave the
                # receiver holding a half-written file it has no hash for.
                if "send" in self._cancelled:
                    raise _Cancelled
                done[0] += 1
                # Outbound chunks are this machine's only heartbeat: the peer we dialled never
                # shows up in an inbound request, so its half of the idle clock is kept here.
                if self._receiver is not None:
                    self._receiver.seen(peer.fingerprint)
                self._progressed.emit(done[0], total_chunks, relpath)

            conn.offer(files)
            conn.send(files, progress=progress)
            # send() only returns once the receiver hashed every chunk it was given, so the
            # report can promise verification instead of a transfer that merely completed.
            self._finished.emit(
                True,
                _("已发给 {name}：{n} 个文件（{size}），对方逐个校验通过。").format(
                    name=peer.name or peer.prefix, n=len(files), size=_human(total_bytes)
                ),
            )
        except _Cancelled:
            # Ask the receiver to drop the half-offer before saying it is done, so the folder
            # it shows the user cannot contain a file this machine refused to finish.
            try:
                conn.abort()
            except (OSError, protocol_spec.ProtocolError, ConnectionError) as error:
                log.warning("could not withdraw the cancelled offer: %s", error)
            self._finished.emit(
                False,
                _("已取消发给 {name}：本机停止发送，对方那半件也撤掉了。").format(name=peer.name or peer.prefix),
            )
        except (PairNeeded, WrongPairCode) as error:
            self._finished.emit(False, refusal_text(error, self.proto))
        except PeerIdentityMismatch:
            self._finished.emit(False, _("配对应答里的指纹和 hello 不一致，已中止"))
        except protocol_spec.ProtocolError as error:
            self._finished.emit(False, _("对方说：{text}").format(text=proto_errors.describe(error.code)))
        except TooManyFilesForOffer as error:
            # §5's number, spent here: this batch never went on the wire, so the sentence names
            # the selection rather than whatever a peer's version-only refusal would have said.
            self._finished.emit(False, _("一次最多 {n} 个文件。").format(n=error.limit))
        except FileNotFoundError as error:
            self._finished.emit(False, _("有文件已经不在了：{path}").format(path=error.filename or error))
        except ConnectionError as error:
            # The roster said this peer existed a moment ago, so a refused or dropped
            # connection almost always means the other side just closed or moved ports.
            log.warning("could not reach the peer: %s", error)
            self._finished.emit(False, _("连不上对方，它可能已经退出或换了端口：{error}").format(error=error.strerror or error))
        except (OSError, RuntimeError, ValueError) as error:
            log.exception("send failed")
            self._finished.emit(False, _("传输中断：{error}").format(error=getattr(error, "strerror", None) or error))

    def _on_progress(self, done: int, total: int, relpath: str) -> None:
        percent = int(done * 100 / total) if total else 0
        self.progress.setValue(percent)
        # The bar is only as wide as the column, so it carries the number and the status
        # line carries the file name; a long Chinese relpath would not fit in the bar.
        self.progress.setFormat(f"{percent}%")
        self._tick_task("send", percent=percent, note=_("{title}（正在发送 {name}）").format(
            title=self._task_rows["send"]["name"].text() if "send" in self._task_rows else "", name=relpath
        ) if "send" in self._task_rows else None)
        self.status_label.setText(_("正在发送：{name}").format(name=relpath))

    def _on_finished(self, ok: bool, message: str) -> None:
        self.progress.setValue(100 if ok else 0)
        if not ok:
            self.progress.setFormat(_("未开始"))
        self._close_task("send", ok)
        self._cancelled.discard("send")
        self.status_label.setText(message)
        log.info("transfer finished ok=%s: %s", ok, message)
        self._sync_buttons()

    # --------------------------------------------------------------- arrivals

    def _on_received(self, who: str, landed: list[dict]) -> None:
        """Runs on the GUI thread: the server-side handler emits, and only that emit is allowed to paint."""
        now = time.time()
        for entry in landed:
            item = dict(entry)
            item["who"] = who
            item["at"] = now
            self._received.append(item)
        self._save_arrivals()
        self._refresh_received()
        total = sum(int(entry["size"]) for entry in landed)
        self.arrived.emit(who, len(landed), _human(total))
        self.status_label.setText(
            _("已收到 {who} 发来的 {n} 个文件（{size}），逐个校验通过。").format(who=who, n=len(landed), size=_human(total))
        )

    @staticmethod
    def _load_arrivals() -> list[dict]:
        """Read the arrival list back, and forget it rather than fail to open the window.

        A record whose file has since been deleted is still worth listing - the point of the
        page is what landed here, and the row says out loud when the bytes are gone.
        """
        try:
            stored = json.loads(_arrivals_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(stored, list):
            return []
        return [e for e in stored if isinstance(e, dict) and e.get("path") and e.get("relpath")]

    def _save_arrivals(self) -> None:
        """Keep the tail of the list; the receive folder itself is never touched here."""
        try:
            target = _arrivals_file()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(self._received[-_ARRIVALS_KEPT:], ensure_ascii=False), encoding="utf-8"
            )
        except OSError as error:
            log.warning("could not save the arrival list: %s", error)

    def _choose_filter(self, chip: QPushButton) -> None:
        self._received_filter = str(chip.property("filter") or "all")
        self._sync_chips()
        self._refresh_received()

    def _sync_chips(self) -> None:
        """Exactly one pill is pressed, including on the first paint."""
        for chip in self._chips:
            chip.blockSignals(True)
            chip.setChecked(str(chip.property("filter")) == self._received_filter)
            chip.blockSignals(False)

    def _filtered_arrivals(self) -> list[dict]:
        needle = self.files_search.text().strip().lower()
        out = []
        for entry in self._received:
            if self._received_filter != "all" and self._file_kind(str(entry["relpath"])) != self._received_filter:
                continue
            if needle and needle not in f"{entry['relpath']} {entry.get('who') or ''}".lower():
                continue
            out.append(entry)
        return out

    #: The mockup draws a sheet in front of every file name. The glyph is the kind the chips
    #: filter by, so the pill above and the row below say the same thing.
    _KIND_GLYPH = {"image": "file-image", "video": "file-video", "doc": "file-doc", "archive": "file-archive"}

    def _refresh_received(self) -> None:
        tree = self.received_list
        p = self._p
        # Inserting into a sorted tree lets each row land where the previous order says, which
        # scrambles a list of identical timestamps. Sort once, at the end.
        tree.setSortingEnabled(False)
        tree.clear()
        arrivals = self._filtered_arrivals()
        # Two transfers can carry a file with the same name, and the mockup's row has room for one
        # word. So the folder stays out of the list until it is the only thing that tells two rows
        # apart - which is exactly when leaving it out would be a lie by ambiguity.
        taken = Counter(Path(str(entry["relpath"])).name for entry in arrivals)
        for entry in reversed(arrivals):
            path = str(entry["path"])
            gone = not Path(path).exists()
            row = _ArrivalRow(tree)
            row.path = path
            size = int(entry.get("size") or 0)
            stamp = float(entry.get("at") or 0)
            who = str(entry.get("who") or "")
            row.setIcon(0, icons.icon(self._KIND_GLYPH.get(self._file_kind(str(entry["relpath"])), "file-unknown"), p.accent))
            label = Path(str(entry["relpath"])).name
            if taken[label] > 1:
                # Two batches can carry the same name. Say which batch this row came from: the
                # folder the sender put it in, or - for a file at the top of a batch, where that
                # says nothing - the folder this machine filed the batch into.
                rel = Path(str(entry["relpath"]))
                label = str(rel) if str(rel.parent) != "." else f"{Path(path).parent.name}/{label}"
            row.setText(0, label + (_("（已经不在了）") if gone else ""))
            # The mockup weights the row: the name is the thing you scan for, so it is the only
            # word in the row that is bold.
            name_font = row.font(0)
            name_font.setBold(True)
            row.setFont(0, name_font)
            row.setData(0, Qt.UserRole, str(entry["relpath"]))
            row.setText(1, _human(size))
            row.setData(1, Qt.UserRole, size)
            row.setText(2, _when(stamp) if stamp else _("时间未知"))
            row.setData(2, Qt.UserRole, stamp)
            row.setText(3, who)
            row.setData(3, Qt.UserRole, who)
            row.setToolTip(0, path if not gone else _("原本落在：{path}").format(path=path))
            if stamp:
                row.setToolTip(2, time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp)))
            if gone:
                # Same row, visibly dimmed: the record still means something even though the
                # bytes moved, and a palette brush keeps it readable in both themes.
                row.setForeground(0, tree.palette().brush(QPalette.Disabled, QPalette.Text))
        if not arrivals:
            placeholder = _ArrivalRow(tree)
            placeholder.path = ""
            filtering = self._received_filter != "all" or bool(self.files_search.text().strip())
            placeholder.setText(
                0,
                _("没有符合条件的文件。") if filtering else _("还没有收到校验通过的文件。"),
            )
            placeholder.setFlags(Qt.NoItemFlags)
        tree.setSortingEnabled(True)

    def _open_received(self, row: QTreeWidgetItem, _column: int = 0) -> None:
        path = str(getattr(row, "path", "") or "")
        if not path:
            return
        if not Path(path).exists():
            # The record is honest about the arrival; only the bytes moved. Say which of the
            # two happened rather than opening an empty explorer window.
            self.status_label.setText(_("这条记录还在，文件已经不在这个位置了：{path}").format(path=path))
            self._refresh_received()
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    # ---------------------------------------------------------- 传输记录 page

    @property
    def _p(self) -> theme.Palette:
        """The palette this panel is being drawn with. QSS cannot reach inside a QIcon, so a
        row that carries an arrow or a check has to ask for the colour and re-rasterise it."""
        return theme.palette_for(self.settings.get("theme", "auto"))

    def _history_rows(self) -> list[dict]:
        """Both kinds of "something moved" in one list, newest first.

        Two sources because the honest answer to the question is two questions: what this
        session tried to send, including the attempts that failed, and what is verified on
        disk, which outlives the window but knows nothing about a send that never left.
        """
        rows: list[dict] = []
        running = self._worker is not None and self._worker.is_alive()
        for key, task in self._task_rows.items():
            state = "running" if (key == "send" and running) or not task["done"] else (
                "done" if task["ok"] else "failed"
            )
            rows.append(
                {
                    # The live card owns rows that came from a task; the history page owns the
                    # rest. The key is what keeps one row from being drawn twice, in two widgets.
                    "key": key,
                    "dir": "up",
                    "name": str(task.get("file") or task["title"]),
                    "size": int(task.get("bytes") or 0),
                    "at": float(task.get("finished") or task["started"]),
                    "state": state,
                    "who": str(task.get("who") or ""),
                    "detail": f"{task['bar'].value()}%" if state == "running" else "",
                }
            )
        for arrival in self._received:
            rows.append(
                {
                    "key": None,
                    "dir": "down",
                    "name": Path(str(arrival["relpath"])).name,
                    "size": int(arrival.get("size") or 0),
                    "at": float(arrival.get("at") or 0),
                    "state": "done",
                    "who": str(arrival.get("who") or ""),
                    "detail": "",
                }
            )
        rows.sort(key=lambda row: row["at"], reverse=True)
        return rows

    def _day_label(self, stamp: float) -> str:
        """今天 / 昨天, then a date - the grouping the mockup draws, in the words a user reads."""
        if not stamp:
            return _("更早")
        today = time.localtime()
        midnight = time.mktime((today.tm_year, today.tm_mon, today.tm_mday, 0, 0, 0, 0, 0, -1))
        if stamp >= midnight:
            return _("今天")
        if stamp >= midnight - 86_400:
            return _("昨天")
        return time.strftime("%Y-%m-%d", time.localtime(stamp))

    def _state_label(self, state: str) -> str:
        return {"running": _("传输中"), "done": _("已完成"), "failed": _("失败")}[state]

    def _choose_history_filter(self, chip: QPushButton) -> None:
        self._history_filter = str(chip.property("filter") or "all")
        for other in self.history_chips:
            other.blockSignals(True)
            other.setChecked(other is chip)
            other.blockSignals(False)
        self._refresh_history()

    def _day_heading(self, label: str) -> QLabel:
        head = QLabel()
        head.setObjectName("DayHeading")
        head.setText(label)
        return head

    def _record_row(self, row: dict) -> QFrame:
        """One transfer, laid out the way the mockup lays it out: mark, name, size, status."""
        p = self._p
        frame = QFrame()
        frame.setObjectName("RecordRow")
        box = QHBoxLayout(frame)
        box.setContentsMargins(2, 11, 2, 11)
        box.setSpacing(10)
        glyph = "upload-circle" if row["dir"] == "up" else "download-circle"
        mark = QLabel(frame)
        mark.setPixmap(icons.pixmap(glyph, p.text, 20))
        box.addWidget(mark)
        name = QLabel(frame)
        name.setObjectName("RecordName")
        name.setText(str(row["name"]))
        box.addWidget(name)
        size = QLabel(frame)
        size.setObjectName("MutedOnCard")
        size.setText(_human(int(row["size"])) if row["size"] else "")
        box.addWidget(size)
        box.addStretch(1)
        state = str(row["state"])
        if state == "done":
            # Only the finished rows earn a tick: an arrow already says which way it went, and a
            # running row that also carried a mark would read as two states at once.
            tick = QLabel(frame)
            tick.setPixmap(icons.pixmap("check-circle", p.ok, 16))
            box.addWidget(tick)
        status = QLabel(frame)
        status.setObjectName({"running": "Running", "done": "Ok", "failed": "Err"}[state])
        status.setText(self._state_label(state))
        box.addWidget(status)
        if row["detail"]:
            rate = QLabel(frame)
            rate.setObjectName("MutedOnCard")
            rate.setText(str(row["detail"]))
            box.addWidget(rate)
        frame.setAccessibleName(f"{row['name']} {self._state_label(state)}")
        if row["who"]:
            frame.setToolTip(
                _("发给 {who}").format(who=row["who"])
                if row["dir"] == "up"
                else _("来自 {who}").format(who=row["who"])
            )
        return frame

    def _add_record_widget(self, box: QListWidget, widget: QWidget, *, selectable: bool = True) -> None:
        item = QListWidgetItem(box)
        item.setSizeHint(widget.sizeHint())
        if not selectable:
            item.setFlags(Qt.NoItemFlags)
        box.setItemWidget(item, widget)

    def _refresh_history(self) -> None:
        """Rebuild the record list: a heading per day, a row per transfer under it."""
        box = self.history_list
        box.clear()
        keep = self._history_filter
        rows = [row for row in self._history_rows() if keep == "all" or row["state"] == keep]
        day = ""
        for row in rows:
            label = self._day_label(row["at"])
            if label != day:
                day = label
                self._add_record_widget(box, self._day_heading(label), selectable=False)
            self._add_record_widget(box, self._record_row(row))
        if not rows:
            placeholder = QLabel()
            placeholder.setObjectName("MutedOnCard")
            placeholder.setText(_("还没有任何传输记录。") if keep == "all" else _("这个筛选下没有记录。"))
            self._add_record_widget(box, placeholder, selectable=False)
        self._refresh_recent()

    def _refresh_recent(self) -> None:
        """The arrivals the live card is not already showing, newest first.

        The 传输 mockup's card has three finished rows in it before anything happens this
        session, and they are received files. The rows a send put up are the live list's own
        widgets - rebuilt here they would lose the progress bar mid-flight - so this only ever
        adds the records that list does not hold.
        """
        box = self.recent_list
        box.clear()
        for row in [r for r in self._history_rows() if r["key"] is None][:_TASK_CARD_ROWS]:
            self._add_record_widget(box, self._record_row(row))

    # --------------------------------------------------------------- lifecycle

    def shutdown(self) -> None:
        with self._ask_lock:
            pending = list(self._decisions.values())
            self._decisions.clear()
        # The window can close while an incoming offer is still on screen, and the server
        # thread holding it is waiting on that answer. Quitting means declining.
        for dialog in list(self._offer_cards.values()):
            # The card runs a nested modal loop; dismissing it first is what lets the close
            # finish instead of leaving a dialog whose parent has already been destroyed.
            dialog.done(QDialog.Rejected)
        self._offer_cards.clear()
        for holder in pending:
            holder["event"].set()
        self.stop_listening()
        # Closing the window is the one moment 听 is allowed to stop too: the process is leaving the LAN.
        if self._discovery is not None:
            self._discovery.stop()
            self._discovery = None
        for conn in self._sessions.values():
            self._close_quietly(conn)
        self._sessions.clear()
        if self._worker is not None and self._worker.is_alive():
            log.info("a transfer is still running; it will finish on its own")
