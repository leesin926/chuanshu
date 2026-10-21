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
from pathlib import Path

import qrcode
from qrcode.image.svg import SvgPathImage
from PySide6.QtCore import QUrl, Qt, QTimer, Signal
from PySide6.QtGui import QDesktopServices, QImage, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import Settings
from app.i18n import _
from app.net import errors as proto_errors
from app.net import spec as protocol_spec
from app.net.discovery import DiscoveryService, Peer, local_ipv4, verify_peer
from app.net.identity import load_or_create
from app.net.receive import ReceiveService
from app.net.send import PairNeeded, PeerConnection, plan
from app.paths import identity_dir, receive_root, user_data_dir

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


def _split_addr(text: str, default_port: int, scheme: str) -> tuple[str, int, str]:
    """Read ``host``, ``host:port`` or a pasted pairing payload.

    Returns ``(host, port, advertised_prefix)``; only the pasted form carries a prefix,
    which is why it gets checked against the certificate and the typed form does not.
    """
    if text.startswith(scheme):
        fields = protocol_spec.parse_qr(text)
        return fields["h"], int(fields.get("p") or default_port), fields.get("f", "")
    host, sep, port = text.rpartition(":")
    if not sep:
        return text, default_port, ""
    if not host or not port.isdigit():
        raise ValueError(text)
    return host, int(port), ""


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _arrivals_file() -> Path:
    """Where verified arrivals are remembered between runs.

    The receive folder is the truth about the bytes; this file is only the reading list that
    makes the 文件 page answer "when did it arrive and from whom", which a folder cannot say.
    """
    return user_data_dir() / "arrivals.json"


def _when(stamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp))


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


class _Cancelled(Exception):
    """Raised inside the send worker when 取消 is pressed on its row."""


class TransferPanel(QWidget):
    _offer_arrived = Signal(dict, str, str)  # manifest, who, token
    _peers_changed = Signal()  # emitted from discovery threads
    _progressed = Signal(int, int, str)  # chunks done, chunks total, current file
    _finished = Signal(bool, str)
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

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.proto = protocol_spec.load()
        self.identity = load_or_create(identity_dir())
        self.device_name = str(settings.get("device_name", "") or socket.gethostname())
        self._receiver: ReceiveService | None = None
        self._discovery: DiscoveryService | None = None
        self._decisions: dict[str, dict] = {}
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
        self._connect_worker: threading.Thread | None = None
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
        self._peers_changed.connect(self._refresh_peers)
        self._progressed.connect(self._on_progress)
        self._finished.connect(self._on_finished)
        self._connected_ok.connect(self._on_connected)
        self._connect_failed.connect(self._on_connect_failed)
        self._received_arrived.connect(self._on_received)
        self._peer_paired.connect(self._on_peer_paired)
        self.retranslate()
        # Opening the app opens the port: the pairing picture is the first thing the window
        # promises, so it is painted by the launch rather than by a click that asks for it.
        self.start_listening()

    # ------------------------------------------------------------------ widgets

    def _build(self) -> None:
        """Three pages the rail can switch between, all owned by this widget.

        Every control keeps its old attribute name: the acceptance script reaches the window
        through these objects, and a rename would turn a passing run into a missing widget.
        """
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.stack = QStackedWidget(self)
        self.page_transfer = self._build_transfer_page()
        self.page_devices = self._build_devices_page()
        self.page_files = self._build_files_page()
        for page in (self.page_transfer, self.page_devices, self.page_files):
            self.stack.addWidget(page)
        outer.addWidget(self.stack, 1)

        self.status_label = QLabel()
        self.status_label.setObjectName("Muted")
        self.status_label.setWordWrap(True)
        outer.addWidget(self.status_label)

        self.setAcceptDrops(True)

    def add_page(self, page: QWidget) -> int:
        """Let the window contribute a rail page. 设置 lives here, not in a second window."""
        return self.stack.addWidget(page)

    def show_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)

    def current_page(self) -> int:
        return self.stack.currentIndex()

    def fit_pages(self) -> None:
        """Ask every page what height its sentences need at the width the rail leaves them.

        A stacked widget sizes itself on the biggest page minimum it is given, and a minimum
        hint counts a wrapping label as one line. At the narrowest width the stack can reach a
        caption needs more lines than that, and the layout paid for the difference out of the
        buttons' height. Measuring at that width is the worst case, because the window cannot
        go narrower than the widest page.
        """
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

    # ----------------------------------------------------------------- 传输 page

    def _build_transfer_page(self) -> QWidget:
        page = QWidget(self)
        page.setObjectName("TransferPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        title = QLabel()
        title.setObjectName("PageTitle")
        self.page_title_transfer = title

        # The drop box is the whole top of the page: dropping is the way anyone actually moves
        # files, and the two pickers are what a keyboard-only user has instead.
        self.drop_box = QFrame(page)
        self.drop_box.setObjectName("DropZone")
        drop_layout = QVBoxLayout(self.drop_box)
        drop_layout.setContentsMargins(18, 20, 18, 16)
        self.drop_big = QLabel()
        self.drop_big.setObjectName("DropBig")
        self.drop_big.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.drop_hint = QLabel()
        self.drop_hint.setObjectName("DropHint")
        self.drop_hint.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
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
        self.stage_label = QLabel()
        self.stage_label.setObjectName("Muted")
        self.stage_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        drop_layout.addWidget(self.drop_big)
        drop_layout.addWidget(self.drop_hint)
        drop_layout.addLayout(pickers)
        drop_layout.addWidget(self.stage_label)

        # Which device this is going to, and what that device asked us to write at. The pace
        # line exists because a paced transfer looks exactly like a slow network from here.
        self.peer_now_box = QGroupBox(page)
        now_layout = QVBoxLayout(self.peer_now_box)
        self.peer_now_label = QLabel()
        self.peer_now_label.setWordWrap(True)
        self.pace_label = QLabel()
        self.pace_label.setObjectName("Muted")
        self.pace_label.setWordWrap(True)
        now_layout.addWidget(self.peer_now_label)
        now_layout.addWidget(self.pace_label)

        self.task_title = QLabel()
        self.task_title.setObjectName("SectionTitle")
        # One row per transfer in flight: name, bar, speed, cancel. The protocol only lets one
        # peer hold the slot at a time, so this list holds at most the send under way plus the
        # offer someone else dialled in and we are still deciding about.
        self.task_list = QListWidget()
        self.task_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.send_button = QPushButton()
        self.send_button.clicked.connect(self._start_send)
        self.send_button.setEnabled(False)

        layout.addWidget(title)
        layout.addWidget(self.drop_box)
        layout.addWidget(self.peer_now_box)
        layout.addWidget(self.task_title)
        layout.addWidget(self.task_list, 1)
        layout.addWidget(self.progress)
        layout.addWidget(self.send_button)
        return page

    # ----------------------------------------------------------------- 设备 page

    def _build_devices_page(self) -> QWidget:
        page = QWidget(self)
        page.setObjectName("DevicesPage")
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(14)
        # Both cards want roughly the same width: the left one is bounded by the QR plus
        # the code beside it, the right one by its row of buttons.
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        # ---- my device (receiving) ----
        mine = QGroupBox(self)
        mine_layout = QVBoxLayout(mine)

        # The facts about this machine sit top-left, and the name is edited right where it
        # is shown. Three buttons on one bottom row did not fit the minimum window width
        # and got clipped, so the two secondary actions became inline text buttons.
        who = QHBoxLayout()
        self.name_label = QLabel()
        # Wrapping rather than eliding: the name is the one thing on this card the user
        # has to be able to read back, and in the wider languages it does not fit.
        self.name_label.setWordWrap(True)
        self.rename_button = QPushButton()
        self.rename_button.setObjectName("Inline")
        self.rename_button.clicked.connect(self.rename_device)
        who.addWidget(self.name_label)
        who.addWidget(self.rename_button)
        who.addStretch(1)
        self.listen_label = QLabel()
        self.channel_label = QLabel()
        self.channel_label.setObjectName("Muted")
        self.channel_label.setWordWrap(True)

        self.qr_label = QLabel()
        self.qr_label.setObjectName("QrBox")
        self.qr_label.setFixedSize(QR_SIZE + 8, QR_SIZE + 8)
        self.qr_label.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        self.qr_label.setToolTip(_("让对方扫这个码，就能带着配对码和密码连过来。"))
        self.code_label = QLabel()
        self.code_label.setObjectName("PairCode")
        self.code_label.setWordWrap(True)
        # Both secrets are read out loud to whoever is on the other side of the desk, so the
        # passphrase gets the same size as the code instead of a footnote.
        self.pass_label = QLabel()
        self.pass_label.setObjectName("PairCode")
        self.pass_label.setWordWrap(True)
        self.pass_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        secrets_column = QVBoxLayout()
        secrets_column.addStretch(1)
        secrets_column.addWidget(self.code_label)
        secrets_column.addWidget(self.pass_label)
        secrets_column.addStretch(1)
        pairing = QHBoxLayout()
        pairing.addStretch(1)
        pairing.addWidget(self.qr_label)
        pairing.addLayout(secrets_column)
        pairing.addStretch(1)
        # start_listening() paints this at launch; it stays hidden only if there is no port.
        self.qr_label.hide()

        where = QHBoxLayout()
        self.receive_dir_label = QLabel()
        self.receive_dir_label.setObjectName("Muted")
        self.receive_dir_label.setWordWrap(True)
        self.receive_dir_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.open_dir_button = QPushButton()
        self.open_dir_button.setObjectName("Inline")
        self.open_dir_button.clicked.connect(self._open_receive_dir)
        where.addWidget(self.receive_dir_label, 1)
        where.addWidget(self.open_dir_button)

        self.refresh_pair_button = QPushButton()
        self.refresh_pair_button.setObjectName("Inline")
        self.refresh_pair_button.clicked.connect(self.rotate_pairing)
        rotate = QHBoxLayout()
        rotate.addWidget(self.refresh_pair_button)
        rotate.addStretch(1)

        mine_layout.addLayout(who)
        mine_layout.addWidget(self.listen_label)
        mine_layout.addWidget(self.channel_label)
        mine_layout.addLayout(pairing)
        mine_layout.addLayout(rotate)
        mine_layout.addLayout(where)
        mine_layout.addStretch(1)

        # ---- peers (sending) ----
        peers = QGroupBox(self)
        peers_layout = QVBoxLayout(peers)
        self.peer_list = QListWidget()
        # Host:port plus a name is wider than the column; elide it instead of letting the
        # list grow a horizontal scrollbar that hides half of every row behind it.
        self.peer_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.peer_list.currentItemChanged.connect(lambda *_: self._sync_buttons())

        # Discovery is a stream of candidates, not a roster. It lives behind a button so this
        # card only ever lists devices whose pair handshake this machine has finished.
        self.nearby_label = QLabel()
        self.nearby_label.setObjectName("Muted")
        self.nearby_label.setWordWrap(True)
        self.pick_peer_button = QPushButton()
        self.pick_peer_button.setObjectName("Inline")
        self.pick_peer_button.clicked.connect(self._choose_peer)
        self.disconnect_button = QPushButton()
        self.disconnect_button.setObjectName("Inline")
        self.disconnect_button.clicked.connect(self._disconnect_selected)
        # The sentence gets its own row: on the same row as the two buttons it was the only
        # widget allowed to shrink, and at the narrowest window it ended up one character wide.
        nearby = QHBoxLayout()
        nearby.addWidget(self.pick_peer_button)
        nearby.addWidget(self.disconnect_button)
        nearby.addStretch(1)

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
        code_row = QHBoxLayout()
        code_row.addWidget(self.code_edit)
        code_row.addWidget(self.secret_edit, 1)
        code_row.addWidget(self.connect_button)

        peers_layout.addWidget(self.peer_list, 1)
        peers_layout.addWidget(self.nearby_label)
        peers_layout.addLayout(nearby)
        peers_layout.addLayout(code_row)

        grid.addWidget(mine, 0, 0)
        grid.addWidget(peers, 0, 1)
        self.mine_box, self.peers_box = mine, peers
        return page

    # ----------------------------------------------------------------- 文件 page

    def _build_files_page(self) -> QWidget:
        page = QWidget(self)
        page.setObjectName("FilesPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.page_title_files = QLabel()
        self.page_title_files.setObjectName("PageTitle")

        # The hint above the table is what this list can honestly promise; the promise changed
        # once arrivals were kept across restarts, so it is still a label and not a caption.
        self.received_label = QLabel()
        self.received_label.setObjectName("SectionTitle")
        self.received_label.setWordWrap(True)

        # Narrow filters rather than a menu: the useful questions are "since when" and "from
        # whom", and both are answerable with a pill or two on screen.
        self.chip_row = QHBoxLayout()
        self.chip_row.setSpacing(8)
        self.chip_all = QPushButton()
        self.chip_all.setObjectName("Chip")
        self.chip_all.setCheckable(True)
        self.chip_today = QPushButton()
        self.chip_today.setObjectName("Chip")
        self.chip_today.setCheckable(True)
        self.chip_week = QPushButton()
        self.chip_week.setObjectName("Chip")
        self.chip_week.setCheckable(True)
        self._chips: list[QPushButton] = []
        for chip, value in ((self.chip_all, "all"), (self.chip_today, "today"), (self.chip_week, "week")):
            chip.setProperty("filter", value)
            chip.clicked.connect(lambda _c=False, picked=chip: self._choose_filter(picked))
            self.chip_row.addWidget(chip)
            self._chips.append(chip)
        self.chip_row.addStretch(1)
        #: Rows are a reading list; the folder is where the bytes actually are, and the two can
        #: disagree (the user may have moved a file), so the folder gets a button of its own.
        self.open_received_dir_button = QPushButton()
        self.open_received_dir_button.setObjectName("Inline")
        self.open_received_dir_button.clicked.connect(self._open_receive_dir)
        self.chip_row.addWidget(self.open_received_dir_button)

        # Columns, because a file list that cannot say which machine it came from or when is
        # a log, not a filing cabinet.
        self.received_list = QTreeWidget()
        self.received_list.setObjectName("ReceivedTable")
        self.received_list.setColumnCount(4)
        self.received_list.setRootIsDecorated(False)
        self.received_list.setAlternatingRowColors(True)
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
        self._received_filter = "all"
        #: Where an arrival stopped existing on disk, so the table can say so instead of
        #: listing a row that opens nothing.
        self._missing: dict[str, str] = {}

        layout.addWidget(self.page_title_files)
        layout.addWidget(self.received_label)
        layout.addLayout(self.chip_row)
        layout.addWidget(self.received_list, 1)
        return page


    def retranslate(self) -> None:
        """Re-apply every visible string, including the ones set from callbacks."""
        self.page_title_transfer.setText(_("传输"))
        self.page_title_files.setText(_("文件"))
        self.mine_box.setTitle(_("我的设备"))
        self.peers_box.setTitle(_("已连接的设备"))
        self.drop_big.setText(_("把文件或文件夹拖到这里"))
        self.drop_hint.setText(
            _("也可以点下面的按钮挑选。对方要先接受，文件才会落到它的接收目录。")
        )
        self.task_title.setText(_("本次会话的传输"))
        self.chip_all.setText(_("全部"))
        self.chip_today.setText(_("今天"))
        self.chip_week.setText(_("近 7 天"))
        self.open_received_dir_button.setText(_("打开接收目录"))
        self.received_list.setHeaderLabels([_("文件"), _("大小"), _("时间"), _("来源设备")])
        self.code_label.setText(self._code_text())
        self.pass_label.setText(self._pass_text())
        self.listen_label.setText(self._listen_text())
        self.channel_label.setText(self._channel_text())
        self.receive_dir_label.setText(_("保存到：{path}").format(path=receive_root()))
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
        self.pick_peer_button.setText(_("从附近选择…"))
        self.pick_peer_button.setToolTip(_("列出广播出来的候选设备，也可以手输地址或粘贴配对串。"))
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
        self.stage_label.setText(self._stage_text())
        self.status_label.setText(self._status_text())
        for row in self._task_rows.values():
            row["cancel"].setText(_("取消"))
        self._sync_chips()
        self._refresh_peers()
        self._refresh_received()

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
        )

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
        self._discovery = DiscoveryService(self.identity, self.device_name, service.port, on_change=self._peers_changed.emit)
        self._discovery.start()
        self._timer.start(CODE_REFRESH_MS)
        # Announcing starts with the port: a machine that is up is a machine worth finding.
        self.qr_label.show()
        self._refresh_pairing()
        log.info("receiving enabled with %d interrupted offer(s) adopted", self._adopted)

    def stop_listening(self) -> None:
        self._timer.stop()
        if self._discovery is not None:
            self._discovery.stop()
            self._discovery = None
        if self._receiver is not None:
            self._receiver.stop()
            self._receiver = None
        # Closing the port ended every session accepted through it, so a row that only ever
        # meant "someone dialled us" would be promising a connection that no longer exists.
        self._connected = [peer for peer in self._connected if peer.fingerprint not in self._inbound]
        self._inbound.clear()
        self._qr_payload = ""
        self.qr_label.clear()
        self.qr_label.hide()
        self.listen_label.setText(self._listen_text())
        self.channel_label.setText(self._channel_text())

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

    def _status_text(self) -> str:
        if self._receive_error:
            return _("这台机器开不了接收端口，但仍能主动发出去：{error}").format(error=self._receive_error)
        if self._adopted and self._receiver is not None:
            return _("上次有 {n} 个传输没传完，对方接着传就会续上。").format(n=self._adopted)
        return ""

    def _refresh_pairing(self) -> None:
        if self._receiver is None or self._discovery is None:
            return
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

    def _decide(self, manifest: dict, who: str, caller: str) -> bool:
        """Called from a server thread; blocks until the user answers or the offer lapses."""
        token = secrets.token_hex(6)
        holder = {"answer": False, "event": threading.Event()}
        with self._ask_lock:
            self._decisions[token] = holder
        self._offer_arrived.emit(manifest, who or f"{caller[:12]}…", token)
        if not holder["event"].wait(self.proto.offer_wait_timeout_s + 5.0):
            log.warning("nobody answered offer %s", manifest.get("offer_id"))
        with self._ask_lock:
            self._decisions.pop(token, None)
        return holder["answer"]

    def _on_offer(self, manifest: dict, who: str, token: str) -> None:
        files = manifest.get("files", [])
        listing = "\n".join(f"· {f.get('relpath')}（{_human(int(f.get('size') or 0))}）" for f in files[:12])
        if len(files) > 12:
            listing += "\n" + _("…共 {n} 个文件").format(n=len(files))
        box = QMessageBox(self)
        box.setWindowTitle(_("接收来自 {who} 的文件？").format(who=who))
        box.setText(_("对方：{who}\n\n{listing}").format(who=who, listing=listing))
        box.setInformativeText(_("保存到：{path}").format(path=receive_root() / str(manifest.get("offer_id", ""))))
        accept = box.addButton(_("接收"), QMessageBox.AcceptRole)
        box.addButton(_("拒绝"), QMessageBox.RejectRole)
        box.exec()
        self._resolve(token, box.clickedButton() is accept)

    def _resolve(self, token: str, answer: bool) -> None:
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
        """The line that says what 连接 will act on. The list above it cannot: it holds peers
        already paired, and the target of the next handshake is by definition not in it."""
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
            return _("自动发现没有运行。点「从附近选择…」手输对方地址。")
        count = len(self._candidate_peers())
        if not count:
            return _("附近暂时没有广播出来的设备。点「从附近选择…」手输地址。")
        return _("附近发现 {n} 台设备，点「从附近选择…」连接。").format(n=count)

    def _is_inbound(self, peer: Peer) -> bool:
        """True for a peer that dialled us: connected, but with no address to send through."""
        return peer.fingerprint in self._inbound and peer.fingerprint not in self._sessions

    def _peer_row(self, peer: Peer) -> str:
        """One roster row as the user reads it. An inbound peer has no known port, so the
        row says what it is instead of printing a colon and a zero."""
        label = peer.name or peer.prefix
        if self._is_inbound(peer):
            return f"{label}    {peer.host}    {_('（对方连进来，只能收）')}"
        return f"{label}    {peer.host}:{peer.port}"

    def _refresh_peers(self) -> None:
        """Paint the connected roster. Discovery callbacks land here too, where they may only
        move the candidate count - a broadcast has no session to send through."""
        current = self._selected()
        self.peer_list.clear()
        for peer in self._connected:
            item = QListWidgetItem(self._peer_row(peer))
            item.setData(Qt.UserRole, peer)
            if self._is_inbound(peer):
                item.setToolTip(
                    _("指纹前缀 {fp}。它主动连进来，本机没有可回拨的地址，所以只能收它的文件。"
                      "要发给它，请由它来连本机。").format(fp=peer.prefix)
                )
            else:
                item.setToolTip(_("指纹前缀 {fp}。已配对，会话保留到点断开为止。").format(fp=peer.prefix))
            self.peer_list.addItem(item)
            if current is not None and peer.fingerprint == current.fingerprint:
                self.peer_list.setCurrentItem(item)
        if not self._connected:
            self.peer_list.addItem(QListWidgetItem(_("还没有已连接的设备。点下面「从附近选择…」挑一台，或手输它的地址。")))
        # The card is the truth about who holds this device's one session, in either direction,
        # so the receiver's door is set from here rather than from each place that moves a row.
        if self._receiver is not None:
            self._receiver.hold_slot_for(self._connected[0].fingerprint if len(self._connected) == 1 else "")
        self.nearby_label.setText(self._nearby_text())
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
        """The 从附近选择… button: discovery's output, one at a time, in a picker."""
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
        self.nearby_label.setText(self._nearby_text())
        self.code_edit.setFocus()

    def verify_address(self, text: str) -> tuple[Peer | None, str]:
        """Reach a device discovery never showed, the way the empty roster promises.

        This works with our own receiver off: verifying an address is one outgoing request,
        and a machine that is not listening has no reason not to send files.
        """
        try:
            host, port, prefix = _split_addr(text, self.proto.transport_port, self.proto.qr_scheme)
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
            self.status_label.setText(_("先在「从附近选择…」里挑一台设备，或手输它的地址。"))
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
        self._connecting = peer
        self.nearby_label.setText(self._nearby_text())
        self._sync_buttons()
        self._connect_worker = threading.Thread(
            target=self._connect_run, args=(peer, code, self.secret_edit.text().strip()), name="chuanshu-connect", daemon=True
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
        except PairNeeded:
            self._close_quietly(conn)
            self._connect_failed.emit(
                _("配对码或密码不对。请照着对方屏幕上现在的 {n} 位码和 {m} 位密码再输一次。").format(
                    n=self.proto.pair_code_digits, m=self.proto.passphrase_chars
                )
            )
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
        self.status_label.setText(_("已连接 {name}，指纹前缀 {fp}。核对无误再发。").format(name=peer.name or peer.prefix, fp=peer.prefix))
        log.info("paired with %s at %s:%d", peer.name, peer.host, peer.port)

    def _on_connect_failed(self, reason: str) -> None:
        self._connecting = None
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

    def _sync_target(self, selected: Peer | None) -> None:
        """Say which device this page would send to, and at what pace it asked to be written at.

        The pace line is not decoration: a peer that declared ``chunk_pace_ms`` makes the
        transfer look exactly like a congested network, and only the receiver knows why.
        """
        if selected is None:
            self.peer_now_label.setText(_("还没有选定接收设备。到「设备」页连一台，或在附近列表里选一台。"))
            self.pace_label.setText("")
            return
        who = selected.name or selected.prefix
        self.peer_now_label.setText(
            _("当前对端：{name}（{addr}，指纹前缀 {fp}）").format(
                name=who, addr=f"{selected.host}:{selected.port}", fp=selected.prefix
            )
        )
        conn = self._sessions.get(selected.fingerprint)
        if conn is None:
            self.pace_label.setText(_("这台设备还没有连接会话，点「连接」建立一条。"))
        elif conn.pace_ms:
            self.pace_label.setText(
                _("对方要求每 {ms} 毫秒写一条 TLS 记录，所以这台设备比局域网正常水平慢，这不是网络故障。").format(
                    ms=conn.pace_ms
                )
            )
        else:
            self.pace_label.setText(_("对方没有要求放慢写入，本机按最快速度发。"))

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

    def _stage_text(self) -> str:
        if not self._staged:
            return _("还没选要发送的内容。")
        total = sum(p.stat().st_size for p in self._staged if p.is_file())
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
        self._add_task_row("send", _("{what} → {who}").format(what=self._stage_text(), who=peer.name or peer.prefix))
        self._worker = threading.Thread(
            target=self._send_worker, args=(peer, paths, base), name="chuanshu-send", daemon=True
        )
        self._worker.start()

    # ---------------------------------------------------------------- task rows

    def _add_task_row(self, key: str, title: str) -> dict:
        """One row per transfer: what, how far, how long, and a way to stop it.

        Rows stay after they finish. A bar that disappears the moment it hits 100% leaves the
        user with no answer to the only question they asked by pressing 发送.
        """
        row = QWidget(self.task_list)
        row.setObjectName("TaskRow")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(8, 6, 8, 6)
        name = QLabel(title)
        name.setWordWrap(True)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(0)
        bar.setFixedSize(150, 16)
        bar.setTextVisible(False)
        # An elapsed clock rather than a throughput estimate: bytes only become a rate once
        # both ends agree the transfer is over, and a mid-flight guess would be a lie.
        elapsed = QLabel("0:00")
        elapsed.setObjectName("Muted")
        cancel = QPushButton(_("取消"))
        cancel.setObjectName("Inline")
        cancel.setToolTip(_("停下这次传输，并让对方扔掉已经收到的半件。"))
        cancel.clicked.connect(lambda _checked=False, stop=key: self._cancel_task(stop))
        layout.addWidget(name, 1)
        layout.addWidget(bar)
        layout.addWidget(cancel)
        item = QListWidgetItem(self.task_list)
        item.setSizeHint(row.sizeHint())
        self.task_list.setItemWidget(item, row)
        entry = {
            "item": item,
            "widget": row,
            "name": name,
            "bar": bar,
            "elapsed": elapsed,
            "cancel": cancel,
            "started": time.time(),
            "title": title,
            "done": False,
        }
        self._task_rows[key] = entry
        self._trim_tasks()
        return entry

    def _trim_tasks(self) -> None:
        """Forget the oldest finished rows so a long session cannot grow the list forever."""
        extra = len(self._task_rows) - _TASK_HISTORY_KEPT
        if extra <= 0:
            return
        finished = [key for key, row in self._task_rows.items() if row["done"]]
        for key in finished[:extra]:
            entry = self._task_rows.pop(key)
            self.task_list.takeItem(self.task_list.row(entry["item"]))

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
        entry["elapsed"].setText(f"{seconds // 60}:{seconds % 60:02d}")
        if percent is not None:
            entry["bar"].setValue(percent)
        if note is not None:
            entry["name"].setText(note)

    def _close_task(self, key: str, ok: bool) -> None:
        entry = self._task_rows.get(key)
        if entry is None:
            return
        entry["bar"].setValue(100 if ok else 0)
        entry["cancel"].setEnabled(False)
        entry["cancel"].setText(_("完成") if ok else _("失败"))
        entry["done"] = True
        self._tick_task(key, note=entry["title"])

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
        except PairNeeded:
            self._finished.emit(False, _("对方不再认识本机的密钥。选中它，输入它屏幕上新显示的配对码再连接。"))
        except protocol_spec.ProtocolError as error:
            self._finished.emit(False, _("对方说：{text}").format(text=proto_errors.describe(error.code)))
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
        if self._received_filter == "all":
            return list(self._received)
        now = time.localtime()
        midnight = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, -1))
        days = 1 if self._received_filter == "today" else 7
        since = midnight - (days - 1) * 86_400
        return [entry for entry in self._received if float(entry.get("at") or 0) >= since]

    def _refresh_received(self) -> None:
        tree = self.received_list
        # Inserting into a sorted tree lets each row land where the previous order says, which
        # scrambles a list of identical timestamps. Sort once, at the end.
        tree.setSortingEnabled(False)
        tree.clear()
        arrivals = self._filtered_arrivals()
        for entry in reversed(arrivals):
            path = str(entry["path"])
            gone = not Path(path).exists()
            row = _ArrivalRow(tree)
            row.path = path
            size = int(entry.get("size") or 0)
            stamp = float(entry.get("at") or 0)
            who = str(entry.get("who") or "")
            row.setText(0, str(entry["relpath"]) + (_("（已经不在了）") if gone else ""))
            row.setData(0, Qt.UserRole, str(entry["relpath"]))
            row.setText(1, _human(size))
            row.setData(1, Qt.UserRole, size)
            row.setText(2, _when(stamp) if stamp else _("时间未知"))
            row.setData(2, Qt.UserRole, stamp)
            row.setText(3, who)
            row.setData(3, Qt.UserRole, who)
            row.setToolTip(0, path if not gone else _("原本落在：{path}").format(path=path))
            if gone:
                # Same row, visibly dimmed: the record still means something even though the
                # bytes moved, and a palette brush keeps it readable in both themes.
                row.setForeground(0, tree.palette().brush(QPalette.Disabled, QPalette.Text))
        if not arrivals:
            placeholder = _ArrivalRow(tree)
            placeholder.path = ""
            placeholder.setText(
                0,
                _("还没有收到校验通过的文件。")
                if self._received_filter == "all"
                else _("这个时间里没有收到的文件。"),
            )
            placeholder.setDisabled(True)
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

    # --------------------------------------------------------------- lifecycle

    def shutdown(self) -> None:
        with self._ask_lock:
            pending = list(self._decisions.values())
            self._decisions.clear()
        # The window can close while an incoming offer is still on screen, and the server
        # thread holding it is waiting on that answer. Quitting means declining.
        for holder in pending:
            holder["event"].set()
        self.stop_listening()
        for conn in self._sessions.values():
            self._close_quietly(conn)
        self._sessions.clear()
        if self._worker is not None and self._worker.is_alive():
            log.info("a transfer is still running; it will finish on its own")
