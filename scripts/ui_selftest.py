"""M1 acceptance harness for the PC transfer UI.

This drives the real window - the real receiving port, the real discovery roster and the
real modal dialogs - rather than mocks of them. QT_QPA_PLATFORM=offscreen keeps it
headless, and APPDATA/XDG_DATA_HOME are repointed at a scratch directory before app.*
loads, so the probe cannot touch a real identity, its pinned peers, its settings or the
files the user has already received.

The fit and squeeze gates are only worth what they measure on the platform the app runs
on: offscreen, Qt substitutes QCommonStyle and forces one font, which inflates every
text-derived minimum and reports a card's padding as zero. That produced squeezes no
window has ever had and hid one it does. Run the layout phases with the real platform:
``QT_QPA_PLATFORM=windows py scripts/ui_selftest.py``.

One shape dominates the code below: the probe IS the GUI thread, so when the app opens a
modal dialog the probe is stuck inside that dialog's nested event loop and can only act on
it from a timer. Hence AutoDialog, and hence every phase triggering work and then reading
back what AutoDialog recorded.

Run:  py -X utf8 scripts/ui_selftest.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The run prints the strings each language puts on screen, and this console is GBK by default:
# a Korean caption would abort the run in the middle of the check that is trying to report it.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
SCRATCH = Path(tempfile.mkdtemp(prefix="chuanshu-ui-"))
os.environ["APPDATA"] = str(SCRATCH / "appdata")
os.environ["XDG_DATA_HOME"] = str(SCRATCH / "xdg")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QPoint, QPointF, QMimeData, QSize, Qt, QTimer, QUrl  # noqa: E402
from PySide6.QtGui import QDropEvent, QFont  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QInputDialog, QLineEdit, QListWidget, QMessageBox  # noqa: E402

from cryptography import x509  # noqa: E402

from app import autostart  # noqa: E402
from app.config import CLOSE_QUIT, Settings  # noqa: E402
from app.logging_setup import setup_logging  # noqa: E402
from app.net import spec as protocol_spec  # noqa: E402
from app.net.discovery import DiscoveryService, Peer  # noqa: E402
from app.net.identity import Identity, client_context, fingerprint_of, load_or_create  # noqa: E402
from app.net.receive import STATE_FILE, ReceiveService  # noqa: E402
from app.net.send import PeerConnection, plan  # noqa: E402
from app.paths import receive_root, user_data_dir  # noqa: E402
from app.ui import theme  # noqa: E402
from app.ui.language_manager import LanguageManager  # noqa: E402
from app.ui.main_window import NAV_ITEMS, PAGE_SETTINGS, MainWindow  # noqa: E402
from app.ui.transfer import PAGE_FILES, PAGE_HISTORY, PAGE_RECEIVE, PAGE_SEND, PAGE_TRANSFER  # noqa: E402

SHOT = SCRATCH / "window.png"
STAGED_SHOT = SCRATCH / "window-staged.png"
# Everything the user is promised they can click or read, checked against its own minimum.
CONTROLS = (
    "name_label", "rename_button", "listen_label", "channel_label", "qr_label", "code_label",
    "pass_label", "refresh_pair_button",
    "receive_dir_field", "open_dir_button", "received_label", "received_list",
    "peer_list", "nearby_label", "pick_peer_button", "code_edit", "secret_edit", "connect_button",
    "disconnect_button", "stage_label", "pick_files_button", "pick_dir_button",
    "clear_stage_button", "progress", "send_button", "status_label",
    # The rail pages each bring their own captions, and every one of them is a control the
    # user is supposed to be able to read at the smallest size the window allows.
    "page_title_transfer", "page_sub_transfer", "drop_box", "drop_big", "drop_hint", "drop_note", "drop_icon",
    "peer_card_title", "scan_button", "show_history_button",
    "page_title_send", "page_sub_send", "send_target_title", "send_stage_title",
    "peer_now_box", "peer_now_label",
    "pace_label", "task_title", "task_list", "recent_list",
    "page_title_receive", "page_sub_receive", "nearby_title", "peer_note", "rescan_button",
    "page_title_history", "history_list",
    "page_title_files", "files_search", "open_received_dir_button",
)
fails: list[str] = []


def check(name: str, ok: bool, info="") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f": {info}" if info != "" else ""), flush=True)
    if not ok:
        fails.append(name)


def pump(app: QApplication, find, timeout: float):
    """Spin the event loop until ``find`` returns something."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        found = find()
        if found is not None:
            return found
        time.sleep(0.02)
    return None


def pump_until(app: QApplication, ready, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if ready():
            return True
        time.sleep(0.02)
    app.processEvents()
    return ready()


ROLE_FOR = {
    "accept": QMessageBox.ButtonRole.AcceptRole,
    "decline": QMessageBox.ButtonRole.RejectRole,
}


class AutoDialog:
    """Answers the app's modal dialogs from a timer and records what they said.

    The test cannot poll for a dialog: ``exec()`` blocks this very thread, so the only code
    that still runs while a dialog is up is timer code.
    """

    def __init__(self, app: QApplication) -> None:
        self.app = app
        #: accept | decline | pick | manual | idle - what to do with the next modal.
        self.mode = "idle"
        #: What to type into a QInputDialog. None means the probe cannot answer it, so it cancels.
        self.text_reply: str | None = None
        #: A folder the offer card is told to file this one transfer under, or None for the
        #: receive root. It stands in for 浏览, whose file picker is the OS's and not ours to drive.
        self.offer_landing: Path | None = None
        #: callable(QListWidget) -> row index or None, used by the candidate picker.
        self.picker = None
        self.events: list[dict] = []
        self.handled: set[int] = set()
        #: Strong references to the dialogs ``handled`` remembers, so their ids stay out of use.
        self._keep: list = []
        self.timer = QTimer(app)
        self.timer.setInterval(50)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def expect(self, mode: str = "idle", text: str | None = None, picker=None, landing: Path | None = None) -> None:
        self.events.clear()
        self.handled.clear()
        self.mode, self.text_reply, self.picker = mode, text, picker
        self.offer_landing = landing

    def last(self, kind: str) -> dict:
        return next((event for event in reversed(self.events) if event["kind"] == kind), {})

    def _tick(self) -> None:
        for widget in self.app.topLevelWidgets():
            if not widget.isVisible():
                continue
            if isinstance(widget, QInputDialog):
                if id(widget) not in self.handled:
                    self._mark(widget)
                    self._fill(widget)
            elif isinstance(widget, QMessageBox):
                if id(widget) not in self.handled:
                    self._mark(widget)
                    self._click(widget)
            elif widget.objectName() == "candidates":
                # The picker is stepped instead of answered once: it can open a modal of its
                # own, and that has to happen on a later tick (see ``_pick``).
                self._pick(widget)
            elif widget.objectName() == "offer":
                if id(widget) not in self.handled:
                    self._mark(widget)
                    self._answer(widget)

    def _mark(self, widget) -> None:
        """Remember a dialog as answered. The wrapper is kept alive because ``id()`` of a
        throwaway PySide wrapper can be handed to the next dialog and silence it."""
        self.handled.add(id(widget))
        self._keep.append(widget)

    def _click(self, box: QMessageBox) -> None:
        record = {"kind": "message", "title": box.windowTitle(), "text": box.text(), "informative": box.informativeText(), "clicked": ""}
        wanted = ROLE_FOR.get(self.mode)
        for button in box.buttons():
            if wanted is not None and box.buttonRole(button) == wanted:
                button.click()
                record["clicked"] = self.mode
                break
        self.events.append(record)

    def _answer(self, card) -> None:
        """Read the fig5 offer card back and press the button the phase asked for."""
        button = {"accept": card.accept_button, "decline": card.decline_button}.get(self.mode)
        if button is not None and self.mode == "accept" and self.offer_landing is not None:
            # Stands in for the 浏览 dialog the OS owns: choose the folder, then re-read the card
            # so the recorded path is the one the user was shown before pressing 接收.
            card.parent_dir = self.offer_landing
            card._sync_dir()
        record = {
            "kind": "offer",
            "title": card.title.text(),
            "files": list(card.names),
            "path": card.dir_field.text(),
            "browse": card.browse_button.isVisible(),
            "clicked": "",
        }
        if button is not None:
            record["clicked"] = self.mode
            button.click()
        self.events.append(record)

    def _fill(self, box: QInputDialog) -> None:
        record = {"kind": "text", "prompt": box.labelText(), "entered": "", "cancelled": ""}
        line = box.findChild(QLineEdit)
        # Both prompts the app still opens ask for a free string: the device name, and the
        # address of a device discovery never announced.
        if self.text_reply is not None and line is not None:
            record["entered"] = self.text_reply
            line.setText(self.text_reply)
            box.accept()
        else:
            # Either no prompt was expected or the test cannot answer it: say so by cancelling.
            box.reject()
            record["cancelled"] = self.mode
        self.events.append(record)

    def _modal_above(self, box) -> bool:
        """True while some other modal dialog is open on top of the picker."""
        return any(
            widget is not box and widget.isVisible() and isinstance(widget, (QDialog, QInputDialog))
            for widget in self.app.topLevelWidgets()
        )

    def _pick(self, box) -> None:
        """Drive the candidate picker the way the user does: add an address by hand if the
        mode says so, then select a row and press the dialog's own 连接 button.

        One step per tick. Qt does not re-enter a timer callback while it is still on the
        stack, so the 手输地址 prompt is scheduled rather than clicked here; and `accept()`
        hides that prompt before the app verifies the address it was given, so the row is
        only picked once the GUI thread has had a free tick to finish the check.
        """
        step = int(box.property("probeStep") or 0)
        if self.mode == "manual" and step == 0:
            box.setProperty("probeStep", 1)
            QTimer.singleShot(0, box.manual_button.click)
            return
        if step == 1:
            # `expect()` cleared the events, so any record means the prompt has been answered.
            if self._modal_above(box) or not self.events:
                return
            box.setProperty("probeStep", 2)
            return
        if box.property("probePicked") or self._modal_above(box):
            return
        box.setProperty("probePicked", True)
        record = {"kind": "pick", "rows": [], "chosen": "", "error": box.error_label.text()}
        rows = [box.list_.item(i).text() for i in range(box.list_.count())]
        record["rows"] = rows
        index = self.picker(box.list_) if self.picker is not None else None
        if index is None:
            record["chosen"] = "(no matching row)"
            box.reject()
        else:
            box.list_.setCurrentRow(index)
            record["chosen"] = rows[index]
            self._accept(box)
        self.events.append(record)

    @staticmethod
    def _accept(box) -> None:
        for button in box.buttons.buttons():
            if box.buttons.buttonRole(button) == QDialogButtonBox.AcceptRole:
                button.click()
                return
        box.accept()


def blob(seed: int, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}|{counter}".encode()).digest()
        counter += 1
    return bytes(out[:size])


def corpus(proto: protocol_spec.Protocol) -> tuple[Path, list[Path]]:
    """A text file, one that spans two chunks and an empty one - the three shapes that
    break a naive progress bar."""
    base = SCRATCH / "outbox"
    files = [base / "hello.txt", base / "相册" / "2026" / "IMG_大文件.bin", base / "empty.dat"]
    payloads = ["传书 UI fixture\n".encode("utf-8") * 4, blob(11, proto.chunk_size + 4096), b""]
    for path, data in zip(files, payloads):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return base, files


def offer_dirs(root: Path) -> set[str]:
    return {p.name for p in root.iterdir() if p.is_dir()} if root.is_dir() else set()


def port_open(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        return probe.connect_ex(("127.0.0.1", port)) == 0
    finally:
        probe.close()


def row_for_port(list_widget: QListWidget, port: int):
    """The picker row for the service on ``port``. Discovery rebuilds the candidate list, so
    this is asked again for every attempt rather than remembering an index."""
    for index in range(list_widget.count()):
        peer = list_widget.item(index).data(Qt.UserRole)
        if isinstance(peer, Peer) and peer.port == port:
            return index
    return None


def roster_row(panel, port: int):
    """The connected-roster row for ``port``, or None. That card only ever holds paired peers,
    so a row appearing here is the finding itself, not a step towards one."""
    for index in range(panel.peer_list.count()):
        peer = panel.peer_list.item(index).data(Qt.UserRole)
        if isinstance(peer, Peer) and peer.port == port:
            return panel.peer_list.item(index)
    return None


def roster_fingerprint(panel, fingerprint: str):
    """The connected-roster row for a key, whatever address it came in on."""
    for index in range(panel.peer_list.count()):
        item = panel.peer_list.item(index)
        if getattr(item.data(Qt.UserRole), "fingerprint", "") == fingerprint:
            return item
    return None


def clear_roster(app: QApplication, panel) -> None:
    """Hand the one session slot back through the door the user has: select the row, click 断开.

    One peer at a time is the rule under test, so a phase that dials out would otherwise be
    refused by the panel itself because an earlier probe - inbound or already connected - still
    holds the slot.
    """
    for _ in range(8):
        rows = [
            panel.peer_list.item(i)
            for i in range(panel.peer_list.count())
            if isinstance(panel.peer_list.item(i).data(Qt.UserRole), Peer)
        ]
        if not rows:
            return
        panel.peer_list.setCurrentItem(rows[0])
        panel.disconnect_button.click()
        app.processEvents()


def roster_texts(panel) -> list[str]:
    """What the connected card says, row by row.

    The rows are widgets drawn the way the mockup draws them, so they carry no item text; the
    accessible name is the same words a screen reader gets, which is what the user reads.
    """
    out = []
    for index in range(panel.peer_list.count()):
        row = panel.peer_list.itemWidget(panel.peer_list.item(index))
        out.append(getattr(row, "accessibleName", lambda: "")() or f"row {index}")
    return out


def received_rows(panel) -> list[str]:
    """The arrivals table as the user reads it. An empty table shows one hint row, and that
    row is not an arrival, so it is reported as no rows rather than counted as one."""
    if not panel._received:
        return []
    tree = panel.received_list
    return [tree.topLevelItem(i).text(0) for i in range(tree.topLevelItemCount())]


# --------------------------------------------------------------------------- phases


def phase_rail(app: QApplication, window: MainWindow) -> None:
    """The rail, the drop box and the arrivals table - what the four pages promise on their own.

    Dropping is driven by handing the panel a real QDropEvent rather than by calling the
    staging helper: the promise is that a drag from explorer lands files in the box, and only
    the event path can show whether the panel accepts it at all.
    """
    panel = window.panel
    # A rail button's position and the stack page it opens are two different numbers: 传输记录
    # sits between 文件 and 设置 in the stack but is not a rail entry, so the pair is read from
    # NAV_ITEMS rather than counted.
    for key, _msgid, _glyph, page in NAV_ITEMS:
        window.nav_buttons[key].click()
        app.processEvents()
        check(f"the rail's {key} button shows page {page}", panel.current_page() == page and window.nav_buttons[key].isChecked(),
              f"{panel.current_page()} | {[b.isChecked() for b in window.nav_buttons.values()]}")
    window.show_page(0)
    app.processEvents()
    check("the drop box is the first thing the page says", "拖拽文件到此处" in panel.drop_big.text(), panel.drop_big.text())
    check("the dashboard sends nowhere until 发送 is opened", panel.stack.currentIndex() == PAGE_TRANSFER,
          panel.stack.currentIndex())
    check("the page names the device it would send to", "还没有选定接收设备" in panel.peer_now_label.text(), panel.peer_now_label.text())

    staged = [SCRATCH / "drag-a.txt", SCRATCH / "nested" / "drag-b.txt"]
    for path in staged:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("dragged", encoding="utf-8")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(p)) for p in staged])
    drop = QDropEvent(QPointF(20, 20), Qt.CopyAction, mime, Qt.LeftButton, Qt.NoModifier)
    panel.dropEvent(drop)
    app.processEvents()
    check("a drop stages the files it carried", [p.name for p in panel._staged] == [p.name for p in staged], panel._staged)
    check("and the box says so", "2" in panel.stage_label.text(), panel.stage_label.text())
    check("a drop from two folders still finds one base", str(panel._staged_base) == str(SCRATCH), panel._staged_base)
    panel._clear_stage()
    app.processEvents()

    spread = [SCRATCH / "x" / "one.txt", Path(os.environ["SystemDrive"]) / "y" / "two.txt"]
    for path in spread:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    far = QMimeData()
    far.setUrls([QUrl.fromLocalFile(str(p)) for p in spread])
    panel.dropEvent(QDropEvent(QPointF(20, 20), Qt.CopyAction, far, Qt.LeftButton, Qt.NoModifier))
    app.processEvents()
    check("a selection with no shared base is refused out loud", panel._staged == [] and "同一个文件夹" in panel.status_label.text(),
          panel.status_label.text())


def phase_arrivals(app: QApplication, window: MainWindow) -> None:
    """The 文件 page over a list that survives this run - and one whose bytes have moved."""
    panel = window.panel
    if not panel._received:
        check("arrivals were recorded", False, "nothing landed, so the table was never exercised")
        return
    stored = json.loads((user_data_dir() / "arrivals.json").read_text(encoding="utf-8"))
    check("every arrival is written down", len(stored) == len(panel._received), f"{len(stored)} vs {len(panel._received)}")
    check("and names where it came from and when", all(e.get("who") and e.get("at") for e in stored), stored[:1])

    window.show_page(PAGE_FILES)
    app.processEvents()
    rows = received_rows(panel)
    # The pills sort by what a file is, not when it landed: the 日期 column already answers the
    # second question with one header click, so a 今天 pill would only re-ask it.
    panel.file_chips["video"].click()
    app.processEvents()
    kept = received_rows(panel)
    # A run where no video ever landed has nothing to keep, and the honest answer there is the
    # placeholder - so the filter passes either by showing only videos or by saying none match.
    check("视频 keeps only the videos", all(".mp4" in t for t in kept) or kept == ["没有符合条件的文件。"], kept)
    check("and says so when none match", not kept or "没有符合条件" in kept[0], kept)
    check("only one pill is pressed", [c.isChecked() for c in panel._chips].count(True) == 1,
          [c.isChecked() for c in panel._chips])
    panel.file_chips["all"].click()
    app.processEvents()
    check("全部 puts the list back", received_rows(panel) == rows, received_rows(panel))
    needle = Path(str(panel._received[-1]["relpath"])).name[:4]
    panel.files_search.setText(needle)
    app.processEvents()
    check("the search box narrows the list", bool(received_rows(panel)) and all(needle in t for t in received_rows(panel)),
          f"{needle} -> {received_rows(panel)}")
    panel.files_search.setText("没有这个名字")
    app.processEvents()
    check("and says so when nothing matches", "没有符合条件" in (received_rows(panel) or [""])[0], received_rows(panel))
    panel.files_search.setText("")
    app.processEvents()

    newest = panel._received[-1]
    victim = Path(newest["path"])
    victim.rename(victim.parent / (victim.name + ".moved"))
    panel._refresh_received()
    app.processEvents()
    listed = [panel.received_list.topLevelItem(i) for i in range(panel.received_list.topLevelItemCount())]
    # Match the row by where its bytes were, not by the words in it: two batches carrying the
    # same file name are shown apart on purpose, so the name alone is no longer an identifier.
    row = next((r for r in listed if r.path == str(victim)), None)
    check("a moved file is still listed, and says it moved", row is not None and "已经不在了" in row.text(0),
          None if row is None else row.text(0))
    if row is not None:
        panel._open_received(row)
        app.processEvents()
        check("opening it explains rather than failing silently", "已经不在这个位置" in panel.status_label.text(), panel.status_label.text())
    victim.parent.joinpath(victim.name + ".moved").rename(victim)
    panel._refresh_received()


def phase_idle(app: QApplication, window: MainWindow, proto: protocol_spec.Protocol) -> None:
    """Launching is listening: the port, the beacon and the picture all come up by themselves."""
    panel = window.panel
    check("opens already receiving", panel._receiver is not None and panel._discovery is not None, panel._receiver)
    check("the rotate button is what the card offers", panel.refresh_pair_button.text() == "更换配对码和密码", panel.refresh_pair_button.text())
    pixmap = panel.qr_label.pixmap()
    check("QR painted at launch", not panel.qr_label.isHidden() and pixmap is not None and not pixmap.isNull(),
          "hidden" if panel.qr_label.isHidden() else (None if pixmap is None else pixmap.size()))
    check("the fixed code is on screen", re.search(rf"(?<!\d)\d{{{proto.pair_code_digits}}}(?!\d)", panel.code_label.text()) is not None, panel.code_label.text())
    check("the passphrase is shown next to it", re.search(rf"[A-Z2-9]{{{proto.passphrase_chars}}}(?![A-Z2-9])", panel.pass_label.text()) is not None, panel.pass_label.text())
    check("the port is stated", str(panel._receiver.port) in panel.listen_label.text(), panel.listen_label.text())
    check("own name carries an inline edit", panel.name_label.text() == f"本机：{panel.device_name}" and panel.rename_button.text() == "编辑",
          f"{panel.name_label.text()} | {panel.rename_button.text()}")
    check("send disabled with nothing staged", not panel.send_button.isEnabled())

    # The sending card promises paired devices only, and the code belongs to it on the page.
    check("the peer card promises only paired devices", panel.peer_card_title.text() == "已连接设备",
          panel.peer_card_title.text())
    check("the roster starts empty and says so",
          panel._connected == [] and panel.peer_note.isVisible() and "还没有已连接的设备" in panel.peer_note.text(),
          panel.peer_note.text())
    check("the pair code is a field, not a prompt", panel.code_edit.maxLength() == proto.pair_code_digits and "配对码" in panel.code_edit.placeholderText(),
          f"{panel.code_edit.maxLength()} | {panel.code_edit.placeholderText()}")
    check("the password is a field too", panel.secret_edit.maxLength() == proto.passphrase_chars and "密码" in panel.secret_edit.placeholderText(),
          f"{panel.secret_edit.maxLength()} | {panel.secret_edit.placeholderText()}")
    check("连接 is clickable before anything is chosen", panel.connect_button.isEnabled() and panel.pick_peer_button.isEnabled(),
          f"{panel.connect_button.isEnabled()} {panel.pick_peer_button.isEnabled()}")
    panel.connect_button.click()
    app.processEvents()
    check("connecting blind names the missing step", "点一台" in panel.status_label.text(), panel.status_label.text())
    check("the arrivals table is promised and honest", "收到的文件" in panel.received_label.text()
          and "校验通过" in panel.received_list.topLevelItem(0).text(0),
          f"{panel.received_label.text()} | {panel.received_list.topLevelItem(0).text(0)}")
    check("断开 is not offered for a device that is not paired", not panel.disconnect_button.isEnabled())


def phase_start(app: QApplication, window: MainWindow, proto: protocol_spec.Protocol) -> int:
    """The code is fixed, so the one thing the page can still do is replace it on request."""
    panel = window.panel
    port = getattr(panel._receiver, "port", 0)
    check("receiving bound a port", port > 0, f"{port} (contract default {proto.transport_port})")
    check("discovery is running", panel._discovery is not None)
    before_code = panel._receiver.current_pair_code()
    before_pass = panel._receiver.passphrase()
    before_qr = panel._qr_payload
    check("the code survives a repaint", before_code == panel._receiver.current_pair_code(), before_code)
    panel.refresh_pair_button.click()
    app.processEvents()
    check("rotate changes the code", panel._receiver.current_pair_code() != before_code, panel._receiver.current_pair_code())
    check("rotate changes the passphrase", panel._receiver.passphrase() != before_pass, panel._receiver.passphrase())
    check("rotate repaints the picture", panel._qr_payload != before_qr, panel._qr_payload)
    check("the new code is on screen", panel._receiver.current_pair_code() in panel.code_label.text(), panel.code_label.text())
    check("the new passphrase is on screen", panel._receiver.passphrase() in panel.pass_label.text(), panel.pass_label.text())
    check("device list explains itself", panel.peer_list.count() >= 1 or panel.peer_note.isVisible(),
          f"{panel.peer_list.count()} rows | {panel.peer_note.text()}")
    check("the candidate line points at the picker", "手输地址" in panel.nearby_label.text()
          or "点上面一台" in panel.nearby_label.text() or "已选择" in panel.nearby_label.text(),
          panel.nearby_label.text())
    check("discovery channels reported", panel.channel_label.text() != "", panel.channel_label.text())
    window.grab().save(str(SHOT))
    check("screenshot captured", SHOT.is_file() and SHOT.stat().st_size > 1000, user_data_dir())
    return port


def squeeze(root, named: dict, scrollable: bool = False) -> tuple[list, list]:
    """Measure every visible control against its own minimum and against the window edge.

    ``root`` is already at the size under test; it is the frame the controls live in, which
    is the main window for the panel and the settings window for its pages.

    ``scrollable`` is for a page that scrolls on purpose: there, running past the bottom edge
    is one wheel-turn away from being seen, so only the horizontal edge can really cut a
    control off - the vertical bar is the one thing that page never shows.
    """
    squeezed, cut_off = [], []
    for name, widget in named.items():
        if not widget.isVisible():
            continue
        if widget.hasHeightForWidth():
            # A wrapping label is allowed to be narrower than one line of text; what must
            # not happen is that it runs out of *height* and loses the tail of the sentence.
            need = widget.heightForWidth(widget.width())
            if widget.height() < need:
                squeezed.append(f"{name} {widget.width()}x{widget.height()} needs {need} tall at that width")
            continue
        floor = widget.minimumSizeHint()
        # A control the code pins below the style's default floor - the mockups' 6px rail - is not
        # being squeezed by the layout. The pin is the design, so only the width can still run short.
        floor = QSize(min(floor.width(), widget.maximumWidth()), min(floor.height(), widget.maximumHeight()))
        # QGridLayout rounds when it hands a cell its column's width, so a widget can land
        # a pixel under its own hint without losing any of its text. Two is the slack the
        # rounding needs; anything past that is the control genuinely not fitting.
        if widget.width() < floor.width() - 2 or widget.height() < floor.height() - 2:
            # The text and the box it was given: a control that needs 300 and gets 234 at a window
            # floor of 1578 is not a translation problem, it is a layout that never got the news.
            holder = widget.parent()
            font = widget.font()
            squeezed.append(
                f"{name} {widget.width()}x{widget.height()} < its own {floor.width()}x{floor.height()}"
                f" [{widget.text()!r} in {type(holder).__name__} {holder.width()}x{holder.height()}"
                f" | {type(widget.style()).__name__} {font.family()}@{font.pointSizeF()}"
                f" ss={bool(widget.styleSheet())}]"
            )
        origin = widget.mapTo(root, QPoint(0, 0))
        outside = origin.x() < 0 or origin.x() + widget.width() > root.width()
        if not scrollable:
            outside = outside or origin.y() < 0 or origin.y() + widget.height() > root.height()
        if outside:
            cut_off.append(f"{name} at {origin.x()},{origin.y()} +{widget.width()}x{widget.height()} in {root.width()}x{root.height()}")
    return squeezed, cut_off


def phase_fit(app: QApplication, window: MainWindow, label: str) -> None:
    """Controls must survive the smallest window the user can drag this to, on every rail page.

    One squeeze per page rather than one per window: a QStackedWidget is sized by its widest
    page, so measuring only the one on screen would let the 设备 card's QR or the 文件 table's
    columns be cut off and nobody would notice until the user clicked there.
    """
    panel = window.panel
    window.resize(window.minimumSize())
    app.processEvents()
    # The size under test is the window's own claim about its floor. When a control still does not
    # fit at that size, the floor is what is wrong, and the report has to say which of the two it is.
    named = {name: getattr(panel, name) for name in CONTROLS}
    print(f"FIT     window floor {window.width()}x{window.height()} min {window.minimumWidth()}x{window.minimumHeight()}",
          flush=True)
    # A control left out of a layout is never measured: it becomes its own top-level widget,
    # invisible, and the loop below skips it as "not visible". Check parentage once, up front,
    # so a widget dropped from a page fails loudly instead of quietly disappearing from it.
    orphans = [name for name, widget in named.items() if widget.window() is not window]
    check("every control is inside a page", not orphans, orphans)
    for page in (PAGE_TRANSFER, PAGE_SEND, PAGE_RECEIVE, PAGE_FILES, PAGE_HISTORY, PAGE_SETTINGS):
        window.show_page(page)
        app.processEvents()
        squeezed, cut_off = squeeze(window, named)
        where = panel.stack.widget(page).objectName() or f"page{page}"
        check(f"every control keeps its own minimum ({label}, {where})", not squeezed, squeezed)
        check(f"no control is cut off by the window edge ({label}, {where})", not cut_off, cut_off)
        window.grab().save(str(SCRATCH / f"window-min-{label.split()[0]}-{page}.png"))
    window.show_page(0)
    window.resize(1080, 680)
    app.processEvents()


def _served_fingerprint(port: int) -> str:
    """The SPKI digest of whatever really answers on this port, without pairing or pinning."""
    try:
        raw = socket.socket()
        raw.settimeout(5.0)
        with client_context().wrap_socket(raw, server_hostname="chuanshu") as conn:
            conn.connect(("127.0.0.1", port))
            return fingerprint_of(x509.load_der_x509_certificate(conn.getpeercert(binary_form=True)))[:12]
    except (OSError, ValueError) as error:
        return f"unreachable({type(error).__name__})"


def phase_incoming(app: QApplication, dialog: AutoDialog, panel, sender: Identity, files, accept: bool, landing: Path | None = None) -> None:
    """An offer arrives over the wire and the user answers the dialog either way.

    ``landing`` is the folder the user picked with 浏览 for this one transfer; None means the
    answer was the plain 接收, which files it under this machine's receive root.
    """
    label = "accept" if accept else "decline"
    arrivals = len(received_rows(panel))
    conn = PeerConnection(sender, "Probe-Sender", "127.0.0.1", panel._receiver.port, panel.identity.fingerprint)
    outcome: dict = {}

    def push() -> None:
        try:
            conn.hello()
            conn.pair(panel._receiver.current_pair_code())
            outcome["offered"] = conn.offer(files)
            outcome["result"] = conn.send(files)
        except BaseException as error:  # noqa: BLE001 - whatever the sender saw is the finding
            # Which port answered, with whose certificate, is the whole difference between "the
            # panel refused us" and "a second instance on this machine took the port".
            outcome["error"] = error
            outcome["where"] = f"127.0.0.1:{panel._receiver.port} want={panel.identity.fingerprint[:12]} served={_served_fingerprint(panel._receiver.port)}"

    dialog.expect(label, landing=landing)
    thread = threading.Thread(target=push, daemon=True, name="probe-sender")
    thread.start()
    done = pump_until(app, lambda: not thread.is_alive(), 90.0)
    thread.join(timeout=5)
    if not done:
        check(f"the {label} path finished", False, outcome)
    card = dialog.last("offer")
    joined = f"{card.get('title', '')} {' '.join(card.get('files', []))} {card.get('path', '')}"
    check(f"incoming offer asks the user ({label})", bool(card), card)
    check(f"the card names the sender ({label})", "Probe-Sender" in card.get("title", ""), card.get("title", ""))
    check(f"the card lists the files ({label})", "IMG_大文件.bin" in joined, joined[:120])
    check(f"the card shows where they land ({label})", str(landing or receive_root()) in card.get("path", ""), card.get("path", "")[:120])
    check(f"the card lets the user choose the folder ({label})", bool(card.get("browse")), card.get("browse"))
    check(f"the {label} button was clicked", card.get("clicked") == label, card.get("clicked", ""))
    # The bug this run exists for: a phone that dialled in never reached the panel, so the
    # user watched a file arrive while 已连接的设备 stayed empty.
    row = roster_fingerprint(panel, sender.fingerprint)
    check(f"an inbound device shows on the connected card ({label})", row is not None, roster_texts(panel))
    if row is not None:
        words = panel.peer_list.itemWidget(row).accessibleName()
        check(f"the inbound row says what it can do ({label})", "只能收" in words, words)
        check(f"the inbound holder owns the one session slot ({label})", panel._locked_out() is not None, panel._locked_out())
    if not accept:
        error = outcome.get("error")
        check("declining stops the transfer", getattr(error, "code", "") == "DECLINED", type(error).__name__ if error else "no error")
        check("a declined offer adds nothing to the arrivals list", len(received_rows(panel)) == arrivals,
              f"{arrivals} -> {len(received_rows(panel))}")
        return
    check("accepted transfer raised nothing", "error" not in outcome, f"{outcome.get('error')} [{outcome.get('where')}]" if "error" in outcome else None)
    verified = (outcome.get("result") or {}).get("verified", [])
    check("receiver verified every file", bool(verified) and all(v["ok"] for v in verified), [v for v in verified if not v["ok"]])
    # The sender comes back the moment finalize's reply lands, but the list is painted by a queued
    # slot on the GUI thread, which has not necessarily run yet. Wait for the paint instead of
    # reading the table at whatever point the two threads happened to be at - a run that counts the
    # rows too early sees the *previous* transfer's total and calls it a missing arrival.
    painted = pump_until(app, lambda: len(received_rows(panel)) >= arrivals + len(files), 20.0)
    check("every verified file was written down on screen", painted, f"{len(received_rows(panel))} of {arrivals + len(files)} rows")
    root = (landing or receive_root()) / conn.offer_id
    bad = [f.relpath for f in files if not (root / f.relpath).is_file() or hashlib.sha256((root / f.relpath).read_bytes()).hexdigest() != f.sha256]
    check("files landed byte-identical where the card said they would", not bad, bad or str(root))
    # The ledger is what makes an interrupted offer resumable - and what makes it look abandoned.
    # A finished one has to take it away, or the next run's reclaim is deleting somebody's files.
    check("a finished transfer leaves no resumable ledger behind", not list(root.glob(STATE_FILE)),
          [str(p) for p in root.glob(STATE_FILE)])
    # The list is painted from finalize's verdict, so a file that arrived on disk but failed to
    # hash would have to stay off it - and a declined one already did, above.
    rows = [[panel.received_list.topLevelItem(i).text(col) for col in range(4)] for i in range(panel.received_list.topLevelItemCount())]
    missing = [file.relpath for file in files if not any(Path(file.relpath).name in row[0] for row in rows)]
    check("the arrivals list shows every verified file", not missing, f"{missing} missing from {rows}")
    check("an arrival is counted, not just named", len(rows) == arrivals + len(files), f"{arrivals} + {len(files)} -> {len(rows)}")
    # The sender is a column now, not a tooltip: a table that cannot say who sent what is a log.
    check("an arrival names its sender", bool(rows) and rows[0][3] == "Probe-Sender", rows[:1])
    check("an arrival carries its size and time", bool(rows) and rows[0][1] and rows[0][2], rows[:1])
    check("the arrivals list puts the newest first", bool(rows) and files[-1].relpath in rows[0][0], [row[0] for row in rows[:2]])


def offer_cards(app: QApplication) -> list:
    """The fig5 cards on screen right now - the ones a user could still press 接收 on."""
    return [widget for widget in app.topLevelWidgets() if widget.objectName() == "offer" and widget.isVisible()]


def phase_offer_expiry(app: QApplication, dialog: AutoDialog, panel, sender: Identity, files) -> None:
    """Nobody answers the card, so the card has to leave the screen by itself.

    The server thread stops waiting after ``offer_wait_timeout_s`` + 5 and says so from another
    thread; the answer it would have read is gone, so a 接收 button still on screen would be a
    button that can no longer be honoured. The wait is shortened rather than waited out - this
    phase is about who closes the card, not about how long a person is allowed to think.
    """
    arrivals = len(received_rows(panel))
    conn = PeerConnection(sender, "Probe-Sender", "127.0.0.1", panel._receiver.port, panel.identity.fingerprint)
    outcome: dict = {}

    def push() -> None:
        try:
            conn.hello()
            conn.pair(panel._receiver.current_pair_code())
            conn.offer(files)
        except BaseException as error:  # noqa: BLE001 - whatever the sender saw is the finding
            outcome["error"] = error
            outcome["where"] = f"served={_served_fingerprint(panel._receiver.port)}"

    original = panel.proto
    panel.proto = replace(original, offer_wait_timeout_s=2)
    thread = threading.Thread(target=push, daemon=True, name="probe-nobody")
    dialog.expect("expire")
    #: Cards the probe had to take off screen because the app had not closed them.
    forced: list[str] = []

    def watchdog() -> None:
        # A card the app leaves up is not a check this probe can reach: ``exec()`` owns this
        # thread until it closes, so the run would stop there instead of reporting the leak.
        for stuck in offer_cards(app):
            forced.append(stuck.title.text())
            stuck.done(QDialog.Rejected)

    guard = QTimer(app)
    guard.setInterval(15_000)
    guard.timeout.connect(watchdog)
    guard.start()
    thread.start()
    try:
        # There is no polling for the card and then for its absence: ``exec()`` blocks this thread,
        # so the one ``processEvents`` call that opens the card does not return until it has been
        # closed again. What the timer recorded on the way through is the evidence it was asked,
        # and the sender coming back is the evidence it was answered - by nobody.
        done = pump_until(app, lambda: not thread.is_alive(), 40.0)
    finally:
        guard.stop()
        panel.proto = original
    thread.join(timeout=20)
    card = dialog.last("offer")
    check("an unanswered offer still asks the user", done and bool(card), f"thread={done} card={card}")
    check("the card names the files it is asking about", card.get("files") == ["hello.txt", "相册/2026/IMG_大文件.bin", "empty.dat"],
          card.get("files"))
    check("nobody answered this card", card.get("clicked") == "", card.get("clicked", ""))
    gone = not offer_cards(app)
    check("the card closes itself once the server stopped waiting", gone and not forced,
          f"{len(offer_cards(app))} card(s) still up" + (f", probe closed {len(forced)}" if forced else ""))
    check("the status line says why it went", "等不到回答" in panel.status_label.text(), panel.status_label.text())
    error = outcome.get("error")
    check("the sender is told the offer was declined", getattr(error, "code", "") == "DECLINED",
          f"{type(error).__name__}: {error} [{outcome.get('where')}]" if error else "the sender was never answered")
    check("an expired offer adds nothing to the arrivals list", len(received_rows(panel)) == arrivals,
          f"{arrivals} -> {len(received_rows(panel))}")


def connect_through_ui(app: QApplication, dialog: AutoDialog, panel, port: int, code: str, label: str, manual: bool = False) -> bool:
    """从附近选择… → choose the row → type the code on the page → 连接, then read the roster back.

    Everything later in a phase depends on this having made a session, so a failed handshake is
    reported here rather than being mistaken for a broken send.
    """
    dialog.expect("manual" if manual else "pick", text=f"127.0.0.1:{port}" if manual else None,
                  picker=lambda boxes: row_for_port(boxes, port))
    panel.pick_peer_button.click()
    app.processEvents()
    pick = dialog.last("pick")
    if manual:
        # Typing an address is the one path with no broadcast to vouch for the host, so the
        # picker has to show the fingerprint it just observed before the row is usable.
        check(f"the address typed by hand was confirmed ({label})", "已确认" in pick.get("error", ""), pick.get("error", ""))
    chosen = pick.get("chosen", "")
    check(f"the picker offered that device ({label})", bool(chosen) and chosen != "(no matching row)", f"{pick.get('rows')} -> {chosen}")
    if not isinstance(panel._pending, Peer):
        check(f"choosing a row names the next target ({label})", False, pick)
        return False
    check(f"the page says whose code it wants ({label})", panel._pending.port == port and "已选择" in panel.nearby_label.text(),
          panel.nearby_label.text())
    panel.code_edit.setText(code)

    connected: list = []
    refused: list[str] = []

    def on_ok(peer, _conn) -> None:
        connected.append(peer)

    def on_fail(reason: str) -> None:
        refused.append(reason)

    panel._connected_ok.connect(on_ok)
    panel._connect_failed.connect(on_fail)
    panel.connect_button.click()
    settled = pump_until(app, lambda: bool(connected) or bool(refused), 30.0)
    panel._connected_ok.disconnect(on_ok)
    panel._connect_failed.disconnect(on_fail)
    check(f"the handshake settled ({label})", settled, f"{connected} {refused}")
    row = roster_row(panel, port)
    check(f"the device joined the connected card ({label})", row is not None, f"{roster_texts(panel)} | {refused}")
    if row is None:
        return False
    check("the fingerprint is offered for reading back", row.data(Qt.UserRole).prefix in panel.status_label.text(), panel.status_label.text())
    check("the code and password fields are emptied", panel.code_edit.text() == "" and panel.secret_edit.text() == "",
          f"{panel.code_edit.text()} | {panel.secret_edit.text()}")
    check("the code on the page is still the fixed one", panel._receiver.current_pair_code() in panel.code_label.text(), panel.code_label.text())
    check("the new row is the send target", panel._selected() is row.data(Qt.UserRole), roster_texts(panel))
    check("断开 became clickable", panel.disconnect_button.isEnabled())
    return True


def send_through_ui(app: QApplication, panel, paths, base, files, service, service_root, label: str) -> bool:
    """Stage files, click Send, verify the landing.

    No dialog may open on the way: pairing happened at 连接, and a send that interrupted the
    user for a code would be the old design leaking back in.
    """
    panel._staged = list(paths)
    panel._staged_base = base
    panel.stage_label.setText(panel._stage_text())
    panel._sync_buttons()
    check(f"stage summary counts the files ({label})", "3" in panel.stage_label.text(), panel.stage_label.text())
    check(f"send is clickable ({label})", panel.send_button.isEnabled(), roster_texts(panel))
    selected = panel._selected()
    check(f"sending targets the connected device ({label})", selected is not None and selected.port == service.port,
          None if selected is None else f"{selected.name}:{selected.port}")
    panel.window().grab().save(str(STAGED_SHOT))

    finished: list[tuple[bool, str]] = []

    def spy(ok: bool, message: str) -> None:
        finished.append((ok, message))

    panel._finished.connect(spy)
    before = offer_dirs(service_root)
    panel.send_button.click()
    # Wait for the verdict itself, not for the worker thread to die: the report arrives as a
    # queued signal, so a localhost transfer can end before the event loop has delivered it.
    done = pump_until(app, lambda: bool(finished), 90.0)
    panel._finished.disconnect(spy)
    check(f"send finished ({label})", done and bool(finished), finished)
    if not finished:
        return False
    ok, message = finished[0]
    check(f"send succeeded ({label})", ok, message)
    new = offer_dirs(service_root) - before
    check(f"one offer directory was created ({label})", len(new) == 1, sorted(new))
    if len(new) != 1:
        return ok
    root = service_root / next(iter(new))
    bad = [f.relpath for f in files if not (root / f.relpath).is_file() or hashlib.sha256((root / f.relpath).read_bytes()).hexdigest() != f.sha256]
    check(f"peer received every file byte-identical ({label})", not bad, bad)
    check(f"progress bar ended at 100% ({label})", panel.progress.value() == 100, panel.progress.value())
    # The task row is what the user reads after the bar stops moving: it has to stay, say
    # how it ended, and no longer offer a 取消 for a transfer that is already over.
    row = panel._task_rows.get("send")
    check(f"the send left a finished row ({label})", row is not None and row["done"] and row["bar"].value() == 100, row and dict((k, v) for k, v in row.items() if k in ("done", "title")))
    check(f"a finished row cannot be cancelled ({label})", row is not None and not row["cancel"].isEnabled() and row["cancel"].text() == "完成",
          row and row["cancel"].text())
    return ok


def phase_outgoing(app: QApplication, dialog: AutoDialog, panel, paths, base, files, service, service_root) -> None:
    found = pump(app, lambda: next((peer for peer in panel._candidate_peers() if peer.port == service.port), None), 20.0)
    check("the stranger service appeared over discovery", found is not None, roster_texts(panel))
    check("a broadcast is not yet a connected device", roster_row(panel, service.port) is None, roster_texts(panel))
    if found is None:
        return
    if not connect_through_ui(app, dialog, panel, service.port, service.current_pair_code(), "first connect"):
        return
    if not send_through_ui(app, panel, paths, base, files, service, service_root, "first send"):
        return
    # 断开 gives the session back but keeps the pin, so the next handshake needs no code at all.
    panel.peer_list.setCurrentItem(roster_row(panel, service.port))
    panel.disconnect_button.click()
    app.processEvents()
    check("断开 takes the device off the card", roster_row(panel, service.port) is None, roster_texts(panel))
    check("断开 keeps the pinned key", panel.identity.is_trusted(found.fingerprint), found.fingerprint[:12])
    panel.code_edit.clear()
    if not connect_through_ui(app, dialog, panel, service.port, "", "known peer"):
        return
    check("a pinned device reconnects on an empty code", roster_row(panel, service.port) is not None, roster_texts(panel))
    send_through_ui(app, panel, paths, base, files, service, service_root, "known peer")

def phase_cancel(app: QApplication, panel, paths, base, files, service_root) -> None:
    """取消 mid-send: the worker stops at the next chunk and the half-offer is withdrawn.

    The ask is raised on the first chunk that reports home rather than on a timer: a localhost
    transfer can finish inside one pump, and a race that happens to win either way proves
    nothing. What is under test is the stop path, not the timing. The connection is DirectConnection
    so the flag lands in the worker before it builds the next chunk's request - a queued signal
    would not run until the send was already over.
    """
    panel._staged = list(paths)
    panel._staged_base = base
    panel._sync_buttons()
    if not panel.send_button.isEnabled():
        check("取消 had a send to work with", False, f"{panel.stage_label.text()} | {roster_texts(panel)}")
        return
    before = offer_dirs(service_root)
    finished: list[tuple[bool, str]] = []

    def spy(ok: bool, message: str) -> None:
        finished.append((ok, message))

    def first_chunk(_done: int, _total: int, _relpath: str) -> None:
        # Asking on the first chunk that lands is the deterministic version of a user pressing
        # 取消 mid-transfer: the worker stops at the next one, and the offer is withdrawn.
        panel._cancelled.add("send")

    panel._finished.connect(spy)
    panel._progressed.connect(first_chunk, Qt.DirectConnection)
    panel.send_button.click()
    done = pump_until(app, lambda: bool(finished), 60.0)
    panel._progressed.disconnect(first_chunk)
    panel._finished.disconnect(spy)
    check("取消 ends the send without hanging", done and bool(finished) and finished[0][0] is False, finished)
    check("取消 says it cancelled", bool(finished) and "取消" in finished[0][1], finished[:1])
    # The receiver's abort unlinks the bytes it was given, so the folders it leaves are empty.
    # That is a tidiness gap, not a lie: no half file may survive.
    new = [service_root / name for name in offer_dirs(service_root) - before]
    left = [str(d / f.relpath) for d in new for f in files if (d / f.relpath).is_file()]
    check("a cancelled send leaves no file behind", not left, left or sorted(new))
    row = panel._task_rows.get("send")
    check("the cancelled row is closed", row is not None and row["done"] and not row["cancel"].isEnabled(),
          None if row is None else row["cancel"].text())
    check("the cancel flag is handed back for the next send", "send" not in panel._cancelled, sorted(panel._cancelled))


def phase_single_slot(app: QApplication, dialog: AutoDialog, panel, hidden) -> None:
    """Two ends are connected, so a third is told so - in the panel and over the wire."""
    holder = panel._locked_out()
    check("the connected peer holds the slot", holder is not None and len(panel._connected) == 1, f"{holder} | {roster_texts(panel)}")
    check("连接 is greyed while someone holds it", not panel.connect_button.isEnabled(), panel.connect_button.isEnabled())
    check("the grey-out explains itself", "断开" in panel.connect_button.toolTip(), panel.connect_button.toolTip())
    dialog.expect("manual", text=f"127.0.0.1:{hidden.port}", picker=lambda boxes: row_for_port(boxes, hidden.port))
    panel.pick_peer_button.click()
    app.processEvents()
    pick = dialog.last("pick")
    if not isinstance(panel._pending, Peer):
        check("the second device was reachable", False, pick)
        return
    check("the second device was chosen", panel._pending.port == hidden.port, panel._pending.public())
    # The button is greyed, so the refusal is reached the way a stale click would be: by the
    # handler the button is wired to, with a target already chosen.
    panel._start_connect()
    app.processEvents()
    check("a third device refused in words", "一次只连一台" in panel.status_label.text(), panel.status_label.text())
    check("the refusal leaves one row on the card", len(panel._connected) == 1, roster_texts(panel))
    # And the kernel refuses on its own, without the panel in the loop.
    stranger = load_or_create(SCRATCH / "peer-d")
    refused: list = []
    try:
        third = PeerConnection(stranger, "Probe-Third", "127.0.0.1", panel._receiver.port, panel.identity.fingerprint)
        third.hello()
        third.pair(panel._receiver.current_pair_code(), panel._receiver.passphrase())
    except protocol_spec.ProtocolError as error:
        refused.append(f"{error.code} {(error.detail or {}).get('reason', '')}")
    check("the receiver refuses a stranger too", refused and "PEER_BUSY one peer at a time" in refused[0], refused)
    panel._pending = None
    app.processEvents()


def phase_reclaim(app: QApplication, panel, proto: protocol_spec.Protocol) -> None:
    """A connection that stopped moving hands the one session slot back by itself (spec §3).

    Nothing is clicked here, which is the point: the panel's pairing tick is what notices the
    silence, so the row has to leave the card, 连接 has to stop being greyed, and the status line
    has to say which window closed - the peer is still pinned and can come back without a code.
    """
    if not panel._connected:
        check("the reclaim had a connected peer to watch", False, roster_texts(panel))
        return
    peer = panel._connected[0]
    minutes = proto.session_idle_timeout_s // 60
    panel._receiver._seen[peer.fingerprint] = time.time() - proto.session_idle_timeout_s - 1
    panel._refresh_pairing()  # the slot the pairing timer fires
    app.processEvents()
    check("a stalled peer's row leaves the card", roster_fingerprint(panel, peer.fingerprint) is None, roster_texts(panel))
    check("the slot is free again", panel._locked_out() is None, panel._locked_out())
    check("连接 is clickable again", panel.connect_button.isEnabled(), panel.connect_button.toolTip())
    shown = panel.status_label.text()
    check("the screen names the peer and the window it ran out",
          f"{peer.name or peer.prefix} 已经 {minutes} 分钟没有动静" in shown, shown)
    check("and says the key is kept", "不用再报配对码" in shown, shown)
    check("the peer is still pinned, so its next pair needs no code", panel.identity.trusted_entry(peer.fingerprint) is not None, "")
    check("the receiver keeps no clock for a session nobody holds", peer.fingerprint not in panel._receiver._seen,
          sorted(panel._receiver._seen))

    # The same clock on the half this machine did not dial: a phone that paired its way in.
    stranger = load_or_create(SCRATCH / "peer-e")
    conn = PeerConnection(stranger, "Probe-Stalled", "127.0.0.1", panel._receiver.port, panel.identity.fingerprint)
    seen: list = []

    def handshake() -> None:
        try:
            conn.hello()
            seen.append(conn.pair(panel._receiver.current_pair_code(), panel._receiver.passphrase())["token"])
        except BaseException as error:  # noqa: BLE001 - whatever the sender saw is the finding
            seen.append(error)

    thread = threading.Thread(target=handshake, daemon=True, name="probe-stall")
    thread.start()
    done = pump_until(app, lambda: not thread.is_alive(), 30.0)
    thread.join(timeout=5)
    check("a stranger that dialled in is on the card", done and roster_fingerprint(panel, stranger.fingerprint) is not None, seen)
    panel._receiver._seen[stranger.fingerprint] = time.time() - proto.session_idle_timeout_s - 1
    panel._refresh_pairing()
    app.processEvents()
    check("an inbound peer is held to the same clock", roster_fingerprint(panel, stranger.fingerprint) is None, roster_texts(panel))
    check("its token is really taken away", stranger.fingerprint not in panel._receiver._tokens, sorted(panel._receiver._tokens))
    conn.close()
    # The reclaim's counterpart: a finished transfer must not look like an abandoned one to the
    # next run, because both are a folder with a ledger - and only one of them may be deleted.
    adopted = panel._receiver.adopt_interrupted_offers()
    check("a restart finds nothing to resume among the finished arrivals", adopted == 0, adopted)


def phase_manual(app: QApplication, dialog: AutoDialog, panel, paths, base, files, hidden, hidden_root) -> None:
    """Reach a device discovery never announced - the fallback the empty picker promises."""
    # The picker asked for this address a phase ago, so it is a candidate by then and has been
    # ever since. What is under test here is that *nobody announced it*: discovery alone would
    # never have listed a port it has only heard of because the user typed it.
    announced = {peer.port for peer in panel._discovery.candidates()}
    check("a silent device is not something discovery found", hidden.port not in announced,
          [peer.public() for peer in panel._discovery.candidates()])
    if not connect_through_ui(app, dialog, panel, hidden.port, hidden.current_pair_code(), "typed address", manual=True):
        return
    peer = roster_row(panel, hidden.port).data(Qt.UserRole)
    check("the typed row is verified on arrival", peer.verified and "manual" in peer.via, peer.public())
    check("its prefix is the observed digest", peer.prefix == peer.fingerprint[: panel.proto.prefix_chars], peer.prefix)
    if not send_through_ui(app, panel, paths, base, files, hidden, hidden_root, "typed address"):
        return
    # And the same door on a machine that does not answer: the picker has to say so itself,
    # because the main window's status line is behind that modal.
    dialog.expect("manual", text="127.0.0.1:1", picker=lambda boxes: row_for_port(boxes, hidden.port))
    panel.pick_peer_button.click()
    app.processEvents()
    pick = dialog.last("pick")
    check("an unreachable address says so in the picker", "连不上" in pick.get("error", ""), pick.get("error", ""))
    check("a failed add leaves no row for that port",
          sum(1 for peer in panel._candidate_peers() if peer.port == 1) == 0,
          [peer.public() for peer in panel._candidate_peers()])
    check("the device typed in by hand is still listed once",
          sum(1 for peer in panel._candidate_peers() if peer.port == hidden.port) == 1, pick.get("rows"))


#: Settings controls that must survive the smallest size of that window.
SETTINGS_CONTROLS = (
    "name_edit", "language_box", "theme_box", "close_box",
    "autostart_switch", "notify_switch", "limit_switch", "limit_spin",
    "dir_edit", "browse_button", "reset_dir_button", "open_dir_button",
    "proto_label", "pin_list", "unpin_button",
    "version_label", "qt_label", "protocol_label", "data_label", "open_log_button",
)


def caption(page, msgid: str) -> str:
    """What the sheet currently shows for one of its row captions.

    The rows have no names of their own - the caption *is* the row - so this asks the page's
    own string table, which is also the only place that knows a translation reached the sheet.
    A switch carries the same caption as its accessible name and paints no text at all, so an
    empty `text()` is not evidence the string never arrived; ask the name before giving up.
    """
    for widget, key, _setter in page._bound:
        if key == msgid:
            shown = str(widget.text()) or str(widget.accessibleName())
            if shown:
                return shown
    return ""


def phase_settings(app: QApplication, window: MainWindow) -> None:
    """The rail's 设置 page and everything it promises to change."""
    panel = window.panel
    settings = window.settings

    window.show_page(0)
    window.title_bar.settings_button.click()
    app.processEvents()
    d = window.settings_page
    check("the gear opens the settings page", d is not None and d.isVisible() and panel.current_page() == PAGE_SETTINGS,
          f"{d} | {panel.current_page()}")
    check("receiving survives while it is open", panel._receiver is not None, panel._receiver)
    check("the rail marks the page you are on", window.nav_buttons["settings"].isChecked() and not window.nav_buttons["transfer"].isChecked(),
          {k: b.isChecked() for k, b in window.nav_buttons.items()})

    named = {name: getattr(d, name) for name in SETTINGS_CONTROLS}
    check("every control the page ever had is still on the sheet", all(w is not None for w in named.values()),
          [n for n, w in named.items() if w is None])
    # The mockup draws one sheet of captioned rows with a hairline between them, and there is no
    # menu to click. n rows means n-1 separators; anything else means a row was added without
    # being drawn apart from its neighbour, or the paging came back.
    titles = [w for w, key, _s in d._bound if w.objectName() == "RowTitle"]
    rules = [
        d.rows.itemAt(i).widget()
        for i in range(d.rows.count())
        if d.rows.itemAt(i).widget() is not None and d.rows.itemAt(i).widget().objectName() == "Hairline"
    ]
    check("the sheet is rows and hairlines, with no menu in front of them",
          len(rules) == len(titles) - 1 and not hasattr(d, "menu"), f"{len(titles)} rows, {len(rules)} hairlines")

    life = d.proto_label.text()
    keeps_its_word = str(panel.proto.pair_code_digits) in life and (
        "固定" in life if panel.proto.pair_code_static else str(panel.proto.pair_code_ttl_s) in life
    )
    check("the page quotes the contract", str(panel.proto.transport_port) in life
          and f"{panel.proto.chunk_size:,}" in life and keeps_its_word, life)

    d.name_edit.setText("Selftest-Renamed")
    d.name_edit.editingFinished.emit()
    app.processEvents()
    check("the name typed here reaches the panel", panel.device_name == "Selftest-Renamed" and "Selftest-Renamed" in panel.name_label.text(),
          f"{panel.device_name} | {panel.name_label.text()}")
    check("and is saved", settings.get("device_name") == "Selftest-Renamed", settings.get("device_name"))
    check("the inline editor keeps the same name", panel.set_device_name("Selftest-Inline") and d.name_edit.text() == "Selftest-Inline",
          d.name_edit.text())

    target_dir = SCRATCH / "selftest-recv"
    d._set_receive_dir(str(target_dir))
    app.processEvents()
    check("the receive folder moved", str(receive_root()) == str(target_dir) and settings.get("receive_dir") == str(target_dir), receive_root())
    check("moving it does not close the port", panel._receiver is not None, panel._receiver)
    check("and the sheet shows where it went", str(target_dir) in d.dir_edit.text(), d.dir_edit.text())
    d.open_dir_button.click()
    app.processEvents()
    d._reset_dir()
    app.processEvents()
    check("restore default points back at the app folder", str(receive_root()) == str(user_data_dir() / "received") and not settings.get("receive_dir"),
          receive_root())

    d.theme_buttons["dark"].click()
    app.processEvents()
    check("a theme pill repaints the app", settings.get("theme") == "dark" and window.palette.name == "dark", settings.get("theme"))
    check("and only the pill you picked is still outlined",
          d.theme_buttons["dark"].isChecked() and not d.theme_buttons["light"].isChecked(),
          {k: b.isChecked() for k, b in d.theme_buttons.items()})
    d.theme_buttons["auto"].click()
    d.close_box.setCurrentIndex(max(0, d.close_box.findData(CLOSE_QUIT)))
    app.processEvents()
    check("the close choice is remembered", settings.get("on_close") == CLOSE_QUIT, settings.get("on_close"))
    # Running from source cannot register autostart, so the switch has to say so by being greyed.
    check("autostart is only offered where it works", d.autostart_switch.isEnabled() == autostart.is_supported(), d.autostart_switch.isEnabled())

    # The two switches the mockup draws but no earlier build had: each one has to be a promise
    # the sender or the tray actually keeps, not a light that comes on.
    d.limit_switch.click()
    app.processEvents()
    check("the speed limit switch is remembered", bool(settings.get("limit_on")), settings.get("limit_on"))
    check("and the number beside it wakes up", d.limit_spin.isEnabled(), d.limit_spin.isEnabled())
    d.limit_spin.setValue(37)
    app.processEvents()
    check("so does the rate", int(settings.get("limit_mbps")) == 37, settings.get("limit_mbps"))
    budget = panel._throttle()
    check("a limited sender budgets the wire", budget is not None and budget.bps == 37 * 1_000_000,
          None if budget is None else budget.bps)
    d.limit_switch.click()
    app.processEvents()
    check("with the switch off nothing is held back", panel._throttle() is None and not d.limit_spin.isEnabled(),
          f"{settings.get('limit_on')} | {d.limit_spin.isEnabled()}")
    d.notify_switch.click()
    app.processEvents()
    check("the notice switch is remembered", settings.get("notify") is False, settings.get("notify"))
    d.notify_switch.click()
    app.processEvents()
    check("and so is putting it back", bool(settings.get("notify")), settings.get("notify"))
    check("a switch says what it is without any text on it",
          bool(d.notify_switch.accessibleName()) and bool(d.limit_switch.accessibleName()),
          f"{d.notify_switch.accessibleName()} | {d.limit_switch.accessibleName()}")

    # Paired devices: the outgoing sends pinned peers, so the list has something in it.
    pinned = panel.identity.pinned_fingerprints()
    d.reload()
    check("the pinned devices are listed", d.pin_list.count() == len(pinned) and pinned, f"{d.pin_list.count()} of {len(pinned)}")
    rows = {d.pin_list.item(i).data(Qt.UserRole): i for i in range(d.pin_list.count())}
    victim = pinned[0]
    d.pin_list.setCurrentRow(rows[victim])
    check("choosing a device enables the revoke button", d.unpin_button.isEnabled(), d.unpin_button.text())
    d.unpin_button.click()
    app.processEvents()
    check("revoking forgets the key", not panel.identity.is_trusted(victim), victim[:12])
    check("and the list follows", d.pin_list.count() == len(pinned) - 1, d.pin_list.count())
    check("a revoked device also leaves the connected card", not any(peer.fingerprint == victim for peer in panel._connected),
          roster_texts(panel))

    d.language_box.setCurrentIndex(max(0, d.language_box.findData("en")))
    app.processEvents()
    # Which English words a row lands on is the catalogue's business; that it landed on some is
    # the page's. An unfilled msgstr mirrors the Chinese back, and an empty one shows nothing.
    check("a language picked here rewrites the sheet too",
          caption(d, "保存路径") not in ("", "保存路径") and window.nav_buttons["transfer"].text() == "Transfer",
          f"{caption(d, '保存路径')} | {window.nav_buttons['transfer'].text()}")
    check("including the caption that carries the product name",
          caption(d, "开机自启") not in ("", "开机自启") and "{" not in caption(d, "开机自启"),
          caption(d, "开机自启"))
    d.language_box.setCurrentIndex(max(0, d.language_box.findData("zh_CN")))
    app.processEvents()
    check("and back", caption(d, "保存路径") == "保存路径" and window.nav_buttons["transfer"].text() == "传输", caption(d, "保存路径"))

    window.show_page(0)
    app.processEvents()
    window.open_settings()
    app.processEvents()
    check("reopening reuses the same page", window.settings_page is d and d.isVisible() and panel.current_page() == PAGE_SETTINGS)
    phase_settings_fit(app, window, "zh_CN")
    window.show_page(0)


def phase_settings_fit(app: QApplication, window: MainWindow, label: str) -> None:
    """The same squeeze the other pages get, for a sheet that scrolls instead of paging.

    The window is the frame under test, not the page: a page inside a rail can be given less
    room than its own layout asks for, and that is exactly the clipping this measures.
    """
    page = window.settings_page
    window.show_page(PAGE_SETTINGS)
    window.resize(window.minimumSize())
    app.processEvents()
    named = {name: getattr(page, name) for name in SETTINGS_CONTROLS}
    # The hint sentences are the controls most likely to be cut off, and they are the ones the
    # page holds by role rather than by name.
    named.update({f"note{i}": note for i, (note, _width) in enumerate(page._wrapping)})
    print(f"FIT     settings floor {window.width()}x{window.height()} min {window.minimumWidth()}x{window.minimumHeight()}",
          flush=True)
    orphans = [n for n, widget in named.items() if widget.window() is not window]
    check(f"every setting control is inside the page ({label})", not orphans, orphans)
    squeezed, cut_off = squeeze(window, named, scrollable=True)
    check(f"every setting control fits at {window.width()}x{window.height()} ({label})", not squeezed, squeezed)
    check(f"no setting control is cut off sideways ({label})", not cut_off, cut_off)
    # The sheet's width is the one number the scroll area cannot fake: a horizontal bar is
    # switched off, so a row wider than the viewport has simply lost its right-hand end.
    room = page.scroll.viewport().width()
    wide = [
        f"{n} wants {widget.minimumSizeHint().width()} of {room}"
        for n, widget in named.items()
        if widget.isVisible() and not widget.hasHeightForWidth() and widget.minimumSizeHint().width() > room
    ]
    check(f"the sheet is wide enough for its own controls ({label})", not wide, wide)
    window.grab().save(str(SCRATCH / f"settings-min-{label}.png"))
    window.resize(1080, 680)
    app.processEvents()
    window.grab().save(str(SCRATCH / f"settings-page-{label}.png"))


def phase_language(app: QApplication, window: MainWindow, languages: LanguageManager) -> None:
    """Every catalogue the menu offers, squeezed at the smallest size both windows allow."""
    panel = window.panel
    for code in languages.available():
        if code == "zh_CN":
            continue
        languages.set_language(code)
        app.processEvents()
        text = panel.refresh_pair_button.text()
        # An empty msgstr would render as nothing; an unfilled one still says 更换配对码和密码.
        check(f"{code} translates instead of mirroring", bool(text) and text != "更换配对码和密码", text)
        phase_fit(app, window, code)
        window.open_settings()
        app.processEvents()
        phase_settings_fit(app, window, code)
        window.show_page(0)
    languages.set_language("en")
    app.processEvents()
    check("english relabels the panel", panel.mine_box.title() == "My device" and panel.refresh_pair_button.text() == "Change code and password",
          f"{panel.mine_box.title()} | {panel.refresh_pair_button.text()}")
    digits = panel.proto.pair_code_digits
    check("english keeps the pairing code", re.search(rf"Pairing code: \d{{{digits}}}(?!\d)", panel.code_label.text()) is not None, panel.code_label.text())
    check("english keeps the password", re.search(rf"Password: [A-Z2-9]{{{panel.proto.passphrase_chars}}}(?![A-Z2-9])", panel.pass_label.text()) is not None, panel.pass_label.text())
    check("english renames the peer card", panel.peer_card_title.text() == "Connected devices", panel.peer_card_title.text())
    roster = " | ".join(roster_texts(panel) or [panel.peer_note.text()])
    # How much is still connected this late in the run is a question of session lifetimes, not of
    # the language, so the count cannot be the assertion. What has to hold in either state is that
    # English wrote it: a row reads Online or Connected, an empty roster says so in English too.
    check("english writes the device roster", bool(roster) and not re.search(r"[\u4e00-\u9fff]", roster), roster)
    check("english keeps the arrivals table", "收到的文件" not in panel.received_label.text() and "verified" in panel.received_label.text(),
          panel.received_label.text())
    # Five stops, in the mockup's order: the 传输 page is where you land, and 发送 and 接收 are
    # its own two directions rather than one merged "Devices" step.
    check("english relabels the rail", [b.text() for b in window.nav_buttons.values()] ==
          ["Transfer", "Send", "Receive", "Files", "Settings"],
          [b.text() for b in window.nav_buttons.values()])
    languages.set_language("zh_CN")
    app.processEvents()
    check("switching back re-applies Chinese", panel.mine_box.title() == "我的设备", panel.mine_box.title())


def phase_shutdown(app: QApplication, window: MainWindow) -> None:
    port = window.panel._receiver.port
    window.quit_app()
    pump(app, lambda: None if port_open(port) else True, 5.0)
    check("quitting released the transport port", not port_open(port), port)


def main() -> int:
    proto = protocol_spec.load()
    setup_logging()
    app = QApplication.instance() or QApplication(sys.argv)
    if app.platformName() == "offscreen":
        # The offscreen plugin resolves no CJK fallback, so a screenshot taken here would be
        # a wall of tofu; ask for a font the real build gets from the OS by default.
        app.setFont(QFont("Microsoft YaHei UI", 9))
    settings = Settings()
    settings.set("language", "zh_CN")
    languages = LanguageManager()
    languages.set_language("zh_CN")
    theme.apply_theme(app, theme.palette_for("light"))

    # Two strangers: one pushes files at the panel, the other is the panel's send target.
    pusher = load_or_create(SCRATCH / "peer-a")
    target = load_or_create(SCRATCH / "peer-b")
    target_root = SCRATCH / "peer-b-received"
    service = ReceiveService(target, "Probe-Receiver", lambda manifest, who, caller: True, port=0, root=target_root)
    service.start()
    announcer = DiscoveryService(target, "Probe-Receiver", service.port)
    announcer.start()
    # A third one that never announces itself: reachable only by typing its address.
    silent = load_or_create(SCRATCH / "peer-c")
    silent_root = SCRATCH / "peer-c-received"
    hidden = ReceiveService(silent, "Probe-Silent", lambda manifest, who, caller: True, port=0, root=silent_root)
    hidden.start()

    base, paths = corpus(proto)
    files = plan(paths, base=base)
    # A live instance on this machine owns the contract port, and Windows lets a second socket
    # claim the same number anyway - the probe would then pair with the neighbour's certificate
    # and fail a dozen checks that have nothing to do with the code under test. So the panel is
    # built with a port nobody is answering on, before it ever binds one, and the run says out
    # loud that it did not use the contract default.
    spare_port = proto.transport_port
    original_load = None
    if port_open(spare_port):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        taken, spare_port = spare_port, probe.getsockname()[1]
        probe.close()
        original_load = protocol_spec.load
        protocol_spec.load = lambda: replace(original_load(), transport_port=spare_port)
        print(f"NOTE  port {taken} already serves another peer; the probe uses {spare_port}", flush=True)
    window = MainWindow(settings, languages)
    window.show()
    app.processEvents()
    dialog = AutoDialog(app)
    panel = window.panel
    try:
        phase_idle(app, window, proto)
        phase_start(app, window, proto)
        phase_rail(app, window)
        phase_fit(app, window, "zh_CN at the minimum size")
        phase_incoming(app, dialog, panel, pusher, files, accept=True)
        # 浏览 picks a parent for this one transfer; it is not a way to move the receive root.
        phase_incoming(app, dialog, panel, pusher, files, accept=True, landing=SCRATCH / "chosen")
        check("a folder picked on the card leaves the receive root alone", str(receive_root()) != str(SCRATCH / "chosen"),
              f"{receive_root()} vs {SCRATCH / 'chosen'}")
        phase_incoming(app, dialog, panel, pusher, files, accept=False)
        phase_offer_expiry(app, dialog, panel, pusher, files)
        phase_arrivals(app, window)
        # Each probe that dials in takes the one session slot, so the card has to be cleared
        # before this machine can be the one that dials out.
        clear_roster(app, panel)
        check("断开 empties the card and frees the slot", panel._connected == [] and panel._locked_out() is None, roster_texts(panel))
        phase_outgoing(app, dialog, panel, paths, base, files, service, target_root)
        # 取消 rides the same session: the peer is still connected and reachable here, which is
        # the only situation where the button on the task row means anything.
        phase_cancel(app, panel, paths, base, files, target_root)
        phase_single_slot(app, dialog, panel, hidden)
        phase_reclaim(app, panel, proto)
        clear_roster(app, panel)
        phase_manual(app, dialog, panel, paths, base, files, hidden, silent_root)
        phase_settings(app, window)
        phase_language(app, window, languages)
        phase_shutdown(app, window)
    finally:
        if original_load is not None:
            protocol_spec.load = original_load
        announcer.stop()
        service.stop()
        hidden.stop()
        print(f"\nscratch: {SCRATCH}\nscreenshot: {SHOT}")
        print("RESULT " + (f"FAILED {len(fails)}: " + " / ".join(fails) if fails else "ALL PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
