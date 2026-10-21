"""M1 acceptance harness for the PC transfer UI.

This drives the real window - the real receiving port, the real discovery roster and the
real modal dialogs - rather than mocks of them. QT_QPA_PLATFORM=offscreen keeps it
headless, and APPDATA/XDG_DATA_HOME are repointed at a scratch directory before app.*
loads, so the probe cannot touch a real identity, its pinned peers, its settings or the
files the user has already received.

One shape dominates the code below: the probe IS the GUI thread, so when the app opens a
modal dialog the probe is stuck inside that dialog's nested event loop and can only act on
it from a timer. Hence AutoDialog, and hence every phase triggering work and then reading
back what AutoDialog recorded.

Run:  py -X utf8 scripts/ui_selftest.py
"""

from __future__ import annotations

import hashlib
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
SCRATCH = Path(tempfile.mkdtemp(prefix="chuanshu-ui-"))
os.environ["APPDATA"] = str(SCRATCH / "appdata")
os.environ["XDG_DATA_HOME"] = str(SCRATCH / "xdg")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QPoint, Qt, QTimer  # noqa: E402
from PySide6.QtGui import QFont  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QInputDialog, QLineEdit, QListWidget, QMessageBox  # noqa: E402

from cryptography import x509  # noqa: E402

from app import autostart  # noqa: E402
from app.config import CLOSE_QUIT, Settings  # noqa: E402
from app.i18n import LanguageManager  # noqa: E402
from app.logging_setup import setup_logging  # noqa: E402
from app.net import spec as protocol_spec  # noqa: E402
from app.net.discovery import DiscoveryService, Peer  # noqa: E402
from app.net.identity import Identity, client_context, fingerprint_of, load_or_create  # noqa: E402
from app.net.receive import ReceiveService  # noqa: E402
from app.net.send import PeerConnection, plan  # noqa: E402
from app.paths import receive_root, user_data_dir  # noqa: E402
from app.ui import theme  # noqa: E402
from app.ui.main_window import MainWindow  # noqa: E402
from app.ui.settings_dialog import SECTIONS  # noqa: E402

SHOT = SCRATCH / "window.png"
STAGED_SHOT = SCRATCH / "window-staged.png"
# Everything the user is promised they can click or read, checked against its own minimum.
CONTROLS = (
    "name_label", "rename_button", "listen_label", "channel_label", "qr_label", "code_label",
    "pass_label", "refresh_pair_button",
    "receive_dir_label", "open_dir_button", "received_label", "received_list",
    "peer_list", "nearby_label", "pick_peer_button", "code_edit", "secret_edit", "connect_button",
    "disconnect_button", "stage_label", "pick_files_button", "pick_dir_button",
    "clear_stage_button", "progress", "send_button", "status_label",
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

    def expect(self, mode: str = "idle", text: str | None = None, picker=None) -> None:
        self.events.clear()
        self.handled.clear()
        self.mode, self.text_reply, self.picker = mode, text, picker

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
    return [panel.peer_list.item(i).text() for i in range(panel.peer_list.count())]


def received_rows(panel) -> list[str]:
    """The arrivals card as the user reads it. An empty list shows one hint sentence, and that
    row is not an arrival, so it is reported as no rows rather than counted as one."""
    if not panel._received:
        return []
    return [panel.received_list.item(i).text() for i in range(panel.received_list.count())]


# --------------------------------------------------------------------------- phases


def phase_idle(app: QApplication, window: MainWindow, proto: protocol_spec.Protocol) -> None:
    """Launching is listening: the port, the beacon and the picture all come up by themselves."""
    panel = window.panel
    check("opens already receiving", panel._receiver is not None and panel._discovery is not None, panel._receiver)
    check("the rotate button is what the card offers", panel.refresh_pair_button.text() == "更换配对码和密码", panel.refresh_pair_button.text())
    pixmap = panel.qr_label.pixmap()
    check("QR painted at launch", not panel.qr_label.isHidden() and pixmap is not None and not pixmap.isNull(),
          "hidden" if panel.qr_label.isHidden() else (None if pixmap is None else pixmap.size()))
    check("the fixed code is on screen", re.search(r"\d{4}", panel.code_label.text()) is not None, panel.code_label.text())
    check("the passphrase is shown next to it", re.search(r"[A-Z2-9]{4}", panel.pass_label.text()) is not None, panel.pass_label.text())
    check("the port is stated", str(panel._receiver.port) in panel.listen_label.text(), panel.listen_label.text())
    check("own name carries an inline edit", panel.name_label.text() == f"本机：{panel.device_name}" and panel.rename_button.text() == "编辑",
          f"{panel.name_label.text()} | {panel.rename_button.text()}")
    check("send disabled with nothing staged", not panel.send_button.isEnabled())

    # The sending card promises paired devices only, and the code belongs to it on the page.
    check("the peer card promises only paired devices", panel.peers_box.title() == "已连接的设备", panel.peers_box.title())
    check("the roster starts empty and says so", panel._connected == [] and "还没有已连接的设备" in panel.peer_list.item(0).text(),
          roster_texts(panel))
    check("the pair code is a field, not a prompt", panel.code_edit.maxLength() == proto.pair_code_digits and "配对码" in panel.code_edit.placeholderText(),
          f"{panel.code_edit.maxLength()} | {panel.code_edit.placeholderText()}")
    check("the password is a field too", panel.secret_edit.maxLength() == proto.passphrase_chars and "密码" in panel.secret_edit.placeholderText(),
          f"{panel.secret_edit.maxLength()} | {panel.secret_edit.placeholderText()}")
    check("连接 is clickable before anything is chosen", panel.connect_button.isEnabled() and panel.pick_peer_button.isEnabled(),
          f"{panel.connect_button.isEnabled()} {panel.pick_peer_button.isEnabled()}")
    panel.connect_button.click()
    app.processEvents()
    check("connecting blind names the missing step", "挑一台" in panel.status_label.text(), panel.status_label.text())
    check("the arrivals list is promised and honest", "接收到的文件" in panel.received_label.text()
          and "校验通过" in panel.received_list.item(0).text(), f"{panel.received_label.text()} | {panel.received_list.item(0).text()}")
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
    check("device list explains itself", panel.peer_list.count() >= 1, panel.peer_list.count())
    check("the candidate line points at the picker", "从附近选择" in panel.nearby_label.text() and panel.nearby_label.text() != "", panel.nearby_label.text())
    check("discovery channels reported", panel.channel_label.text() != "", panel.channel_label.text())
    window.grab().save(str(SHOT))
    check("screenshot captured", SHOT.is_file() and SHOT.stat().st_size > 1000, user_data_dir())
    return port


def squeeze(root, named: dict) -> tuple[list, list]:
    """Measure every visible control against its own minimum and against the window edge.

    ``root`` is already at the size under test; it is the frame the controls live in, which
    is the main window for the panel and the settings window for its pages.
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
        # QGridLayout rounds when it hands a cell its column's width, so a widget can land
        # a pixel under its own hint without losing any of its text. Two is the slack the
        # rounding needs; anything past that is the control genuinely not fitting.
        if widget.width() < floor.width() - 2 or widget.height() < floor.height() - 2:
            squeezed.append(f"{name} {widget.width()}x{widget.height()} < its own {floor.width()}x{floor.height()}")
        origin = widget.mapTo(root, QPoint(0, 0))
        if origin.x() < 0 or origin.y() < 0 or origin.x() + widget.width() > root.width() or origin.y() + widget.height() > root.height():
            cut_off.append(f"{name} at {origin.x()},{origin.y()} +{widget.width()}x{widget.height()} in {root.width()}x{root.height()}")
    return squeezed, cut_off


def phase_fit(app: QApplication, window: MainWindow, label: str) -> None:
    """Controls must survive the smallest window the user can drag this to, not only a roomy one."""
    panel = window.panel
    window.resize(window.minimumSize())
    app.processEvents()
    squeezed, cut_off = squeeze(window, {name: getattr(panel, name) for name in CONTROLS})
    check(f"every control keeps its own minimum ({label})", not squeezed, squeezed)
    check(f"no control is cut off by the window edge ({label})", not cut_off, cut_off)
    window.grab().save(str(SCRATCH / f"window-min-{label.split()[0]}.png"))
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


def phase_incoming(app: QApplication, dialog: AutoDialog, panel, sender: Identity, files, accept: bool) -> None:
    """An offer arrives over the wire and the user answers the dialog either way."""
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

    dialog.expect(label)
    thread = threading.Thread(target=push, daemon=True, name="probe-sender")
    thread.start()
    done = pump_until(app, lambda: not thread.is_alive(), 90.0)
    thread.join(timeout=5)
    if not done:
        check(f"the {label} path finished", False, outcome)
    box = dialog.last("message")
    joined = f"{box.get('title', '')} {box.get('text', '')} {box.get('informative', '')}"
    check(f"incoming offer asks the user ({label})", bool(box), box)
    check(f"dialog names the sender ({label})", "Probe-Sender" in joined, joined[:120])
    check(f"dialog lists the files ({label})", "IMG_大文件.bin" in joined, joined[:120])
    check(f"dialog shows the save path ({label})", str(receive_root()) in joined, box.get("informative", "")[:120])
    check(f"the {label} button was clicked", box.get("clicked") == label, box.get("clicked", ""))
    # The bug this run exists for: a phone that dialled in never reached the panel, so the
    # user watched a file arrive while 已连接的设备 stayed empty.
    row = roster_fingerprint(panel, sender.fingerprint)
    check(f"an inbound device shows on the connected card ({label})", row is not None, roster_texts(panel))
    if row is not None:
        check(f"the inbound row says what it can do ({label})", "只能收" in row.text(), row.text())
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
    root = receive_root() / conn.offer_id
    bad = [f.relpath for f in files if not (root / f.relpath).is_file() or hashlib.sha256((root / f.relpath).read_bytes()).hexdigest() != f.sha256]
    check("files landed byte-identical in the receive root", not bad, bad or str(root))
    # The list is painted from finalize's verdict, so a file that arrived on disk but failed to
    # hash would have to stay off it - and a declined one already did, above.
    rows = [panel.received_list.item(i).text() for i in range(panel.received_list.count())]
    missing = [file.relpath for file in files if not any(file.relpath in row for row in rows)]
    check("the arrivals list shows every verified file", not missing, f"{missing} missing from {rows}")
    check("an arrival is counted, not just named", len(rows) == arrivals + len(files), f"{arrivals} + {len(files)} -> {len(rows)}")
    check("an arrival names its sender", "Probe-Sender" in panel.received_list.item(0).toolTip(), panel.received_list.item(0).toolTip())
    check("the arrivals list puts the newest first", bool(rows) and files[-1].relpath in rows[0], rows[:2])


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


def phase_manual(app: QApplication, dialog: AutoDialog, panel, paths, base, files, hidden, hidden_root) -> None:
    """Reach a device discovery never announced - the fallback the empty picker promises."""
    check("a silent device is not a candidate", hidden.port not in {peer.port for peer in panel._candidate_peers()},
          [peer.public() for peer in panel._candidate_peers()])
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
    "name_edit", "language_box", "theme_box", "autostart_check", "close_box",
    "dir_edit", "browse_button", "reset_dir_button", "open_dir_button",
    "port_label", "chunk_label", "code_life_label", "pin_list", "unpin_button",
    "version_label", "qt_label", "protocol_label", "data_label", "open_log_button",
)


def phase_settings(app: QApplication, window: MainWindow) -> None:
    """The gear button and everything its window promises to change."""
    panel = window.panel
    settings = window.settings

    window.title_bar.settings_button.click()
    app.processEvents()
    d = window.settings_window
    check("the gear opens a settings window", d is not None and d.isVisible() and d.windowTitle() == "设置", d)
    check("receiving survives while it is open", panel._receiver is not None, panel._receiver)
    check("menu lists the sections", [d.menu.item(i).text() for i in range(d.menu.count())] == list(SECTIONS),
          [d.menu.item(i).text() for i in range(d.menu.count())])
    wrong = []
    for row in range(len(SECTIONS)):
        d.menu.setCurrentRow(row)
        app.processEvents()
        if d.stack.currentIndex() != row:
            wrong.append(f"{SECTIONS[row]} -> {d.stack.currentIndex()}")
    check("every menu row shows its own page", not wrong, wrong)
    life = d.code_life_label.text()
    keeps_its_word = str(panel.proto.pair_code_digits) in life and (
        "固定" in life if panel.proto.pair_code_static else str(panel.proto.pair_code_ttl_s) in life
    )
    check("the transfer page quotes the contract", str(panel.proto.transport_port) in d.port_label.text()
          and f"{panel.proto.chunk_size:,}" in d.chunk_label.text() and keeps_its_word,
          f"{d.port_label.text()} | {d.chunk_label.text()} | {life}")

    d.menu.setCurrentRow(0)
    d.name_edit.setText("Selftest-Renamed")
    d.name_edit.editingFinished.emit()
    app.processEvents()
    check("the name typed here reaches the panel", panel.device_name == "Selftest-Renamed" and "Selftest-Renamed" in panel.name_label.text(),
          f"{panel.device_name} | {panel.name_label.text()}")
    check("and is saved", settings.get("device_name") == "Selftest-Renamed", settings.get("device_name"))
    check("the inline editor keeps the same name", panel.set_device_name("Selftest-Inline") and d.name_edit.text() == "Selftest-Inline",
          d.name_edit.text())

    target_dir = SCRATCH / "selftest-recv"
    d.menu.setCurrentRow(1)
    d._set_receive_dir(str(target_dir))
    app.processEvents()
    check("the receive folder moved", str(receive_root()) == str(target_dir) and settings.get("receive_dir") == str(target_dir), receive_root())
    check("moving it does not close the port", panel._receiver is not None, panel._receiver)
    d._reset_dir()
    app.processEvents()
    check("restore default points back at the app folder", str(receive_root()) == str(user_data_dir() / "received") and not settings.get("receive_dir"),
          receive_root())

    d.menu.setCurrentRow(0)
    d.theme_buttons["dark"].click()
    app.processEvents()
    check("a theme radio repaints the app", settings.get("theme") == "dark" and window.palette.name == "dark", settings.get("theme"))
    d.theme_buttons["auto"].click()
    d.close_buttons[CLOSE_QUIT].click()
    app.processEvents()
    check("the close radio is remembered", settings.get("on_close") == CLOSE_QUIT, settings.get("on_close"))
    # Running from source cannot register autostart, so the box has to say so by being greyed.
    check("autostart is only offered where it works", d.autostart_check.isEnabled() == autostart.is_supported(), d.autostart_check.isEnabled())

    # Paired devices: the outgoing sends pinned peers, so the list has something in it.
    d.menu.setCurrentRow(2)
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
    check("a language picked here rewrites this window too", d.windowTitle() == "Settings" and d.menu.item(0).text() == "General",
          f"{d.windowTitle()} | {d.menu.item(0).text()}")
    d.language_box.setCurrentIndex(max(0, d.language_box.findData("zh_CN")))
    app.processEvents()
    check("and back", d.menu.item(0).text() == SECTIONS[0], d.menu.item(0).text())

    d.close()
    app.processEvents()
    window.open_settings()
    app.processEvents()
    check("reopening reuses the same window", window.settings_window is d and d.isVisible())
    # Back to row 0: a measurement pass that starts on the last page would skip the pages
    # before it, because only the current one is visible.
    d.menu.setCurrentRow(0)
    phase_settings_fit(app, d, "zh_CN")
    d.close()


def phase_settings_fit(app: QApplication, dialog, label: str) -> None:
    """The same squeeze the main window gets, for the window the settings promise lives in."""
    dialog.resize(dialog.minimumSize())
    app.processEvents()
    room = dialog.menu.viewport().width()
    cut = [
        dialog.menu.item(row).text()
        for row in range(dialog.menu.count())
        if dialog.menu.fontMetrics().horizontalAdvance(dialog.menu.item(row).text()) > room
    ]
    check(f"the section menu truncates nothing ({label})", not cut, cut)
    bad = []
    for row in range(dialog.menu.count()):
        dialog.menu.setCurrentRow(row)
        app.processEvents()
        named = {name: getattr(dialog, name) for name in SETTINGS_CONTROLS}
        # The hint sentences are the controls most likely to be cut off, and they are the
        # ones the dialog holds by role rather than by name.
        named.update({f"note{i}": note for i, note in enumerate(dialog._wrapping)})
        squeezed, cut_off = squeeze(dialog, named)
        if squeezed or cut_off:
            bad.append(f"{SECTIONS[row]}: {squeezed + cut_off}")
        # One picture per page: the numbers say a control is short, only the shot says whether
        # the sentence above it still reads as a sentence.
        dialog.grab().save(str(SCRATCH / f"settings-min-{label}-{row}.png"))
    check(f"every setting control fits at {dialog.width()}x{dialog.height()} ({label})", not bad, bad)
    dialog.resize(760, 500)
    app.processEvents()
    if label == "zh_CN":
        dialog.menu.setCurrentRow(1)
        dialog.grab().save(str(SCRATCH / "settings-page.png"))


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
        phase_settings_fit(app, window.settings_window, code)
        window.settings_window.close()
    languages.set_language("en")
    app.processEvents()
    check("english relabels the panel", panel.mine_box.title() == "My device" and panel.refresh_pair_button.text() == "Change code and password",
          f"{panel.mine_box.title()} | {panel.refresh_pair_button.text()}")
    check("english keeps the pairing code", re.search(r"Pairing code: \d{4}", panel.code_label.text()) is not None, panel.code_label.text())
    check("english keeps the password", re.search(r"Password: [A-Z2-9]{4}", panel.pass_label.text()) is not None, panel.pass_label.text())
    check("english renames the peer card", panel.peers_box.title() == "Connected devices", panel.peers_box.title())
    check("english keeps the roster", panel.peer_list.count() >= 1, panel.peer_list.count())
    check("english keeps the arrivals list", panel.received_label.text() == "Received files (verified this session)", panel.received_label.text())
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

    window = MainWindow(settings, languages)
    window.show()
    app.processEvents()
    dialog = AutoDialog(app)
    panel = window.panel
    # A live instance on this machine owns the contract port, and Windows lets a second socket
    # claim the same number anyway - the probe would then pair with the neighbour's certificate
    # and fail a dozen checks that have nothing to do with the code under test. So ask for a port
    # nobody is answering on, and say out loud that the run did not use the contract default.
    if port_open(panel.proto.transport_port):
        spare = socket.socket()
        spare.bind(("127.0.0.1", 0))
        taken, spare_port = panel.proto.transport_port, spare.getsockname()[1]
        spare.close()
        panel.proto = replace(panel.proto, transport_port=spare_port)
        print(f"NOTE  port {taken} already serves another peer; the probe uses {panel.proto.transport_port}", flush=True)
    base, paths = corpus(proto)
    files = plan(paths, base=base)
    try:
        phase_idle(app, window, proto)
        phase_start(app, window, proto)
        phase_fit(app, window, "zh_CN at the minimum size")
        phase_incoming(app, dialog, panel, pusher, files, accept=True)
        phase_incoming(app, dialog, panel, pusher, files, accept=False)
        # Each probe that dials in takes the one session slot, so the card has to be cleared
        # before this machine can be the one that dials out.
        clear_roster(app, panel)
        check("断开 empties the card and frees the slot", panel._connected == [] and panel._locked_out() is None, roster_texts(panel))
        phase_outgoing(app, dialog, panel, paths, base, files, service, target_root)
        phase_single_slot(app, dialog, panel, hidden)
        clear_roster(app, panel)
        phase_manual(app, dialog, panel, paths, base, files, hidden, silent_root)
        phase_settings(app, window)
        phase_language(app, window, languages)
        phase_shutdown(app, window)
    finally:
        announcer.stop()
        service.stop()
        hidden.stop()
        print(f"\nscratch: {SCRATCH}\nscreenshot: {SHOT}")
        print("RESULT " + (f"FAILED {len(fails)}: " + " / ".join(fails) if fails else "ALL PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
