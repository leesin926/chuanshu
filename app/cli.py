"""Headless entry point: the same protocol as the window, without Qt.

Why this module exists: a server, a container or a Linux box with no display still has to
receive files and push them out, and the contract is identical either way. Nothing here
imports PySide6 - the Qt-free language core in app/i18n.py and the QTranslator/sign half
in app/ui/language_manager.py are what let app/net/ be imported from a terminal at all.

GUI and CLI are two faces of one identity directory, so ``self``, ``pins`` and the receive
root show the same numbers the window shows. Two caveats that follow from that:

* 43720 is one socket. If the window is already listening, ``receive`` binds an ephemeral
  port and says so; discovery advertises the real number, so a phone still finds it.
* the pin list and the pair code are one file each, written by whichever face changed them.
  A save merges with what is on disk instead of overwriting it, so a device pinned by the
  window is still here after the terminal pins its own.

What is printed on stdout is not run through gettext: a script reads the numbers and the
error codes, and the catalogue is loaded only because the protocol error text is owned by
the contract's own entries (app/net/errors.py).
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time
from pathlib import Path

from app import i18n
from app.config import Settings
from app.logging_setup import setup_logging
from app.meta import APP_NAME, VERSION
from app.net import errors as proto_errors
from app.net import firewall
from app.net import spec as protocol_spec
from app.net.discovery import DiscoveryService, Peer, verify_peer
from app.net.identity import load_or_create
from app.net.receive import ReceiveService
from app.net.send import PairNeeded, PeerConnection, plan
from app.paths import identity_dir, receive_root, user_data_dir

log = logging.getLogger(__name__)

#: A terminal user is slower than a dialog button, and the peer stops waiting at
#: offer_wait_timeout_s no matter what this side is doing, so the deadline is shown.
_PROMPT_MARGIN_S = 5


def device_name(settings: Settings) -> str:
    """What this machine advertises - the same rule the window uses."""
    return str(settings.get("device_name", "") or socket.gethostname())


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


class Terminal:
    """One owner of stdout, so a progress line never corrupts a result line.

    Chunk progress is rewritten in place, which only means something on a terminal: piped
    into a file or another process it would pile up one line per chunk and bury the summary
    a script is there to read, so it is dropped there instead.
    """

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self._live = sys.stdout.isatty()
        self._last = 0.0
        self._done = 0
        self._painted = False

    def say(self, line: str = "") -> None:
        self._erase()
        print(line, flush=True)

    def detail(self, line: str) -> None:
        if not self.quiet:
            self.say(line)

    def progress(self, relpath: str, index: int, total: int) -> None:
        """A callback matching app/net/send.py's ``Progress``.

        ``index`` counts inside one file while ``total`` counts the whole offer, so the
        only honest number here is how many chunks this side has pushed.
        """
        if self.quiet:
            return
        self._done += 1
        if not self._live:
            return
        now = time.monotonic()
        if now - self._last < 0.1:
            return
        self._last = now
        text = f"已推 {self._done}/{max(total, self._done)} 块 · {relpath}"
        sys.stdout.write("\r" + text.ljust(78)[:78])
        sys.stdout.flush()
        self._painted = True

    def _erase(self) -> None:
        if self._painted:
            sys.stdout.write("\r" + " " * 78 + "\r")
            sys.stdout.flush()
            self._painted = False


#: Flags that belong to the run rather than to one command. Declared on a parent so they
#: are accepted on either side of the subcommand, and left without a value otherwise:
#: a plain default here would overwrite whatever the other side of the command line set.
_COMMON = argparse.ArgumentParser(add_help=False)
_COMMON.add_argument("--lang", default=argparse.SUPPRESS, help="这次运行的语言（如 en），默认跟随设置")
_COMMON.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS, help="只打印结果，不打印过程")
_COMMON.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="把日志同时打到屏幕")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chuanshu",
        parents=[_COMMON],
        description=f"{APP_NAME} {VERSION} - 局域网直传（命令行）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "例子：\n"
            "  python -m app.cli self                        本机身份、配对码、目录\n"
            "  python -m app.cli receive                     等人传进来，在终端里问你要不要\n"
            "  python -m app.cli receive --yes --root D:/in  来单就收，落到指定目录\n"
            "  python -m app.cli peers                       列出局域网里应答的设备\n"
            "  python -m app.cli send 192.168.1.7 a.pdf      发给对方（配对码从它屏幕上抄）\n"
            "  python -m app.cli pins                        列出固定的设备\n"
            "  python -m app.cli firewall                     问防火墙：这台机器放不放别人连进来\n"
            "  python -m app.cli unpair 0a1b2c               忘记一台\n"
            "  python -m app.cli pair-code --rotate          换掉配对码和密码\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help_text, parents=[_COMMON])

    add("self", "本机身份、配对码与目录").set_defaults(func=cmd_self)

    p = add("receive", "开一个接收端，等对端传进来")
    p.add_argument("--root", type=Path, default=None, help="落到哪个目录（默认用设置里的接收目录）")
    p.add_argument("--port", type=int, default=None, help="监听端口（默认协议端口，被占用时自动换一个）")
    p.add_argument("--yes", action="store_true", help="来单就收，不在终端里问")
    p.add_argument("--seconds", type=float, default=0, help="收多久后自己退出（0=一直收到按 Ctrl-C）")
    p.add_argument("--no-discover", action="store_true", help="不广播自己，也不听 mDNS")
    p.set_defaults(func=cmd_receive)

    p = add("send", "把文件发给一台设备")
    p.add_argument("address", help="host[:port]，或粘贴配对用的 chuanshu:// 串")
    p.add_argument("files", nargs="+", type=Path, help="要发的文件或文件夹")
    p.add_argument("--code", default="", help="对方屏幕上那几位配对码（没固定过时必填）")
    p.add_argument("--secret", default="", help="对方的密码")
    p.add_argument("--base", type=Path, default=None, help="按哪个目录算相对路径，让对方还原层级")
    p.set_defaults(func=cmd_send)

    p = add("peers", "列出局域网里应答的设备")
    p.add_argument("--seconds", type=float, default=3.0, help="听多久（默认 3 秒）")
    p.add_argument("--no-verify", action="store_true", help="只列发现到的，不逐个连过去读全指纹")
    p.set_defaults(func=cmd_peers)

    add("pins", "列出固定的设备").set_defaults(func=cmd_pins)

    p = add("firewall", "问平台防火墙这台机器放不放对端连进来（只读）")
    p.add_argument("--exe", type=Path, default=None, help="Windows 上问哪个程序（默认正在跑的这个）")
    p.add_argument("--port", type=int, default=None, help="Linux 上按端口问（默认协议端口）")
    p.set_defaults(func=cmd_firewall)

    p = add("unpair", "忘记一台设备，它要重新配对")
    p.add_argument("fingerprint", help="指纹（可只输前缀，但要唯一）")
    p.set_defaults(func=cmd_unpair)

    p = add("pair-code", "显示或换掉配对码与密码")
    p.add_argument("--rotate", action="store_true", help="换一对新的")
    p.set_defaults(func=cmd_pair_code)

    return parser


def _identity():
    """This machine's key, peer id and pin list - the same directory the window uses.

    Pairing material is minted here because `self` and `pair-code` display it: without this,
    a first run straight from a terminal shows two empty lines where the window would show
    the code a peer has to type. Idempotent, so a receiver that mints it again is a no-op.
    """
    identity = load_or_create(identity_dir())
    proto = protocol_spec.load()
    identity.ensure_pairing(proto.pair_code_digits, proto.passphrase_chars)
    return identity


# ---------------------------------------------------------------- commands


def cmd_self(args: argparse.Namespace, out: Terminal) -> int:
    settings = Settings()
    identity = _identity()
    proto = protocol_spec.load()
    out.say(f"本机：{device_name(settings)}")
    out.say(f"设备 ID：{identity.peer_id}")
    out.say(f"指纹：{identity.fingerprint}")
    out.say(f"协议版本：{proto.version}")
    out.say(f"配对码：{identity.pair_code}")
    if proto.passphrase_chars:
        out.say(f"密码：{identity.passphrase}")
    out.say(f"接收目录：{receive_root()}")
    out.say(f"数据目录：{user_data_dir()}")
    out.say(f"身份目录：{identity_dir()}")
    return 0


def cmd_receive(args: argparse.Namespace, out: Terminal) -> int:
    settings = Settings()
    identity = _identity()
    proto = protocol_spec.load()
    root = Path(args.root).expanduser() if args.root else receive_root()
    root.mkdir(parents=True, exist_ok=True)
    ask = threading.Lock()

    def decide(manifest: dict, who: str, caller: str):
        """Answer POST /v1/offer from the terminal.

        Runs on the server thread while the peer's socket stays open, so blocking here is
        the point - it is what makes the offer's long-poll honest. The answer is True for
        this machine's receive root, a folder to use instead, or False to turn it down.
        """
        files = manifest.get("files") or []
        total = int(manifest.get("total_size") or sum(int(f.get("size") or 0) for f in files))
        out.say("")
        out.say(f"来了一个传输请求：{who or caller[:12] or '匿名'}（{len(files)} 个文件，{_human(total)}）")
        for item in files:
            out.say(f"  {item.get('relpath')}  {_human(int(item.get('size') or 0))}")
        if args.yes:
            out.say(f"--yes：收进 {root}")
            return True
        deadline = max(int(proto.offer_wait_timeout_s) - _PROMPT_MARGIN_S, 1)
        with ask:
            out.say(f"落到：{root}")
            try:
                # input() from the server thread is the whole UI here:回车 takes it, a path
                # moves this one offer, and anything else is a refusal. A run whose stdin has
                # nothing on the other end raises EOFError, and no answer is a refusal too.
                answer = input(f"回车接收 / r 拒绝 / 输入一个目录收进那里（{deadline} 秒内回答）：").strip()
            except EOFError:
                answer = "r"
                out.say("（stdin 里没有回答，这单先拒了。要自动收请用 --yes。）")
        if answer.lower() in ("r", "n", "no", "reject"):
            out.say("已拒绝，对方会收到 DECLINED。")
            return False
        if answer:
            parent = Path(answer).expanduser()
            parent.mkdir(parents=True, exist_ok=True)
            out.say(f"收进 {parent}")
            return parent
        return True

    def arrived(who: str, landed: list) -> None:
        out.say(f"{who or '对方'} 的 {len(landed)} 个文件已经校验通过：")
        for item in landed:
            out.say(f"  {item.get('path')}")

    def paired(fingerprint: str, peer_id: str, name: str, client_ip: str) -> None:
        out.say(f"{name or fingerprint[:12]}（{client_ip}）配上了，它现在占着这台机器的会话。")

    service, adopted = _serve(identity, settings, decide, root, args.port, out, arrived, paired)
    discovery = None
    if not args.no_discover:
        discovery = DiscoveryService(identity, device_name(settings), service.port)
        discovery.start()
    out.say(f"本机：{device_name(settings)}")
    out.say(f"监听：{service.port}")
    out.say(f"配对码：{service.current_pair_code()}    密码：{service.passphrase()}")
    out.say(f"指纹：{identity.fingerprint}")
    out.say(f"接收目录：{root}")
    out.say(_inbound_line(service.port))
    if adopted:
        out.say(f"上一次没传完的有 {adopted} 单，对方接着发会自动续上。")
    out.say("按 Ctrl-C 停止。" if not args.seconds else f"听 {args.seconds:.0f} 秒。")
    started = time.monotonic()
    try:
        while not args.seconds or time.monotonic() - started < args.seconds:
            time.sleep(0.2)
    except KeyboardInterrupt:
        out.say("")
    finally:
        if discovery is not None:
            discovery.stop()
        service.stop()
    out.say("已停止接收。")
    return 0


def _serve(identity, settings: Settings, decide, root: Path, port, out: Terminal, arrived, paired):
    """Bind the port the contract names, or an ephemeral one when something already holds it.

    The window keeps 43720 whenever it is open, so a CLI receiver on the same machine
    landing on the fallback is the ordinary case rather than a failure. Construction is
    what binds the socket, so the interrupted offers are adopted before the thread starts.

    On Windows the probe is the only way to find that out: SO_REUSEADDR lets a second
    process bind a port that is already being listened on, so both would print the same
    number while the first one answers every connection. POSIX refuses that bind outright,
    yet in practice it answers through the same probe too - measured under WSL against both
    a 传书 and a bare socket holding the port. The branch below is what a POSIX bind beats
    the probe to, and it is there so that race costs a port change rather than a crash.
    """
    def build(number: int):
        service = ReceiveService(
            identity,
            device_name(settings),
            decide,
            port=number,
            root=root,
            on_received=arrived,
            on_paired=paired,
        )
        adopted = service.adopt_interrupted_offers()
        service.start()
        return service, adopted

    wanted = proto_port() if port is None else port
    holder = listener_on(wanted)
    if holder is not None:
        out.say(f"{wanted} 端口已经有人在听了（{holder}），这个接收端改用临时端口。")
        return build(0)
    try:
        return build(wanted)
    except OSError as error:
        log.warning("port %d unavailable (%s), binding an ephemeral port", wanted, error)
        out.say(f"{wanted} 端口被人占着（多半是窗口已经开着），这个接收端改用临时端口。")
        return build(0)


def listener_on(port: int) -> str | None:
    """Whoever is answering on loopback, or None when the port is free.

    Asking instead of binding is the only honest option on Windows: SO_REUSEADDR lets a
    second process bind a port that is already being listened on, so both sides would print
    the same number while the first one answers every connection. POSIX refuses that bind
    with EADDRINUSE, which the OSError branch above handles.
    """
    proto = protocol_spec.load()
    try:
        peer = verify_peer(proto, Peer(prefix="", host="127.0.0.1", port=port, via={"cli"}))
    except ConnectionRefusedError:
        return None
    except (protocol_spec.ProtocolError, OSError) as error:
        log.debug("127.0.0.1:%d answered, but not as a 传书: %s", port, error)
        return "不是传书"
    return peer.name or peer.fingerprint[: proto.prefix_chars]


def proto_port() -> int:
    return protocol_spec.load().transport_port


def cmd_send(args: argparse.Namespace, out: Terminal) -> int:
    settings = Settings()
    identity = _identity()
    proto = protocol_spec.load()
    try:
        host, port, prefix = protocol_spec.split_addr(args.address, proto)
        peer = verify_peer(proto, Peer(prefix=prefix, host=host, port=port, via={"cli"}))
    except protocol_spec.ProtocolError as error:
        out.say(f"地址应答了，但不是能配的版本：{proto_errors.describe(error.code)}")
        return 1
    except (OSError, ValueError) as error:
        out.say(f"连不上 {args.address}：{getattr(error, 'strerror', None) or error}")
        return 1

    out.say(f"对端：{peer.name or peer.prefix}（{peer.host}:{peer.port}）")
    try:
        files = plan(args.files, args.base)
    except FileNotFoundError as error:
        out.say(f"没有这个文件：{error}")
        return 1
    if not files:
        out.say("要发的东西里没有文件。")
        return 1
    total_bytes = sum(item.size for item in files)
    if not getattr(args, "quiet", False):
        for item in files:
            out.say(f"  {item.relpath}  {_human(item.size)}")
    known = identity.is_trusted(peer.fingerprint)
    if not known and not args.code:
        out.say(f"没固定过这台，得用它的配对码：--code（{proto.pair_code_digits} 位，在它屏幕上）")
        return 2
    out.say(f"{'它已经固定过' if known else '第一次见它，要用配对码'}：{len(files)} 个文件，{_human(total_bytes)}")

    conn = PeerConnection(identity, device_name(settings), peer.host, peer.port, peer.fingerprint)
    started = time.monotonic()
    try:
        result = conn.transfer(files, args.code, out.progress, args.secret)
    except PairNeeded:
        out.say(f"对方不认识这把钥匙。把它屏幕上那 {proto.pair_code_digits} 位配对码用 --code 传给我。")
        return 1
    except protocol_spec.ProtocolError as error:
        out.say(f"传输失败：{proto_errors.describe(error.code)}")
        if error.detail:
            out.detail(f"  {error.detail}")
        return 1
    except OSError as error:
        out.say(f"传输失败：{getattr(error, 'strerror', None) or error}")
        return 1
    finally:
        conn.close()
    elapsed = max(time.monotonic() - started, 0.001)
    out.say(f"发完了：{_human(total_bytes)}，{elapsed:.1f} 秒（{_human(int(total_bytes / elapsed))}/秒）")
    by_id = {item.id: item for item in files}
    for entry in result["result"]["verified"]:
        item = by_id.get(str(entry["id"]))
        name = item.relpath if item is not None else entry["id"]
        digest = item.sha256[:12] if item is not None else ""
        out.detail(f"  {'ok ' if entry['ok'] else 'BAD '} {name}  {digest}")
    return 0


def cmd_peers(args: argparse.Namespace, out: Terminal) -> int:
    settings = Settings()
    identity = _identity()
    service = DiscoveryService(identity, device_name(settings), proto_port())
    service.start()
    out.say(f"本机广播自己是 {identity.fingerprint[: protocol_spec.load().prefix_chars]}，听 {args.seconds:.0f} 秒…")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    found = service.candidates()
    for peer in found:
        if args.no_verify:
            out.say(f"{peer.prefix}  {peer.host}:{peer.port}  {peer.name or '?'}  {'+'.join(sorted(peer.via))}")
            continue
        try:
            whole = service.verify(peer)
        except (protocol_spec.ProtocolError, OSError) as error:
            out.say(f"{peer.prefix}  {peer.host}:{peer.port}  连过去问它没成功：{type(error).__name__}")
            continue
        pinned = "已固定" if identity.is_trusted(whole.fingerprint) else "未固定"
        out.say(f"{whole.fingerprint}  {whole.host}:{whole.port}  {whole.name or '?'}  {pinned}")
    if not found:
        out.say("没听到任何设备。确认两边在同一个局域网，或者直接 send <ip>:<port>。")
    service.stop()
    return 0


def cmd_pins(args: argparse.Namespace, out: Terminal) -> int:
    identity = _identity()
    pinned = identity.pinned_fingerprints()
    if not pinned:
        out.say("还没有固定过任何设备。")
        return 0
    for fingerprint in pinned:
        entry = identity.trusted_entry(fingerprint) or {}
        leaf = str(entry.get("tls_fingerprint") or "")
        line = f"{fingerprint}  {entry.get('name') or '?'}"
        if leaf:
            line += f"  它serve的证书 {leaf[:12]}"
        out.say(line)
    return 0


#: ``firewall`` exit codes: a script branches on the number, not on the Chinese sentence.
_FIREWALL_EXIT = {"open": 0, "unknown": 1, "no_allow": 2, "blocked": 3}
#: The four verdicts, written out here because the window has the same four sentences to pick from.
_FIREWALL_TEXT = {
    "open": "端口开着，放行规则在，外面连得进来。",
    "no_allow": "这台机器在听，但这个网络下没有任何放行规则，而默认入站是挡，所以外面连不进来。",
    "blocked": "这个程序名下压着阻止入站的规则。Windows 判阻止优先，所以再加多少条允许规则都不生效。",
    "unknown": "读不到防火墙的状态，这一条不能当结论。",
}
#: The same four, in the one line `receive` owes the person standing at the port: "监听：43720"
#: alone reads as a promise that peers can get in, and this is the half the listener cannot see.
_INBOUND_LINE = {
    "open": "入站：防火墙放行了，别人连得进来。",
    "no_allow": "入站：没有任何规则放行这个端口，局域网里别人连不进来（细节跑 `firewall` 看）。",
    "blocked": "入站：这个程序名下压着阻止入站的规则，局域网里别人连不进来（细节跑 `firewall` 看）。",
    "unknown": "入站：读不到防火墙的状态，这一句给不了保证（细节跑 `firewall` 看）。",
}


def _inbound_line(port: int) -> str:
    """One line about whether a device that found this port can also get in through it."""
    status = firewall.inspect(port=port)
    return _INBOUND_LINE[status.verdict]


def cmd_firewall(args: argparse.Namespace, out: Terminal) -> int:
    proto = protocol_spec.load()
    port = int(args.port or proto.transport_port)
    # Windows pins rules to the program's path, so the answer is about *this* binary: a rule that
    # lets ChuanShu.exe in says nothing about ChuanShu-cli.exe. Linux reads ports, not paths.
    status = firewall.inspect(Path(args.exe).expanduser() if args.exe else None, port)
    word, on_off = firewall.word, firewall.on_off
    target = status.target
    out.say(f"问的是：{target if target is not None else f'端口 {status.port}'}")
    out.say(f"平台：{status.tool}  当前网络：{word(status.profile) or '未知'}  "
            f"防火墙：{on_off(status.enabled)}  默认入站：{word(status.default_inbound) or '未知'}")
    for rule in status.rules:
        out.say(f"规则  {word(rule.action)} {word(rule.direction)}"
                f"  {'、'.join(word(p) for p in rule.profiles) or '所有网络'}"
                f"  {on_off(rule.enabled)}  {rule.name}")
    if not status.rules:
        out.say("规则  " + ("这个程序名下没有任何入站规则。" if target is not None
                            else f"端口 {status.port} 上没有任何放行规则。"))
    for note in status.notes:
        out.say(f"平台说：{note}")
    for failure in status.failed:
        out.say(f"没读到：{failure}")
    out.say(f"结论：{status.verdict} —— {_FIREWALL_TEXT[status.verdict]}")
    if status.verdict != "open":
        out.say("要放行就自己提权跑这几条（传书不替你写防火墙规则）：")
        for line in firewall.fix_commands(status, APP_NAME):
            out.say(f"  {line}")
    out.say(f"退出码：{status.verdict} -> {_FIREWALL_EXIT[status.verdict]}")
    return _FIREWALL_EXIT[status.verdict]


def cmd_unpair(args: argparse.Namespace, out: Terminal) -> int:
    identity = _identity()
    wanted = args.fingerprint.lower()
    matches = [fp for fp in identity.pinned_fingerprints() if fp.startswith(wanted)]
    if not matches:
        out.say(f"固定列表里没有 {wanted}。")
        return 1
    if len(matches) > 1:
        out.say(f"{wanted} 命中 {len(matches)} 台，请输长一点：")
        for fp in matches:
            out.say(f"  {fp}")
        return 2
    identity.untrust(matches[0])
    out.say(f"已经忘掉 {matches[0]}，它下次要重新配对。")
    return 0


def cmd_pair_code(args: argparse.Namespace, out: Terminal) -> int:
    identity = _identity()
    proto = protocol_spec.load()
    if args.rotate:
        identity.rotate_pairing(proto.pair_code_digits, proto.passphrase_chars)
        out.say("已经换成一对新的。")
    out.say(f"配对码：{identity.pair_code}")
    if proto.passphrase_chars:
        out.say(f"密码：{identity.passphrase}")
    out.say("这份和窗口里显示的是同一份：这边换了，窗口里也换了。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings()
    setup_logging(console=bool(getattr(args, "verbose", False)))
    # The CLI's own prose is Chinese and not in the catalogue, so "auto" here means Chinese:
    # following the system locale would leave one German error label sitting in a Chinese run.
    # A language is only loaded when --lang asks for it, or when the window was told to pin one.
    wanted = str(getattr(args, "lang", "") or settings.get("language", "auto"))
    i18n.use(i18n.resolve("zh_CN" if wanted in ("", "auto") else wanted))
    return int(args.func(args, Terminal(quiet=getattr(args, "quiet", False))) or 0)


if __name__ == "__main__":
    sys.exit(main())
