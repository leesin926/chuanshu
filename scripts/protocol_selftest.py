"""M0 acceptance harness for protocol v1.

The contract in protocol/spec.md is only "frozen" once this runs green end to end,
including the part that is easy to fake: a receiver that is *killed mid-transfer and
restarted as a new process* must still be able to finish the same offer.

Run:  py scripts/protocol_selftest.py
"""

from __future__ import annotations

import gettext
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.net import errors  # noqa: E402
from app.net import spec as protocol_spec  # noqa: E402
from app.net.identity import load_or_create  # noqa: E402
from app.net.receive import STATE_FILE, ReceiveService, sanitize_relpath  # noqa: E402
from app.net.send import PairNeeded, PeerConnection, plan  # noqa: E402

REPORT = Path(os.environ.get("CHUANSHU_REPORT", str(ROOT / ".probe" / "protocol_report.txt")))
REPORT.parent.mkdir(parents=True, exist_ok=True)
fails: list[str] = []


def check(name: str, ok: bool, info="") -> None:
    line = ("PASS  " if ok else "FAIL  ") + name + (f": {info}" if info != "" else "")
    with REPORT.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    if not ok:
        fails.append(name)


def expect_error(name: str, code: str, call):
    try:
        call()
    except protocol_spec.ProtocolError as error:
        check(name, error.code == code, f"{error.code} {error.detail if code != error.code else ''}".strip())
        return
    except Exception as error:  # noqa: BLE001 - a wrong exception type is a failure worth reporting
        check(name, False, f"{type(error).__name__}: {error}")
        return
    check(name, False, "no error raised")


def blob(seed: int, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}|{counter}".encode()).digest()
        counter += 1
    return bytes(out[:size])


def build_corpus(base: Path) -> list[Path]:
    """A small file, a multi-chunk file with a Chinese nested path, and a plain one."""
    proto = protocol_spec.load()
    base.mkdir(parents=True, exist_ok=True)
    files = [
        base / "hello.txt",
        base / "相册" / "2026" / "IMG_大文件.bin",
        base / "note.pdf",
    ]
    payloads = ["传书 protocol fixture\n".encode("utf-8") * 3, blob(7, proto.chunk_size + 1), blob(9, 2_000_000)]
    for path, data in zip(files, payloads):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return files


def read_port_file(path: Path, stderr_log: Path) -> dict:
    deadline = time.time() + 20
    while time.time() < deadline:
        if path.is_file():
            body = path.read_text(encoding="utf-8").strip()
            if body:
                return json.loads(body)
        time.sleep(0.05)
    raise TimeoutError(
        f"receiver host never wrote {path}: {stderr_log.read_text(encoding='utf-8', errors='replace')}"
    )


def start_host(workspace: Path, name: str) -> tuple[subprocess.Popen, dict]:
    port_file = workspace / f"{name}.port.json"
    if port_file.exists():
        port_file.unlink()
    stderr_log = workspace / f"{name}.err.log"
    handle = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts" / "receiver_host.py"),
            "--identity", str(workspace / "receiver-id"),
            "--root", str(workspace / "received"),
            "--port-file", str(port_file),
            "--name", name,
        ],
        stdout=subprocess.DEVNULL,
        stderr=open(stderr_log, "w", encoding="utf-8"),
    )
    return handle, read_port_file(port_file, stderr_log)


def stop_host(handle: subprocess.Popen) -> None:
    handle.terminate()
    try:
        handle.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        handle.kill()


def phase_in_process(proto: protocol_spec.Protocol, workspace: Path) -> None:
    corpus = build_corpus(workspace / "corpus")
    sender = load_or_create(workspace / "sender-id")
    receiver = load_or_create(workspace / "receiver-id")
    accepted: list[str] = []

    def decide(manifest: dict, who: str, caller: str) -> bool:
        accepted.append((who, caller))
        return True

    service = ReceiveService(receiver, "Phone-Simulator", decide, host="127.0.0.1", port=0, root=workspace / "inproc-received")
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.fingerprint)
        hello = conn.hello()
        check("hello reports v1 + resume", hello["protocol_version"] == proto.version and "resume" in hello["features"], hello)

        wrong = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.fingerprint)
        try:
            current = service.current_pair_code()
            wrong.pair(("1" if current[0] != "1" else "2") + current[1:])
            check("wrong pair code rejected", False, "pairing succeeded with a bogus code")
        except PairNeeded:
            check("wrong pair code rejected", True)
        except protocol_spec.ProtocolError as error:
            check("wrong pair code rejected", error.code == "BAD_PAIR_CODE", error.code)

        # The code is read off the screen, the password typed; getting one right and the other
        # wrong must not be a way in. The refusal arrives as PairNeeded rather than a labelled
        # BAD_PAIR_CODE because the sender turns any failed pair into that one prompt on purpose -
        # a wrong password is not a different kind of mistake to a stranger than a wrong code is.
        bogus = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.fingerprint)
        try:
            bogus.pair(service.current_pair_code(), "!" * proto.passphrase_chars)
            check("right code with a wrong password rejected", False, "pairing succeeded with a bogus password")
        except PairNeeded:
            check("right code with a wrong password rejected", True)
        except protocol_spec.ProtocolError as error:
            check("right code with a wrong password rejected", error.code == "BAD_PAIR_CODE", error.code)

        paired = conn.pair(service.current_pair_code(), service.passphrase())
        check("pair issues a session token", len(paired["token"]) >= 32 and paired["resumed"] is False, paired["resumed"])
        check("receiver pinned the sender key", receiver.is_trusted(sender.fingerprint), sender.fingerprint[:12])
        check("sender pinned the receiver cert", sender.is_trusted(receiver.fingerprint), receiver.fingerprint[:12])

        # One device, one peer: a stranger with the right code and the right password is still
        # turned away while this session holds the slot.
        second = PeerConnection(load_or_create(workspace / "second-id"), "PC-Second", "127.0.0.1", service.port, receiver.fingerprint)
        second.hello()
        try:
            second.pair(service.current_pair_code(), service.passphrase())
            check("a second device refused while one is connected", False, "two peers paired at once")
        except protocol_spec.ProtocolError as error:
            check("a second device refused while one is connected",
                  error.code == "PEER_BUSY" and (error.detail or {}).get("reason") == "one peer at a time",
                  f"{error.code} {error.detail}")
        check("the refusal did not pin the stranger", not receiver.is_trusted(second.fingerprint), second.fingerprint[:12])

        files = plan(corpus, base=workspace / "corpus")
        check("plan covers 3 files with posix relpaths", len(files) == 3 and all("\\" not in f.relpath for f in files), [f.relpath for f in files])
        offered = conn.offer(files)
        check("offer accepted with all chunks missing", all(e["missing"] for e in offered["state"]["files"]))
        # `who` is the name frozen in the receiver's pin list at pairing time, not whatever
        # this manifest happens to claim now.
        check("offer handler is told who actually called", accepted[0] == ("PC-Sender", sender.fingerprint), accepted[0])
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        check("multi-chunk file needs 2 chunks", len(next(e for e in offered["state"]["files"] if e["id"] == big.id)["missing"]) == 2)

        seen: list[tuple[str, int]] = []
        result = conn.send(files, progress=lambda rel, idx, total: seen.append((rel, idx)))
        check("finalize verifies every file", all(v["ok"] for v in result["verified"]), len(result["verified"]))
        check("all chunks pushed once", len(seen) == sum(conn._chunk_count(f) for f in files), seen)
        landing = workspace / "inproc-received" / conn.offer_id / big.relpath
        check("received bytes identical", landing.is_file() and hashlib.sha256(landing.read_bytes()).hexdigest() == big.sha256, str(landing))
        check("nested chinese path preserved", (workspace / "inproc-received" / conn.offer_id / "相册" / "2026" / "IMG_大文件.bin").is_file())

        status, payload = conn._request("PUT", f"/v1/offer/{conn.offer_id}/chunk/{big.id}/0", raw_body=blob(7, proto.chunk_size), headers={"X-Sha256": "0" * 64})
        check("false chunk digest rejected", status == proto.http_status("CHUNK_DIGEST_MISMATCH") and payload["code"] == "CHUNK_DIGEST_MISMATCH", f"{status} {payload}")
        status, payload = conn._request("PUT", f"/v1/offer/{conn.offer_id}/chunk/{big.id}/0", raw_body=big.path.read_bytes()[: proto.chunk_size], headers={"X-Sha256": hashlib.sha256(big.path.read_bytes()[: proto.chunk_size]).hexdigest()})
        check("re-send of a stored chunk is idempotent", status == 200 and payload.get("idempotent") is True, payload)
        status, payload = conn._request("PUT", f"/v1/offer/{conn.offer_id}/chunk/{big.id}/99", raw_body=b"x", headers={"X-Sha256": "1" * 64})
        check("out-of-range chunk index rejected", payload.get("code") == "BAD_CHUNK_INDEX", f"{status} {payload}")

        # A device that has never paired is refused, and _call cannot silently repair it
        # because that peer's key is not in the sender's trust list either.
        stranger = load_or_create(workspace / "stranger-id")
        unpaired = PeerConnection(stranger, "Never-Paired", "127.0.0.1", service.port, receiver.fingerprint)
        unpaired.hello()
        expect_error("unpaired device cannot offer", "NOT_PAIRED", lambda: unpaired.offer(files))

        # A known key with a stale token is refused at the transport; the silent re-pair
        # that phase_restart exercises is _call's repair, not the receiver waving it through.
        no_token = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.fingerprint)
        no_token.hello()
        status, payload = no_token._request("POST", "/v1/offer", json_body=conn._manifest)
        check("stale token rejected by the receiver", status == proto.http_status("NOT_PAIRED") and payload["code"] == "NOT_PAIRED", f"{status} {payload}")
        check("known key repairs its own session", conn.pair()["resumed"] is True)

        hostile = [
            ("../escape.txt", "PATH_REJECTED"),
            ("a/../../escape.txt", "PATH_REJECTED"),
            ("C:/Windows/x", "PATH_REJECTED"),
            ("/etc/passwd", "PATH_REJECTED"),
            ("a\\b.txt", "PATH_REJECTED"),
            (".chuanshu/state", "PATH_REJECTED"),
            ("CON.txt", "PATH_REJECTED"),
            ("bad name.", "PATH_REJECTED"),
            ("相册/ok.txt", None),
        ]
        for relpath, expected in hostile:
            try:
                got = str(sanitize_relpath(relpath, proto))
                actual = None
            except protocol_spec.ProtocolError as error:
                got, actual = "", error.code
            check(f"sanitize {relpath!r} -> {expected or 'accepted'}", actual == expected, got or actual)

        declined = ReceiveService(receiver, "Declining-Phone", lambda m, who, caller: False, host="127.0.0.1", port=0, root=workspace / "declined-received")
        declined.start()
        try:
            loser = PeerConnection(sender, "PC-Sender", "127.0.0.1", declined.port, receiver.fingerprint)
            loser.hello()
            loser.pair(declined.current_pair_code())
            expect_error("user decline surfaces as DECLINED", "DECLINED", lambda: loser.offer(files))
        finally:
            declined.stop()
    finally:
        service.stop()


def phase_restart(proto: protocol_spec.Protocol, workspace: Path) -> None:
    corpus = build_corpus(workspace / "corpus")
    sender = load_or_create(workspace / "sender-id")
    handle, info = start_host(workspace, "host1")
    try:
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", info["port"], info["fingerprint"])
        conn.hello()
        conn.pair(info["code"])
        files = plan(corpus, base=workspace / "corpus")
        offered = conn.offer(files)
        offer_id = conn.offer_id
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        half = {"files": [{"id": big.id, "missing": [0]}]}
        conn.push_missing(files, half, None, 3)
        written = workspace / "received" / offer_id / big.relpath
        check("first chunk landed before the crash", written.stat().st_size == proto.chunk_size + 1 and written.read_bytes()[:1] != b"")
    finally:
        stop_host(handle)

    handle2, info2 = None, None
    try:
        handle2, info2 = start_host(workspace, "host2")
        check("restarted host adopted the interrupted offer", info2["adopted"] >= 1, info2["adopted"])
        conn2 = PeerConnection(sender, "PC-Sender", "127.0.0.1", info2["port"], info2["fingerprint"])
        conn2.hello()
        resumed = conn2.pair()
        check("known key re-pairs without a code", resumed["resumed"] is True, resumed["resumed"])
        state = conn2.reopen(offer_id)
        entry = next(e for e in state["files"] if e["id"] == big.id)
        check("receiver reports only the missing tail", entry["missing"] == [1] and entry["received"] == 1, entry)
        result = conn2.send(files, None)
        check("resumed offer verifies", all(v["ok"] for v in result["verified"]), [v["missing"] for v in result["verified"] if not v["ok"]])
        landing = workspace / "received" / offer_id / big.relpath
        check("resumed file byte-identical", hashlib.sha256(landing.read_bytes()).hexdigest() == big.sha256)
    finally:
        if handle2 is not None:
            stop_host(handle2)


def phase_stalled_offer(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """spec §4 counts an idle offer from the last chunk that landed, so that moment is data.

    Re-stamping it when a receiver boots is what keeps a phone's card saying "还没收到分块" about a
    sender that died an hour ago - every restart buys the offer a fresh window, so the reclaim that
    the contract allows never arrives.
    """
    corpus = build_corpus(workspace / "stall-corpus")
    sender = load_or_create(workspace / "stall-sender")
    receiver = load_or_create(workspace / "stall-receiver")
    root = workspace / "stall-received"
    service = ReceiveService(receiver, "PC-Stall", lambda manifest, who, caller: True, host="127.0.0.1", port=0, root=root)
    service.start()
    stopped = False
    try:
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        files = plan(corpus, base=workspace / "stall-corpus")
        conn.offer(files)
        offer_id = conn.offer_id
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        conn.push_missing(files, {"files": [{"id": big.id, "missing": [0]}]}, None, 3)
        service.stop()
        stopped = True

        document = root / offer_id / STATE_FILE
        body = json.loads(document.read_text(encoding="utf-8"))
        check("the ledger writes down when a chunk last landed", "touched" in body and "created" in body, sorted(body))
        body["touched"] = time.time() - proto.offer_idle_timeout_s - 5
        document.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")

        again = ReceiveService(receiver, "PC-Stall", lambda manifest, who, caller: True, host="127.0.0.1", port=0, root=root)
        again.start()
        try:
            check("a stalled offer is still adoptable after a restart", again.adopt_interrupted_offers() == 1)
            again.sweep()
            check("whose window ran out is reclaimed, not renewed", not (root / offer_id / big.relpath).exists())
            expect_error("and it answers the sender as unknown", "OFFER_UNKNOWN", lambda: again.handle_state(offer_id))
        finally:
            again.stop()
    finally:
        if not stopped:
            service.stop()


def phase_offer_poll(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """#96: a poll that cannot read the reply is not the end of the transfer.

    The socket timeout is longer than the decision window on purpose (a peer that holds the
    connection open answers only once its user has decided), so a stalled read says nothing about
    whether anybody decided. The manifest keeps one offer_id, and a receiver counts repeats of it as
    one delivery, so trying again costs a second - giving up costs a person a batch they approved.
    """
    corpus = build_corpus(workspace / "poll-corpus")
    sender = load_or_create(workspace / "poll-sender")
    receiver = load_or_create(workspace / "poll-receiver")
    root = workspace / "poll-received"
    service = ReceiveService(receiver, "PC-Poll", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        files = plan(corpus, base=workspace / "poll-corpus")

        def dial(name: str, seconds: int) -> PeerConnection:
            conn = PeerConnection(sender, name, "127.0.0.1", service.port, receiver.fingerprint)
            if seconds:
                conn.proto = replace(proto, offer_wait_timeout_s=seconds)
            conn.hello()
            conn.pair(service.current_pair_code())
            return conn

        conn = dial("PC-Sender", 0)
        real = conn._once
        left = [2]

        def flaky(method, path, body, headers, pace_ms=0):
            if method == "POST" and path == "/v1/offer" and left[0] > 0:
                left[0] -= 1
                raise ConnectionResetError("peer dropped the connection before the reply")
            return real(method, path, body, headers, pace_ms)

        conn._once = flaky
        try:
            offered = conn.offer(files)
        finally:
            conn._once = real
        check("两次读不通之后这一单还在", bool(offered["state"].get("files")), offered["state"])
        check("重发的轮询在接收端只算一单", [p.name for p in root.iterdir()] == [conn.offer_id],
              [p.name for p in root.iterdir()])
        result = conn.send(files)
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        landing = root / conn.offer_id / big.relpath
        check("那单照样传完并校验通过",
              all(v["ok"] for v in result["verified"]) and landing.is_file()
              and hashlib.sha256(landing.read_bytes()).hexdigest() == big.sha256)

        slow = dial("PC-Slow", 2)
        dead_real = slow._once

        def dead(method, path, body, headers, pace_ms=0):
            if method == "POST" and path == "/v1/offer":
                raise ConnectionResetError("peer never answers")
            return dead_real(method, path, body, headers, pace_ms)

        slow._once = dead
        started = time.monotonic()
        try:
            expect_error("一直读不通到期限才算没人决定", "DECLINED", lambda: slow.offer(files))
        finally:
            slow._once = dead_real
        waited = time.monotonic() - started
        check("失败要等满整个决定窗口而不是第一下就抛", waited >= 2.0, round(waited, 2))
    finally:
        service.stop()


def phase_discovery(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """Two symmetric peers finding each other, then promoting a prefix to an anchor."""
    from app.net.discovery import DiscoveryService, Peer

    a_id = load_or_create(workspace / "disc-a")
    b_id = load_or_create(workspace / "disc-b")

    def make_receiver(identity: object, name: str, root: str):
        service = ReceiveService(identity, name, lambda manifest, who, caller: True, host="0.0.0.0", port=0, root=workspace / root)
        service.start()
        return service

    a_svc = make_receiver(a_id, "PC-A", "disc-a-received")
    b_svc = make_receiver(b_id, "Phone-B", "disc-b-received")
    # Broadcast, not a unicast to 127.0.0.1: measured on this host, a unicast aimed at a
    # port two sockets share is delivered to only one of them, while broadcast reaches
    # every local listener. Two instances on one machine is exactly the case that has to
    # work before two machines do.
    a = DiscoveryService(a_id, "PC-A", a_svc.port)
    b = DiscoveryService(b_id, "Phone-B", b_svc.port)
    try:
        a.start()
        b.start()
        states = {name: channel.state for name, channel in b.channels.items()}
        check("at least one discovery channel is up", any(c.state == "ok" for c in b.channels.values()), states)

        candidate = None
        deadline = time.time() + 15
        while time.time() < deadline and candidate is None:
            a.announce()
            b.announce()
            found = [p for p in b.candidates() if p.prefix == a.prefix]
            candidate = found[0] if found else None
            if candidate is None:
                time.sleep(0.5)
        roster = {p.prefix: sorted(p.via) for p in b.candidates()}
        check("peer found over the wire", candidate is not None, f"channels={states} roster={roster}")
        check("a device never lists itself", all(p.prefix != a.prefix for p in a.candidates()), [p.prefix for p in a.candidates()])
        if candidate is not None:
            # Give mDNS a grace window of its own: it announces once at registration and
            # the browser resolves asynchronously, so it can legitimately trail UDP here.
            grace = time.time() + 6.0
            via: list[str] = sorted(candidate.via)
            while time.time() < grace and "mdns" not in via:
                time.sleep(0.5)
                again = [p for p in b.candidates() if p.prefix == a.prefix]
                via = sorted(again[0].via) if again else via
            checked = b.verify(candidate)
            check("verify promotes the prefix to a pinnable digest", checked.fingerprint == a_id.fingerprint and checked.verified, checked.fingerprint[:12])
            check("verify keeps what hello says", checked.peer_id == a_id.peer_id and checked.name == "PC-A" and checked.port == a_svc.port, checked.public())
            check("candidate reached us over", bool(via), f"via={via} channels={states}")
            if b.channels["mdns"].state == "ok":
                # A channel that reports ok has to actually deliver, or the status lie is
                # worse than the outage the UI would have shown.
                check("mdns claiming ok really delivered", "mdns" in via, f"via={via}")

            impostor = Peer(prefix="0" * proto.prefix_chars, host=candidate.host, port=candidate.port)
            try:
                b.verify(impostor)
                check("prefix mismatch rejected", False, "a wrong prefix was accepted")
            except Exception as error:  # noqa: BLE001 - any rejection of the mismatch is fine
                check("prefix mismatch rejected", True, type(error).__name__)

        code = b_svc.current_pair_code()
        url = b.pairing_qr(code, host="127.0.0.1")
        fields = protocol_spec.parse_qr(url)
        check(
            "qr carries address, version, full fingerprint and code",
            fields == {"h": "127.0.0.1", "p": str(b_svc.port), "v": str(proto.version), "f": b_id.fingerprint, "c": code},
            fields,
        )
        # The password half rides along only when this build has one: a QR without it is a
        # legacy promise, and the reader must not invent an empty key for it.
        with_pass = protocol_spec.parse_qr(b.pairing_qr(code, host="127.0.0.1", passphrase=b_svc.passphrase()))
        check("qr carries the password when there is one", with_pass.get("k") == b_svc.passphrase(), with_pass)
        check("qr without a password has no empty k", "k" not in fields and "k" not in protocol_spec.parse_qr(
            b.pairing_qr(code, host="127.0.0.1", passphrase="")), with_pass.keys())
        expect_error("qr with an unsupported version is refused", "UNSUPPORTED_PROTOCOL", lambda: protocol_spec.parse_qr(url.replace(f"v={proto.version}", "v=99")))
        expect_error("qr without a fingerprint is refused", "UNSUPPORTED_PROTOCOL", lambda: protocol_spec.parse_qr("chuanshu://p?h=127.0.0.1&p=43720&v=1"))
        truncated = protocol_spec.qr_url(h="127.0.0.1", p=str(b_svc.port), v=str(proto.version), f=b_id.fingerprint[:60], c=code)
        expect_error("qr with a truncated fingerprint is refused", "UNSUPPORTED_PROTOCOL", lambda: protocol_spec.parse_qr(truncated))
        junk_fp = protocol_spec.qr_url(h="127.0.0.1", p=str(b_svc.port), v=str(proto.version), f="z" * 64, c=code)
        expect_error("qr with a non-hex fingerprint is refused", "UNSUPPORTED_PROTOCOL", lambda: protocol_spec.parse_qr(junk_fp))
    finally:
        b.stop()
        a.stop()
        b_svc.stop()
        a_svc.stop()


def phase_reverse_pin(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """One pairing must open the door from both ends, not only the end that typed the code.

    The machine that dialled pinned its peer out of the pair response, and that response carries no
    public key. Recognizing a pin by the key on file therefore treats the peer this end added itself
    as a stranger the next time it calls - it asks for a code the other screen no longer shows. Two
    PC instances swapping directions hit exactly this; the check runs on its own identities because
    a re-pair rewrites the name frozen in the pin list, and the phases above assert on theirs.
    """
    pc = load_or_create(workspace / "reverse-pc")
    phone = load_or_create(workspace / "reverse-phone")
    let_in = lambda manifest, who, caller: True  # noqa: E731 - both ends always accept in this phase

    # Leg 1: the phone dials the PC and types the code. The PC pins a key it was told about; the
    # phone pins a fingerprint it only read out of the pair response.
    pc_service = ReceiveService(pc, "PC-Waiting", let_in, host="127.0.0.1", port=0,
                                root=workspace / "reverse-pc-received")
    pc_service.start()
    try:
        out = PeerConnection(phone, "Phone-Simulator", "127.0.0.1", pc_service.port, pc.fingerprint)
        out.hello()
        out.pair(pc_service.current_pair_code(), pc_service.passphrase())
        entry = phone.trusted_entry(pc.fingerprint) or {}
        check("the end that dialled pins with no key on file", entry.get("public_key", "") == "", entry)
    finally:
        pc_service.stop()

    # Leg 2: the PC calls back with no code, and the phone has to recognize its own pin.
    phone_service = ReceiveService(phone, "Phone-Receiver", let_in, host="127.0.0.1", port=0,
                                   root=workspace / "reverse-phone-received")
    phone_service.start()
    try:
        back = PeerConnection(pc, "PC-Waiting", "127.0.0.1", phone_service.port, phone.fingerprint)
        back.hello()
        again = back.pair()
        check("a peer once dialled re-pairs by signature alone", again["resumed"] is True, again["resumed"])
        filled = (phone.trusted_entry(pc.fingerprint) or {}).get("public_key", "")
        check("its key is filled in on the way in", filled != "", filled[:12])
    finally:
        phone_service.stop()


def phase_shared_identity(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """The window and the terminal open one identity directory, so each is the other's second process.

    Two of them hold two dicts, and both used to write the whole dict over the file: whichever saved
    last dropped the peer the other had just pinned, and a revocation came back to life on the next
    unrelated write. The pair code had the same split - one screen could show a secret the file no
    longer contains. These run on two load_or_create() calls against one directory, which is what the
    shipped layout actually gives you.
    """
    window = load_or_create(workspace / "shared-id")
    terminal = load_or_create(workspace / "shared-id")
    window.ensure_pairing(proto.pair_code_digits, proto.passphrase_chars)
    check("both processes mint the same pairing code",
          window.pair_code == terminal.pair_code and len(window.pair_code) == proto.pair_code_digits, window.pair_code)

    window.trust("w" * 64, "peer-w", "Window pin", "pk-w")
    terminal.trust("t" * 64, "peer-t", "Terminal pin")
    pins = json.loads((workspace / "shared-id" / "trusted.json").read_text(encoding="utf-8"))
    check("a second process's write keeps the first's pin", set(pins) >= {"w" * 64, "t" * 64}, sorted(pins))
    check("and the writer sees both too", set(window.pinned_fingerprints()) >= {"w" * 64, "t" * 64}, window.pinned_fingerprints())

    window.untrust("t" * 64)
    terminal.trust("n" * 64, "peer-n", "Later pin")
    pins = json.loads((workspace / "shared-id" / "trusted.json").read_text(encoding="utf-8"))
    check("an unpinned peer does not come back", "t" * 64 not in pins, sorted(pins))
    check("the revoking side agrees", not terminal.is_trusted("t" * 64))

    terminal.rotate_pairing(proto.pair_code_digits, proto.passphrase_chars)
    check("a rotation lands on the other screen", window.pair_code == terminal.pair_code, window.pair_code)

    (workspace / "shared-id" / "trusted.json").write_text(
        json.dumps({"junk": "not a pin", "r" * 64: {"name": "Readable"}}), encoding="utf-8")
    check("a foreign value in the file is skipped, not fatal", window.pinned_fingerprints() == ["r" * 64],
          window.pinned_fingerprints())


def phase_catalogue(proto: protocol_spec.Protocol) -> None:
    en = gettext.translation("app", str(ROOT / "locale"), languages=["en"])
    zh = gettext.translation("app", str(ROOT / "locale"), languages=["zh_CN"])
    drift = sorted(errors.codes() ^ set(proto.error_codes))
    check("errors.py and protocol.json list the same codes", not drift, drift)
    wrong = [c for c in sorted(errors.codes() & set(proto.error_codes)) if errors.describe(c) != proto.msgid(c)]
    check("each label matches the contract msgid", not wrong, wrong)
    missing = []
    for code, entry in proto.error_codes.items():
        msgid = entry["msgid"]
        if not isinstance(entry["http"], int) or en.gettext(msgid) == msgid:
            missing.append(code)
    check("every error code has an english msgid", not missing, missing)
    sample = proto.msgid("CHUNK_DIGEST_MISMATCH")
    check("zh catalogue echoes the msgid", zh.gettext(sample) == sample, zh.gettext(sample))
    check("http status mapping", proto.http_status("STORAGE_FULL") == 507 and proto.http_status("DECLINED") == 403)


def main() -> int:
    proto = protocol_spec.load()
    REPORT.write_text("", encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="chuanshu-proto-") as tmp:
        workspace = Path(tmp)
        phase_in_process(proto, workspace)
        phase_restart(proto, workspace)
        phase_stalled_offer(proto, workspace)
        phase_offer_poll(proto, workspace)
        phase_discovery(proto, workspace)
        phase_reverse_pin(proto, workspace)
        phase_shared_identity(proto, workspace)
    phase_catalogue(proto)
    check("chunks per file match the contract", proto.chunk_size == 4194304, proto.chunk_size)
    print("\n".join(REPORT.read_text(encoding="utf-8").splitlines()))
    print("RESULT " + (f"FAILED {len(fails)}: " + " / ".join(fails) if fails else "ALL PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
