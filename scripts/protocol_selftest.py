"""M0 acceptance harness for protocol v1.

The contract in protocol/spec.md is only "frozen" once this runs green end to end,
including the part that is easy to fake: a receiver that is *killed mid-transfer and
restarted as a new process* must still be able to finish the same offer.

Run:  py scripts/protocol_selftest.py        (Windows launcher)
Run:  python3 scripts/protocol_selftest.py   (Linux - the three mDNS legs skip when the host gives no multicast)
"""

from __future__ import annotations

import base64
import gettext
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import types
from dataclasses import replace
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402

from app.net import errors  # noqa: E402
from app.net import identity as identity_mod  # noqa: E402
from app.net import receive as receive_mod  # noqa: E402
from app.net import spec as protocol_spec  # noqa: E402
from app.net.identity import fingerprint_of_public_key, load_or_create  # noqa: E402
from app.net.receive import STATE_FILE, ReceiveService, sanitize_relpath  # noqa: E402
from app.net.send import (  # noqa: E402
    PACE_MS_LADDER, PairNeeded, PeerConnection, PeerIdentityMismatch, TooManyFilesForOffer, WrongPairCode, plan,
)

REPORT = Path(os.environ.get("CHUANSHU_REPORT", str(ROOT / ".probe" / "protocol_report.txt")))
REPORT.parent.mkdir(parents=True, exist_ok=True)
fails: list[str] = []


class _Slot:
    """A wire value that a dict cannot carry: this round's legs are about exactly that.

    ``None`` is a real answer here (a JSON null), so "leave the key off" and "let the peer serve its own
    signing key as the leaf" need their own markers rather than a falsy value the handler would read.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<{self.name}>"


_ABSENT = _Slot("键不在")
_SELF = _Slot("用本机那张叶")


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
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        hello = conn.hello()
        check("hello reports v1 + resume", hello["protocol_version"] == proto.version and "resume" in hello["features"], hello)
        # spec §7: `features` is one list off the contract, sent verbatim, and in v1 it decides nothing. The
        # membership test above cannot tell a correct list from a retyped one, and a word that reads
        # differently on the three ends is what the next person mistakes for a second compatibility rule.
        check("hello's feature list is the contract's, word for word",
              sorted(hello["features"]) == sorted(proto.hello_features), hello["features"])

        wrong = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        try:
            current = service.current_pair_code()
            wrong.pair(("1" if current[0] != "1" else "2") + current[1:])
            check("wrong pair code rejected", False, "pairing succeeded with a bogus code")
        except WrongPairCode:
            check("wrong pair code rejected", True)
        except PairNeeded:
            # §3's two faces shared this one prompt until #198: a code the person typed is refused
            # with the same wire shape as their own empty one, and only this end knows which it sent.
            check("wrong pair code rejected", False, "答成了「对方不再认识这把钥匙」——那一趟人没输过任何东西")
        except protocol_spec.ProtocolError as error:
            check("wrong pair code rejected", error.code == "BAD_PAIR_CODE", error.code)

        # The code is read off the screen, the password typed; getting one right and the other
        # wrong must not be a way in. Both of those are things the person *typed*, so the refusal
        # arrives as WrongPairCode - the sentence that asks them to look at the screen and enter it
        # again (#198). PairNeeded now belongs only to a repair this end started on its own empty
        # code, where nothing was typed and retyping would be advice about an event that never happened.
        bogus = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        try:
            bogus.pair(service.current_pair_code(), "!" * proto.passphrase_chars)
            check("right code with a wrong password rejected", False, "pairing succeeded with a bogus password")
        except WrongPairCode:
            check("right code with a wrong password rejected", True)
        except PairNeeded:
            check("right code with a wrong password rejected", False, "答成了「对方不再认识这把钥匙」")
        except protocol_spec.ProtocolError as error:
            check("right code with a wrong password rejected", error.code == "BAD_PAIR_CODE", error.code)

        paired = conn.pair(service.current_pair_code(), service.passphrase())
        check("pair issues a session token", len(paired["token"]) >= 32 and paired["resumed"] is False, paired["resumed"])
        check("receiver pinned the sender key", receiver.is_trusted(sender.fingerprint), sender.fingerprint[:12])
        check("sender pinned the receiver cert", sender.is_trusted(receiver.fingerprint), receiver.fingerprint[:12])

        # One device, one peer: a stranger with the right code and the right password is still
        # turned away while this session holds the slot.
        second = PeerConnection(load_or_create(workspace / "second-id"), "PC-Second", "127.0.0.1", service.port, receiver.served_fingerprint)
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
        unpaired = PeerConnection(stranger, "Never-Paired", "127.0.0.1", service.port, receiver.served_fingerprint)
        unpaired.hello()
        expect_error("unpaired device cannot offer", "NOT_PAIRED", lambda: unpaired.offer(files))

        # A known key with a stale token is refused at the transport, and the line below pairs
        # explicitly - so neither of these is the sentence §3 writes next, which is a still-alive
        # connection repairing its own session inside `_call`. That one is phase_token_repair (#196);
        # this pair only shows the receiver is the one that said no, and that a known key can get in
        # without a code when somebody asks for it.
        no_token = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        no_token.hello()
        status, payload = no_token._request("POST", "/v1/offer", json_body=conn._manifest)
        check("stale token rejected by the receiver", status == proto.http_status("NOT_PAIRED") and payload["code"] == "NOT_PAIRED", f"{status} {payload}")
        check("known key repairs its own session", conn.pair()["resumed"] is True)
        check("pair reply restates the peer's version set", conn.peer.get("compatible_versions") == list(proto.compatible_versions), conn.peer)

        # spec §1: the pair reply carries the same identity hello did, and this end keys its trust store
        # by that number. A peer that says one thing on the socket and another in the reply gets stopped
        # - the mobile client has always done this; the PC used to write down whatever it was told.
        honest = service.handle_pair
        service.handle_pair = lambda body, client_ip: {**honest(body, client_ip), "fingerprint": "0" * 64}
        try:
            liar = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
            liar.hello()
            liar.pair()
            check("a pair reply naming another identity is refused", False, "the reply was believed")
        except PeerIdentityMismatch:
            check("a pair reply naming another identity is refused", not sender.is_trusted("0" * 64))
        finally:
            service.handle_pair = honest
            # A pair mints a token for the key, and the receiver keeps one per peer: the refused reply
            # still took conn's session away, so the phase's later offers need the token back.
            conn.pair()

        # spec §7 decides from two version sets, not from the one number a peer prints: the set a sender
        # speaks has to ride on its own bodies (a receiver never dials back for a hello), and a peer whose
        # set holds nothing we speak is stopped at the hello - the direction this end read backwards.
        check("offer carries this end's version set", conn._manifest.get("compatible_versions") == list(proto.compatible_versions), conn._manifest)
        other = replace(conn.proto, compatible_versions=(2,))
        single_version = ReceiveService(receiver, "Other-Version", decide, host="127.0.0.1", port=0, root=workspace / "v2-received")
        single_version.proto = other
        single_version.start()
        try:
            later = PeerConnection(sender, "PC-Sender", "127.0.0.1", single_version.port, receiver.served_fingerprint)
            expect_error("a peer speaking only another set stops at the hello", "UNSUPPORTED_PROTOCOL", lambda: later.hello())
        finally:
            single_version.stop()

        strays = dict(conn._manifest)
        strays["offer_id"] = "strayversion"
        strays["compatible_versions"] = [2]
        status, payload = conn._request("POST", "/v1/offer", json_body=strays)
        check("an offer whose set excludes us is refused", status == proto.http_status("UNSUPPORTED_PROTOCOL") and payload["code"] == "UNSUPPORTED_PROTOCOL", f"{status} {payload}")

        legacy = dict(conn._manifest)
        legacy["offer_id"] = "legacyversion"
        legacy.pop("compatible_versions")
        status, payload = conn._request("POST", "/v1/offer", json_body=legacy)
        check("an offer naming no set is judged by its own number", status == 200, f"{status} {payload}")

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
            # The three numbers of §5, each measured at its boundary rather than somewhere inside it:
            # both ends read the gate as `>`, so the only leg that tells `>` from `>=` is one shape that
            # still has to be taken and one that has one segment / one byte too many.
            ("a" * proto.limits["max_name_bytes"], None),
            ("a" * (proto.limits["max_name_bytes"] + 1), "PATH_REJECTED"),
            ("/".join(f"d{i}" for i in range(proto.limits["max_path_depth"] - 1)) + "/x.txt", None),
            ("/".join(f"d{i}" for i in range(proto.limits["max_path_depth"])) + "/x.txt", "PATH_REJECTED"),
            # §5 widens the dot rule to every dot-leading segment, and de-platforms the reserved names:
            # a Linux or Harmony receiver refuses them too, so these have to be refused here as well.
            (".env", "PATH_REJECTED"),
            ("sub/.git/config", "PATH_REJECTED"),
            ("CON", "PATH_REJECTED"),
            ("nul.txt", "PATH_REJECTED"),
        ]
        for relpath, expected in hostile:
            try:
                got = str(sanitize_relpath(relpath, proto))
                actual = None
            except protocol_spec.ProtocolError as error:
                got, actual = "", error.code
            check(f"sanitize {relpath!r} -> {expected or 'accepted'}", actual == expected, got or actual)

        # The third number of §5 is about the size of a manifest, not the shape of a name, so it lives in
        # the offer handler rather than in `sanitize_relpath`: it has to be asked over the wire. The reason
        # leg is that a person who selected too many files used to be told the other machine runs another
        # version - `UNSUPPORTED_PROTOCOL` is the only 400 this code has for a batch that is simply big.
        asked_before = len(accepted)
        oversize = dict(conn._manifest)
        oversize["offer_id"] = "oversizebatch"
        template = dict(conn._manifest["files"][0], size=1, sha256=hashlib.sha256(b"").hexdigest())
        bulk = [dict(template, relpath=f"bulk/{i}.txt", id=f"{i:016x}") for i in range(proto.limits["max_files_per_offer"] + 1)]
        oversize["files"] = bulk
        status, payload = conn._request("POST", "/v1/offer", json_body=oversize)
        check(
            "a manifest over max_files_per_offer is refused with a reason, not a version complaint",
            status == proto.http_status("UNSUPPORTED_PROTOCOL") and payload.get("code") == "UNSUPPORTED_PROTOCOL"
            and payload.get("detail", {}).get("reason") == "too many files",
            f"{status} {payload}",
        )
        check("nobody was asked to decide a manifest that never became a plan", len(accepted) == asked_before, accepted[asked_before:])

        within = dict(oversize)
        within["offer_id"] = "withinsize"
        within["files"] = bulk[: proto.limits["max_files_per_offer"]]
        status, payload = conn._request("POST", "/v1/offer", json_body=within)
        check("the same manifest one file short is taken", status == 200 and payload.get("accepted") is True, f"{status} {payload}")
        conn._request("DELETE", "/v1/offer/withinsize")

        # §5's sender half of the same number. A receiver can only answer a manifest over the limit
        # with `UNSUPPORTED_PROTOCOL` - v1's table has no "too big" slot - so a sender that ships one
        # tells its user the *peer* runs another version while the thing at fault is this machine's
        # own batch. The contract writes that the phone's client stops locally at the same number;
        # these two legs hold the PC senders (plan() for GUI/CLI, offer() for any other route) to it.
        batch = workspace / "sender-oversize"
        batch.mkdir(parents=True, exist_ok=True)
        for i in range(proto.limits["max_files_per_offer"] + 1):
            (batch / f"s{i}.bin").write_bytes(b"")
        ask_before = len(accepted)
        try:
            plan([batch], base=batch)
            stopped = None
        except Exception as error:  # noqa: BLE001 - the leg below names the one that is right
            stopped = error
        check(
            "a selection over max_files_per_offer is stopped by plan() before the first byte leaves",
            type(stopped).__name__ == "TooManyFilesForOffer"
            and getattr(stopped, "limit", None) == proto.limits["max_files_per_offer"],
            repr(stopped),
        )
        check("a stopped batch put no offer question to anybody", len(accepted) == ask_before, accepted[ask_before:])
        one_more = sorted(batch.glob("*.bin"))
        seen = []
        real_request = conn._request

        def counting_request(method, path, **kwargs):
            seen.append((method, path))
            return real_request(method, path, **kwargs)

        conn._request = counting_request
        try:
            conn.offer(one_more)
            choke = "offer() put a manifest over its own limit on the wire"
        except TooManyFilesForOffer as error:
            choke = "ok" if error.limit == proto.limits["max_files_per_offer"] else f"wrong number in the refusal: {error.limit}"
        except protocol_spec.ProtocolError as error:
            choke = f"the peer answered instead of the local gate: {error.code}"
        finally:
            conn._request = real_request
        check("offer() carries the same number on the choke point itself", choke == "ok", f"{choke} | wire calls: {seen}")
        try:
            planned = plan(one_more[: proto.limits["max_files_per_offer"]])
            exact_ok = len(planned) == proto.limits["max_files_per_offer"]
            exact_detail = str(len(planned))
        except Exception as error:  # noqa: BLE001
            exact_ok = False
            exact_detail = repr(error)
        check("the same batch one file short plans fine", exact_ok, exact_detail)

        declined = ReceiveService(receiver, "Declining-Phone", lambda m, who, caller: False, host="127.0.0.1", port=0, root=workspace / "declined-received")
        declined.start()
        try:
            loser = PeerConnection(sender, "PC-Sender", "127.0.0.1", declined.port, receiver.served_fingerprint)
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


def phase_token_repair(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3 那句「发送方此时用已有的 key 做一次只靠签名、不靠配对码的重配对补回来」——中间那一段第一次被跑起来。

    挨着它的两条腿各自量的是别的两头：``stale token rejected by the receiver`` 量的是对端把旧 token
    拒了，``known key re-pairs without a code``（phase_restart）量的是显式调 ``conn.pair()`` 时进门那
    一步不要码。这两头中间那句原话由谁兑现——一个还活着的连接，它的 token 在对端没了——今天没有任何
    一档走过，而 :246-247 那句注释把它说成是 phase_restart 覆盖的。这里三处补的地方各跑一趟（``_call``、
    offer 轮询、写块重试），每趟都记下发出去的 ``code`` 究竟是不是空的；最后一条量的是这一趟**不该**
    静默的那一面：对面连信任那份也收回了，报的要是一句"需要配对码"，而不是一句"补好了"。
    """
    corpus = build_corpus(workspace / "corpus-repair")
    sender = load_or_create(workspace / "sender-repair")
    receiver = load_or_create(workspace / "receiver-repair")
    service = ReceiveService(receiver, "PC-Repair-Host", lambda m, who, caller: True,
                             host="127.0.0.1", port=0, root=workspace / "received-repair")
    honest_pair = service.handle_pair
    seen_codes: list[str] = []

    def spy_pair(body: dict, client_ip: str) -> dict:
        code = str(body.get("code"))
        seen_codes.append(code)
        return honest_pair(body, client_ip)

    service.handle_pair = spy_pair
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code(), service.passphrase())
        files = plan(corpus, base=workspace / "corpus-repair")
        conn.offer(files)
        offer_id = conn.offer_id
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))

        # 第一处：`_call`（state / finalize / abort 都从它走）
        seen_codes.clear()
        stale = conn.token
        service._tokens.clear()
        status, payload = conn._request("GET", f"/v1/offer/{offer_id}/state")
        check("§3 令牌没了的第一问确实吃 403 NOT_PAIRED（补之前它先是一次失败）",
              status == proto.http_status("NOT_PAIRED") and payload.get("code") == "NOT_PAIRED", f"{status} {payload}")
        try:
            state = conn.state()
            check("§3 `_call` 那一处自己补回来了：同一句原话第二次问就读得回来", bool(state.get("files")), state)
        except Exception as exc:  # noqa: BLE001
            check("§3 `_call` 那一处自己补回来了：同一句原话第二次问就读得回来", False, f"{type(exc).__name__}: {exc}")
        check("§3 `_call` 补的那一趟发出去的是一对空码（它没去碰屏幕上那个数）", seen_codes == [""], seen_codes)
        check("§3 `_call` 补回来的是一枚新的 bearer：旧的那枚从此不再在任何一边算话",
              conn.token != "" and conn.token != stale and conn.token in set(service._tokens.values()), conn.token[:8])

        # 第二处：写块。它不走 `_call`，所以它必须自己有一处补
        seen_codes.clear()
        service._tokens.clear()
        try:
            conn._put_chunk(big, 1, 2, None, 3)
            landed = 1 not in next(e for e in service.handle_state(offer_id)["files"] if e["id"] == big.id)["missing"]
            check("§3 写块那一处自己补回来了：这一块仍然落上", landed, big.relpath)
        except Exception as exc:  # noqa: BLE001
            check("§3 写块那一处自己补回来了：这一块仍然落上", False, f"{type(exc).__name__}: {exc}")
        check("§3 写块那一处补的趟也只发空码", seen_codes == [""], seen_codes)

        # 第三处：offer 轮询。它也不走 `_call`，而它守的是"有人正在决定"这一趟最贵的时候
        seen_codes.clear()
        honest_offer = service.handle_offer
        polls: list[int] = []

        def flaky_offer(body: dict, caller: str) -> dict:
            polls.append(1)
            if len(polls) == 1:
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "the peer restarted mid-decision"})
            return honest_offer(body, caller)

        service.handle_offer = flaky_offer
        try:
            got = conn.offer(files)
            check("§3 offer 轮询那一处第一问吃 403 后仍然把这单谈成", got["state"].get("accepted") is True, got["state"])
        except Exception as exc:  # noqa: BLE001
            check("§3 offer 轮询那一处第一问吃 403 后仍然把这单谈成", False, f"{type(exc).__name__}: {exc}")
        finally:
            service.handle_offer = honest_offer
        check("§3 offer 轮询那一处补的趟只发空码", seen_codes == [""], seen_codes)
        # §4：同一份清单按 offer_id 算一次投递，所以补回来再问一次不会把这一单变成两单
        check("§3 补回来以后重问的那一次清单，在对方仍然只算一单", len(polls) == 2, len(polls))

        # 反面：信任那份也没了，这一趟不该静默——它要如实报成"需要配对码"，而不是假装补好了
        receiver.untrust(sender.fingerprint)
        service._tokens.clear()
        seen_codes.clear()
        try:
            conn.state()
            check("§3 对面连信任都收回时这一趟不静默：报的是要配对码", False, "补回来了，可对面已经不认识这把钥匙")
        except PairNeeded:
            check("§3 对面连信任都收回时这一趟不静默：报的是要配对码", True)
        except protocol_spec.ProtocolError as error:
            check("§3 对面连信任都收回时这一趟不静默：报的是要配对码", False, f"{error.code} {error.detail}")
        check("§3 那一次不肯静默的补也没有偷偷带码：它带的仍是空码，所以拒绝来自对面",
              seen_codes == [""], seen_codes)
        # 第三十二轮（#198）：这一格线上是同一个形状，能分开两面的只有「这一趟的码是不是本机自己填的空」。
        # 改前 `pair()` 对所有 `BAD_PAIR_CODE` 一律抛 PairNeeded，于是两句话各自配错了一面——连接那一站把
        # 机器自补说成「请再输一次」，发送那一站把人输错码说成「对方不再认识本机的密钥」。这里量的不是异常
        # 名，是给人看的那两句，以及它们各自只在自己的那一面出现。
        machine_said = protocol_spec.pair_refusal(True, proto)
        person_said = protocol_spec.pair_refusal(False, proto)
        check("§3 机器自补被拒时，给人看的那句要的是屏幕上那个新码，而不是让人重输",
              "新显示的配对码" in machine_said and "再输一次" not in machine_said, machine_said)
        check("§3 人输错码那一句说的是照着屏幕再输一次，并把两个位数都念出来",
              "再输一次" in person_said and f"{proto.pair_code_digits} 位" in person_said
              and f"{proto.passphrase_chars} 位" in person_said, person_said)
        check("§3 两面不共用一句话（同一条 BAD_PAIR_CODE 不许有两个一样的说法）",
              machine_said != person_said, machine_said)
        spent_after_repair = sum(len(v) for v in service._code_failures.values())
        check("§3 那一趟不肯静默的补在对面记了一次：空码就是一次错猜，纸面不能只当它没花什么",
              spent_after_repair == 1, spent_after_repair)
        wrong = "0" * proto.pair_code_digits
        if wrong == service.current_pair_code():
            wrong = "1" * proto.pair_code_digits
        try:
            conn.pair(wrong, "")
            check("§3 人自己输错的那一趟也得有个答案（它不该配上）", False, "它居然配上了")
        except WrongPairCode:
            check("§3 人输错码那一面报的是重输那一面，不再是「对方不再认识这把钥匙」", True)
        except PairNeeded:
            check("§3 人输错码那一面报的是重输那一面，不再是「对方不再认识这把钥匙」", False,
                  "两面又串回同一句：PairNeeded")
        check("§3 人输错码那一趟同样在对面记了一次（它和机器那一趟共用同一格来源的名额）",
              sum(len(v) for v in service._code_failures.values()) == spent_after_repair + 1,
              sum(len(v) for v in service._code_failures.values()))
    finally:
        service.stop()


def phase_lying_ledger(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """A resume ledger can be contradicted by the disk, and then it stops being evidence (#127).

    Both chunks of one file land and the offer is never finalized, so the ledger vouches for the whole
    file; the file is then deleted out from under it, which is what a phone looks like once its written
    bytes are removed and only the state document survives. `finalize` has to refuse it - the verdict is
    the digest, never the ledger - and the sender's whole-file resend then has to actually write. A
    receiver that answers "already stored" from the very ledger the disk just denied repairs nothing,
    and the offer can never come back: that is the shape the Android emulator produced, with
    FILE_DIGEST_MISMATCH as the last word.
    """
    corpus = build_corpus(workspace / "lie-corpus")
    sender = load_or_create(workspace / "lie-sender")
    receiver = load_or_create(workspace / "lie-receiver")
    root = workspace / "lie-received"
    service = ReceiveService(receiver, "PC-Lie", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        files = plan(corpus, base=workspace / "lie-corpus")
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        count = (big.size + proto.chunk_size - 1) // proto.chunk_size
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        conn.offer(files)
        conn.push_missing(files, conn.state(), None, 3)
        landing = root / conn.offer_id / big.relpath
        check("every chunk of that file was on disk before the lie", landing.stat().st_size == big.size, landing)
        landing.unlink()
        bad = [v for v in conn.finalize()["verified"] if not v["ok"]]
        check("finalize refuses the file the disk denies", [v["id"] for v in bad] == [big.id], bad)
        check("it stops vouching for the chunks it cannot show", bad and bad[0]["missing"] == list(range(count)),
              bad[0] if bad else None)
        result = conn.send(files, None)
        check("the resend writes bytes instead of being skipped", all(v["ok"] for v in result["verified"]),
              [v for v in result["verified"] if not v["ok"]])
        check("repaired file byte-identical", hashlib.sha256(landing.read_bytes()).hexdigest() == big.sha256)
    finally:
        service.stop()


def phase_state_lost(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """spec §4's other half of 它只是提示: a state document that cannot be read back claims nothing (#165).

    That sentence used to promise more than the disk can tell. It said the receiver re-derives the missing
    chunks from "已落盘字节 / chunk_size" - but the length of a landing is not evidence of what landed,
    because the moment the user accepts, the receiver allocates the declared length: the first check below
    is exactly that, one chunk written into a file that already measures the whole file. So the branch both
    ends actually take is the honest one: nothing is adopted, the interrupted offer answers OFFER_UNKNOWN,
    the same manifest arrives as a new all-missing offer, and the transfer still finishes byte for byte.
    Losing the state costs re-sent bytes - never a 已完成 that the digest has not earned.
    """
    corpus = build_corpus(workspace / "lost-corpus")
    sender = load_or_create(workspace / "lost-sender")
    receiver = load_or_create(workspace / "lost-receiver")
    root = workspace / "lost-received"
    service = ReceiveService(receiver, "PC-Lost", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    offer_id = ""
    try:
        files = plan(corpus, base=workspace / "lost-corpus")
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        count = (big.size + proto.chunk_size - 1) // proto.chunk_size
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        conn.offer(files)
        offer_id = conn.offer_id
        conn.push_missing(files, {"files": [{"id": big.id, "missing": [0]}]}, None, 3)
        landing = root / offer_id / big.relpath
        check("one chunk in, and the landing already measures the whole file - so a byte count cannot say what landed",
              count > 1 and landing.stat().st_size == big.size, (count, landing.stat().st_size, big.size))
    finally:
        service.stop()
    document = root / offer_id / STATE_FILE
    intact = document.read_text(encoding="utf-8")
    document.write_text(intact[: len(intact) // 2], encoding="utf-8")  # torn, the way a crash mid-rewrite leaves it
    lost = ReceiveService(receiver, "PC-Lost", lambda manifest, who, caller: True,
                          host="127.0.0.1", port=0, root=root)
    lost.start()
    try:
        check("a torn state document adopts no offer", lost.adopt_interrupted_offers() == 0,
              list((root / offer_id).iterdir()))
        conn2 = PeerConnection(sender, "PC-Sender", "127.0.0.1", lost.port, receiver.served_fingerprint)
        conn2.hello()
        conn2.pair(lost.current_pair_code())
        why = ""
        try:
            conn2.reopen(offer_id)
        except protocol_spec.ProtocolError as exc:  # noqa: BLE001 - the code is the answer under test
            why = exc.code
        check("the interrupted offer is refused, not guessed at", why == "OFFER_UNKNOWN", why)
        conn2.offer(files)
        fresh = [e for e in conn2.state()["files"] if e["id"] == big.id]
        check("the same manifest registers as all-missing", bool(fresh) and fresh[0]["missing"] == list(range(count)),
              fresh)
        result = conn2.send(files, None)
        check("and still finishes", all(v["ok"] for v in result["verified"]),
              [v for v in result["verified"] if not v["ok"]])
        landed = root / conn2.offer_id / big.relpath
        check("re-sent file byte-identical", hashlib.sha256(landed.read_bytes()).hexdigest() == big.sha256)
    finally:
        lost.stop()


def phase_chunk_escape(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """spec §4 的零字节转义读成两句（#167）：体里没有零就不转义；收货一方认的是头的「值」，不是「头在不在」。

    第一句是发送方的。两个手机端的 `escapeChunk` 只要数得出转义就打包并抬头，于是一整块 0x1B、一个零也没有
    的体，手机翻倍发出而桌面原样发出——这一端从一开始就只看有没有零（`app/net/spec.py:escape_chunk`），因为
    要藏的只有零。第二句是接收方的。两个手机端的老分支都写的是「头非空就反解」，对面一个它不认识的编码值会被
    当成编码过的读掉，字节凭空少一截，而合同要的是原样交给后面的长度与摘要去判。两条都在这一端有参照实现，
    下面的腿就是把参照钉住的那几条——镜像守卫 `check_chunk_escape` 现在按同一个值查三端。
    """
    packed, header = protocol_spec.escape_chunk(b"\x1bA\x1b\x1b\x1b")
    check("§4 一个零也没有的体不打包也不抬头（0x1B 只是普通字节）",
          header == "" and packed == b"\x1bA\x1b\x1b\x1b", header)
    raw = b"A\x00\x1b\x00B"
    packed, header = protocol_spec.escape_chunk(raw)
    check("§4 有零才抬头，报的就是合同那一个值，线上一个零也不剩",
          header == protocol_spec.CHUNK_ESCAPE_VALUE and b"\x00" not in packed, header)
    check("§4 解回来逐字节等于原文", protocol_spec.unescape_chunk(packed) == raw)

    corpus = workspace / "esc-corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    block = b"\x1b\x00A\x1bB\x00"
    payload = (block * (proto.chunk_size // len(block) + 1))[: proto.chunk_size]
    (corpus / "escapes.bin").write_bytes(payload)
    sender = load_or_create(workspace / "esc-sender")
    receiver = load_or_create(workspace / "esc-receiver")
    root = workspace / "esc-received"
    service = ReceiveService(receiver, "PC-Esc", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        files = plan([corpus / "escapes.bin"], base=corpus)
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        conn.offer(files)
        digest = hashlib.sha256(payload).hexdigest()
        path = f"/v1/offer/{conn.offer_id}/chunk/{files[0].id}/0"
        packed, header = protocol_spec.escape_chunk(payload)
        status, resp = conn._request("PUT", path, raw_body=packed,
                                     headers={"X-Sha256": digest, protocol_spec.CHUNK_ESCAPE_HEADER: header})
        landing = root / conn.offer_id / files[0].relpath
        check("§4 转义过的块配上正确的头：X-Sha256 是原块的，落点逐字节回到原文",
              status == 200 and landing.is_file() and landing.read_bytes() == payload, f"{status} {resp}")
        status, resp = conn._request("PUT", path, raw_body=packed,
                                     headers={"X-Sha256": digest, protocol_spec.CHUNK_ESCAPE_HEADER: "stu2"})
        check("§4 不认识的头值原样进内核：由长度/摘要拒掉，而不是被偷偷反解成原文收下",
              status == proto.http_status("CHUNK_DIGEST_MISMATCH") and resp.get("code") == "CHUNK_DIGEST_MISMATCH",
              f"{status} {resp}")
        document = root / conn.offer_id / STATE_FILE
        before = json.loads(document.read_text(encoding="utf-8")).get("touched") or 0.0
        time.sleep(1.1)
        status, resp = conn._request("PUT", path, raw_body=payload, headers={"X-Sha256": digest})
        after = json.loads(document.read_text(encoding="utf-8")).get("touched") or 0.0
        check("§4 幂等那一句照样给这一单续命：请求落到了盘上的 touched，而不是只在内存里",
              status == 200 and resp.get("idempotent") is True and after > before, (before, after))
    finally:
        service.stop()


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
        conn = PeerConnection(sender, "PC-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
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
            conn = PeerConnection(sender, name, "127.0.0.1", service.port, receiver.served_fingerprint)
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


def phase_chunk_reply_lost(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """A chunk whose reply never came is not a chunk the peer does not have.

    Measured on the Harmony emulator at the top of the pace ladder (2026-10-25): the relay takes the
    whole body - the receiver's own record accounting adds up and its recomputed digest is the right
    one - and then aborts the socket before the response is written. The sender had no rung left to
    spend, so it raised, and the person watched a transfer fail that the other end had completed.
    One GET is the repair, and a GET that cannot be read must still fail the chunk: the peer being
    gone is a different fact from the peer being slow, and only the first one has no answer.
    """
    corpus = workspace / "reply-corpus"
    (corpus / "相册").mkdir(parents=True, exist_ok=True)
    (corpus / "相册" / "第一张.bin").write_bytes(blob(11, 20_000))
    (corpus / "相册" / "第二张.bin").write_bytes(blob(13, 31_000))
    sender = load_or_create(workspace / "reply-sender")
    receiver = load_or_create(workspace / "reply-receiver")
    root = workspace / "reply-received"
    service = ReceiveService(receiver, "PC-Reply", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        files = plan(sorted(corpus.rglob("*.bin")), base=corpus)
        first_file = next(f for f in files if f.relpath.endswith("第一张.bin"))
        other = next(f for f in files if f.relpath.endswith("第二张.bin"))

        def dial(name: str) -> PeerConnection:
            conn = PeerConnection(sender, name, "127.0.0.1", service.port, receiver.served_fingerprint)
            conn.hello()
            conn.pair(service.current_pair_code())
            return conn

        conn = dial("PC-Reply-Landed")
        conn.offer(files)
        real = conn._once
        asked = [0]
        put_first = f"/v1/offer/{conn.offer_id}/chunk/{first_file.id}/0"

        def lost_reply(method, path, body, headers, pace_ms=0):
            got = real(method, path, body, headers, pace_ms)
            if method == "PUT" and path == put_first:
                asked[0] += 1
                raise ConnectionResetError("body landed, the relay dropped the reply")
            return got

        conn.pace_ms = PACE_MS_LADDER[-1]
        conn._once = lost_reply
        try:
            result = conn.send(files)
        finally:
            conn._once = real
        check("回复丢了但体已经落对，这单照样传完",
              all(v["ok"] for v in result["verified"])
              and hashlib.sha256((root / conn.offer_id / first_file.relpath).read_bytes()).hexdigest() == first_file.sha256
              and (root / conn.offer_id / other.relpath).is_file(),
              [v["id"] for v in result["verified"] if not v["ok"]])
        check("问一次就够了，没有把那一块重发", asked[0] == 1, asked[0])

        gone = dial("PC-Reply-Missing")
        gone.offer(files)
        gone_real = gone._once
        gone_put = f"/v1/offer/{gone.offer_id}/chunk/{first_file.id}/0"
        gone_puts = [0]

        def never_landed(method, path, body, headers, pace_ms=0):
            if method == "PUT" and path == gone_put:
                gone_puts[0] += 1
                raise ConnectionResetError("the body never arrived either")
            return gone_real(method, path, body, headers, pace_ms)

        gone.pace_ms = PACE_MS_LADDER[-1]
        gone._once = never_landed
        try:
            gone.send(files)
            check("体真没落时要照旧失败", False, "send returned")
        except ConnectionResetError as exc:
            check("体真没落时要照旧失败", "never arrived" in str(exc), str(exc))
            # The peer *answered* this one - "I do not have it" - which is the hiccup shape, so the sender
            # is supposed to spend the rest of the attempts on it. Counting the writes is what tells this
            # leg apart from the one below, where nobody answers and rewriting would be dialling a dead end.
            check("问到了「没到」就把剩下的尝试次数花在这一块上", gone_puts[0] == 3, gone_puts[0])
        finally:
            gone._once = gone_real

        # The middle of those two facts, and the one the Harmony tunnel actually hit the next day: at the
        # bottom rung a 4 MiB body was dropped *before* any of it arrived, three times running, and the
        # fourth write landed. That is a relay hiccup, not a pipe that is too fast, and the first drop
        # used to be fatal - so a transfer the person had already approved died on a socket that recovered
        # one second later. Bounded by the attempt budget, which the paragraph above keeps failing honestly.
        hiccup = dial("PC-Pipe-Hiccup")
        hiccup.offer(files)
        hiccup_real = hiccup._once
        hiccup_put = f"/v1/offer/{hiccup.offer_id}/chunk/{first_file.id}/0"
        tries = [0]

        def aborts_once(method, path, body, headers, pace_ms=0):
            if method == "PUT" and path == hiccup_put:
                tries[0] += 1
                if tries[0] < 2:
                    raise ConnectionResetError("the tunnel dropped this body before it landed")
            return hiccup_real(method, path, body, headers, pace_ms)

        hiccup.pace_ms = PACE_MS_LADDER[-1]
        hiccup._once = aborts_once
        try:
            healed = hiccup.send(files)
        finally:
            hiccup._once = hiccup_real
        check("节奏已在下限、体被管道吐掉一次时：重发那一块，这单照样传完",
              all(v["ok"] for v in healed["verified"])
              and hashlib.sha256((root / hiccup.offer_id / first_file.relpath).read_bytes()).hexdigest() == first_file.sha256
              and tries[0] == 2,
              [tries[0], [v["id"] for v in healed["verified"] if not v["ok"]]])

        # The third case is the one the sentence above names and neither PC leg covers: the body went
        # away *and* the one question the sender is allowed to ask got no answer either. A peer nobody can
        # reach has said nothing about the bytes, so writing that chunk again is not a repair - the phone
        # sender raises on the first write (#132, the leg the devices call `mute`), and the PC read an
        # unanswered question as a plain "no" and kept dialling a dead socket until the attempts ran out.
        mute = dial("PC-Reply-Mute")
        mute.offer(files)
        mute_real = mute._once
        mute_put = f"/v1/offer/{mute.offer_id}/chunk/{first_file.id}/0"
        mute_puts = [0]
        mute_asks = [0]

        def deaf(method, path, body, headers, pace_ms=0):
            if method == "PUT" and path == mute_put:
                mute_puts[0] += 1
                raise ConnectionResetError("the body was dropped and nobody is left to ask")
            if path.endswith("/state") and mute_puts[0]:
                mute_asks[0] += 1
                raise ConnectionResetError("the question got no answer either")
            return mute_real(method, path, body, headers, pace_ms)

        mute.pace_ms = PACE_MS_LADDER[-1]
        mute._once = deaf
        try:
            mute.send(files)
            check("问不到答案就不重写：那一次写就是最后一次", False, "send returned")
        except ConnectionResetError as exc:
            check("问不到答案就不重写：那一次写就是最后一次",
                  mute_puts[0] == 1 and mute_asks[0] == 1,
                  [mute_puts[0], mute_asks[0]])
            check("报出去的还是那一次写自己的错", "nobody is left" in str(exc), str(exc))
        finally:
            mute._once = mute_real

        # And the half #138 was about: the question came back, and what came back was a refusal. The peer
        # is reachable and just told us this offer is over - a fact the eaten reply never carried - so the
        # verdict the person reads has to be *that*, while the write's own broken pipe stays in the log.
        refused = dial("PC-Ask-Refused")
        refused.offer(files)
        refused_real = refused._once
        refused_put = f"/v1/offer/{refused.offer_id}/chunk/{first_file.id}/0"
        refused_puts = [0]
        refused_asks = [0]

        def answering(method, path, body, headers, pace_ms=0):
            if method == "PUT" and path == refused_put:
                refused_puts[0] += 1
                raise ConnectionResetError("the body died on the way in, and the answer to that is the point")
            if path.endswith("/state") and refused_puts[0]:
                refused_asks[0] += 1
                return 404, {"code": "OFFER_UNKNOWN",
                             "detail": {"reason": "injected: that offer is over down here"}}, b""
            return refused_real(method, path, body, headers, pace_ms)

        refused.pace_ms = PACE_MS_LADDER[-1]
        refused._once = answering
        try:
            refused.send(files)
            check("那一问答的是拒绝时这一单也判死", False, "send returned")
        except protocol_spec.ProtocolError as exc:
            check("那一问答的是拒绝时这一单也判死",
                  refused_puts[0] == 1 and refused_asks[0] == 1, [refused_puts[0], refused_asks[0]])
            check("报出去的是对面那句拒绝，不是本机那次断管",
                  exc.code == "OFFER_UNKNOWN" and "断管" not in str(exc), f"{exc.code} {exc.detail}")
        except ConnectionResetError as exc:
            check("那一问答的是拒绝时这一单也判死", False, f"报的还是写自己的错：{exc}")
        finally:
            refused._once = refused_real
    finally:
        service.stop()


def phase_repeated_offer(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """#145: one offer_id is one question. §4 says the answer a user already gave is what a
    re-posted manifest gets, so nobody is asked twice for one transfer.

    The re-post is not a hypothetical: #96 makes the sender try again whenever a poll cannot be
    read, §4's keep-alive trap says a closed connection resends once, and a Harmony peer answers
    every poll of the same id. Before this, each of those re-posts reached the decision callback
    again - a second dialog for one batch, and a batch somebody declined could be accepted by
    whoever reached the second card.
    """
    corpus = build_corpus(workspace / "repeat-corpus")
    sender = load_or_create(workspace / "repeat-sender")
    receiver = load_or_create(workspace / "repeat-receiver")
    files = plan(corpus, base=workspace / "repeat-corpus")
    asks: list[str] = []

    def dial(name: str) -> PeerConnection:
        conn = PeerConnection(sender, name, "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        return conn

    def declined(manifest: dict, who: str, caller: str) -> bool:
        asks.append(str(manifest["offer_id"]))
        return False

    service = ReceiveService(receiver, "PC-Repeating", declined, host="127.0.0.1", port=0,
                             root=workspace / "repeat-declined")
    service.start()
    try:
        conn = dial("PC-Sender")
        expect_error("a declined offer is refused", "DECLINED", lambda: conn.offer(files))
        status, payload = conn._request("POST", "/v1/offer", json_body=conn._manifest)
        check("the same id re-posted gets that refusal back, not a second question",
              status == proto.http_status("DECLINED") and payload.get("code") == "DECLINED"
              and len(asks) == 1, f"{status} {payload} asked={asks}")
    finally:
        service.stop()

    # A poll that arrives while the first one is still in front of the user must not open a second
    # card either - §4's other legal answer is "registered, nobody has decided yet".
    gate = threading.Event()
    settled = threading.Event()
    answer_box: list[object] = []

    def pondering(manifest: dict, who: str, caller: str) -> bool:
        asks.append(str(manifest["offer_id"]))
        gate.set()
        settled.wait(10.0)
        return bool(answer_box[0])

    thinking = ReceiveService(receiver, "PC-Thinking", pondering, host="127.0.0.1", port=0,
                             root=workspace / "repeat-pending")
    thinking.start()
    first: dict = {}
    try:
        manifest = {"offer_id": "thinkingoffer", "protocol_version": proto.version,
                    "total_size": sum(f.size for f in files),
                    "from": {"peer_id": sender.peer_id, "name": "PC-Sender"},
                    "files": [f.manifest() for f in files]}
        asks.clear()
        worker = threading.Thread(target=lambda: first.update(
            thinking.handle_offer(manifest, sender.fingerprint)), daemon=True)
        worker.start()
        check("the question reached the user once", gate.wait(5.0) and len(asks) == 1, asks)
        polled = thinking.handle_offer(manifest, sender.fingerprint)
        check("a poll while that card is open answers 'not decided yet'",
              polled.get("accepted") is False and polled.get("offer_id") == "thinkingoffer", polled)
        check("and it did not ask the user again", len(asks) == 1, asks)
        answer_box.append(True)
        settled.set()
        worker.join(10.0)
        check("the answer the user gave comes out of the connection that asked",
              first.get("accepted") is True and bool(first.get("files")), first)
        again = thinking.handle_offer(manifest, sender.fingerprint)
        check("a third poll now reads the progress of that one transfer",
              again.get("accepted") is True and len(asks) == 1, f"{again} asked={asks}")
    finally:
        thinking.stop()

    # The other half of §4's sentence: an id that ended is not a new question either.
    decided: list[str] = []

    def accepting(manifest: dict, who: str, caller: str) -> bool:
        decided.append(str(manifest["offer_id"]))
        return True

    service2 = ReceiveService(receiver, "PC-Ended", accepting, host="127.0.0.1", port=0,
                              root=workspace / "repeat-ended")
    service2.start()
    try:
        conn2 = PeerConnection(sender, "PC-Sender-2", "127.0.0.1", service2.port,
                               receiver.served_fingerprint)
        conn2.hello()
        conn2.pair(service2.current_pair_code())
        offered = conn2.offer(files)
        check("an accepted id is one delivery", len(decided) == 1 and offered["state"].get("files"), decided)
        conn2.abort()
        status, payload = conn2._request("POST", "/v1/offer", json_body=conn2._manifest)
        check("a manifest re-posted after that id ended is not asked again",
              status == proto.http_status("OFFER_UNKNOWN") and payload.get("code") == "OFFER_UNKNOWN"
              and len(decided) == 1, f"{status} {payload} asked={decided}")
    finally:
        service2.stop()


def phase_same_name(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§5's other clause: 同名文件加「 (2)」后缀，而不是覆盖.

    ``plan()`` with no base names every entry after its basename, so a selection that spans two roots
    is a real shape and not a hostile peer: ``ChuanShu-cli send C:\\a\\report.txt D:\\b\\report.txt``
    puts two ids on one destination. #128 gave each *offer* its own folder, which stops two transfers
    colliding but says nothing about two entries of the same manifest - and until this leg both ends
    re-derived the landing from ``relpath`` on every chunk, so the two files' bytes were written into
    one file at the same offsets and finalize could not pass either of them.
    """
    corpus = workspace / "same-name"
    big = corpus / "c1" / "report.txt"
    small = corpus / "c2" / "report.txt"
    big.parent.mkdir(parents=True, exist_ok=True)
    small.parent.mkdir(parents=True, exist_ok=True)
    big.write_bytes(blob(11, proto.chunk_size + 1000))
    small.write_bytes(blob(12, 2000))
    sender = load_or_create(workspace / "same-sender")
    receiver = load_or_create(workspace / "same-receiver")
    files = plan([big, small])
    check("两个不同根目录下的同名文件在这一单里确实是同一个名字",
          len(files) == 2 and files[0].relpath == files[1].relpath == "report.txt",
          " / ".join(f.relpath for f in files))
    root = workspace / "same-received"
    service = ReceiveService(receiver, "PC-Same-Name", lambda m, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Same-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        conn.offer(files)
        result = conn.send(files)
        verified = result["verified"]
        by_id = {f.id: f for f in files}
        check("一单里两个同名文件都过了整文件摘要", all(bool(v["ok"]) for v in verified), str(verified))
        paths = [str(v["path"]) for v in verified]
        check("两份同名的字节落在两个不同的路径上", len(set(paths)) == 2, " | ".join(paths))
        check("后拿到的那一个改名成 §5 说的「 (2)」后缀",
              any(p.endswith("report (2).txt") for p in paths), " | ".join(paths))
        for v in verified:
            source = by_id[str(v["id"])]
            landed = Path(str(v["path"]))
            check(f"{source.path.parent.name} 那一份落盘的字节和它自己的一致",
                  hashlib.sha256(landed.read_bytes()).hexdigest() == source.sha256
                  and landed.stat().st_size == source.size,
                  f"{landed} {landed.stat().st_size} vs {source.size}")
    finally:
        service.stop()


def phase_hidden_segments(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§5's dot rule read as a claim about the *sender*: 「发送方（PC 与手机）也按段拦」.

    Round twenty (#186) measured the PC half of that sentence against the wire. ``plan()`` walked
    ``rglob("*")`` and filtered on ``entry.name.startswith(".")`` - the leaf name only - so
    ``工程/.git/config`` was offered as ``工程/.git/config`` and the receiving end, which does apply §5 per
    segment, answered the whole manifest with ``400 PATH_REJECTED {'segment': '.git'}``: the two
    innocent files in that folder never landed either (``.probe/r20_before_probe.txt`` [2]). Drop the
    base and the same entry shipped under its leaf name ``config`` - the bytes the user hides reach the
    peer as soon as one path stops carrying the dot ([3]/[4]). The three shapes below are the three
    ways that hole could re-open, so each one has its own leg.
    """
    def dots(relpath: str) -> list[str]:
        return [p for p in PurePosixPath(relpath).parts if p.startswith(".")]

    proj = workspace / "hidden-tree" / "工程"
    (proj / ".git").mkdir(parents=True)
    (proj / "相册").mkdir(parents=True)
    (proj / "读我.txt").write_bytes(b"readme-" * 4)
    (proj / ".git" / "config").write_bytes(b"[core]\n")
    (proj / "相册" / "照片.bin").write_bytes(blob(21, 4096))
    (proj / ".env").write_bytes(b"SECRET=1\n")

    with_base = [f.relpath for f in plan([proj], base=proj.parent)]
    check("带 base 的清单里没有一个点开头的段（§5 那句按段拦的就是这一条 relpath）",
          all(not dots(name) for name in with_base) and sorted(with_base) == ["工程/相册/照片.bin", "工程/读我.txt"],
          " / ".join(with_base))
    check("点开头目录里那一份压根没进清单，而不是进去以后由对面拒掉",
          not any(name.endswith("config") for name in with_base), " / ".join(with_base))

    flat = [f.relpath for f in plan([proj])]
    check("base 摘掉、名字拍平成叶子名以后，那一份还是不进清单",
          sorted(flat) == ["照片.bin", "读我.txt"], " / ".join(flat))

    check("叶子名自己带点的那一份照旧不报",
          [f.relpath for f in plan([proj / ".env"])] == [], "")

    hidden_root = workspace / "hidden-tree" / ".私有"
    hidden_root.mkdir()
    (hidden_root / "笔记.txt").write_bytes(b"note\n")
    whole_folder = [f.relpath for f in plan([hidden_root], base=hidden_root.parent)]
    check("用户整目录挑的是一个点开头的目录时，里面一份都不出去",
          whole_folder == [], " / ".join(whole_folder))

    sender = load_or_create(workspace / "hidden-sender")
    receiver = load_or_create(workspace / "hidden-receiver")
    files = plan([proj], base=proj.parent)
    root = workspace / "hidden-received"
    service = ReceiveService(receiver, "PC-Hidden", lambda m, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Hidden-Sender", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        conn.offer(files)
        result = conn.send(files)
        verified = result["verified"]
        check("这一单被对面收下：一份点段都没报出去，无辜的那两份不必再为它陪葬",
              len(verified) == 2 and all(bool(v["ok"]) for v in verified), str(verified))
        check("落地的就是那两份无辜的字节，路径里带出用户选的目录层级",
              sorted(Path(str(v["path"])).name for v in verified) == ["照片.bin", "读我.txt"]
              and all(Path(str(v["path"])).parent.name in ("相册", "工程") for v in verified),
              " | ".join(str(v["path"]) for v in verified))
    finally:
        service.stop()


def phase_manifest_fields(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§4's manifest block, read as a claim about the wire: every sender emits exactly the fields listed,
    and the three numbers peers never act on (`total_size`, `mtime`, `type`) stay non-binding here too.

    Round-fourteen shape (§6 第 31 条): the block listed four top-level keys; both senders have shipped
    six for ages (`compatible_versions` arrived with §7, `from` with §3's self-announcement), and per-file
    `type` was never named at all. The prose now says what each field is for - and the legs below prove the
    prose: a receiver that quietly trusted the bogus sum, or stamped `mtime` onto the disk, would go red here.
    """
    spec = (ROOT / "protocol" / "spec.md").read_text(encoding="utf-8")
    block = json.loads(re.search(r"```json\n(.*?)```", spec.split("## 4. 传输")[1].split("## 5.")[0], re.S).group(1))
    contract_top = set(block.keys())
    contract_file = set(block["files"][0].keys())

    corpus = build_corpus(workspace / "fields-corpus")
    sender = load_or_create(workspace / "fields-sender")
    receiver = load_or_create(workspace / "fields-receiver")
    files = plan(corpus, base=workspace / "fields-corpus")

    seen: dict = {}

    def capture(self: PeerConnection, method: str, path: str, json_body=None, raw_body: bytes = b"",
                headers: dict | None = None, pace_ms: int = 0):
        if method == "POST" and path == "/v1/offer":
            seen.update(json_body)
        return 403, {"code": "DECLINED"}

    conn = PeerConnection(sender, "PC-Fields", "127.0.0.1", 1, receiver.served_fingerprint)
    conn.abort = lambda: None
    original = PeerConnection._request
    PeerConnection._request = capture
    try:
        expect_error("the offer question is parked before the first byte", "DECLINED", lambda: conn.offer(files))
    finally:
        PeerConnection._request = original
    check("what this sender puts on the wire is exactly the fields §4 lists",
          set(seen.keys()) == contract_top and all(set(entry.keys()) == contract_file for entry in seen.get("files", [])),
          f"{sorted(seen.keys())} | files[0]={sorted((seen.get('files') or [{}])[0].keys())}")

    root = workspace / "fields-received"
    service = ReceiveService(receiver, "PC-Fields-Receiver", lambda m, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Fields", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        dishonest = {"offer_id": "fieldsoffer", "protocol_version": proto.version,
                     "compatible_versions": list(proto.compatible_versions),
                     "from": {"peer_id": sender.peer_id, "name": "PC-Fields"},
                     "total_size": 999_999_999_999,
                     "files": [f.manifest() for f in files]}
        first = service.handle_offer(dishonest, sender.fingerprint)
        entry = next(e for e in first["files"] if e["id"] == big.id)
        check("§4 total_size：总数谎报九个千亿，这一端照样收下，缺块照条目自己的 size 算",
              first.get("accepted") is True and entry["missing"] == [0, 1] and entry["received"] == 0, entry)
        lying = json.loads(json.dumps(dishonest))
        lying["offer_id"] = "dishonest"
        lying["files"][0]["mtime"] = 100
        lying["files"][0]["type"] = "x-字节不会据此存在"
        service.handle_offer(lying, sender.fingerprint)
        landed = json.loads((root / "dishonest" / STATE_FILE).read_text(encoding="utf-8"))["files"][0]
        check("§4 mtime/type：接收方把它们原样记进台账，一个字都不改口",
              landed["mtime"] == 100 and landed["type"] == "x-字节不会据此存在", landed)
        disk = [p for p in (root / "dishonest").rglob("*") if p.is_file()]
        check("§4 mtime：没有一个字节的落盘时间被那个数写过",
              disk and all(p.stat().st_mtime > 1_000_000 for p in disk),
              str([p.stat().st_mtime for p in disk][:3]))
        conn.offer_id = "fieldsoffer"
        conn._manifest = dishonest
        result = conn.send(files)
        landing = next(iter([Path(str(v["path"])) for v in result["verified"] if str(v["path"]).endswith("note.pdf")]), None)
        check("§4 total_size：整单照常过摘要，落盘字节是发出去的那些（那个谎数没挡路、也没被拿去开档）",
              all(bool(v["ok"]) for v in result["verified"])
              and landing is not None and landing.stat().st_size == sum(f.size for f in files if f.relpath == "note.pdf"),
              f"{[v['ok'] for v in result['verified']]} | {landing}")
    finally:
        service.stop()


def phase_finalize_reply(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§4's `finalize` reply read as a claim about the wire - and about where the sender's
    "resend just that file's problem chunks" can possibly read which chunks those are.

    Round-fifteen shape (§6 第 32 条): the paper showed `{"verified": [{"id", "ok"}]}` while both receivers
    answer `{offer_id, verified[]}` with per-entry `missing` and `path`, and the same section already promised
    `path` two pages up. `missing` is the field the retry clause depends on, so the legs below drive it: one
    erased ledger → the reply names every chunk → the sender PUTs exactly those indexes and none for the files
    that were already green. The other half is what that clause cannot do: a `size: 0` entry has no chunks to
    name, so the retry writes zero bytes and the batch dies on FILE_DIGEST_MISMATCH for that file alone
    (`.probe/r15_finalize_probe.txt`).
    """
    spec = (ROOT / "protocol" / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4. 传输")[1].split("## 5.")[0]
    block = next(json.loads(body) for body in re.findall(r"```json\n(.*?)```", section, re.S)
                 if "verified" in body)
    contract_top = set(block.keys())
    contract_entry = set(block["verified"][0].keys())

    base = workspace / "reply-corpus"
    (base / "相册").mkdir(parents=True, exist_ok=True)
    (base / "空.txt").write_bytes(b"")
    (base / "相册" / "两块.bin").write_bytes(b"A" * proto.chunk_size + b"B" * 7)
    (base / "小.txt").write_bytes(b"z" * 5)
    files = plan([base / "空.txt", base / "小.txt", base / "相册" / "两块.bin"], base=base)
    empty = next(f for f in files if f.size == 0)
    big = next(f for f in files if f.relpath.endswith("两块.bin"))
    small = next(f for f in files if f.relpath == "小.txt")

    sender = load_or_create(workspace / "reply-sender")
    receiver = load_or_create(workspace / "reply-receiver")
    root = workspace / "reply-received"
    service = ReceiveService(receiver, "PC-Reply", lambda m, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Reply", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())

        conn.offer(files)
        conn.push_missing(files, conn.state(), None, 3)
        green = conn.finalize()
        check("§4 finalize：这条应答摊开就是纸上那份块——顶层两个键、每个条目四个键",
              set(green.keys()) == contract_top
              and all(set(v.keys()) == contract_entry for v in green["verified"]),
              f"{sorted(green.keys())} | entries={sorted(green['verified'][0].keys())}")
        by_id = {f.id: f for f in files}
        check("§4 finalize 的 path：`ok: true` 报回的那条路径就是磁盘上那份，字节对得上清单",
              all(v["path"] is not None and Path(str(v["path"])).is_file()
                  and hashlib.sha256(Path(str(v["path"])).read_bytes()).hexdigest() == by_id[str(v["id"])].sha256
                  for v in green["verified"]),
              [str(v["path"]).rsplit("\\", 1)[-1] for v in green["verified"]])

        # A hole the ledger does not know about: the disk contradicts it, so the answer becomes every chunk.
        conn.offer(files)
        conn.push_missing(files, conn.state(), None, 3)
        (root / conn.offer_id / big.relpath).unlink()
        pushed: list[str] = []
        first: dict = {}
        original = conn._put_chunk
        raw_finalize = conn.finalize
        conn._put_chunk = lambda f, i, t, p, r: (pushed.append(f"{f.relpath}#{i}"), original(f, i, t, p, r))[1]
        conn.finalize = lambda: (first.update(raw_finalize()), first)[1] if not first else raw_finalize()
        try:
            repaired = conn.send(files, None)
        finally:
            conn._put_chunk = original
            conn.finalize = raw_finalize
        denied = next(v for v in first["verified"] if v["id"] == big.id)
        check("§4 finalize 的 missing：被摘要推翻的那一份改口成全缺，落点写成空",
              set(first.keys()) == contract_top and set(denied.keys()) == contract_entry
              and denied["ok"] is False and denied["missing"] == [0, 1] and denied["path"] is None, denied)
        check("§4 那句「只补传该文件的问题分块」：发送方 PUT 的正是答复点名的那几个块，别的文件一块都没动",
              pushed == [f"{big.relpath}#0", f"{big.relpath}#1"], pushed)
        check("补完第二次 finalize 就绿，那一文件逐字节回到原位",
              all(bool(v["ok"]) for v in repaired["verified"])
              and hashlib.sha256((root / conn.offer_id / big.relpath).read_bytes()).hexdigest() == big.sha256,
              [v["ok"] for v in repaired["verified"]])

        # The clause's other half: an entry with nothing to name.
        conn.offer(files)
        conn.push_missing(files, conn.state(), None, 3)
        (root / conn.offer_id / empty.relpath).unlink()
        again: list[str] = []
        original = conn._put_chunk
        conn._put_chunk = lambda f, i, t, p, r: (again.append(f"{f.relpath}#{i}"), original(f, i, t, p, r))[1]
        try:
            conn.send(files, None)
            check("§4 零块的文件：finalize 判它不合规，答复给不出任何问题分块，这一手也就写不出一个字节",
                  False, "send() returned green")
        except protocol_spec.ProtocolError as error:
            check("§4 零块的文件：finalize 判它不合规，答复给不出任何问题分块，这一手也就写不出一个字节",
                  error.code == "FILE_DIGEST_MISMATCH" and error.detail == {"files": [empty.id]} and again == [],
                  f"{error.code} {error.detail} | PUT: {again}")
        finally:
            conn._put_chunk = original
        check("同一单里另外两份不受这一格牵连：块还在盘上，缺的那一份也没有被偷偷重开",
              (root / conn.offer_id / big.relpath).is_file() and (root / conn.offer_id / small.relpath).is_file()
              and not (root / conn.offer_id / empty.relpath).exists(), str(root / conn.offer_id))
    finally:
        service.stop()


def phase_offer_reply(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§4's three replies read as claims about the wire - and about the moment a `DELETE` lands.

    Round-sixteen shape (§6 第 33 条): the paper showed the accepted manifest answer as
    `200 {"accepted": true}` while all three receivers answer `{offer_id, accepted, files[]}` - the very
    body `GET /v1/offer/{id}/state` gives back, same bytes, because one function makes both - and showed
    no body at all for `DELETE`, which every receiver answers with `{offer_id, dropped}`. `files[].missing`
    is what the phone's sender pushes from without a second request (`cs-client.uts:610`), so "同一份
    `files[]`" is load-bearing, not a nicety; `received` and `dropped` travel on every reply and drive
    nothing, which is written down rather than quietly deleted.

    The half that was missing in code is the *when* of the abort: §4's 「中止并清理」 named only an offer
    already being filled, and PC took that literally - an offer still waiting for its person was not in
    `_offers`, so the `DELETE` a sender makes when its own window expires answered `OFFER_UNKNOWN` and
    left the dialog on screen; a 接受 tapped afterwards registered the offer and opened files for a peer
    that had already walked away (`.probe/r16_reply_probe.txt` D1/D4). The phones' `abortReply` has always
    dropped the card, because a pending offer lives in their inbox. The legs below drive both halves.
    """
    spec = (ROOT / "protocol" / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4. 传输")[1].split("## 5.")[0]
    block = next(json.loads(body) for body in re.findall(r"```json\n(.*?)```", section, re.S)
                 if '"accepted"' in body)
    contract_top = set(block.keys())
    contract_entry = set(block["files"][0].keys())

    base = workspace / "reply-corpus3"
    base.mkdir(parents=True, exist_ok=True)
    (base / "两块.bin").write_bytes(blob(16, proto.chunk_size + 7))
    files = plan([base / "两块.bin"], base=base)

    sender = load_or_create(workspace / "reply-sender3")
    receiver = load_or_create(workspace / "reply-receiver3")

    # --- the answer nobody has given yet -----------------------------------------------
    deciding = threading.Event()
    release = threading.Event()
    withdrawn: list[str] = []

    def ask_then_accept(manifest: dict, who: str, caller) -> bool:
        deciding.set()
        release.wait(60)
        return True

    pending_root = workspace / "reply-pending3"
    service = ReceiveService(receiver, "PC-Reply3", ask_then_accept, host="127.0.0.1", port=0,
                             root=pending_root, on_withdrawn=withdrawn.append)
    service.start()
    try:
        conn = PeerConnection(sender, "PC-Reply3", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        holder: dict = {}

        def offer_in_background() -> None:
            try:
                holder["reply"] = conn.offer(files)
            except Exception as exc:  # noqa: BLE001 - the answer this leg is about
                holder["error"] = f"{type(exc).__name__}: {exc}"

        thread = threading.Thread(target=offer_in_background, daemon=True)
        thread.start()
        deciding.wait(10)
        time.sleep(0.3)
        offer_id = conn.offer_id

        # One peer holds one session token, so the second connection is paired only now - after the
        # blocked POST is authenticated and in flight, and on its own socket.
        other = PeerConnection(sender, "PC-Reply3", "127.0.0.1", service.port, receiver.served_fingerprint)
        other.hello()
        other.pair("")

        status, body = other._request("POST", "/v1/offer", json_body=conn._manifest)
        check("§4 待决应答：还没人回答时重投清单，回的体就只有 offer_id 与 accepted 两个键",
              status == 200 and set(body) == {"offer_id", "accepted"} and body["accepted"] is False,
              f"{status} {sorted(body)}")

        status, dropped = other._request("DELETE", f"/v1/offer/{offer_id}")
        check("§4 中止：撤一单还没人回答的，回的是 offer_id 加 dropped（发送方只在没回 200 时才读它）",
              status == 200 and set(dropped) == {"offer_id", "dropped"} and dropped["dropped"] is True,
              f"{status} {json.dumps(dropped, ensure_ascii=False)}")
        check("§4 中止：这一端手里那一问被告知停下了，这个 offer_id 记成「已撤回」而不是「不认识」",
              withdrawn == [offer_id] and service._answered.get(offer_id) == "withdrawn",
              f"{withdrawn} {service._answered.get(offer_id)}")
        status, again = other._request("POST", "/v1/offer", json_body=conn._manifest)
        check("§4 中止：撤回之后同一份清单再投，拿的是 OFFER_UNKNOWN 而不是第二张确认框",
              status == 404 and again.get("code") == "OFFER_UNKNOWN"
              and again.get("detail") == {"offer_id": offer_id},
              f"{status} {json.dumps(again, ensure_ascii=False)}")
        release.set()
        thread.join(20)
        check("§4 中止：人在这期间点了「接受」，那一问拿到的答案也是 OFFER_UNKNOWN（不是 declined）",
              holder.get("error", "").endswith("OFFER_UNKNOWN"), holder)
        check("这一单既没有登记进接收表，磁盘上也没替它开档",
              offer_id not in service._offers and not (pending_root / offer_id).is_dir(),
              f"in table={offer_id in service._offers} dir={(pending_root / offer_id).is_dir()}")
    finally:
        service.stop()

    # --- an offer that was answered, filled, then walked away from ----------------------
    # No on_withdrawn here on purpose: a receiver with no card to close (the command line) must still
    # answer these replies correctly - the callback is the screen's business, not the contract's.
    root = workspace / "reply-received3"
    service2 = ReceiveService(receiver, "PC-Reply3", lambda m, who, caller: True,
                              host="127.0.0.1", port=0, root=root)
    service2.start()
    try:
        conn = PeerConnection(sender, "PC-Reply3b", "127.0.0.1", service2.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service2.current_pair_code())
        payload = conn.offer(files)["state"]
        check("§4 清单被接受那条 200 摊开就是纸上这块：顶层三个键、每个条目三个数",
              set(payload) == contract_top and set(payload["files"][0]) == contract_entry,
              f"{sorted(payload)} | entries={sorted(payload['files'][0])}")
        offer_id = conn.offer_id
        manifest_body = json.dumps(conn._manifest, ensure_ascii=False).encode("utf-8")
        _, reposted, repost_raw = conn._once("POST", "/v1/offer", manifest_body,
                                             {"Content-Type": "application/json"})
        _, state, state_raw = conn._once("GET", f"/v1/offer/{offer_id}/state", b"", {})
        check("§4 那句「与 GET state 同一份 files[]」是逐字节的同一份：重投已接受的清单与那次 GET 回同样的体",
              repost_raw == state_raw and set(state) == contract_top and state["files"][0]["received"] == 0
              and state["files"][0]["missing"] == [0, 1],
              f"{len(repost_raw)} vs {len(state_raw)} 字节 | {state['files']}")

        conn.push_missing(files, state, None, 3)
        conn.finalize()
        filled = conn._once("GET", f"/v1/offer/{offer_id}/state", b"", {})[1]
        check("落齐之后回的还是同一形状：三个数都换成完成后的值，missing 空、received 记满",
              set(filled) == contract_top and set(filled["files"][0]) == contract_entry
              and filled["files"][0]["missing"] == [] and filled["files"][0]["received"] == 2,
              filled["files"][0])

        status, dropped = conn._request("DELETE", f"/v1/offer/{offer_id}")
        check("§4 中止：撤一单已经填完的，回的仍是这两个键",
              status == 200 and set(dropped) == {"offer_id", "dropped"}, f"{status} {sorted(dropped)}")
        check("它从表里消失，名下的文件也没了",
              offer_id not in service2._offers and not (root / offer_id / "两块.bin").exists(),
              str(root / offer_id))
        expect_error("§4 中止：撤掉之后 GET state 拿到 OFFER_UNKNOWN，而不是空表",
                     "OFFER_UNKNOWN", conn.state)
        _, again, _ = conn._once("POST", "/v1/offer", manifest_body, {"Content-Type": "application/json"})
        check("§4 中止：撤掉之后同一份清单再投，拿的也是 OFFER_UNKNOWN（不是重新问一遍）",
              again.get("code") == "OFFER_UNKNOWN" and again.get("detail") == {"offer_id": offer_id},
              json.dumps(again, ensure_ascii=False))
    finally:
        service2.stop()


def phase_pending_answer(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§4's other writing, measured from the sender: a receiver that answers pending on the spot.

    Every other leg drives the PC's sender against a PC-style receiver, which holds the POST open and puts
    the decision in the first reply. Both phones answer `accepted: false` immediately - Android since #83,
    Harmony since #59 - and the decision comes out of a later POST; round twenty-one (#187) found the
    contract still naming Android among the ends that hold the connection. §4 says the two writings are one
    path for the sender, so this leg runs the second one instead of taking the sentence on trust.
    """
    corpus = build_corpus(workspace / "pending-corpus")
    sender = load_or_create(workspace / "pending-sender")
    receiver = load_or_create(workspace / "pending-receiver")
    root = workspace / "pending-received"
    asked: list[str] = []
    release = threading.Event()
    settled: dict = {}

    def ponder(manifest: dict, who: str, caller: str) -> bool:
        asked.append(str(manifest["offer_id"]))
        release.wait(30)
        return True

    service = ReceiveService(receiver, "Phone-Like", ponder, host="127.0.0.1", port=0, root=root)
    real_offer = service.handle_offer
    posts: list[int] = []

    def phones_like(body: dict, caller: str) -> dict:
        """The host half of a phone: the request is answered where it landed, the user's answer goes
        into the inbox, and the next POST of the same manifest is what carries the decision."""
        posts.append(1)
        offer_id = str(body["offer_id"])
        if len(posts) == 1:
            threading.Thread(target=lambda: settled.update(
                reply=real_offer(body, caller)), daemon=True).start()
            return {"offer_id": offer_id, "accepted": False}
        return settled.get("reply") or {"offer_id": offer_id, "accepted": False}

    service.handle_offer = phones_like  # type: ignore[method-assign]
    service.start()
    threading.Timer(2.0, release.set).start()
    try:
        files = plan(corpus, base=workspace / "pending-corpus")
        conn = PeerConnection(sender, "Phone-Like", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        offered = conn.offer(files)
        check("§4 待决应答：接收端当场回「还没人决定」，发送端按同一个 offer_id 重投而不是判死这一单",
              len(posts) >= 2 and offered["state"].get("accepted") is True
              and bool(offered["state"].get("files")), f"posts={len(posts)}")
        check("这一单只问到用户一次（重投不是第二张确认框）", len(asked) == 1, asked)
        result = conn.send(files)
        big = next(f for f in files if f.relpath.endswith("IMG_大文件.bin"))
        landing = root / conn.offer_id / big.relpath
        check("两种写法对发送端是同一条路径：照旧把整单传完并逐字节校验",
              all(v["ok"] for v in result["verified"]) and landing.is_file()
              and hashlib.sha256(landing.read_bytes()).hexdigest() == big.sha256,
              str(landing))
    finally:
        service.stop()


def phase_chunk_reply(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§4's chunk replies read as claims about wire bytes - and about how many times a sender writes.

    Round-seventeen shape (§6 第 34 条): the paper drew no body for the chunk `200`, although every receiver
    answers `{index, stored}` and the idempotent repeat adds `idempotent: true`; it drew no detail for either
    `422`, although the two refusals travel as `{index, expected}` (carrying the *sender's own claim*, never
    the digest the receiver computed) and `{reason, got, want}`; it promised 「最多 3 次」, which the two
    senders spell as `retries=3` writes and `CHUNK_RESEND_MAX = 2` resends and which measures as three writes
    on both; and it listed `X-File-Size` among the chunk headers when no end sends it and no end reads it,
    while a PUT with no `X-Sha256` is accepted with the block check skipped (`receive.py:766`,
    `cs-receive.uts:1009`) - so the bytes land as sent and only `finalize`'s whole-file digest can say so.
    """
    spec = (ROOT / "protocol" / "spec.md").read_text(encoding="utf-8")
    section = spec.split("## 4. 传输")[1].split("## 5.")[0]
    blocks = [json.loads(body) for body in re.findall(r"```json\n(.*?)```", section, re.S)]
    first_answer = next(b for b in blocks if set(b) == {"index", "stored"})
    repeat_answer = next(b for b in blocks if "idempotent" in b)
    length_detail = next(b for b in blocks if set(b) == {"reason", "got", "want"})
    digest_detail = next(b for b in blocks if set(b) == {"index", "expected"})

    base = workspace / "chunk-corpus"
    base.mkdir(parents=True, exist_ok=True)
    payload = blob(31, proto.chunk_size + 7)
    (base / "两块.bin").write_bytes(payload)
    head, tail = payload[: proto.chunk_size], payload[proto.chunk_size:]
    head_sha, tail_sha = hashlib.sha256(head).hexdigest(), hashlib.sha256(tail).hexdigest()

    sender = load_or_create(workspace / "chunk-sender17")
    receiver = load_or_create(workspace / "chunk-receiver17")
    root = workspace / "chunk-received17"
    service = ReceiveService(receiver, "PC-Chunk17", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root)
    service.start()
    try:
        files = plan([base / "两块.bin"], base=base)
        conn = PeerConnection(sender, "PC-Chunk17", "127.0.0.1", service.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service.current_pair_code())
        conn.offer(files)
        landing = root / conn.offer_id / files[0].relpath

        def put(index: int, body: bytes, sha: str, extra: dict | None = None):
            headers = {"X-Sha256": sha} if sha else {}
            if extra:
                headers.update(extra)
            return conn._request("PUT", f"/v1/offer/{conn.offer_id}/chunk/{files[0].id}/{index}",
                                 raw_body=body, headers=headers)

        status, reply = put(0, head, head_sha)
        check("§4 一块写成的 200 摊开就是纸上这块：两个键，stored 是真",
              status == 200 and set(reply) == first_answer.keys() and reply.get("stored") is True
              and reply.get("index") == 0, f"{status} {reply}")
        written = landing.stat().st_mtime_ns
        time.sleep(0.05)
        status, repeat = put(0, head, head_sha)
        check("§4 重复写入同一 index 且这一条请求整体一致：多带的那一个键也是纸上那个",
              status == 200 and set(repeat) == repeat_answer.keys() and repeat.get("idempotent") is True,
              f"{status} {repeat}")
        check("§4 那一个键换来的是不重写：落点的 mtime 没动过",
              landing.stat().st_mtime_ns == written, (written, landing.stat().st_mtime_ns))

        status, truncated = put(0, head[:2048], head_sha)
        check("§4「摘要一致」比的是一条完整请求的体，不是块号：同一 index 只送前 2048 字节配全块那份摘要是 422",
              status == proto.http_status("CHUNK_DIGEST_MISMATCH")
              and truncated.get("code") == "CHUNK_DIGEST_MISMATCH", f"{status} {truncated}")
        status, lied = put(1, b"Z" * len(tail), tail_sha)
        detail = lied.get("detail") or {}
        check("§4 摘要与体不符那副 detail 摊开就是纸上这块，而 expected 装的是发送方自己声明的那一份",
              status == proto.http_status("CHUNK_DIGEST_MISMATCH") and set(detail) == digest_detail.keys()
              and detail.get("index") == 1 and detail.get("expected") == tail_sha
              and detail.get("expected") != hashlib.sha256(b"Z" * len(tail)).hexdigest(), f"{status} {lied}")
        status, wrong_len = put(1, tail + b"!", tail_sha)
        detail = wrong_len.get("detail") or {}
        check("§4 长度不对那副 detail 摊开就是纸上这块，报的是反解之后该有多长",
              status == proto.http_status("CHUNK_DIGEST_MISMATCH") and set(detail) == length_detail.keys()
              and detail.get("reason") == "length" and detail.get("got") == len(tail) + 1
              and detail.get("want") == len(tail), f"{status} {wrong_len}")
        status, phantom = put(0, head[:2048], head_sha, extra={"X-File-Size": "2048"})
        check("§4 的 X-File-Size 谁都不读：谎报这个头的截断体拿的还是同一句 422「该有 4 MiB」",
              status == proto.http_status("CHUNK_DIGEST_MISMATCH")
              and (phantom.get("detail") or {}).get("want") == proto.chunk_size, f"{status} {phantom}")
        status, out_of_range = put(len(payload) // proto.chunk_size + 5, head, head_sha)
        detail = out_of_range.get("detail") or {}
        check("§4 序号越界是 400 BAD_CHUNK_INDEX，detail 只有 index 与 count 两个键",
              status == proto.http_status("BAD_CHUNK_INDEX") and out_of_range.get("code") == "BAD_CHUNK_INDEX"
              and set(detail) == {"index", "count"} and detail.get("count") == 2, f"{status} {out_of_range}")

        status, naked = put(1, b"ZZZZZZZ", "")
        check("§4 不带 X-Sha256 的 PUT 三端都照收：这一端回 200，七个字节真的落进那个偏移",
              status == 200 and set(naked) == first_answer.keys()
              and landing.stat().st_size == proto.chunk_size + 7
              and landing.read_bytes()[proto.chunk_size:] == b"ZZZZZZZ", f"{status} {naked}")
        done = conn.finalize()
        entry = (done.get("verified") or [{}])[0]
        check("§4 块级校验被跳过时最后的防线只剩整文件摘要：那一单判不过，而台账作废后好块陪坏块一起重报",
              entry.get("ok") is False and entry.get("missing") == [0, 1] and entry.get("path") is None,
              json.dumps(entry, ensure_ascii=False))
    finally:
        service.stop()

    # The write budget §4 states as 「最多 3 次」: one peer that refuses every chunk, counting the PUTs.
    root2 = workspace / "chunk-received17b"
    service2 = ReceiveService(receiver, "PC-Chunk17b", lambda manifest, who, caller: True,
                              host="127.0.0.1", port=0, root=root2)
    service2.start()
    try:
        files = plan([base / "两块.bin"], base=base)
        conn = PeerConnection(sender, "PC-Chunk17b", "127.0.0.1", service2.port, receiver.served_fingerprint)
        conn.hello()
        conn.pair(service2.current_pair_code())
        conn.offer(files)
        writes: list[str] = []
        real = conn._request

        def always_reject(method, path, json_body=None, raw_body=b"", headers=None, pace_ms=0):
            if path.startswith(f"/v1/offer/{conn.offer_id}/chunk/"):
                writes.append(path.rsplit("/", 1)[1])
                return 422, {"code": "CHUNK_DIGEST_MISMATCH",
                             "detail": {"index": int(path.rsplit("/", 1)[1]), "expected": "0" * 64}}
            return real(method, path, json_body=json_body, raw_body=raw_body, headers=headers, pace_ms=pace_ms)

        conn._request = always_reject
        raised = ""
        try:
            conn.send(files)
        except protocol_spec.ProtocolError as exc:
            raised = exc.code
        finally:
            conn._request = real
        check("§4 那一块一共写三次：首发一次、重传至多两次，第三次之后把 422 抛出去",
              writes == ["0", "0", "0"] and raised == "CHUNK_DIGEST_MISMATCH", f"{writes} {raised}")
        check("§4 重传之间节奏往上升一档：三写之后 ladder 离开了起点",
              conn.pace_ms > PACE_MS_LADDER[0], conn.pace_ms)
    finally:
        service2.stop()


def phase_discovery(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """Two symmetric peers finding each other, then promoting a prefix to an anchor."""
    from app.net.discovery import DiscoveryService, Peer, adopt_hello

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
            check("verify promotes the prefix to a pinnable digest", checked.fingerprint == a_id.served_fingerprint and checked.verified, checked.fingerprint[:12])
            check("verify keeps what hello says", checked.peer_id == a_id.peer_id and checked.name == "PC-A" and checked.port == a_svc.port, checked.public())
            # Behind a forward, the port in the hello is the peer's own number and unreachable from
            # here; following it moves every request after the hello to a dead socket.
            elsewhere = Peer(prefix=checked.prefix, host=checked.host, port=43999, via={"selftest"})
            adopt_hello(proto, elsewhere, checked.fingerprint, {**checked.public(), "protocol_version": proto.version, "port": a_svc.port})
            check("a hello naming another port does not move the connection", elsewhere.port == 43999 and elsewhere.name == "PC-A", elsewhere.public())
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

        # §3's 「端口/地址变了画面要重画」 is about the address a peer dials, not only the one on the
        # screen. The QR is re-read every tick; the mDNS A record is what a browser clicks, and it is
        # the one channel where a PC writes its own address down - Android registers no host on its
        # NsdServiceInfo and Harmony hands the SDK 0.0.0.0 to fill in, so only this end can keep
        # advertising an address it no longer owns. Moving the network has to move the record, and
        # back again, with no restart in between.
        if a.channels["mdns"].state == "ok" and b.channels["mdns"].state == "ok":
            from app.net import discovery as discovery_module

            instance_name = a._service_info.name
            moved = "198.51.100.7"
            real_host = discovery_module.local_ipv4()
            original = discovery_module.local_ipv4

            def wait_for(published: str) -> bool:
                """The announce tick is what notices, so wait out the interval it runs on."""
                deadline = time.time() + 4 * proto.announce_interval_s
                while time.time() < deadline:
                    if a._mdns_host == published:
                        return True
                    time.sleep(0.25)
                return False

            def answered() -> list[str]:
                got = b._zeroconf.get_service_info(proto.mdns_service_type, instance_name, timeout=3000)
                return [] if got is None else got.parsed_addresses()

            discovery_module.local_ipv4 = lambda: moved
            try:
                ticked = wait_for(moved)
                addresses = answered() if ticked else []
                check("a moved address is republished in mDNS", addresses == [moved],
                      f"ticked={ticked} answered={addresses} want={moved}")
            finally:
                discovery_module.local_ipv4 = original
            moved_back = wait_for(real_host)
            back_addresses = answered() if moved_back else []
            check("the record moves back when the network does", back_addresses == [real_host],
                  f"back={moved_back} answered={back_addresses} want={real_host}")

        code = b_svc.current_pair_code()
        url = b.pairing_qr(code, host="127.0.0.1")
        fields = protocol_spec.parse_qr(url)
        check(
            "qr carries address, version, full fingerprint and code",
            fields == {"h": "127.0.0.1", "p": str(b_svc.port), "v": str(proto.version), "f": b_id.served_fingerprint, "c": code},
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
        truncated = protocol_spec.qr_url(h="127.0.0.1", p=str(b_svc.port), v=str(proto.version), f=b_id.served_fingerprint[:60], c=code)
        expect_error("qr with a truncated fingerprint is refused", "UNSUPPORTED_PROTOCOL", lambda: protocol_spec.parse_qr(truncated))
        junk_fp = protocol_spec.qr_url(h="127.0.0.1", p=str(b_svc.port), v=str(proto.version), f="z" * 64, c=code)
        expect_error("qr with a non-hex fingerprint is refused", "UNSUPPORTED_PROTOCOL", lambda: protocol_spec.parse_qr(junk_fp))

        # 第三十四轮（#200）：§2 那句「每 3s 发一次 `{…port…}`，监听常驻」里，`port` 是一句关于套接字的话——
        # 听见的一方照着它拨。所以"这一端没在收"必须说不出口，而不是继续播合同那个默认口。量的就是发的那一步：
        # 把发送套接字换成一个记录本，看这一拍到底有没有字节出去。
        packets: list[tuple[str, dict]] = []

        class _CapturingSocket:
            def sendto(self, data, addr):  # noqa: ANN001 - the shape socket.sendto takes
                packets.append((addr[0], json.loads(data.decode("utf-8"))))

        silent = DiscoveryService(a_id, "PC-没在监听", None)
        silent._udp_socket = _CapturingSocket()
        silent.announce()
        check("§2 没在监听的一端一条公告也不发", packets == [], packets)
        listening = DiscoveryService(a_id, "PC-在监听", b_svc.port)
        listening._udp_socket = _CapturingSocket()
        listening.announce()
        check("§2 在监听的一端播的是它真绑上的那个端口",
              len(packets) == 1 and packets[0][1]["port"] == b_svc.port, packets)
        try:
            silent.pairing_qr(code, host="127.0.0.1")
            check("§2 没监听时那一格 QR 不画一个拨不通的端口", False, "pairing_qr answered")
        except ValueError as error:
            check("§2 没监听时那一格 QR 不画一个拨不通的端口", "没有在接收" in str(error), str(error))
        # 第四十轮（#207）：同一条串里的 `p` 是谁。§2 已经管住了公告的 `port`，这条串以前没人问过——PC 恰好
        # 一直答对（`_dialable_port()` 读的是真绑上的那一个），手机那边念的是合同常量。这条腿钉住"答对"那一侧，
        # 用的就是被占位退到临时口的那种形状：这里的 `b_svc.port` 是 port=0 真绑出来的，不等于 43720。
        qr_live = listening.pairing_qr(code, host="127.0.0.1", passphrase="ABCDEFGH")
        check("§3 配对串里那个 `p` 是本机此刻真绑上的端口，不是 ports.transport 那个常量",
              f"p={b_svc.port}" in qr_live and f"p={proto.transport_port}" not in qr_live
              and b_svc.port != proto.transport_port,
              (qr_live, b_svc.port, proto.transport_port))

        # 第四十一轮（#208）：同一条串里 `k` 写不写，判的是接收方那份材料里有没有密码，不是卡片上印的那句话。
        # PC 两处本来就对（`pairing_qr` 的 `if passphrase:`，加上 `qr_url` 对六格一视同仁的空值跳过），所以这几条
        # 腿钉的是新写进纸面的那半句：**少一格不是少一条串**——没有 `k` 的那一条仍然拨得进去、只靠码就配上。
        bare_qr = b.pairing_qr(code, host="127.0.0.1", passphrase="")
        bare_fields = protocol_spec.parse_qr(bare_qr)
        check("§3 没有密码的那一端不写 k 这个键，其余五格照给",
              "k" not in bare_fields and bare_fields == {
                  "h": "127.0.0.1", "p": str(b_svc.port), "v": str(proto.version),
                  "f": b_id.served_fingerprint, "c": code},
              (bare_qr, bare_fields))
        sparse = protocol_spec.qr_url(h="127.0.0.1", p="", v=str(proto.version),
                                      f=b_id.served_fingerprint, c=code, k="")
        check("§3 值为空就不写键这条对六格一视同仁，不只管 k",
              sparse == f"{proto.qr_scheme}?h=127.0.0.1&v={proto.version}&f={b_id.served_fingerprint}&c={code}",
              sparse)
        scanned_code, scanned_secret = protocol_spec.pairing_secrets(bare_qr, proto)
        check("§3 读回来那一格是空的：这条串上「键不在」与「值是空」是同一个读法，报文里才分得开",
              scanned_code == code and scanned_secret == "", (scanned_code, scanned_secret))
        scanner = PeerConnection(load_or_create(workspace / "disc-scan"), "PC-扫了那条没有 k 的串",
                                 "127.0.0.1", b_svc.port, b_id.served_fingerprint)
        answered = scanner.pair(scanned_code, scanned_secret)
        check("§3 少那一格不是少一条串：照它拨进去，只靠那 6 位码就拿到 token",
              bool(answered.get("token")) and scanner.token != "", answered)

        # 第三十五轮（#201）：「监听常驻」的主语那一半——起了监听就得有一个在跑的公告线程。PC 两端今天都是
        # 这一形（图形端 `transfer.py:1484`、命令行 `receive` 也一样），手机那一半过去要人点一下才补上；
        # 这条腿钉的是三端要对齐的那个参照，名字来自 `_spawn(..., "announce")`。
        announcing = [t.name for t in threading.enumerate() if t.name.endswith("announce")]
        check("§2 起了监听的那一端也在每 3 s 播自己（公告线程在跑）", len(announcing) >= 2, announcing[:4])

        # 注册那一支用同一个判别：公告不发的这一端也不该在 DNS-SD 里留一个端口。`_start_mdns` 里那句
        # `from zeroconf import ...` 换成一个记账的假货，量的就是"注册有没有被叫到"这一件事。
        registered: list[int] = []
        browsed: list[str] = []

        class _FakeZeroconf:
            def register_service(self, info):  # noqa: ANN001 - zeroconf's own shape
                registered.append(info.port)

            def unregister_service(self, info):  # noqa: ANN001
                pass

            def close(self) -> None:
                pass

        class _FakeServiceInfo:
            def __init__(self, *args, **kwargs) -> None:  # noqa: ANN003 - the stub records what it is handed
                self.port = kwargs.get("port")

        class _FakeBrowser:
            def __init__(self, zc, service_type, listener) -> None:  # noqa: ANN001
                browsed.append(service_type)

            def cancel(self) -> None:
                pass

        fake_zeroconf = types.ModuleType("zeroconf")
        fake_zeroconf.Zeroconf = _FakeZeroconf
        fake_zeroconf.ServiceInfo = _FakeServiceInfo
        fake_zeroconf.ServiceBrowser = _FakeBrowser
        real_zeroconf = sys.modules.get("zeroconf")
        sys.modules["zeroconf"] = fake_zeroconf
        try:
            for name, port in (("在监听", b_svc.port), ("没在监听", None)):
                probe = DiscoveryService(a_id, f"PC-{name}", port)
                probe._start_mdns()
            check("§2 没在监听的一端也不注册 mDNS 服务", registered == [b_svc.port], registered)
            check("§2 不注册的那一趟还是在听别人的公告（浏览那一支没跟着关）",
                  len(browsed) == 2 and browsed[0] == browsed[1], browsed)
        finally:
            if real_zeroconf is None:
                sys.modules.pop("zeroconf", None)
            else:
                sys.modules["zeroconf"] = real_zeroconf

        # 第三十七轮（#204）：§2.1 那条记录与 §2.2 那一拍是同一个断言的两个副本，所以「接收停了就停、端口换了
        # 就播新那个」也要落在注册上。PC 两端今天不犯，因为整 DiscoveryService 随监听建拆（`transfer.py:1484`
        # 起、`1496` 停）；这两条腿钉的就是那个参照——一次关掉必须撤掉记录，一次重开必须注册这一次真绑上的
        # 端口。手机那一半改的就是这两件事（CsDiscovery.kt 的 reconcileMdns、鸿蒙的 discBeat）。
        acts: list[str] = []

        class _CycleZeroconf:
            def register_service(self, info):  # noqa: ANN001 - zeroconf's own shape
                acts.append(f"注册 {info.port}")

            def unregister_service(self, info):  # noqa: ANN001
                acts.append(f"撤掉 {getattr(info, 'port', '?')}")

            def close(self) -> None:
                pass

        class _CycleServiceInfo:
            def __init__(self, *args, **kwargs) -> None:  # noqa: ANN003 - the stub keeps what it is handed
                self.port = kwargs.get("port")

        cycle = types.ModuleType("zeroconf")
        cycle.Zeroconf = _CycleZeroconf
        cycle.ServiceInfo = _CycleServiceInfo
        cycle.ServiceBrowser = _FakeBrowser
        real_zeroconf = sys.modules.get("zeroconf")
        sys.modules["zeroconf"] = cycle
        try:
            first = DiscoveryService(a_id, "PC-第一趟监听", b_svc.port)
            first._start_mdns()
            first.stop()
            check("§2.1 关掉发现通道时那条 DNS-SD 记录一起撤了",
                  acts == [f"注册 {b_svc.port}", f"撤掉 {b_svc.port}"], acts)
            second = DiscoveryService(a_id, "PC-换端口后重开", a_svc.port)
            second._start_mdns()
            check("§2.1 重开监听时注册的是这一次真绑上的端口，不是上一次那个",
                  acts[-1] == f"注册 {a_svc.port}" and a_svc.port != b_svc.port, (acts, a_svc.port, b_svc.port))
            second.stop()
        finally:
            if real_zeroconf is None:
                sys.modules.pop("zeroconf", None)
            else:
                sys.modules["zeroconf"] = real_zeroconf

        # 第三十六轮（#203）：§2.1 那条 mDNS 路径上 `fp` 不是可选字段——没有它，一个解析到的服务只是
        # 一个名字加一个地址，"没有东西可钉"，而 §2 明写 Presence is not trust。安卓那侧的写法是把整条
        # 通道判不可用（CsDiscovery.kt: SDK_INT < 28 时 TXT 带不出 fp），内核与 iOS 的读者则丢弃无摘要的记录；
        # 这两条腿第一次把 **PC 这一端的读者**执行一遍：同一台服务，带 fp 的进名单，不带的连名单都不该看见。
        class _Record:
            def __init__(self, props: dict, port: int, name: str) -> None:
                self.properties = props
                self.port = port
                self.name = name

            def parsed_addresses(self) -> list[str]:
                return ["192.168.1.77"]

        before = len(b.candidates())
        b._on_mdns_record(_Record({"ver": "1", "name": "书房-PC"}, 43720, "没带摘要那台._chuanshu._tcp.local."))
        check("§2.1 没有 fp 的 mDNS 记录进不了名单（PC 的读者第一次被执行）", len(b.candidates()) == before,
              [(p.prefix, p.host) for p in b.candidates()])
        b._on_mdns_record(_Record({"ver": "1", "name": "书房-PC", "fp": "1111222233334444"}, 43720,
                                  "带摘要那台._chuanshu._tcp.local."))
        after = b.candidates()
        check("§2.1 带 fp 的那一条照常进名单，端口与地址取自记录本身",
              len(after) == before + 1 and any(p.prefix == "1111222233334444" and p.port == 43720 for p in after),
              [(p.prefix, p.host, p.port) for p in after])

        # 第三十八轮（#205）：§2.1 的**下线那一半**。一条 goodbye 只说"这个名字走了"，不带 `fp`，而名单按前缀键，
        # 所以每一端必须自己记住上一次解析时 name→fp 的对应。PC 这两个读者（`_MdnsListener.remove_service` 与
        # `_forget_mdns`）到今天才被真的执行过一次：上一批腿量的是同一台服务"进来"那一半。这里自己造一台陌生的
        # 服务，走 add（要记下名字）→ remove（要撤掉通道而不是机器）→ 再 remove 一次（记忆已清空，什么都不动）。
        from app.net.discovery import _MdnsListener

        gone_prefix = "9999888877776666"
        gone_name = f"下线那台.{b.proto.mdns_service_type}"

        class _Resolver:
            def __init__(self, info) -> None:  # noqa: ANN001 - zeroconf hands get_service_info a name
                self._info = info
                self.asks: list[str] = []

            def get_service_info(self, service_type: str, name: str, timeout: int = 1500):
                self.asks.append(name)
                return self._info if name == self._info.name else None

        resolver = _Resolver(_Record({"ver": "1", "name": "下线那台-PC", "fp": gone_prefix}, 43731, gone_name))
        listener = _MdnsListener(b)
        listener.add_service(resolver, b.proto.mdns_service_type, gone_name)
        arrived = [p for p in b.candidates() if p.prefix == gone_prefix]
        check("§2.1 解析到的那一趟把 name→fp 记下来，goodbye 才有东西可撤",
              len(arrived) == 1 and "mdns" in arrived[0].via
              and b._mdns_names.get(gone_name) == gone_prefix,
              (len(arrived), arrived[0].via if arrived else [], b._mdns_names.get(gone_name, "")))
        listener.remove_service(resolver, b.proto.mdns_service_type, gone_name)
        stayed = [p for p in b.candidates() if p.prefix == gone_prefix]
        check("§2.1 一条 goodbye 只撤掉 mdns 那一路，这台机器与它的地址端口都留在名单里",
              len(stayed) == 1 and "mdns" not in stayed[0].via
              and stayed[0].host == "192.168.1.77" and stayed[0].port == 43731,
              [(p.prefix, p.via, p.host, p.port) for p in stayed])
        check("§2.1 撤完那份 name→fp 的记忆也放下，第二次 goodbye 什么都不动",
              gone_name not in b._mdns_names and len(stayed) == 1, b._mdns_names)
        listener.remove_service(resolver, b.proto.mdns_service_type, f"没记住那台.{b.proto.mdns_service_type}")
        check("§2.1 没记住那个名字的 goodbye 不炸名单，也不为它重解析一次",
              len([p for p in b.candidates() if p.prefix == gone_prefix]) == 1
              and arrived[0].via == set() and resolver.asks == [gone_name],
              (len(resolver.asks), resolver.asks))

        # 第三十九轮（#206）：§2 把"跟着监听"这一句拆成了两路。**播**（公告 + 注册）跟着端口起落，
        # **听**（DNS-SD 浏览 + 43721 收包）不跟着——命令行的 `peers` 一直是这一形的标本，而 PC 图形端
        # 过去把整具服务随监听建拆，于是"我只想发文件"的人关掉接收之后连设备都找不到了。这几条腿量的是
        # `set_port()` 那一步到底动了哪两路、没动哪一路，顺带把 §1 的改名接在同一条判断上。
        acts: list[str] = []
        sent: list[dict] = []

        class _SplitZeroconf:
            def register_service(self, info):  # noqa: ANN001 - zeroconf's own shape
                acts.append(f"注册 {info.port}")

            def unregister_service(self, info):  # noqa: ANN001
                acts.append(f"撤掉 {getattr(info, 'port', '?')}")

            def close(self) -> None:
                pass

        class _SplitServiceInfo:
            def __init__(self, *args, **kwargs) -> None:  # noqa: ANN003 - the stub keeps what it is handed
                self.port = kwargs.get("port")
                self.props = kwargs.get("properties") or {}

        class _SplitBrowser:
            def __init__(self, zc, service_type, listener) -> None:  # noqa: ANN001
                acts.append("浏览起来")

            def cancel(self) -> None:
                acts.append("浏览被关")

        class _CapturingBeacon:
            def sendto(self, data, addr):  # noqa: ANN001 - socket.sendto's own shape
                sent.append(json.loads(data.decode("utf-8")))

            def close(self) -> None:
                # stop() closes the socket it is handed, so the ledger needs the same goodbye.
                pass

        split = types.ModuleType("zeroconf")
        split.Zeroconf = _SplitZeroconf
        split.ServiceInfo = _SplitServiceInfo
        split.ServiceBrowser = _SplitBrowser
        real_zeroconf = sys.modules.get("zeroconf")
        sys.modules["zeroconf"] = split
        try:
            quiet = DiscoveryService(a_id, "PC-只听不播", None)
            quiet._start_mdns()
            quiet._udp_socket = _CapturingBeacon()
            quiet.announce()
            check("§2 没在监听的一端：浏览与收包都留着，公告一条也不发",
                  acts == ["浏览起来"] and sent == [] and quiet._browser is not None, (acts, sent))
            acts.clear()
            quiet.set_port(a_svc.port)
            quiet.announce()
            check("§2 报上端口之后公告与注册一起跟回来，说的就是这一个号",
                  acts == [f"注册 {a_svc.port}"] and len(sent) == 1 and sent[0]["port"] == a_svc.port,
                  (acts, sent))
            acts.clear()
            sent.clear()
            quiet.set_port(b_svc.port)
            check("§2 端口换了是撤了旧的再注册新的（第三十七轮那条规矩在 PC 这一端的同一形）",
                  acts == [f"撤掉 {a_svc.port}", f"注册 {b_svc.port}"], acts)
            acts.clear()
            sent.clear()
            quiet.set_port(None)
            quiet.announce()
            check("§2 关掉监听只撤播的那两路：记录下来了、浏览没人关",
                  acts == [f"撤掉 {b_svc.port}"] and sent == [] and quiet._browser is not None, acts)
            acts.clear()
            sent.clear()
            quiet.set_device_name("改名那台-PC")
            quiet.announce()
            check("§1 改名时这台没在监听：记录不该被注册回来，公告也照旧一条不发",
                  acts == [] and sent == [], (acts, sent))
            acts.clear()
            quiet.set_port(a_svc.port)
            quiet.announce()
            check("§1 之后再开监听，注册与公告带的是同一个新名字，不是构造时那一个",
                  acts == [f"注册 {a_svc.port}"] and bool(sent) and sent[0]["name"] == "改名那台-PC"
                  and quiet._service_info is not None
                  and quiet._service_info.props.get("name") == "改名那台-PC",
                  (acts, sent[0]["name"] if sent else None,
                   dict(quiet._service_info.props) if quiet._service_info else None))
            acts.clear()
            quiet.set_device_name("又改名那台-PC")
            check("§1 开着监听再改名，是撤了旧的再注册新的",
                  acts == [f"撤掉 {a_svc.port}", f"注册 {a_svc.port}"]
                  and quiet._service_info is not None
                  and quiet._service_info.props.get("name") == "又改名那台-PC",
                  (acts, dict(quiet._service_info.props) if quiet._service_info else None))
            acts.clear()
            quiet.stop()
            check("§2 关掉窗口才是把听也关掉的唯一一刻：浏览被取消、记录也撤了",
                  "浏览被关" in acts and any(line.startswith("撤掉") for line in acts), acts)
        finally:
            if real_zeroconf is None:
                sys.modules.pop("zeroconf", None)
            else:
                sys.modules["zeroconf"] = real_zeroconf
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
        out = PeerConnection(phone, "Phone-Simulator", "127.0.0.1", pc_service.port, pc.served_fingerprint)
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
        back = PeerConnection(pc, "PC-Waiting", "127.0.0.1", phone_service.port, phone.served_fingerprint)
        back.hello()
        again = back.pair()
        check("a peer once dialled re-pairs by signature alone", again["resumed"] is True, again["resumed"])
        filled = (phone.trusted_entry(pc.fingerprint) or {}).get("public_key", "")
        check("its key is filled in on the way in", filled != "", filled[:12])
    finally:
        phone_service.stop()


#: The twelve DER bytes in front of an Ed25519 key inside a SubjectPublicKeyInfo - spelled array-by-array in
#: app-android/CsIdentity.kt, app-harmony/index.uts and web/index.uts, because no phone platform hands a bare
#: Ed25519 key to a DER encoder. The digest every peer pins is taken over these twelve plus the 32 key bytes.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def phase_identity_shapes(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§1's identity shapes, taken from a device's own files rather than from a peer's answer.

    The paragraph the round rewrote said the fingerprint is the digest of an identity *certificate*. It never
    was on the wire: pair carries 32 bare bytes (`send.py`'s `public_key`), and a phone digests the SPKI it
    builds itself, with no certificate anywhere in its private directory (#106). These legs are what the
    rewording now stands on - that the number every peer pins is reconstructible from the bytes that travel,
    that `peer_id` is the sixteen random bytes §1 promises, and that a device's two digests are two numbers.
    """
    ident = load_or_create(workspace / "shapes")
    check("§1 peer_id is 16 random bytes, written as hex",
          re.fullmatch(r"[0-9a-f]{32}", ident.peer_id) is not None, ident.peer_id)
    wire = ident.raw_public_key()
    check("§1 the pair request carries a bare 32-byte key, not a certificate", len(wire) == 32, len(wire))
    rebuilt = hashlib.sha256(ED25519_SPKI_PREFIX + wire).hexdigest()
    check("§1 fingerprint is the SPKI digest a peer rebuilds from those 32 bytes",
          rebuilt == ident.fingerprint == fingerprint_of_public_key(ed25519.Ed25519PublicKey.from_public_bytes(wire)),
          rebuilt[:12])
    served = ident.served_fingerprint
    leaf = x509.load_pem_x509_certificate((workspace / "shapes" / "tls-leaf.pem").read_bytes())
    check("§1 the leaf a socket serves is RSA-2048, so it cannot be the identity key",
          isinstance(leaf.public_key(), rsa.RSAPublicKey) and leaf.public_key().key_size == 2048)
    check("§1 the two digests of one device are two numbers",
          served != ident.fingerprint and re.fullmatch(r"[0-9a-f]{64}", served) is not None,
          f"{ident.fingerprint[:8]} / {served[:8]}")


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
    # That spot-check covered two of eleven cells. The number is the half the *peer* reads - the words stay
    # home, the status goes on the wire, and §7 quotes one of them in prose (400 for a version it cannot
    # talk to) - so every cell is compared now, not two of them.
    wrong_http = [c for c, entry in proto.error_codes.items() if proto.http_status(c) != int(entry["http"])]
    check("every code answers with the contract's http status", not wrong_http, wrong_http)


def phase_finalize_replay(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """The keep-alive trap has a sender half, and it lands on `finalize`.

    §4 says 「发送方看到连接被关要重连重发一次」. The PC transport does exactly that - `_once` tries
    twice - so a verify question whose reply could not be read is re-posted, and measured here the
    re-post comes back with the same bytes (.probe/r18_before_probe.py, 2026-10-29). What that resend
    used to do at the other end is the half that was missing: every re-post re-ran the arrival
    announcement, so one file put two rows in 收到的文件 and the person was told about the same bytes
    twice. The phone's shared kernel guarded by landing path (`hasArrival`); the PC had none. Both
    halves are pinned here: the second pass brings the answer, and it announces nothing a second time.
    """
    corpus = workspace / "replay-corpus"
    (corpus / "相册").mkdir(parents=True, exist_ok=True)
    good = corpus / "好的一份.txt"
    good.write_bytes(b"a verified file\n")
    big = corpus / "相册" / "两块.bin"
    big.write_bytes(blob(17, proto.chunk_size + 7))
    sender = load_or_create(workspace / "replay-sender")
    receiver = load_or_create(workspace / "replay-receiver")
    root = workspace / "replay-received"
    arrivals: list[list[dict]] = []
    late: list[list[dict]] = []
    restarted: ReceiveService | None = None
    service = ReceiveService(receiver, "PC-Replay", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=root,
                             on_received=lambda who, landed: arrivals.append(list(landed)))
    service.start()
    try:
        files = plan([good, big], base=corpus)
        big_file = next(f for f in files if f.relpath.endswith("两块.bin"))
        good_rel = next(f.relpath for f in files if f.relpath.endswith("好的一份.txt"))
        good_tail = good_rel.rsplit("/", 1)[-1]
        by_id = {f.id: f for f in files}

        def dial(name: str) -> PeerConnection:
            conn = PeerConnection(sender, name, "127.0.0.1", service.port, receiver.served_fingerprint)
            conn.hello()
            conn.pair(service.current_pair_code())
            return conn

        def verdict(v: dict) -> list[str]:
            return sorted(by_id[str(e["id"])].relpath for e in v["verified"] if e["ok"])

        def rows() -> list[str]:
            return [str(item["path"]) for batch in arrivals for item in batch]

        def tail(path_str: str) -> str:
            return path_str.replace("\\", "/").rsplit("/", 1)[-1]

        conn = dial("PC-Replay-Sender")
        snapshots: list[bytes] = []
        real_once = conn._once

        def spy(method, path, body, headers, pace_ms=0):
            status, payload, raw = real_once(method, path, body, headers, pace_ms)
            if method == "POST" and path.endswith("/finalize"):
                snapshots.append(raw)
            return status, payload, raw

        conn._once = spy
        conn.offer(files)
        conn.push_missing(files, conn.state(), None, 3)
        landing = root / conn.offer_id
        # The disk says otherwise: the same length, the wrong bytes. Nothing is missing, so only a
        # digest can refuse this one - and that refusal is what §4's resend arrives on.
        bad = landing / big_file.relpath
        bad.write_bytes(b"X" * bad.stat().st_size)
        first = conn.finalize()
        check("磁盘与台账对不上时，这一份被拒且缺块当场点名",
              verdict(first) == [good_rel]
              and [e["missing"] for e in first["verified"] if not e["ok"]] == [[0, 1]],
              first["verified"])
        again = conn.finalize()
        check("重投的那一问不再把同一个文件报第二遍",
              verdict(again) == verdict(first) and len(rows()) == 1 and tail(rows()[0]) == good_tail,
              [verdict(again), rows()])
        conn.push_missing(files, conn.state(), None, 3)
        settled = conn.finalize()
        check("补好之后这一单全过，每一份字节只在收到的文件里出现一次",
              len(verdict(settled)) == 2 and sorted(map(tail, rows())) == sorted([good_tail, "两块.bin"]),
              [verdict(settled), rows()])

        # The re-post is not merely harmless - it is the answer the sender needs, so it has to stay an
        # answer. By now the resume ledger has handed itself back; the offer itself has not gone away.
        check("整单校验通过后，续传台账自己让位", (landing / STATE_FILE).is_file() is False,
              str(landing / STATE_FILE))
        after = conn.finalize()
        check("台账没了，重投的这一问仍答得出而不是「没这单」", verdict(after) == verdict(settled),
              after["verified"])
        check("重投 finalize 的应答逐字节相同",
              len(snapshots) >= 2 and snapshots[-1] == snapshots[-2], len(snapshots))
        kept = conn.state()
        check("state 也还认这一单", kept.get("offer_id") == conn.offer_id
              and all(not e["missing"] for e in kept["files"]), kept)

        # Keyed by destination, not by name: a second batch with the same relpaths lands somewhere else,
        # and to the person reading the list those are different bytes.
        second = dial("PC-Replay-Second")
        second.offer(files)
        second.send(files, None)
        check("另一单的同名文件是新的一行，不是重复", len(set(rows())) == 4 and len(rows()) == 4, rows())

        # And the sender half itself: the first connection dies mid-request, the second carries the
        # answer - then stops trying. A peer that answers nothing is a failure after one resend, not
        # after a hundred.
        real_connect = conn._connect
        boomed = [0]

        def flaky(always: bool):
            def arm():
                out = real_connect()
                if always or boomed[0] == 0:
                    def boom(*args, **kwargs):
                        boomed[0] += 1
                        raise ConnectionResetError("对面把这根连接关了")
                    out.request = boom  # type: ignore[method-assign]
                return out
            return arm

        conn._connect = flaky(False)
        try:
            rescued = conn.finalize()
        finally:
            conn._connect = real_connect
        check("第一趟连接被关掉，第二趟把答案带回来",
              verdict(rescued) == verdict(settled) and boomed[0] == 1, boomed[0])
        check("重发那一趟不再多报一次收到的文件", len(rows()) == 4, rows())

        boomed[0] = 0
        conn._connect = flaky(True)
        try:
            conn.finalize()
            check("没人接的电话重发一次就收口", False, "finalize returned")
        except (ConnectionResetError, OSError) as exc:
            check("没人接的电话重发一次就收口", boomed[0] == 2, [boomed[0], type(exc).__name__])
        finally:
            conn._connect = real_connect

        # The boundary the guard must not cross: the offer being *gone* is the one case where a
        # re-posted verify has no answer to give.
        conn.abort()
        expect_error("收回这单之后重投，才轮到「没这单」", "OFFER_UNKNOWN", conn.finalize)

        # Round nineteen (#185): the announce-once gate is only worth anything if it outlives the
        # process, because the ledger it guards does. One file verified and announced, the receiver
        # restarts over the same root and finishes the other half - the first file's news stays told.
        third = dial("PC-Replay-Third")
        third.offer(files)
        whole = sum(third._chunk_count(f) for f in files)
        for item in files:
            if not item.relpath.endswith("好的一份.txt"):
                continue
            for index in range(third._chunk_count(item)):
                third._put_chunk(item, index, whole, None, 3)
        partial = third.finalize()
        check("一单里先齐的那一份报了一次，欠着的那一份把台账留在磁盘上",
              verdict(partial) == [good_rel] and len(partial["verified"]) == 2
              and (root / third.offer_id / STATE_FILE).is_file(), verdict(partial))
        ledger = json.loads((root / third.offer_id / STATE_FILE).read_text(encoding="utf-8"))
        # The landing paths the receiver hands out are resolved ones (§5 does the containment check on
        # that form), so the prefix this leg compares against has to be resolved too.
        here = str((root / third.offer_id).resolve())
        announced_here = [str(e["path"]) for batch in arrivals for e in batch
                          if str(e["path"]).startswith(here)]
        check("已经报过的那一笔写在续传台账里，而不是只写在这一场内存里",
              ledger.get("announced") == announced_here and len(announced_here) == 1,
              [ledger.get("announced"), announced_here])

        port = service.port
        service.stop()
        restarted = ReceiveService(receiver, "PC-Replay", lambda manifest, who, caller: True,
                                   host="127.0.0.1", port=port, root=root,
                                   on_received=lambda who, landed: late.append(list(landed)))
        restarted.start()
        adopted = restarted.adopt_interrupted_offers()
        check("重开以后这一单被认领，而不是当成没这单", adopted == 1, adopted)
        resumed = PeerConnection(sender, "PC-Replay-Resumed", "127.0.0.1", port, receiver.served_fingerprint)
        resumed.offer_id = third.offer_id
        resumed.hello()
        resumed.pair(restarted.current_pair_code())
        resumed.push_missing(files, resumed.state(), None, 3)
        done = resumed.finalize()
        check("接收方重启之后，第一份字节不再报第二遍",
              len(verdict(done)) == 2 and len(late) == 1
              and tail(str(late[0][0]["path"])) == "两块.bin",
              [late, verdict(done)])
        check("重启前后摊开一共两行，各自一份字节",
              len({*announced_here, *[str(e["path"]) for batch in late for e in batch]}) == 2,
              [announced_here, late])
    finally:
        service.stop()
        if restarted is not None:
            restarted.stop()


def phase_pair_throttle(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3's throttle: which five failures, sixty seconds measured from which moment, and what a 来源 is.

    Round twenty-three (#189) read 「同一来源 5 次失败锁 60s」 - a sentence that fits a sliding window and a
    fixed one equally well, which is the problem, because the two answer differently at second 59. Both
    ends build the sliding one: the door opens `pair_code_lock_s` after the *oldest* of the five failures,
    and an attempt refused while the door is shut records nothing, so hammering cannot push the lock out.
    Neither number was in the contract, no gate held either shape, and the list lives in memory on all four
    ends. These legs go through ``handle_pair`` directly instead of a socket because the sentence keys on
    the *source address* and a localhost socket only ever has one of those.
    """
    receiver = load_or_create(workspace / "throttle-receiver")
    service = ReceiveService(receiver, "PC-Throttle", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=workspace / "throttle-received")
    service.start()
    code, secret = service.current_pair_code(), service.passphrase()
    wrong_code = ("1" if code[0] != "1" else "2") + code[1:]

    def attempt(ip: str, ident, code_ok: bool = False, secret_ok=None) -> dict:
        """A well-formed, correctly signed pair body whose *answer* is what this leg is about.

        The signature always verifies: a refusal that came from the throttle has to be distinguishable
        from one that came from a body the receiver could not read at all.
        """
        nonce = secrets.token_hex(16)
        leaf = ident.declared_tls_fingerprint
        message = protocol_spec.pair_message(ident.peer_id, nonce, leaf)
        body = {
            "peer_id": ident.peer_id,
            "name": "Stranger-" + ip,
            "protocol_version": proto.version,
            "compatible_versions": list(proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(ident.raw_public_key()).decode(),
            "signature": base64.b64encode(ident.key.sign(message)).decode(),
            "code": code if code_ok else wrong_code,
        }
        if secret_ok is not None:
            body["secret"] = secret if secret_ok else "!" * proto.passphrase_chars
        if leaf:
            body["tls_fingerprint"] = leaf
        return body

    def refused(ip: str, ident, into=None, **keys) -> tuple[str, dict]:
        """The answer ``handle_pair`` gives, or ``("PAIRED", reply)`` when it gives a token."""
        try:
            return ("PAIRED", (into or service).handle_pair(attempt(ip, ident, **keys), ip))
        except protocol_spec.ProtocolError as error:
            return (error.code, error.detail or {})

    def release() -> None:
        # §3's other rule - one peer at a time - is checked elsewhere; here it would only shadow the
        # throttle, because the busy answer comes first. The slot is handed back after each success.
        service._tokens.clear()
        service._seen.clear()
        service._held_by = ""

    guesser, mixed, slid, other, single, rebooted = (
        load_or_create(workspace / f"throttle-{n}")
        for n in ("guesser", "mixed", "slid", "other", "single", "rebooted"))
    try:
        # Four guesses are four wrong codes, not a lock: the count has not been reached yet, so every
        # one of them has to answer with the mistake the sender can actually do something about.
        first_four = [refused("10.0.0.11", guesser)[0] for _ in range(proto.pair_code_max_fails - 1)]
        check("§3 攒够之前的每一次猜错都答 BAD_PAIR_CODE",
              first_four == ["BAD_PAIR_CODE"] * (proto.pair_code_max_fails - 1), first_four)
        check("§3 名额是合同里那个数：差一次的时候门还开着",
              len(service._code_failures["10.0.0.11"]) == proto.pair_code_max_fails - 1,
              service._code_failures["10.0.0.11"])

        # The fifth wrong guess is still answered on its merits: the door shuts once five records are in
        # the bucket, and this is the attempt that puts the fifth there.
        code_5 = refused("10.0.0.11", guesser)[0]
        filled = len(service._code_failures["10.0.0.11"])
        check("§3 第五次猜错照样答 BAD_PAIR_CODE：门是这一趟之后才关上的",
              code_5 == "BAD_PAIR_CODE" and filled == proto.pair_code_max_fails, f"{code_5} {filled}")

        # The sixth is the one that would have got in - right code, right passphrase - and it is
        # refused anyway. That is the only way to tell a throttle from a wrong guess by its answer.
        code_, detail = refused("10.0.0.11", guesser, code_ok=True, secret_ok=True)
        check("§3 攒够 5 次以后连猜对也拒，说的是「too many failed codes」",
              code_ == "PEER_BUSY" and detail.get("reason") == "too many failed codes", f"{code_} {detail}")

        # Three more, all of them correct, all of them refused. If any of those recorded itself the
        # window would slide forward on a guess that learned nothing - the lock would never open.
        for _ in range(3):
            refused("10.0.0.11", guesser, code_ok=True, secret_ok=True)
        check("§3 被锁住期间的尝试不往清单里添记录：砸得再多也不会把这道锁推远",
              len(service._code_failures["10.0.0.11"]) == proto.pair_code_max_fails,
              service._code_failures["10.0.0.11"])

        # A wrong passphrase is the same mistake as a wrong code (spec §3 says so out loud), and this
        # leg shows they share a bucket: three wrong codes and two wrong passphrases, and the door is
        # already shut for the attempt that gets both right.
        release()
        for bad in ((False, None), (True, False), (False, None), (True, False), (False, None)):
            refused("10.0.0.12", mixed, code_ok=bad[0], secret_ok=bad[1])
        code_, detail = refused("10.0.0.12", mixed, code_ok=True, secret_ok=True)
        check("§3 密码猜错和配对码猜错记在同一桶里",
              code_ == "PEER_BUSY" and detail.get("reason") == "too many failed codes",
              f"{code_} {detail} {len(service._code_failures.get('10.0.0.12', []))}")

        # The window slides per failure, so the release belongs to the oldest one. Rewinding only
        # that record opens the door - and the bucket that filled a moment ago stays shut.
        for _ in range(proto.pair_code_max_fails):
            refused("10.0.0.13", slid)
        service._code_failures["10.0.0.13"][0] -= proto.pair_code_lock_s + 1
        opened = refused("10.0.0.13", slid, code_ok=True, secret_ok=True)
        check("§3 60 秒从最早那一次失败起算：那一条一满，门就开了",
              opened[0] == "PAIRED" and isinstance(opened[1].get("token"), str), opened)
        release()
        code_, detail = refused("10.0.0.11", guesser, code_ok=True, secret_ok=True)
        check("§3 同一时刻另一路还锁着：这道锁量的是各来源自己那五次",
              code_ == "PEER_BUSY" and detail.get("reason") == "too many failed codes", f"{code_} {detail}")

        # And 「来源」 means what it says: a bucket nobody filled is still answering on its own mistakes
        # while the first one is locked. Both phones fold an unreadable address into one shared '?'
        # bucket for the same reason (app-android/CsServe.kt, app-harmony/index.uts) - a per-connection
        # number would hand a guesser a clean allowance on every retry, and a global one would let
        # anybody lock out the whole LAN.
        release()
        code_16 = refused("10.0.0.16", single)[0]
        opened14 = refused("10.0.0.14", other, code_ok=True, secret_ok=True)
        check("§3 「来源」按地址分桶：那一路锁着，这一路只错了一次、答的仍是配对码不对，而且照样进",
              code_16 == "BAD_PAIR_CODE" and len(service._code_failures["10.0.0.16"]) == 1
              and opened14[0] == "PAIRED" and isinstance(opened14[1].get("token"), str),
              f"{code_16} {opened14[0]} {sorted(service._code_failures)}")
        release()

        # Nothing about this list is written to disk. A restart is a fresh allowance on every end -
        # which is a real property of a LAN receiver, not an oversight to be fixed by a stranger.
        for _ in range(proto.pair_code_max_fails):
            refused("10.0.0.15", rebooted)
        again = ReceiveService(receiver, "PC-Throttle-Restarted", lambda manifest, who, caller: True,
                               host="127.0.0.1", port=0, root=workspace / "throttle-received")
        again.start()
        try:
            answered = refused("10.0.0.15", rebooted, into=again, code_ok=True, secret_ok=True)
            old_records = len(service._code_failures.get("10.0.0.15", []))
            fresh_records = sum(len(v) for v in again._code_failures.values())
            check("§3 这份失败清单哪一端都不落盘：重启接收方以后那道锁是空的",
                  answered[0] == "PAIRED" and isinstance(answered[1].get("token"), str)
                  and old_records == proto.pair_code_max_fails and fresh_records == 0,
                  f"旧进程里那一路记了 {old_records} 条，新进程一条都没有：{answered[0]}")
        finally:
            again.stop()
    finally:
        service.stop()


def phase_random_source(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3's three secrets: whose hand minted each one, and what that hand is allowed to hand back.

    Round twenty-four (#190) read 「返回随机会话 `token`（32 字节）」 and 「`k` 是 32 字母表 8 位」. Both said
    随机 and stopped, and the four ends filled the gap differently: the PC has always gone through
    ``secrets`` (``app/net/identity.py:51``, ``:56``, ``app/net/receive.py:626``) while the phone kernel rolled
    ``Math.random()`` - a generator whose state a peer that saw a few outputs could work out, which is exactly
    what a bearer token is for. The paper now names the source, so the legs below are about *that* promise:
    swap the generator for a scripted hand and every one of the three secrets has to follow it, because a
    credential that does not change with the source is one the body minted somewhere else.

    The patch is on the module attribute - ``identity_mod.secrets`` - not on the stdlib ``secrets`` module, so
    the other phases, and the nonces minted inside this one, keep their real generator either way.
    """
    class Stub:
        """A hand instead of a generator: it answers whatever the leg needs and counts being asked."""

        def __init__(self, char: str, token: str = "") -> None:
            self.char = char
            self.token = token
            self.choice_calls = 0
            self.hex_sizes: list[int] = []

        def choice(self, seq):
            self.choice_calls += 1
            return self.char

        def token_hex(self, n):
            self.hex_sizes.append(n)
            return self.token

    real_secrets = identity_mod.secrets
    stubbed = Stub("7")
    identity_mod.secrets = stubbed
    try:
        fake_code = identity_mod.new_pair_code(proto.pair_code_digits)
        fake_phrase = identity_mod.new_passphrase(proto.passphrase_chars)
    finally:
        identity_mod.secrets = real_secrets
    check("§3 码与密码没有第二只手：源换成假的那一只手给什么就是什么",
          fake_code == "7" * proto.pair_code_digits
          and fake_phrase == "7" * proto.passphrase_chars,
          f"{fake_code} {fake_phrase}")
    check("§3 每一位各问一次：6 位码问 6 次、8 位密码问 8 次，没有谁多要也没有谁少要",
          stubbed.choice_calls == proto.pair_code_digits + proto.passphrase_chars,
          stubbed.choice_calls)

    receiver = load_or_create(workspace / "random-receiver")
    service = ReceiveService(receiver, "PC-Random", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=workspace / "random-received")
    service.start()
    stranger = load_or_create(workspace / "random-stranger")

    def pair_body() -> dict:
        nonce = secrets.token_hex(16)
        leaf = stranger.declared_tls_fingerprint
        message = protocol_spec.pair_message(stranger.peer_id, nonce, leaf)
        body = {
            "peer_id": stranger.peer_id,
            "name": "Random-Stranger",
            "protocol_version": proto.version,
            "compatible_versions": list(proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(stranger.raw_public_key()).decode(),
            "signature": base64.b64encode(stranger.key.sign(message)).decode(),
            "code": service.current_pair_code(),
            "secret": service.passphrase(),
        }
        if leaf:
            body["tls_fingerprint"] = leaf
        return body

    def release() -> None:
        # §3's one-peer-at-a-time would shadow the second pair of these legs; the throttle would too.
        service._tokens.clear()
        service._seen.clear()
        service._held_by = ""

    fake_token = "ab" * 32
    token_stub = Stub("7", fake_token)
    real_receive_secrets = receive_mod.secrets
    receive_mod.secrets = token_stub
    try:
        minted = service.handle_pair(pair_body(), "10.0.0.31")
    finally:
        receive_mod.secrets = real_receive_secrets
    check("§3 token 就是那 32 个字节：问的是 32，答上线的也是那一只手的原话，中间没人重铸",
          minted.get("token") == fake_token and token_stub.hex_sizes == [32],
          f"{minted.get('token')} {token_stub.hex_sizes}")

    release()
    first = service.handle_pair(pair_body(), "10.0.0.32").get("token", "")
    release()
    second = service.handle_pair(pair_body(), "10.0.0.33").get("token", "")
    check("§3 不动源的时候形状不动：token 是 32 字节的十六进制，两次配对不是同一个",
          re.fullmatch(r"[0-9a-f]{64}", first) is not None
          and re.fullmatch(r"[0-9a-f]{64}", second) is not None and first != second,
          f"{len(first)} {len(second)} {first == second}")

    live_code = identity_mod.new_pair_code(proto.pair_code_digits)
    live_phrase = identity_mod.new_passphrase(proto.passphrase_chars)
    check("§3 配对码只有数字、密码只有那 32 个字母：字母表与长度照纸上那两句",
          set(live_code) <= set("0123456789") and len(live_code) == proto.pair_code_digits
          and set(live_phrase) <= set(identity_mod.PASSPHRASE_ALPHABET)
          and len(live_phrase) == proto.passphrase_chars,
          f"{live_code} {live_phrase}")
    check("§3 每一台铸的码不一样：那不是一个数被抄了两次",
          identity_mod.new_pair_code(proto.pair_code_digits) !=
          identity_mod.new_pair_code(proto.pair_code_digits),
          live_code)

    # The last leg closes the loop the first two only half proved: a minted secret is not just *shaped*
    # like the source's output, it is the value the door then accepts - so there is no third hand between
    # the generator and the comparison.
    minter = load_or_create(workspace / "random-mints")
    code_stub = Stub("4")
    identity_mod.secrets = code_stub
    try:
        minter.rotate_pairing(proto.pair_code_digits, proto.passphrase_chars)
    finally:
        identity_mod.secrets = real_secrets
    armed = ReceiveService(minter, "PC-Random-Mints", lambda manifest, who, caller: True,
                           host="127.0.0.1", port=0, root=workspace / "random-minted")
    armed.start()
    try:
        door_code, door_phrase = armed.current_pair_code(), armed.passphrase()
        body = pair_body()
        body["code"], body["secret"] = door_code, door_phrase
        nonce = secrets.token_hex(16)
        leaf = stranger.declared_tls_fingerprint
        body["nonce"] = nonce
        body["signature"] = base64.b64encode(
            stranger.key.sign(protocol_spec.pair_message(stranger.peer_id, nonce, leaf))).decode()
        accepted = armed.handle_pair(body, "10.0.0.34")
        check("§3 那一只手铸的码，就是这道门认的码：门与铸密共用一只手，没有第二份",
              door_code == "4" * proto.pair_code_digits
              and door_phrase == "4" * proto.passphrase_chars
              and isinstance(accepted.get("token"), str) and len(accepted.get("token", "")) == 64,
              f"{door_code} {door_phrase} {accepted.get('token', '')[:8]}")
    finally:
        armed.stop()
        service.stop()


def phase_pair_scope(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3 pairs whoever knocks: the socket listens on every interface and the source's range is not a door.

    Round twenty-five (#191) read 「这份失败清单哪一端都不落盘，且只在局域网内可达时开放」. The second half
    read as a security boundary and no end implemented one: the three listeners bind the wildcard and the
    pair handlers keep the source address only as a bucket key for the throttle. This phase measures the two
    halves that are still machine-checkable here - which address the default-constructed receiver actually
    bound, and whether a source that is certainly *not* a LAN peer still gets a token. The second leg is the
    one that turns red the day someone writes the sentence the paper just deleted: ``handle_pair`` takes the
    address as a plain string, so a TEST-NET peer, a loopback dial-in and ``10.0.2.2`` (what the emulator's
    forwarded port reports, #149/#154) are three sources a filter would refuse.
    """
    receiver = load_or_create(workspace / "scope-receiver")
    stranger = load_or_create(workspace / "scope-stranger")
    service = ReceiveService(receiver, "PC-Pair-Scope", lambda manifest, who, caller: True,
                             port=0, root=workspace / "scope-received")
    service.start()
    code, secret = service.current_pair_code(), service.passphrase()

    def pair(ip: str, who=None, code_ok: bool = True) -> tuple[str, str]:
        """("PAIRED", token) when the receiver answers with one, else the error code it raised."""
        who = who or stranger
        nonce = secrets.token_hex(16)
        leaf = who.declared_tls_fingerprint
        message = protocol_spec.pair_message(who.peer_id, nonce, leaf)
        body = {
            "peer_id": who.peer_id,
            "name": "Scope-Peer",
            "protocol_version": proto.version,
            "compatible_versions": list(proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(who.raw_public_key()).decode(),
            "signature": base64.b64encode(who.key.sign(message)).decode(),
            "code": code if code_ok else ("1" if code[0] != "1" else "2") + code[1:],
            "secret": secret,
        }
        if leaf:
            body["tls_fingerprint"] = leaf
        try:
            return ("PAIRED", service.handle_pair(body, ip).get("token", ""))
        except protocol_spec.ProtocolError as error:
            return (error.code, str(error.detail or {}))

    # Nothing named a host in the constructor - the way the GUI and the CLI both start it - so whatever the
    # socket reports back is the interface this machine actually listens on.
    bound = service._http.server_address[0]
    check("§3 三端的接收服务都绑在本机所有接口上：默认参数起的那台落在 0.0.0.0",
          bound == "0.0.0.0", bound)

    # One peer at a time is §3's other rule and it would shadow every leg below, so the slot is handed back
    # between the three sources - this phase is about which address may knock, not how many may sit.
    def release() -> None:
        service._tokens.clear()
        service._seen.clear()
        service._held_by = ""

    # Each source gets its own identity: a peer the receiver has already pinned would answer from the
    # signature alone (``handle_pair``'s known-key branch), and that would prove nothing about the code
    # round trip these legs are about.
    outsider, loopback_peer, forwarded_peer, guesser = (
        load_or_create(workspace / f"scope-{n}")
        for n in ("outsider", "loopback", "forwarded", "guesser"))
    outside = pair("203.0.113.7", outsider)
    release()
    looped = pair("127.0.0.1", loopback_peer)
    release()
    forwarded = pair("10.0.2.2", forwarded_peer)
    check("§3 「来源」不是一道网段的门：TEST-NET 那个地址第一次配对就拿到 32 字节的 token",
          outside[0] == "PAIRED" and re.fullmatch(r"[0-9a-f]{64}", outside[1]) is not None, outside)
    check("§3 环回与端口转发那两路也照样配对：#149/#154 那几条腿走的正是这两种来源",
          looped[0] == "PAIRED" and forwarded[0] == "PAIRED"
          and re.fullmatch(r"[0-9a-f]{64}", looped[1]) is not None
          and re.fullmatch(r"[0-9a-f]{64}", forwarded[1]) is not None,
          f"{looped[0]} {forwarded[0]}")

    # A wrong code from an out-of-range source still gets the answer a wrong code gets: an address the paper
    # once called unreachable is not a different *kind* of request, and its mistake is booked into the bucket
    # that address owns - which is all 「来源」 has ever meant in §3.
    release()
    guess = pair("203.0.113.8", guesser, code_ok=False)
    check("§3 网段外的来源第一次配对猜错码，答的是「配对码不对」并记进它自己那一桶：地址是桶键不是门",
          guess[0] == "BAD_PAIR_CODE" and len(service._code_failures.get("203.0.113.8", [])) == 1,
          f"{guess[0]} {sorted(service._code_failures)}")
    service.stop()


def phase_optional_secret(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3's two optional pair keys are read off their value, so null is absence and "" is a wrong guess.

    Round twenty-six (#192) asked 「没有它」 - what does a receiver treat as a missing optional field - and the
    two bodies that answer it answered differently for the same bytes. PC read the passphrase by *key presence*
    (`"secret" in body`) while the shared kernel reads it by value (`body.get('secret') != null`), so a sender
    that serialises its optional field as JSON null paired on the code alone on a phone and got
    `BAD_PAIR_CODE {reason: "passphrase"}` plus one of its five tries burnt on the PC (`.probe/r26_before.txt`).
    The PC is now on the kernel's reading; these legs hold the rule in both directions, because the other half -
    an empty string is *not* absence - is what stops a blank passphrase box from quietly downgrading a pair to
    the 6-digit code. The leaf legs are the same question one line earlier in the same handler, and there the
    two ends already agreed: the paper had the wrong words for it.
    """
    receiver = load_or_create(workspace / "optsec-receiver")
    service = ReceiveService(receiver, "PC-Optional-Secret", lambda manifest, who, caller: True,
                             port=0, root=workspace / "optsec-received")
    service.start()
    code, secret = service.current_pair_code(), service.passphrase()

    def release() -> None:
        service._tokens.clear()
        service._seen.clear()
        service._held_by = ""

    def pair(source: str, secret_slot, leaf_slot, *, use_code: str | None = None,
             who=None) -> tuple[str, str, int]:
        """Send one pair body whose optional slots are set exactly as a foreign sender might write them.

        ``secret_slot``/``leaf_slot`` of ``_ABSENT`` leave the key off; ``None`` puts a JSON null on the wire.
        Returns (code, detail, tries spent in this source's bucket) - the bucket is half the measurement,
        because spending a try is the harm the old reading did.
        """
        who = who or load_or_create(workspace / f"optsec-{source}")
        nonce = secrets.token_hex(16)
        if leaf_slot is _SELF:
            signed = who.declared_tls_fingerprint
        elif leaf_slot is _ABSENT or leaf_slot is None or leaf_slot == "":
            signed = ""
        else:
            signed = str(leaf_slot)
        message = protocol_spec.pair_message(who.peer_id, nonce, signed)
        body = {
            "peer_id": who.peer_id,
            "name": "Opt-Secret-Peer",
            "protocol_version": proto.version,
            "compatible_versions": list(proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(who.raw_public_key()).decode(),
            "signature": base64.b64encode(who.key.sign(message)).decode(),
            "code": code if use_code is None else use_code,
        }
        if leaf_slot is _SELF:
            body["tls_fingerprint"] = signed
        elif leaf_slot is not _ABSENT:
            body["tls_fingerprint"] = leaf_slot
        if secret_slot is not _ABSENT:
            body["secret"] = secret_slot
        try:
            token = service.handle_pair(body, source).get("token", "")
            return ("PAIRED", token[:12], len(service._code_failures.get(source, [])))
        except protocol_spec.ProtocolError as error:
            return (error.code, json.dumps(error.detail, ensure_ascii=False),
                    len(service._code_failures.get(source, [])))

    absent = pair("optsec-absent", _ABSENT, _SELF)
    release()
    null = pair("optsec-null", None, _SELF)
    release()
    blank = pair("optsec-blank", "", _SELF)
    release()
    wrong = pair("optsec-wrong", "ZZZZZZZZ", _SELF)
    release()
    right = pair("optsec-right", secret, _SELF)
    release()
    bad_code = pair("optsec-badcode", secret, _SELF,
                    use_code=("1" if code[0] != "1" else "2") + code[1:])
    release()
    leaf_null = pair("optsec-leaf-null", secret, None)
    release()
    leaf_blank = pair("optsec-leaf-blank", secret, "")

    check("§3 「没有它」读的是这一格的值不是键在不在：密码那一节省略、给 null，两个都只靠码配上",
          absent[0] == "PAIRED" and null[0] == "PAIRED" and null[2] == 0 and absent[2] == 0,
          f"{absent} {null}")
    check("§3 空串不是「没有它」：它是一次错误的猜测，答 passphrase 并烧掉那一格里的一枚名额",
          blank[0] == "BAD_PAIR_CODE" and blank[1] == '{"reason": "passphrase"}' and blank[2] == 1, blank)
    check("§3 密码写错了也是这一句、这一格：与空串同一种答、同样烧一枚（合同只给 secret 那一支点名 reason）",
          wrong[0] == "BAD_PAIR_CODE" and wrong[1] == '{"reason": "passphrase"}' and wrong[2] == 1, wrong)
    check("§3 值对才配得上：同一把钥匙带对的密码拿到 token",
          right[0] == "PAIRED" and re.fullmatch(r"[0-9a-f]{12}", right[1]) is not None, right)
    check("§3 码错的那一支不写 reason：detail 是空的，「passphrase」只在密码那一格错的时候出现",
          bad_code[0] == "BAD_PAIR_CODE" and bad_code[1] == "null", bad_code)
    check("§3 叶指纹那一格同读法：null 与空串都算\"我的叶就是签名的这把钥匙\"，三段前像照样配上",
          leaf_null[0] == "PAIRED" and leaf_blank[0] == "PAIRED", f"{leaf_null} {leaf_blank}")
    service.stop()


def phase_second_layer(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3 那句「码固定之后单次锁流不够看，所以这道承诺加了第二层：`k` 是 32 字母表 8 位」——它绑的是把 `k` 发上线的那一方。

    第三十一轮（#197）。这句话读起来像一道门：线上多了一个 40 bit 的东西，猜中 6 位码的那一位还差一层。
    量下来它不是门——接收器对 `secret` 这一格的读法是「键不在，或者值是 null = 旧构建」（§3 明写的兼容让步，
    §7 又不许改已有字段的语义），所以只带正确码、把这格整个省略的发送方照样拿到 token 且一枚名额都不烧，
    而错值的空串要烧（`.probe/r31_probe.txt`）。于是这一层的强度落在**发送方是否肯把它发上线**：这一端留空，
    线上就没有这一格。这些腿一半量那道门今天真实有几层——省略不是第二条路、码错照样烧一枚、限流数的是来源
    而不是这 10⁶——另一半量发送方自己的形状：`secret` 那一格在留空时是不是真的不在体里，以及这一端有没有在
    上线前把「这一趟只剩 6 位」说出来。
    """
    receiver = load_or_create(workspace / "second-layer-receiver")
    service = ReceiveService(receiver, "PC-Second-Layer", lambda manifest, who, caller: True,
                             host="127.0.0.1", port=0, root=workspace / "second-layer-received")
    service.start()
    code, secret = service.current_pair_code(), service.passphrase()
    wrong_code = ("1" if code[0] != "1" else "2") + code[1:]

    def release() -> None:
        service._tokens.clear()
        service._seen.clear()
        service._held_by = ""

    class _Absent:
        pass

    absent = _Absent()

    def ask(source: str, slot, *, use_code: str | None = None):
        """One pair body whose `secret` slot is left off / nulled / filled, answered by the real receiver."""
        release()
        who = load_or_create(workspace / f"second-layer-{source}")
        nonce = secrets.token_hex(16)
        leaf = who.declared_tls_fingerprint
        message = protocol_spec.pair_message(who.peer_id, nonce, leaf)
        body = {
            "peer_id": who.peer_id,
            "name": f"Second-Layer-{source}",
            "protocol_version": proto.version,
            "compatible_versions": list(proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(who.raw_public_key()).decode(),
            "signature": base64.b64encode(who.key.sign(message)).decode(),
            "code": code if use_code is None else use_code,
            "tls_fingerprint": leaf,
        }
        if slot is not absent:
            body["secret"] = slot
        try:
            reply = service.handle_pair(body, source)
            return ("PAIRED", reply.get("token", "")[:12], reply.get("resumed"),
                    len(service._code_failures.get(source, [])))
        except protocol_spec.ProtocolError as error:
            return (error.code, error.detail, None, len(service._code_failures.get(source, [])))

    # 一、那两句里的两个数：这一层值多少，是这两个数算出来的，不是形容词。
    alphabet, digits = protocol_spec.PASSPHRASE_ALPHABET, protocol_spec.CODE_DIGITS
    check("§3 「`k` 是 32 字母表 8 位」那两个数：字母表真 32 个（去掉 I/O/0/1 后）、位数真取合同那个 8，"
          "而 32^8 正好等于 2^40——纸上这句不许多算",
          len(alphabet) == 32 and "I" not in alphabet and "0" not in alphabet
          and proto.passphrase_chars == 8 and len(alphabet) ** proto.passphrase_chars == 2 ** 40,
          (len(alphabet), proto.passphrase_chars))
    check("§3 「`c` 那 10^6 是线上唯一的凭据」：码那一格的空间由合同的位数算出来，字母表是十进制",
          len(digits) == 10 and proto.pair_code_digits == 6 and len(digits) ** proto.pair_code_digits == 10 ** 6,
          (len(digits), proto.pair_code_digits))

    # 二、省略不另开一条路：码错的那一趟，少了 `secret` 也照烧一枚，答的还是那一句、detail 还是空的。
    bad_omitted = ask("badcode", absent, use_code=wrong_code)
    check("§3 省略不是第二条路：码错 + 不带 `secret` 那一格，答 BAD_PAIR_CODE（不点名 passphrase）并烧一枚名额",
          bad_omitted[0] == "BAD_PAIR_CODE" and bad_omitted[1] is None and bad_omitted[3] == 1, bad_omitted)

    # 三、那道锁的范围：密码猜错攒满的来源，换成「省略」也不再得到一次机会——它数的是这台机器试了几次。
    floods = [ask("flooded", "ZZZZZZZZ") for _ in range(proto.pair_code_max_fails)]
    locked = ask("flooded", absent)
    check("§3 限流不看这一格填没填：同一来源被密码错值攒满以后，带正确的码、省略 `secret` 也被拒",
          floods[-1][3] == proto.pair_code_max_fails and locked[0] == "PEER_BUSY"
          and locked[1] == {"reason": "too many failed codes"}, f"{floods[-1]} {locked}")

    # 四、已经钉住的那一把：这一层连问都不问——签名就是这一支的凭据，错的码也进得来。
    pinned = ask("pinned", absent)
    again_wrong = ask("pinned", absent, use_code=wrong_code)
    check("§3 已固定的钥匙不走这一层：同一把钉住的 key 带**错误的码 + 省略密码**照样拿到 token，且答的是 resumed",
          pinned[0] == "PAIRED" and again_wrong[0] == "PAIRED" and again_wrong[2] is True, f"{pinned} {again_wrong}")

    # 五、发送方那一半才是这一层的落点：留空时这一格真的不在线上，填了才在。
    seen_bodies: list[dict] = []
    honest_pair = service.handle_pair

    def spy_pair(body: dict, client_ip: str) -> dict:
        seen_bodies.append(dict(body))
        return honest_pair(body, client_ip)

    service.handle_pair = spy_pair
    try:
        omitter = load_or_create(workspace / "second-layer-omitter")
        typer = load_or_create(workspace / "second-layer-typer")
        for who, secret_slot in ((omitter, ""), (typer, secret)):
            # One peer at a time (§3) would shadow this measurement, so the slot goes back between the two.
            release()
            conn = PeerConnection(who, "PC-Second-Layer", "127.0.0.1", service.port, receiver.served_fingerprint)
            conn.hello()
            conn.pair(code, secret_slot)
        service.handle_pair = honest_pair
    finally:
        if len(seen_bodies) != 2:
            service.handle_pair = honest_pair
    omitted_body, filled_body = seen_bodies
    check("§3 这一层绑的是发送方：密码框留空时这一整个键不上线（不是空串），填了才带上对的值",
          "secret" not in omitted_body and filled_body.get("secret") == secret,
          (sorted(omitted_body), sorted(filled_body)))

    # 六、降级要在这上线之前说得出声：留空那一趟是本机唯一能把这句话讲出来的地方，填了的那趟它必须闭嘴。
    note = protocol_spec.pass_omitted("", proto)
    check("§3 留空那一趟不是安静的：这一端在上线前说清「只剩屏幕上那 6 位」，句子带着合同的位数",
          note != "" and str(proto.pair_code_digits) in note, note)
    check("§3 填了密码的那一趟这句不开口：它只会在真的少一格时说话",
          protocol_spec.pass_omitted(secret, proto) == "", protocol_spec.pass_omitted(secret, proto))
    service.stop()


def phase_session_release(proto: protocol_spec.Protocol, workspace: Path) -> None:
    """§3's three named ways the one-session slot is given back, measured on the PC's receiver.

    Round twenty-seven (#193) read 「持有方点「断开」、接收服务重启、**或这台设备连续
    session_idle_timeout_s 没有任何带 token 的请求**都会释放这个名额」 as a claim about every end, and the
    phone's own reading is what was missing: its 断开 only ever gave back the half it took by dialling out,
    and 不再监听 closed the port while the inbox - and the token handed to whoever dialled *in* - stayed
    beside it (`.probe/r27_before.txt`). PC has had the whole sentence since #53, so these legs hold the PC
    to the same words the shared kernel now answers, and one of them is a claim the old PC code got wrong on
    its own side: `release()` used to answer "was this peer ever handed a token", which is not the question 断开
    asks about a peer this machine dialled out to - that one occupies the slot through ``_held_by`` alone.
    """
    receiver = load_or_create(workspace / "sesrel-receiver")
    service = ReceiveService(receiver, "PC-Session-Release", lambda manifest, who, caller: True,
                             port=0, root=workspace / "sesrel-received")
    service.start()
    code = service.current_pair_code()

    def pair(ident, *, blank_code: bool = False):
        """A signature that verifies, so every answer below is about the slot and not about the pair code."""
        nonce = secrets.token_hex(16)
        leaf = ident.declared_tls_fingerprint
        message = protocol_spec.pair_message(ident.peer_id, nonce, leaf)
        body = {
            "peer_id": ident.peer_id,
            "name": "Slot-Peer",
            "protocol_version": proto.version,
            "compatible_versions": list(proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(ident.raw_public_key()).decode(),
            "signature": base64.b64encode(ident.key.sign(message)).decode(),
            "code": "" if blank_code else code,
            "tls_fingerprint": leaf,
        }
        try:
            reply = service.handle_pair(body, "10.0.0.70")
            return ("PAIRED", reply.get("token", ""), bool(reply.get("resumed", False)))
        except protocol_spec.ProtocolError as error:
            return (error.code, "", error.detail or {})

    def fp_of(ident) -> str:
        return fingerprint_of_public_key(
            ed25519.Ed25519PublicKey.from_public_bytes(ident.raw_public_key()))

    holder, third, dialled, nobody = (
        load_or_create(workspace / f"sesrel-{n}") for n in ("holder", "third", "dialled", "nobody"))
    first = pair(holder)
    busy = pair(third)
    check("§3 名额只有一个：第二台首次配对拿到 PEER_BUSY，detail 里是当前那台的名字",
          first[0] == "PAIRED" and busy[0] == "PEER_BUSY"
          and busy[2].get("reason") == "one peer at a time" and busy[2].get("peer") != "",
          f"{first[:2]} {busy}")
    released = service.release(fp_of(holder))
    check("§3 持有方点「断开」这一趟：release 拿走那枚 token，答的是这台对端确实占着名额",
          released is True and fp_of(holder) not in service._tokens, released)
    freed = pair(third)
    check("§3 名额真给了下一台：同一个人若不释放，这一趟只会再拿到 PEER_BUSY",
          freed[0] == "PAIRED" and freed[1] != "", freed[0])
    check("§3 被请出去的那台带的旧 token 不再算话（它下一次会拿到 403 NOT_PAIRED）",
          not service.token_valid(first[1]) and service.caller_fingerprint(first[1]) == "",
          service.caller_fingerprint(first[1]))
    service.release(fp_of(third))
    resumed = pair(holder, blank_code=True)
    check("§3 释放不等于撤销：这台对端留空配对码、只靠签名就配回来，resumed 为真",
          resumed[0] == "PAIRED" and resumed[2] is True and resumed[1] != "", resumed)
    service.release(fp_of(holder))
    service.hold_slot_for(fp_of(dialled))
    held = service.release(fp_of(dialled))
    check("§3 两半都算占着名额：本机拨出去的那台没有 token，断开它照样答 True 并把名额收回",
          held is True and service.active_peers() == [], (held, service.active_peers()))
    service.hold_slot_for(fp_of(dialled))
    missed = service.release(fp_of(nobody))
    check("§3 没占着名额的那一台：release 答 False，且不把别人那一格一起清掉",
          missed is False and service.active_peers() == [fp_of(dialled)],
          (missed, service.active_peers()))
    service.release(fp_of(dialled))
    restarted = ReceiveService(receiver, "PC-Session-Release", lambda manifest, who, caller: True,
                               port=0, root=workspace / "sesrel-received")
    check("§3 「接收服务重启」在 PC 是不需要新线上字段的：换一个新接收器，旧 token 一句也不认",
          restarted._tokens == {} and not restarted.token_valid(first[1]), len(restarted._tokens))

    # 第二十八轮（#194）后半句：本机拨出去的那台「超时同样登记为已断开」。PC 登记的是 fingerprint——这台对端
    # 在接收器里连一个名字都没有（名字只活在界面上那份名单里），所以按名字登记的写法在这一端压根写不出来。
    lost: list[str] = []
    service.on_lost = lost.append
    service.hold_slot_for(fp_of(dialled))
    service._seen[fp_of(dialled)] = time.time() - proto.session_idle_timeout_s - 1
    swept = service.sweep()
    check("§3 拨出去那一格的钟走完后 sweep 收回它，并把这一台的 fingerprint 交给登记",
          swept == [fp_of(dialled)] and lost == [fp_of(dialled)] and service.active_peers() == [],
          (swept, lost, service.active_peers()))
    check("§3 登记是一次性的：名额已经收回的那一台，下一次 sweep 不再替它登记一遍",
          service.sweep() == [] and lost == [fp_of(dialled)], (lost,))
    service.stop()


def phase_pair_shape(proto: protocol_spec.Protocol) -> None:
    """§3: the shape of a typed-in code and passphrase is asked on THIS end, before either goes on the wire.

    第二十九轮（#195）。合同在纸上早写了两条形状——那 {n} 位数字、那 {m} 位且字母表去掉 I/O/0/1——而接收方拿
    这两个串只做一件事：逐字相等。所以多抄的第 7 位、抄成小写的那个字母，不是一次更弱的承诺，它是对面那一格
    来源 `pair_code_max_fails` 枚名额里的一次，答完还替下一个真来配的人锁上 `pair_code_lock_s`。改前 PC 这一半
    一个都不问：`parse_qr` 只筛 h/f/v/p，界面上那 `setMaxLength` 限长度不限字符，两个入口只问「填了没有」；
    手机那半边的两个函数早就有，但扫码/粘贴读的是 `parsePairUrl`，它把两个字段写成 if/else，于是带 `c` 的
    那一串（现在每一张二维码都带）从来没量过 `k`。
    """
    n, m = proto.pair_code_digits, proto.passphrase_chars
    good_code, good_phrase = "1" * n, "K7QMXZ2P" if m == 8 else "K" * m
    check(f"§3 照屏幕抄对的 {n} 位码与 {m} 位密码不会被本机拦下：这一问只在真答不上时才开口",
          protocol_spec.code_reject(good_code, proto) == "" and protocol_spec.pass_reject(good_phrase, proto) == "",
          (protocol_spec.code_reject(good_code, proto), protocol_spec.pass_reject(good_phrase, proto)))
    long_code = protocol_spec.code_reject("1" * (n + 1), proto)
    check(f"§3 码多抄一位时本机答的是「那 {n} 位」，而不是让对端去数",
          long_code != "" and str(n) in long_code, long_code)
    letter_code = protocol_spec.code_reject("12345a"[: n - 1] + "a", proto)
    check("§3 码里混进字母时先答「只能是数字」：框上那个最大长度挡不住一个字母",
          letter_code != "" and "数字" in letter_code and str(n) not in letter_code, letter_code)
    lower_phrase = protocol_spec.pass_reject(good_phrase.lower(), proto)
    check("§3 密码抄成小写在本地就停住，说的是大写字母：对面逐字比，不会替人改大小写",
          lower_phrase != "" and "大写" in lower_phrase, lower_phrase)
    ambiguous = {one: protocol_spec.pass_reject(good_phrase[:-1] + one, proto) for one in "IO01"}
    check("§3 字母表去掉的 I/O/0/1 四个字符，抄进密码框也照样被本机拦下——每一个都点名是哪一个",
          all(why != "" and bad in why for bad, why in ambiguous.items()), ambiguous)
    short_phrase = protocol_spec.pass_reject(good_phrase[:-1], proto)
    check(f"§3 密码少抄一位时本机答的是「那 {m} 位」", short_phrase != "" and str(m) in short_phrase, short_phrase)
    check("§3 密码留空是一个答案而不是错误：那是 §3 的「没有这个字段」，量它 = 把诚实的省略烧成一次错误猜测",
          protocol_spec.pass_reject("", proto) == "", protocol_spec.pass_reject("", proto))

    minted = [(identity_mod.new_pair_code(n), identity_mod.new_passphrase(m)) for _ in range(300)]
    refused = [(code, phrase) for code, phrase in minted
               if protocol_spec.code_reject(code, proto) or protocol_spec.pass_reject(phrase, proto)]
    check("§3 铸出来的一组自己过得了自己那道问：铸的表与量的表是同一张（本轮删掉 identity.py 里那份复制品，"
          "两张表意味着一台机器能拒掉自己发的正确答案）",
          not refused, refused[:3])

    payload = f"{proto.qr_scheme}?h=127.0.0.1&p={proto.transport_port}&v={proto.version}&f={'0' * 64}&c={good_code}&k={good_phrase.lower()}"
    fields = protocol_spec.parse_qr(payload)
    baked_code, baked_phrase = protocol_spec.pairing_secrets(payload, proto)
    why = (protocol_spec.code_reject(baked_code, proto) if baked_code else "") or protocol_spec.pass_reject(baked_phrase, proto)
    check("§3 读串那一步照旧只管 h/f/v/p（§7：字段只会长），形状问在发送那一步：带小写 k 的一串读得进来、发不出去",
          fields.get("k") == good_phrase.lower() and why != "" and "大写" in why, (fields.get("k"), why))


def main() -> int:
    proto = protocol_spec.load()
    REPORT.write_text("", encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="chuanshu-proto-") as tmp:
        workspace = Path(tmp)
        phase_in_process(proto, workspace)
        phase_identity_shapes(proto, workspace)
        phase_restart(proto, workspace)
        phase_token_repair(proto, workspace)
        phase_lying_ledger(proto, workspace)
        phase_state_lost(proto, workspace)
        phase_chunk_escape(proto, workspace)
        phase_stalled_offer(proto, workspace)
        phase_offer_poll(proto, workspace)
        phase_repeated_offer(proto, workspace)
        phase_same_name(proto, workspace)
        phase_hidden_segments(proto, workspace)
        phase_manifest_fields(proto, workspace)
        phase_finalize_reply(proto, workspace)
        phase_offer_reply(proto, workspace)
        phase_pending_answer(proto, workspace)
        phase_chunk_reply(proto, workspace)
        phase_chunk_reply_lost(proto, workspace)
        phase_finalize_replay(proto, workspace)
        phase_discovery(proto, workspace)
        phase_reverse_pin(proto, workspace)
        phase_shared_identity(proto, workspace)
        phase_pair_throttle(proto, workspace)
        phase_random_source(proto, workspace)
        phase_pair_scope(proto, workspace)
        phase_optional_secret(proto, workspace)
        phase_second_layer(proto, workspace)
        phase_session_release(proto, workspace)
        phase_pair_shape(proto)
    phase_catalogue(proto)
    check("chunks per file match the contract", proto.chunk_size == 4194304, proto.chunk_size)
    # The four shapes §7 can arrive in; the wire legs above are what prove both ends consult them.
    check("§7 a peer that can speak one of ours fits, whatever it is", proto.intersects([1, 2], 9))
    check("§7 a peer whose set excludes us does not, whatever it prints", not proto.intersects([2], 1))
    check("§7 a peer naming no set falls back to the number it printed", proto.intersects(None, 1) and proto.intersects([], 1))
    check("§7 a legacy peer on another version is still refused", not proto.intersects(None, 9))
    print("\n".join(REPORT.read_text(encoding="utf-8").splitlines()))
    print("RESULT " + (f"FAILED {len(fails)}: " + " / ".join(fails) if fails else "ALL PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
