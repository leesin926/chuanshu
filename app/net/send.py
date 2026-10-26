"""Sender half of the protocol: an HTTPS client pinned to one peer fingerprint.

Two failure modes drive the shape of this module:

* the receiver may restart, which invalidates the session token but not the pinned
  key, so a 403 NOT_PAIRED is repaired by a signature-only re-pair inside `_call`,
  not by asking the user for a code again;
* a chunk may be lost or corrupted, and recovering must cost one chunk rather than
  one file, so every resume decision is driven by the receiver's `missing` lists.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import logging
import mimetypes
import secrets
import time
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Iterable

from app.net import spec as protocol_spec
from app.net.identity import Identity, client_context, verify_pinned

log = logging.getLogger(__name__)

#: Largest TLS record body a peer is asked to swallow. See _connect: the Harmony TLS server hands a
#: record to the app only up to about 8 KiB and dies on a 16 KiB one, which is what every mainstream
#: stack writes when given a whole chunk at once.
MAX_TLS_RECORD_PLAINTEXT = 4096

#: Milliseconds to wait between TLS records when a body is larger than one pipe can drain. A Harmony
#: receiver measured on this ladder: at 0-10 ms per 4 KiB record a 4 MiB body arrives with the declared
#: byte count and different content every time (12/12, `.probe/records.py`), from 15 ms up it arrives
#: byte-identical (6/6, `.probe/pace.py`); record count does not matter, only rate, and 8 KiB records kill
#: the connection outright. Full speed is worse than a wrong digest there: the receiving process dies with
#: it (`.probe/crashlog.py`), so the pace has to come from the peer's own declaration before the first big
#: body - the ladder below is the fallback for a peer that never declared anything and then complained.
PACE_MS_LADDER = (0, 15, 40)

#: Optional `GET /v1/hello` field: how slowly this peer wants a big body written, in milliseconds per
#: 4 KiB TLS record (spec §4). Absent or 0 means "write it as fast as you can".
PACE_FIELD = "chunk_pace_ms"

#: relpath, chunk index, total chunks in this offer
Progress = Callable[[str, int, int], None]


class PairNeeded(RuntimeError):
    """The peer does not know our key yet, so its one-time pair code has to be entered."""

    def __init__(self, reason: str = "peer does not recognise our key") -> None:
        super().__init__(reason)
        self.reason = reason


class Throttle:
    """A bytes-per-second budget shared by everything one connection writes.

    It is spent at the seam where the body leaves as TLS records, because that is the only place
    a transfer is small enough to stop between: a ``sendall`` of a 4 MiB chunk has already handed
    the whole thing to the socket before anyone can object.
    """

    #: How far ahead of the clock the bucket may run, in seconds of traffic. Without headroom the
    #: first record waits out its own transfer time before a single byte is on the wire.
    BURST_S = 0.5

    def __init__(self, bps: int) -> None:
        self.bps = max(0, int(bps))
        self.start = time.monotonic()
        self.sent = 0

    def spend(self, n: int) -> None:
        if not self.bps:
            return
        self.sent += n
        allowed = (time.monotonic() - self.start + self.BURST_S) * self.bps
        if self.sent > allowed:
            time.sleep((self.sent - allowed) / self.bps)


class _Paced:
    """A body http.client reads one record at a time, with a pause between reads.

    ``send()`` pulls a file-like body a ``blocksize`` piece at a time and each piece becomes its own TLS
    record, which is the only way to keep records under the size a Harmony peer survives. A pause has to
    ride on that same seam: sleeping here spaces the records themselves, which is what an undrainable pipe
    needs. A bytes body would go out in one ``sendall`` and one oversized record.
    """

    def __init__(self, data: bytes, ms: float, throttle: Throttle | None = None) -> None:
        self.data = data
        self.ms = ms / 1000.0
        self.throttle = throttle
        self.at = 0

    def read(self, size: int) -> bytes:
        if self.ms:
            time.sleep(self.ms)
        piece = self.data[self.at:self.at + size]
        self.at += len(piece)
        if self.throttle is not None:
            self.throttle.spend(len(piece))
        return piece


@dataclass
class OutgoingFile:
    path: Path
    relpath: str
    id: str
    size: int
    sha256: str
    mtime: int

    def manifest(self) -> dict:
        return {
            "id": self.id,
            "relpath": self.relpath,
            "size": self.size,
            "sha256": self.sha256,
            "mtime": self.mtime,
            "type": mimetypes.guess_type(self.path.name)[0] or "application/octet-stream",
        }


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_chunk(file: OutgoingFile, index: int, chunk_size: int) -> bytes:
    with open(file.path, "rb") as handle:
        handle.seek(index * chunk_size)
        return handle.read(chunk_size)


def plan(paths: Iterable[Path], base: Path | None = None) -> list[OutgoingFile]:
    """Hash and name everything about to be offered.

    relpath is derived here rather than taken from any display string, so the
    receiver reproduces the directory layout the user actually picked.
    """
    items: list[OutgoingFile] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(str(path))
        entries = sorted(path.rglob("*")) if path.is_dir() else [path]
        for entry in entries:
            if not entry.is_file() or entry.name.startswith("."):
                continue
            relative = entry.relative_to(base) if base else Path(entry.name)
            digest = hashlib.sha256()
            with open(entry, "rb") as handle:
                for block in iter(partial(handle.read, 1 << 20), b""):
                    digest.update(block)
            stat = entry.stat()
            items.append(
                OutgoingFile(
                    path=entry,
                    relpath=relative.as_posix(),
                    id=secrets.token_hex(8),
                    size=stat.st_size,
                    sha256=digest.hexdigest(),
                    mtime=int(stat.st_mtime),
                )
            )
    return items


class PeerConnection:
    def __init__(self, identity: Identity, device_name: str, host: str, port: int, fingerprint: str) -> None:
        self.identity = identity
        self.device_name = device_name
        self.host = host
        self.port = port
        self.fingerprint = fingerprint
        self.proto = protocol_spec.load()
        self.token = ""
        self.peer: dict = {}
        self.offer_id = ""
        self.pace_ms = PACE_MS_LADDER[0]
        #: None means the wire runs as fast as the peer will take it. The UI owns this value: it is
        #: the 传输限速 switch, read again before every transfer.
        self.throttle: Throttle | None = None
        self.hello_read = False
        self._conn: http.client.HTTPSConnection | None = None

    # ------------------------------------------------------------- transport

    def _connect(self) -> http.client.HTTPSConnection:
        self.close()
        # The receiver may hold POST /v1/offer open while its user decides. Timing out
        # before it answers would resend the offer and ask that person twice, so the socket
        # has to outlive the whole decision window.
        conn = http.client.HTTPSConnection(
            self.host, self.port, context=client_context(), timeout=self.proto.offer_wait_timeout_s + 15
        )
        # One TLS record per 4 KiB of body, see _once. A Harmony peer's TLS server dies outright on a
        # record over 8 KiB, and every mainstream stack happily writes 16 KiB ones.
        conn.blocksize = MAX_TLS_RECORD_PLAINTEXT
        conn.connect()
        verify_pinned(conn.sock, self.fingerprint)
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _once(self, method: str, path: str, body: bytes, headers: dict, pace_ms: int = 0) -> tuple[int, dict, bytes]:
        merged = dict(headers)
        if self.token:
            merged.setdefault("X-Chuanshu-Auth", self.token)
        merged["Content-Length"] = str(len(body))
        for attempt in (0, 1):
            # A fresh connection per request, hung up as soon as the reply is read. A Harmony peer
            # serves one request per connection and then closes it, so reusing a keep-alive socket
            # writes into a connection that is already being torn down: those bytes are then
            # reported against the *next* connection, where they land ahead of that request's own
            # header and poison its parser - the trace showed a chunk's body fragment arriving as
            # the first packet of the connection carrying the PUT that sent it.
            conn = self._connect()
            try:
                # A readable body, not the bytes themselves: http.client hands a bytes body to one
                # sendall, which OpenSSL turns into 16 KiB records, and a 16 KiB record is enough to
                # kill a Harmony peer. Read in blocksize pieces and each piece becomes its own record,
                # and when the pipe has proven it cannot drain that, one record per `pace_ms`.
                writer = _Paced(body, pace_ms, self.throttle) if (pace_ms or self.throttle) else io.BytesIO(body)
                conn.request(method, path, body=writer if body else None, headers=merged)
                response = conn.getresponse()
                raw = response.read()
            except (http.client.HTTPException, OSError) as exc:
                log.warning("%s %s 第%d次没走通：%s", method, path, attempt + 1, exc)
                self.close()
                if attempt:
                    raise
                continue
            payload: dict = {}
            if raw:
                try:
                    loaded = json.loads(raw.decode("utf-8"))
                    payload = loaded if isinstance(loaded, dict) else {"code": "UNSUPPORTED_PROTOCOL"}
                except (UnicodeDecodeError, ValueError):
                    payload = {"code": "UNSUPPORTED_PROTOCOL", "detail": {"reason": "reply was not JSON"}}
            status = response.status
            self.close()
            return status, payload, raw
        raise http.client.HTTPException(f"{method} {path} failed twice")

    def _request(self, method: str, path: str, json_body: dict | None = None, raw_body: bytes = b"",
                 headers: dict | None = None, pace_ms: int = 0) -> tuple[int, dict]:
        body = raw_body
        merged = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            merged["Content-Type"] = "application/json"
        status, payload, _ = self._once(method, path, body, merged, pace_ms)
        return status, payload

    def _call(self, method: str, path: str, json_body: dict | None = None, raw_body: bytes = b"", headers: dict | None = None) -> dict:
        """Authorized request: repairs a dropped session once, then raises."""
        status, payload = self._request(method, path, json_body=json_body, raw_body=raw_body, headers=headers)
        if payload.get("code") == "NOT_PAIRED" and self.identity.is_trusted(self.fingerprint):
            log.info("session token rejected, re-pairing silently")
            self.token = ""
            self.pair()
            status, payload = self._request(method, path, json_body=json_body, raw_body=raw_body, headers=headers)
        if status >= 400:
            code = str(payload.get("code") or "UNSUPPORTED_PROTOCOL")
            raise protocol_spec.ProtocolError(code, payload.get("detail"))
        return payload

    # ---------------------------------------------------------------- pairing

    def hello(self) -> dict:
        """Read the peer's own answer, including how slowly it wants big bodies written.

        Re-read every time: a fixed pairing code, a restart, a different app on the same fingerprint all
        make an earlier answer stale, and the pace a peer declares is one of the things it decides for
        itself. A transport failure here is its own error, the same as any other first request.
        """
        status, payload = self._request("GET", "/v1/hello")
        if status != 200:
            raise protocol_spec.ProtocolError(str(payload.get("code")), payload.get("detail"))
        peer_version = int(payload.get("protocol_version") or 0)
        if not self.proto.intersects(payload.get("compatible_versions"), peer_version):
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {
                "peer_version": payload.get("protocol_version"),
                "peer_compatible": payload.get("compatible_versions"),
                "mine": list(self.proto.compatible_versions),
            })
        self.peer = payload
        self.hello_read = True
        self.learn_pace()
        return payload

    def learn_pace(self) -> None:
        """Take the pace this peer asked for, and never hand it back.

        A full-speed 4 MiB body does not only arrive wrong on a Harmony receiver, it takes the receiving
        process down with it, so the floor has to be read before the first big body rather than learned
        from the wreckage of one.
        """
        declared = int(self.peer.get(PACE_FIELD) or 0)
        if declared > self.pace_ms:
            log.info("peer asks for %d ms per TLS record, pacing this transfer accordingly", declared)
            self.pace_ms = declared

    def pair(self, code: str = "", secret: str = "", tls_fingerprint: str = "") -> dict:
        """Redeem a pair code, and a passphrase when the user typed one.

        An empty ``secret`` is left off the wire rather than sent blank: a peer that predates
        the passphrase reads a missing key as "this sender has no passphrase to offer" and
        accepts on the code alone, while an empty one would look like a wrong guess.
        ``tls_fingerprint`` follows the same rule - it is this device's served leaf certificate,
        and is only declared when that leaf is not signed by the identity key (spec §3). Since task
        #106 that is always true here: the socket answers under an RSA-2048 leaf because an Android
        client cannot be pointed at an Ed25519 one, so the value comes from the identity rather than
        from each caller.
        """
        tls_fingerprint = tls_fingerprint or self.identity.declared_tls_fingerprint
        nonce = secrets.token_hex(16)
        message = protocol_spec.pair_message(self.identity.peer_id, nonce, tls_fingerprint)
        request = {
            "peer_id": self.identity.peer_id,
            "name": self.device_name,
            "protocol_version": self.proto.version,
            # §7's intersection needs both sets, and the receiver never dials back to read mine - so
            # the pair body carries it. A peer that predates the field reads no key and falls back.
            "compatible_versions": list(self.proto.compatible_versions),
            "nonce": nonce,
            "public_key": base64.b64encode(self.identity.raw_public_key()).decode(),
            "signature": base64.b64encode(self.identity.key.sign(message)).decode(),
            "code": code,
        }
        if secret:
            request["secret"] = secret
        if tls_fingerprint:
            request["tls_fingerprint"] = tls_fingerprint
        status, payload = self._request("POST", "/v1/pair", json_body=request)
        if status == 403 and payload.get("code") == "BAD_PAIR_CODE":
            raise PairNeeded()
        if status != 200:
            raise protocol_spec.ProtocolError(str(payload.get("code") or "NOT_PAIRED"), payload.get("detail"))
        self.token = str(payload["token"])
        self.peer = payload
        # Two numbers for one device: this end pinned the certificate it got out of TLS, the
        # signature names an identity key. Recording both is what stops a peer whose leaf is
        # not its identity from being trusted under one key and dialled under another.
        peer_identity = str(payload["fingerprint"])
        self.identity.trust(peer_identity, str(payload["peer_id"]), str(payload.get("name", "")),
                            tls_fingerprint="" if peer_identity == self.fingerprint else self.fingerprint)
        log.info("paired with %s (resumed=%s)", payload.get("name"), payload.get("resumed"))
        return payload

    # --------------------------------------------------------------- transfer

    def offer(self, files: list[OutgoingFile]) -> dict:
        """Send the manifest and come back with the peer's answer.

        A peer that can hold a socket open answers this POST itself, and the first reply is the decision.
        A Harmony peer cannot: its TLS server frees the session of a connection that is only waiting about
        a tenth of a second after the request lands, with no disconnect reaching the app, so the answer
        would have to be written onto a session that is gone (`.probe/death.py`, and `SSL is null` in the
        phone's own trace). That end answers `accepted: false` straight away and the decision is read from
        the next POST of the same manifest, which the receiver already treats as one delivery rather than
        a second one.
        """
        manifest = {
            "offer_id": secrets.token_hex(8),
            "protocol_version": self.proto.version,
            # Same reason as in pair(): the receiver decides §7 from two sets, not from one number.
            "compatible_versions": list(self.proto.compatible_versions),
            "total_size": sum(f.size for f in files),
            "from": {"peer_id": self.identity.peer_id, "name": self.device_name},
            "files": [f.manifest() for f in files],
        }
        self.offer_id = str(manifest["offer_id"])
        self._manifest = manifest
        deadline = time.monotonic() + self.proto.offer_wait_timeout_s
        while True:
            try:
                status, payload = self._request("POST", "/v1/offer", json_body=manifest)
            except (http.client.HTTPException, OSError) as exc:
                # One poll that fails to read is not the end of this transfer. The manifest carries the
                # same offer_id every time, and the receiver counts it as one delivery rather than a
                # second request, so the cost of trying again is one second - while the cost of giving up
                # is a person watching a batch they already approved disappear. The socket timeout is
                # deliberately longer than the decision window (a peer that holds the connection open
                # while its user decides answers only at the end), so a stall here says nothing about
                # whether anybody decided. Only the window itself says DECLINED.
                if time.monotonic() >= deadline:
                    self._withdraw("no decision in time")
                    raise protocol_spec.ProtocolError(
                        "DECLINED", {"reason": "no decision in time", "last_error": str(exc)}
                    ) from exc
                log.warning("offer 轮询没读通，一秒后重来：%s", exc)
                time.sleep(1.0)
                continue
            if status == 403 and payload.get("code") == "NOT_PAIRED" and self.identity.is_trusted(self.fingerprint):
                # The peer restarted while somebody was deciding; the pin survives, so re-pair quietly.
                self.token = ""
                self.pair()
                continue
            if status >= 400:
                raise protocol_spec.ProtocolError(str(payload.get("code") or "UNSUPPORTED_PROTOCOL"), payload.get("detail"))
            if payload.get("accepted") is not False:
                log.info("offer %s accepted (%d files)", self.offer_id[:8], len(files))
                return {"manifest": manifest, "state": payload}
            if time.monotonic() >= deadline:
                self._withdraw("no decision in time")
                raise protocol_spec.ProtocolError("DECLINED", {"reason": "no decision in time"})
            time.sleep(1.0)

    def _withdraw(self, why: str) -> None:
        """Tell the peer to drop the offer this machine is walking away from.

        §4's window closing is the sender's own fact, and the peer cannot derive it: an offer nobody
        decided holds that end's single offer slot, and one somebody decided holds the space reserved
        for its files, until its own idle floor passes. Saying so is the same withdrawal the 取消 button
        already sends (``app/ui/transfer.py``), and a peer that has already forgotten the id simply
        answers OFFER_UNKNOWN - which is why a failure here is only a log line.
        """
        try:
            self.abort()
        except (http.client.HTTPException, OSError, protocol_spec.ProtocolError) as exc:
            log.warning("could not withdraw the offer (%s): %s", why, exc)

    def state(self) -> dict:
        return self._call("GET", f"/v1/offer/{self.offer_id}/state")

    def reopen(self, offer_id: str) -> dict:
        """Adopt an offer created before either side restarted, then read its state.

        The offer id is the resume handle: the receiver keeps the chunks it already
        has under it, so a fresh connection can finish the job.
        """
        self.offer_id = offer_id
        return self.state()

    def finalize(self) -> dict:
        return self._call("POST", f"/v1/offer/{self.offer_id}/finalize", json_body={})

    def abort(self) -> dict:
        return self._call("DELETE", f"/v1/offer/{self.offer_id}")

    def push_missing(self, files: list[OutgoingFile], state: dict, progress: Progress | None, retries: int) -> int:
        by_id = {f.id: f for f in files}
        pushed = 0
        total = sum(self._chunk_count(f) for f in files)
        for entry in state["files"]:
            file = by_id.get(str(entry["id"]))
            if file is None:
                continue
            for index in entry["missing"]:
                self._put_chunk(file, index, total, progress, retries)
                pushed += 1
        return pushed

    def send(self, files: list[OutgoingFile], progress: Progress | None = None, retries: int = 3) -> dict:
        """Push what the receiver still needs, verify, and re-push once if it complains."""
        if not self.offer_id:
            raise RuntimeError("call offer() before send()")
        if not self.hello_read:
            # The peer's own pace declaration is worth one more request if the caller went straight to
            # pairing: a body written too fast is not merely rejected by a Harmony receiver.
            self.hello()
        self.push_missing(files, self.state(), progress, retries)
        result = self.finalize()
        broken = [v for v in result["verified"] if not v["ok"]]
        if not broken:
            return result
        # A digest failure with no missing chunks means the bytes on disk are wrong,
        # so resend that file in full rather than guessing which chunk drifted.
        by_id = {f.id: f for f in files}
        for bad in broken:
            file = by_id.get(str(bad["id"]))
            if file is None:
                continue
            indexes = list(bad["missing"]) or list(range(self._chunk_count(file)))
            for index in indexes:
                self._put_chunk(file, index, sum(self._chunk_count(f) for f in files), progress, retries)
        result = self.finalize()
        still = [v for v in result["verified"] if not v["ok"]]
        if still:
            raise protocol_spec.ProtocolError("FILE_DIGEST_MISMATCH", {"files": [v["id"] for v in still]})
        return result

    def transfer(self, files: list[OutgoingFile], code: str = "", progress: Progress | None = None, secret: str = "") -> dict:
        self.hello()
        if not self.identity.is_trusted(self.fingerprint):
            self.pair(code, secret)
        else:
            self.pair()
        offered = self.offer(files)
        result = self.send(files, progress)
        return {"offer_id": self.offer_id, "state": offered["state"], "result": result}

    # -------------------------------------------------------------- internals

    def _chunk_count(self, file: OutgoingFile) -> int:
        return (file.size + self.proto.chunk_size - 1) // self.proto.chunk_size if file.size else 0

    def _put_chunk(self, file: OutgoingFile, index: int, total: int, progress: Progress | None, retries: int) -> None:
        path = f"/v1/offer/{self.offer_id}/chunk/{file.id}/{index}"
        for attempt in range(retries):
            data = _read_chunk(file, index, self.proto.chunk_size)
            body, escaped = protocol_spec.escape_chunk(data)
            headers = {"X-Sha256": _digest(data)}
            if escaped:
                headers[protocol_spec.CHUNK_ESCAPE_HEADER] = escaped
            try:
                status, payload = self._request("PUT", path, raw_body=body, headers=headers, pace_ms=self.pace_ms)
            except (http.client.HTTPException, OSError) as exc:
                # A body that dies on the way in is the same complaint as a wrong digest, only louder: the
                # pipe could not carry it at this rate. Slowing down is the one repair that does not need
                # the peer's help, so spend a rung of the ladder before giving up on the chunk.
                if self._slow_pipe(f"{type(exc).__name__}: {exc}"):
                    continue
                # The ladder is spent, and this attempt says nothing about the bytes: a relay can drop the
                # socket after the body landed and before the reply was written. Ask before raising - one
                # GET is cheap next to a transfer the person already approved.
                landed = self._chunk_landed(file, index)
                if landed is None:
                    # Nobody answered. That is the one shape where writing the chunk again has no chance of
                    # being the repair, so the question is the verdict: spec §4 sends the original error up.
                    raise
                if landed:
                    log.warning("chunk %d of %s died on the reply, not the body: the peer already has it", index, file.relpath)
                    if progress is not None:
                        progress(file.relpath, index, total)
                    return
                # "Never got it" is a hiccup, not a verdict. On a pipe already at the bottom rung an
                # abort says nothing about speed - measured on the Harmony fport tunnel, a 4 MiB body
                # was dropped three times in a row at 40 ms and the fourth write landed - so spend what
                # is left of the attempt budget writing it again. A relay that drops every attempt
                # still raises.
                if attempt + 1 < retries:
                    log.warning("chunk %d of %s aborted at the pace floor, writing it again (attempt %d)",
                                index, file.relpath, attempt + 2)
                    continue
                raise
            if status == 200:
                if progress is not None:
                    progress(file.relpath, index, total)
                return
            if payload.get("code") == "NOT_PAIRED" and self.identity.is_trusted(self.fingerprint):
                self.token = ""
                self.pair()
                continue
            if payload.get("code") == "CHUNK_DIGEST_MISMATCH" and attempt + 1 < retries:
                log.warning("chunk %d of %s rejected, resending (attempt %d)", index, file.relpath, attempt + 1)
                self._slow_pipe("every byte counted, different content")
                continue
            raise protocol_spec.ProtocolError(str(payload.get("code") or "CHUNK_DIGEST_MISMATCH"), payload.get("detail"))

    def _slow_pipe(self, reason: str) -> bool:
        """Hand the next attempt a rung of the pacing ladder; False when there is no rung left.

        The pace is learned for the rest of this peer, not for one chunk: a pipe that could not drain a
        4 MiB body at full speed has not become faster because that body was written again.
        """
        try:
            rung = next(ms for ms in PACE_MS_LADDER if ms > self.pace_ms)
        except StopIteration:
            log.warning("chunk rejected (%s) with the pipe already paced at %d ms", reason, self.pace_ms)
            return False
        self.pace_ms = rung
        log.warning("chunk rejected (%s): pacing to %d ms per TLS record for the rest of this peer", reason, self.pace_ms)
        return True

    def _chunk_landed(self, file: OutgoingFile, index: int) -> bool | None:
        """What the peer says about this chunk: True/False once it answered, None when nothing answered.

        Only ever asked after a body whose reply never came. Spec §4 sorts these three apart, and the third
        is not a "no": a peer that cannot be reached tells us nothing about the bytes, and spending the rest
        of the attempts writing into that socket is what the phones already refuse to do.
        """
        try:
            state = self.state()
        except (http.client.HTTPException, OSError, protocol_spec.ProtocolError) as exc:
            log.warning("could not ask the peer what it holds: %s", exc)
            return None
        for entry in state.get("files", []):
            if str(entry.get("id")) == file.id:
                return index not in entry.get("missing", [])
        return False
