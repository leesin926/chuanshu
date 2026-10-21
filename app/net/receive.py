"""Receiver half of the protocol: the HTTPS server behind the seven endpoints.

Trust runs in two directions and uses two different anchors, which is why pairing
looks asymmetric:

* the *connecting* peer authenticates this server with the SPKI fingerprint that
  came out of the QR code;
* this server authenticates the connecting peer with an Ed25519 signature over a
  nonce, and on first contact additionally with the one-time pair code (TOFU).

The UI plugs a decision callback into ``OfferHandler``; blocking inside it is
intended, it is what makes an offer's long-poll honest.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.net import spec as protocol_spec
from app.net.identity import Identity, fingerprint_of_public_key, new_pair_code
from app.paths import receive_root

log = logging.getLogger(__name__)

STATE_FILE = ".chuanshu.state.json"
_WINDOWS_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$", re.I)
_REPLAY_WINDOW_S = 300
_CODE_LOCK_S = 60
_CODE_MAX_FAILS = 5
#: How much of an unconsumed request body an error reply is allowed to swallow.
_MAX_ERROR_DRAIN = 65536

OfferHandler = Callable[[dict, str, str], bool]
#: Fires once an offer has been verified chunk-for-chunk: who sent it, and which files this
#: machine can now vouch for. Only the UI's answer can say a file was *received* - a directory
#: listing cannot tell a finished file from one whose tail is still on the wire.
ReceivedHandler = Callable[[str, list[dict]], None]
#: Fires on every accepted pair, so the roster can show a device that dialled *us*. Without
#: this the list only ever holds peers this machine dialled, which is the wrong half of the
#: story: the phone sending files to a PC never appears on that PC.
#: (fingerprint, peer_id, name, client ip)
PairedHandler = Callable[[str, str, str, str], None]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_relpath(relpath: str, proto: protocol_spec.Protocol) -> PurePosixPath:
    """Turn a peer-supplied path into one that is safe to write under a root.

    Every rejection is a 400 PATH_REJECTED, never a silent fix-up: the sender has to
    learn the name is unusable instead of having it quietly moved somewhere else.
    """
    if not relpath or relpath.startswith("/") or "\\" in relpath or ":" in relpath:
        raise protocol_spec.ProtocolError("PATH_REJECTED", {"relpath": relpath})
    parts = relpath.split("/")
    if len(parts) > proto.limits["max_path_depth"]:
        raise protocol_spec.ProtocolError("PATH_REJECTED", {"reason": "too deep"})
    out: list[str] = []
    for part in parts:
        if part in ("", ".", "..") or part.startswith("."):
            raise protocol_spec.ProtocolError("PATH_REJECTED", {"segment": part})
        if len(part.encode("utf-8")) > proto.limits["max_name_bytes"]:
            raise protocol_spec.ProtocolError("PATH_REJECTED", {"reason": "name too long"})
        if _WINDOWS_RESERVED.match(part) or part.endswith(".") or part.endswith(" "):
            raise protocol_spec.ProtocolError("PATH_REJECTED", {"segment": part})
        out.append(part)
    return PurePosixPath(*out)


@dataclass
class OfferState:
    offer_id: str
    directory: Path
    files: list[dict]
    proto: protocol_spec.Protocol
    received: dict[str, dict[int, str]] = field(default_factory=dict)
    #: The name this machine's pin list gives the sender, not what the manifest called itself.
    who: str = ""
    created: float = field(default_factory=time.time)

    def chunk_count(self, file: dict) -> int:
        size = int(file["size"])
        return (size + self.proto.chunk_size - 1) // self.proto.chunk_size if size else 0

    def missing(self, file: dict) -> list[int]:
        done = self.received.get(str(file["id"]), {})
        return [i for i in range(self.chunk_count(file)) if i not in done]

    def payload(self) -> dict:
        return {
            "offer_id": self.offer_id,
            "accepted": True,
            "files": [
                {"id": f["id"], "received": len(self.received.get(str(f["id"]), {})), "missing": self.missing(f)}
                for f in self.files
            ],
        }

    def persist(self) -> None:
        body = {
            "offer_id": self.offer_id,
            "who": self.who,
            "files": self.files,
            "received": {
                fid: {str(index): digest for index, digest in chunks.items()}
                for fid, chunks in self.received.items()
            },
        }
        (self.directory / STATE_FILE).write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path, proto: protocol_spec.Protocol) -> "OfferState | None":
        """Re-adopt an interrupted offer after a restart; the chunks on disk stay valid."""
        path = directory / STATE_FILE
        if not path.is_file():
            return None
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
            files = list(body["files"])
            received = {
                str(fid): {int(index): str(digest) for index, digest in chunks.items()}
                for fid, chunks in body["received"].items()
            }
        except (OSError, ValueError, TypeError, KeyError):
            log.exception("offer state unreadable, ignoring: %s", path)
            return None
        return cls(
            offer_id=str(body["offer_id"]),
            directory=directory,
            files=files,
            proto=proto,
            received=received,
            who=str(body.get("who", "")),
        )


class _RequestHandler(BaseHTTPRequestHandler):
    server_version = "ChuanShu"
    protocol_version = "HTTP/1.1"
    #: One handler instance serves every request on a keep-alive connection.
    _body_consumed = False

    def setup(self) -> None:
        """Wrap per request, not per accept.

        Wrapping the listening socket would run the handshake on the accept loop and
        let one slow peer stall every other connection.
        """
        try:
            self.request = self.server.ssl_context.wrap_socket(self.request, server_side=True)
        except ssl.SSLError as error:
            raise OSError(f"TLS handshake failed: {error}") from error
        super().setup()

    def log_message(self, fmt: str, *args) -> None:
        log.debug("http " + fmt, *args)

    @property
    def service(self) -> "ReceiveService":
        return self.server.service  # type: ignore[attr-defined]

    def _reply(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json_body(self) -> dict:
        self._body_consumed = True
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"reason": "body is not a JSON object"})
        if not isinstance(data, dict):
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"reason": "body is not a JSON object"})
        return data

    def _raw_body(self) -> bytes:
        self._body_consumed = True
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _fail(self, error: protocol_spec.ProtocolError) -> None:
        # An error raised before the body was read leaves that body in the socket, and the
        # next request line would then be parsed out of it. Drain it - but only once, since
        # reading a body that is already gone blocks until the client times out.
        length = int(self.headers.get("Content-Length") or 0)
        if length and not self._body_consumed:
            if length <= _MAX_ERROR_DRAIN:
                self._raw_body()
            else:
                self.close_connection = True
        self._reply(self.service.proto.http_status(error.code), {"code": error.code, "detail": error.detail})

    def _dispatch(self, method: str) -> None:
        self._body_consumed = False
        try:
            self.service.route(method, self)
        except protocol_spec.ProtocolError as error:
            self._fail(error)
        except (BrokenPipeError, ConnectionResetError):
            log.info("peer dropped the connection mid-request: %s", self.path)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], service: "ReceiveService") -> None:
        super().__init__(address, _RequestHandler)
        self.service = service
        self.ssl_context = service.identity.server_context()

    def handle_error(self, request, client_address) -> None:
        # A peer that hangs up mid-handshake is routine, not a stack trace.
        log.debug("connection from %s ended early", client_address)


class ReceiveService:
    def __init__(
        self,
        identity: Identity,
        device_name: str,
        handler: OfferHandler,
        host: str = "",
        port: int = 0,
        root: Path | None = None,
        on_received: ReceivedHandler | None = None,
        on_paired: PairedHandler | None = None,
    ) -> None:
        self.identity = identity
        self.device_name = device_name
        self.handler = handler
        self.on_received = on_received
        self.on_paired = on_paired
        self.proto = protocol_spec.load()
        self.root = Path(root or receive_root())
        self._offers: dict[str, OfferState] = {}
        self._tokens: dict[str, str] = {}
        self._seen_nonces: dict[str, float] = {}
        self._code_failures: dict[str, list[float]] = {}
        # Only used when the contract says the code lapses (pair_code_static=false).
        self._ephemeral: tuple[str, float] = ("", 0.0)
        # Whose session this device is committed to, set by the UI when it dials out.
        self._held_by: str = ""
        self.identity.ensure_pairing(self.proto.pair_code_digits, self.proto.passphrase_chars)
        # RLock: handle_pair takes it and then reads the session slots through the same lock.
        self._lock = threading.RLock()
        self._http = _Server((host, port), self)
        self._thread = threading.Thread(target=self._http.serve_forever, name="chuanshu-serve", daemon=True)

    # ------------------------------------------------------------ lifecycle

    @property
    def port(self) -> int:
        return int(self._http.server_address[1])

    def start(self) -> int:
        self._thread.start()
        log.info("transport listening on port %d", self.port)
        return self.port

    def stop(self) -> None:
        self._http.shutdown()
        self._http.server_close()
        self._thread.join(timeout=3)

    def adopt_interrupted_offers(self) -> int:
        if not self.root.is_dir():
            return 0
        count = 0
        for child in self.root.iterdir():
            if not child.is_dir():
                continue
            state = OfferState.load(child, self.proto)
            if state is not None:
                self._offers[state.offer_id] = state
                count += 1
        if count:
            log.info("adopted %d interrupted offer(s) under %s", count, self.root)
        return count

    # --------------------------------------------------------------- pairing

    def current_pair_code(self) -> str:
        """What a stranger has to read off this screen to get in.

        With ``pair_code_static`` this is the code the device minted on first run and keeps
        until the user rotates it by hand - which is what lets the pairing QR be printed and
        stay true. A build without the flag falls back to one code per ``pair_code_ttl_s``.
        """
        if self.proto.pair_code_static:
            return self.identity.pair_code
        with self._lock:
            if not self._ephemeral[0] or time.time() > self._ephemeral[1]:
                self._ephemeral = (
                    new_pair_code(self.proto.pair_code_digits),
                    time.time() + self.proto.pair_code_ttl_s,
                )
            return self._ephemeral[0]

    def passphrase(self) -> str:
        """The second secret, or "" on a build whose contract has none."""
        return self.identity.passphrase if self.proto.passphrase_chars else ""

    def active_peers(self) -> list[str]:
        """Fingerprints holding the open session slot, inbound or dialled by us."""
        with self._lock:
            return sorted({fp for fp in (*self._tokens, self._held_by) if fp})

    def release(self, fingerprint: str) -> bool:
        """Take a peer's session token away, freeing the slot for the next device.

        Revoking it here rather than waiting for the socket to close is what makes 断开 mean
        something on the receiving side too: without it an inbound peer would keep sending
        chunks against a token the user believes is gone.
        """
        with self._lock:
            gone = self._tokens.pop(fingerprint, None)
        if gone is None:
            return False
        log.info("released the session of %s", fingerprint[:12])
        return True

    def hold_slot_for(self, fingerprint: str) -> None:
        """Tell the receiver which peer this machine already talks to.

        One peer at a time is a promise about the device, not about the direction: a PC that
        dialled out itself has no inbound token to count, so without this a stranger could still
        pair beside the session the user already sees on screen.
        """
        with self._lock:
            self._held_by = fingerprint or ""

    def _prune(self) -> None:
        now = time.time()
        self._seen_nonces = {n: t for n, t in self._seen_nonces.items() if now - t < _REPLAY_WINDOW_S}
        self._code_failures = {k: [t for t in v if now - t < _CODE_LOCK_S] for k, v in self._code_failures.items()}

    def _pinned_key(self, fingerprint: str) -> ed25519.Ed25519PublicKey | None:
        entry = self.identity.trusted_entry(fingerprint)
        if entry is None or not entry.get("public_key"):
            return None
        return ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"]))

    def handle_pair(self, body: dict, client_ip: str) -> dict:
        with self._lock:
            self._prune()
            peer_id = str(body.get("peer_id", ""))
            name = str(body.get("name", ""))
            nonce = str(body.get("nonce", ""))
            declared = str(body.get("public_key", ""))
            signature = str(body.get("signature", ""))
            code = str(body.get("code", ""))
            declared_leaf = str(body.get("tls_fingerprint") or "")
            if declared_leaf and not protocol_spec.is_fingerprint(declared_leaf):
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "tls_fingerprint is not a full SPKI digest"})
            version = int(body.get("protocol_version") or 0)
            if not self.proto.supports(version):
                raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"peer_version": version})
            if not peer_id or not nonce or not declared or not signature:
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "pair request is incomplete"})
            if nonce in self._seen_nonces:
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "replayed nonce"})
            try:
                key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(declared))
            except ValueError:
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "public key is not base64 raw ed25519"})

            message = protocol_spec.pair_message(peer_id, nonce, declared_leaf)
            fingerprint = fingerprint_of_public_key(key)
            pinned = self._pinned_key(fingerprint)
            if pinned is not None and _raw(pinned) != _raw(key):
                # Same fingerprint, different bytes cannot happen; this is a collision
                # of peer identity and must not silently pass.
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "pinned key mismatch"})
            try:
                key.verify(base64.b64decode(signature), message)
            except (InvalidSignature, ValueError):
                raise protocol_spec.ProtocolError("NOT_PAIRED", {"reason": "signature does not match the key"})

            # Only now, with the key proven to own its own claim, is it safe to say anything
            # about who else is connected. The slot counts a peer this side dialled too, so the
            # promise does not depend on which end of the cable clicked first. A platform whose
            # TLS leaf is not its identity key shows up under two numbers here, so the comparison
            # has to be "same device", not "same hex".
            occupied = [fp for fp in (*self._tokens, self._held_by)
                        if fp and not self.identity.same_peer(fp, fingerprint)]
            if occupied:
                holder = self.identity.trusted_entry(occupied[0]) or {}
                raise protocol_spec.ProtocolError(
                    "PEER_BUSY",
                    {
                        "reason": "one peer at a time",
                        "peer": str(holder.get("name") or "") or occupied[0][: self.proto.prefix_chars],
                    },
                )

            if pinned is None:
                failures = self._code_failures.setdefault(client_ip, [])
                if len(failures) >= _CODE_MAX_FAILS:
                    raise protocol_spec.ProtocolError("PEER_BUSY", {"reason": "too many failed codes"})
                if code != self.current_pair_code():
                    failures.append(time.time())
                    raise protocol_spec.ProtocolError("BAD_PAIR_CODE")
                if "secret" in body and not hmac.compare_digest(str(body.get("secret") or ""), self.passphrase()):
                    # A wrong passphrase is the same mistake as a wrong code as far as the
                    # sender is concerned, and a single error code keeps both builds honest.
                    failures.append(time.time())
                    raise protocol_spec.ProtocolError("BAD_PAIR_CODE", {"reason": "passphrase"})
                self.identity.trust(fingerprint, peer_id, name, declared, declared_leaf)
                log.info("pinned new peer %s (%s)", name or "?", fingerprint[:12])
            else:
                # Known key: the signature alone is enough, no code round trip.
                self.identity.remember_peer(fingerprint, peer_id, name, declared_leaf)

            self._seen_nonces[nonce] = time.time()
            token = secrets.token_hex(32)
            self._tokens[fingerprint] = token
            if self.on_paired is not None:
                self.on_paired(fingerprint, peer_id, name, client_ip)
            return {
                "token": token,
                "peer_id": self.identity.peer_id,
                "name": self.device_name,
                "protocol_version": self.proto.version,
                "fingerprint": self.identity.fingerprint,
                "resumed": pinned is not None,
            }

    def token_valid(self, token: str) -> bool:
        if not token:
            return False
        with self._lock:
            return token in set(self._tokens.values())

    def caller_fingerprint(self, token: str) -> str:
        """Which pinned key this session token belongs to."""
        with self._lock:
            # handle_pair writes the map from another request thread, so take a snapshot.
            pairs = list(self._tokens.items())
        for fingerprint, value in pairs:
            if value == token:
                return fingerprint
        return ""

    def handle_hello(self) -> dict:
        return {
            "peer_id": self.identity.peer_id,
            "name": self.device_name,
            "protocol_version": self.proto.version,
            "compatible_versions": list(self.proto.compatible_versions),
            "features": ["resume", "chunk-hash", "directory"],
            "port": self.port,
            # Discovery advertises a prefix only; the full digest here is what lets a
            # candidate become a peer you can pin.
            "fingerprint": self.identity.fingerprint,
        }

    # ------------------------------------------------------------- transfers

    def handle_offer(self, body: dict, caller: str) -> dict:
        version = int(body.get("protocol_version") or 0)
        if not self.proto.supports(version):
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"peer_version": version})
        offer_id = str(body.get("offer_id", ""))
        files = list(body.get("files", []))
        if not offer_id or not files:
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"reason": "offer has no id or files"})
        if len(files) > self.proto.limits["max_files_per_offer"]:
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"reason": "too many files"})
        restored = self._offers.get(offer_id)
        if restored is not None:
            return restored.payload()

        targets = {str(f["id"]): sanitize_relpath(str(f["relpath"]), self.proto) for f in files}
        entry = self.identity.trusted_entry(caller) if caller else None
        # A peer may call itself anything inside the manifest, so the name the user sees
        # comes from the pin list; caller's fingerprint prefix is the only real anchor.
        who = str((entry or {}).get("name") or "")
        if not self.handler(body, who, caller):
            raise protocol_spec.ProtocolError("DECLINED")

        directory = self.root / offer_id
        directory.mkdir(parents=True, exist_ok=True)
        state = OfferState(offer_id=offer_id, directory=directory, files=files, proto=self.proto, who=who)
        for entry in files:
            target = self._target(state, targets[str(entry["id"])])
            _prepare(target, int(entry["size"]))
            state.received.setdefault(str(entry["id"]), {})
        state.persist()
        self._offers[offer_id] = state
        log.info("accepted offer %s (%d files, %s bytes)", offer_id[:8], len(files), body.get("total_size"))
        return state.payload()

    def handle_state(self, offer_id: str) -> dict:
        state = self._offers.get(offer_id)
        if state is None:
            raise protocol_spec.ProtocolError("OFFER_UNKNOWN", {"offer_id": offer_id})
        return state.payload()

    def handle_chunk(self, offer_id: str, file_id: str, index: int, data: bytes, claimed_digest: str) -> dict:
        state = self._offers.get(offer_id)
        if state is None:
            raise protocol_spec.ProtocolError("OFFER_UNKNOWN", {"offer_id": offer_id})
        file = next((f for f in state.files if str(f["id"]) == file_id), None)
        if file is None:
            raise protocol_spec.ProtocolError("OFFER_UNKNOWN", {"file_id": file_id})
        count = state.chunk_count(file)
        if not 0 <= index < count:
            raise protocol_spec.ProtocolError("BAD_CHUNK_INDEX", {"index": index, "count": count})
        size = int(file["size"])
        want = min(self.proto.chunk_size, size - index * self.proto.chunk_size)
        if len(data) != want:
            raise protocol_spec.ProtocolError("CHUNK_DIGEST_MISMATCH", {"reason": "length", "got": len(data), "want": want})
        digest = _digest(data)
        if claimed_digest and claimed_digest != digest:
            raise protocol_spec.ProtocolError("CHUNK_DIGEST_MISMATCH", {"index": index, "expected": claimed_digest})
        stored = state.received.setdefault(file_id, {})
        if stored.get(index) == digest:
            return {"index": index, "stored": True, "idempotent": True}
        target = self._target(state, sanitize_relpath(str(file["relpath"]), self.proto))
        with open(target, "r+b") as handle:
            handle.seek(index * self.proto.chunk_size)
            handle.write(data)
        stored[index] = digest
        if not state.missing(file) or len(stored) % self.proto.limits["state_flush_chunks"] == 0:
            state.persist()
        return {"index": index, "stored": True}

    def handle_finalize(self, offer_id: str) -> dict:
        state = self._offers.get(offer_id)
        if state is None:
            raise protocol_spec.ProtocolError("OFFER_UNKNOWN", {"offer_id": offer_id})
        results = []
        landed: list[dict] = []
        for file in state.files:
            missing = state.missing(file)
            target = self._target(state, sanitize_relpath(str(file["relpath"]), self.proto))
            ok = not missing and _digest_file(target) == str(file["sha256"])
            results.append({"id": file["id"], "ok": ok, "missing": missing, "path": str(target) if ok else None})
            if ok:
                landed.append({"relpath": str(file["relpath"]), "size": int(file["size"]), "path": str(target)})
            else:
                log.warning("finalize rejected %s: %s", file["relpath"], "missing chunks" if missing else "digest mismatch")
        if landed and self.on_received is not None:
            self.on_received(state.who, landed)
        return {"offer_id": offer_id, "verified": results}

    def handle_abort(self, offer_id: str) -> dict:
        state = self._offers.pop(offer_id, None)
        if state is None:
            raise protocol_spec.ProtocolError("OFFER_UNKNOWN", {"offer_id": offer_id})
        for child in sorted(state.directory.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
        return {"offer_id": offer_id, "dropped": True}

    def _target(self, state: OfferState, relative: PurePosixPath) -> Path:
        root = state.directory.resolve()
        resolved = (root / str(relative)).resolve()
        if root not in resolved.parents:
            raise protocol_spec.ProtocolError("PATH_REJECTED", {"relpath": str(relative)})
        return resolved

    # -------------------------------------------------------------- routing

    def route(self, method: str, request: _RequestHandler) -> None:
        parts = [p for p in request.path.split("?")[0].split("/") if p]
        if method == "GET" and parts == ["v1", "hello"]:
            request._reply(200, self.handle_hello())
            return
        if method == "POST" and parts == ["v1", "pair"]:
            request._reply(200, self.handle_pair(request._json_body(), request.client_address[0]))
            return
        token = request.headers.get("X-Chuanshu-Auth", "")
        if not self.token_valid(token):
            raise protocol_spec.ProtocolError("NOT_PAIRED")
        if method == "POST" and parts == ["v1", "offer"]:
            request._reply(200, self.handle_offer(request._json_body(), self.caller_fingerprint(token)))
            return
        if method == "DELETE" and parts[:2] == ["v1", "offer"] and len(parts) == 3:
            request._reply(200, self.handle_abort(parts[2]))
            return
        if parts[:2] == ["v1", "offer"] and len(parts) >= 4:
            offer_id = parts[2]
            if method == "GET" and parts[3] == "state" and len(parts) == 4:
                request._reply(200, self.handle_state(offer_id))
                return
            if method == "POST" and parts[3] == "finalize" and len(parts) == 4:
                request._reply(200, self.handle_finalize(offer_id))
                return
            if method == "PUT" and parts[3] == "chunk" and len(parts) == 6:
                body = request._raw_body()
                # A sender that had to hide the zero bytes says so; the digest it signed is over these bytes.
                if request.headers.get(protocol_spec.CHUNK_ESCAPE_HEADER, "") == protocol_spec.CHUNK_ESCAPE_VALUE:
                    body = protocol_spec.unescape_chunk(body)
                request._reply(
                    200,
                    self.handle_chunk(
                        offer_id, parts[4], int(parts[5]), body, request.headers.get("X-Sha256", "")
                    ),
                )
                return
        raise protocol_spec.ProtocolError("OFFER_UNKNOWN", {"path": f"{method} {request.path}"})


def _raw(key: ed25519.Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _prepare(target: Path, size: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as handle:
        handle.truncate(size)


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(partial(handle.read, 1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
