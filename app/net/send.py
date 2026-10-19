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
import json
import logging
import mimetypes
import secrets
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Iterable

from app.net import spec as protocol_spec
from app.net.identity import Identity, client_context, verify_pinned

log = logging.getLogger(__name__)

#: relpath, chunk index, total chunks in this offer
Progress = Callable[[str, int, int], None]


class PairNeeded(RuntimeError):
    """The peer does not know our key yet, so its 4-digit code has to be entered."""

    def __init__(self, reason: str = "peer does not recognise our key") -> None:
        super().__init__(reason)
        self.reason = reason


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
    root = base or Path.home()
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
        self._conn: http.client.HTTPSConnection | None = None

    # ------------------------------------------------------------- transport

    def _connect(self) -> http.client.HTTPSConnection:
        self.close()
        conn = http.client.HTTPSConnection(self.host, self.port, context=client_context(), timeout=60)
        conn.connect()
        verify_pinned(conn.sock, self.fingerprint)
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _once(self, method: str, path: str, body: bytes, headers: dict) -> tuple[int, dict, bytes]:
        merged = dict(headers)
        if self.token:
            merged.setdefault("X-Chuanshu-Auth", self.token)
        merged["Content-Length"] = str(len(body))
        for attempt in (0, 1):
            conn = self._conn if self._conn is not None else self._connect()
            try:
                conn.request(method, path, body=body, headers=merged)
                response = conn.getresponse()
                raw = response.read()
            except (http.client.HTTPException, OSError):
                # A keep-alive connection dies quietly between transfers; one retry.
                self._conn = None
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
            return response.status, payload, raw
        raise http.client.HTTPException(f"{method} {path} failed twice")

    def _request(self, method: str, path: str, json_body: dict | None = None, raw_body: bytes = b"", headers: dict | None = None) -> tuple[int, dict]:
        body = raw_body
        merged = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            merged["Content-Type"] = "application/json"
        status, payload, _ = self._once(method, path, body, merged)
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
        status, payload = self._request("GET", "/v1/hello")
        if status != 200:
            raise protocol_spec.ProtocolError(str(payload.get("code")), payload.get("detail"))
        if not self.proto.supports(int(payload.get("protocol_version") or 0)):
            raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"peer_version": payload.get("protocol_version")})
        self.peer = payload
        return payload

    def pair(self, code: str = "") -> dict:
        nonce = secrets.token_hex(16)
        message = f"pair|{self.identity.peer_id}|{nonce}".encode("utf-8")
        status, payload = self._request(
            "POST",
            "/v1/pair",
            json_body={
                "peer_id": self.identity.peer_id,
                "name": self.device_name,
                "protocol_version": self.proto.version,
                "nonce": nonce,
                "public_key": base64.b64encode(self.identity.raw_public_key()).decode(),
                "signature": base64.b64encode(self.identity.key.sign(message)).decode(),
                "code": code,
            },
        )
        if status == 403 and payload.get("code") == "BAD_PAIR_CODE":
            raise PairNeeded()
        if status != 200:
            raise protocol_spec.ProtocolError(str(payload.get("code") or "NOT_PAIRED"), payload.get("detail"))
        self.token = str(payload["token"])
        self.peer = payload
        self.identity.trust(str(payload["fingerprint"]), str(payload["peer_id"]), str(payload.get("name", "")))
        log.info("paired with %s (resumed=%s)", payload.get("name"), payload.get("resumed"))
        return payload

    # --------------------------------------------------------------- transfer

    def offer(self, files: list[OutgoingFile]) -> dict:
        manifest = {
            "offer_id": secrets.token_hex(8),
            "protocol_version": self.proto.version,
            "total_size": sum(f.size for f in files),
            "from": {"peer_id": self.identity.peer_id, "name": self.device_name},
            "files": [f.manifest() for f in files],
        }
        state = self._call("POST", "/v1/offer", json_body=manifest)
        self.offer_id = str(manifest["offer_id"])
        self._manifest = manifest
        log.info("offer %s accepted (%d files)", self.offer_id[:8], len(files))
        return {"manifest": manifest, "state": state}

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

    def transfer(self, files: list[OutgoingFile], code: str = "", progress: Progress | None = None) -> dict:
        self.hello()
        if not self.identity.is_trusted(self.fingerprint):
            self.pair(code)
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
            status, payload = self._request("PUT", path, raw_body=data, headers={"X-Sha256": _digest(data)})
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
                continue
            raise protocol_spec.ProtocolError(str(payload.get("code") or "CHUNK_DIGEST_MISMATCH"), payload.get("detail"))
