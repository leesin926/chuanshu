"""Loader for the machine-readable protocol contract.

protocol/protocol.json is the single source of truth shared with the mobile repo;
nothing in app/net/ may hardcode a port, a chunk size or an error code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.paths import resource_path


class ProtocolError(Exception):
    """A protocol-level failure that maps onto one error code in the contract."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Protocol:
    version: int
    compatible_versions: tuple[int, ...]
    technical_name: str
    display_name_zh: str
    package_id: str
    mdns_service_type: str
    qr_scheme: str
    transport_port: int
    discovery_port: int
    announce_interval_s: float
    peer_expiry_s: float
    prefix_chars: int
    chunk_size: int
    max_parallel_chunks: int
    offer_wait_timeout_s: int
    pair_code_ttl_s: int
    pair_code_digits: int
    pair_code_static: bool
    passphrase_chars: int
    limits: dict[str, int]
    error_codes: dict[str, dict[str, Any]]

    def supports(self, peer_version: int) -> bool:
        return peer_version in self.compatible_versions

    def http_status(self, code: str) -> int:
        entry = self.error_codes.get(code)
        if entry is None:
            raise ProtocolError("UNSUPPORTED_PROTOCOL", {"unknown_error_code": code})
        return int(entry["http"])

    def msgid(self, code: str) -> str:
        entry = self.error_codes.get(code)
        if entry is None:
            raise ProtocolError("UNSUPPORTED_PROTOCOL", {"unknown_error_code": code})
        return str(entry["msgid"])


def _contract() -> dict:
    return json.loads(resource_path("protocol", "protocol.json").read_text(encoding="utf-8-sig"))


def load() -> Protocol:
    c = _contract()
    brand, ports, transport, limits, discovery = c["brand"], c["ports"], c["transport"], c["limits"], c["discovery"]
    return Protocol(
        version=int(c["protocol_version"]),
        compatible_versions=tuple(int(v) for v in c["compatible_versions"]),
        technical_name=brand["technical_name"],
        display_name_zh=brand["display_name_zh"],
        package_id=brand["package_id"],
        mdns_service_type=brand["mdns_service_type"],
        qr_scheme=brand["qr_scheme"],
        transport_port=int(ports["transport_default"]),
        discovery_port=int(ports["discovery_udp"]),
        announce_interval_s=float(discovery["announce_interval_s"]),
        peer_expiry_s=float(discovery["peer_expiry_s"]),
        prefix_chars=int(discovery["fingerprint_prefix_chars"]),
        chunk_size=int(transport["chunk_size"]),
        max_parallel_chunks=int(transport["max_parallel_chunks"]),
        offer_wait_timeout_s=int(transport["offer_wait_timeout_s"]),
        pair_code_ttl_s=int(transport["pair_code_ttl_s"]),
        pair_code_digits=int(transport["pair_code_digits"]),
        # A peer that has no opinion about this keeps rotating on pair_code_ttl_s, so the
        # field only ever opts a build out of rotation. Unknown keys are ignored by readers
        # that predate it (spec §7).
        pair_code_static=bool(transport.get("pair_code_static", False)),
        passphrase_chars=int(transport.get("passphrase_chars", 8)),
        limits={k: int(v) for k, v in limits.items()},
        error_codes=dict(c["error_codes"]),
    )


def qr_url(**fields: str) -> str:
    """chuanshu://p?... ; field order fixed so the two clients render the same string."""
    from urllib.parse import urlencode

    order = ("h", "p", "v", "f", "c", "k")
    return f"{load().qr_scheme}?" + urlencode({k: fields[k] for k in order if k in fields and fields[k]})


def is_fingerprint(text: str) -> bool:
    """A whole 64-hex SPKI digest. The prefix shown on screen is never what gets checked."""
    return len(text) == 64 and all(c in "0123456789abcdef" for c in text.lower())


def pair_message(peer_id: str, nonce: str, tls_fingerprint: str = "") -> bytes:
    """The exact bytes POST /v1/pair's signature covers (spec §3).

    Both ends build it here, because the fourth field is the only thing that names a peer whose TLS
    certificate is signed by a different key than its identity - and agreeing on three-versus-four
    the same way on both sides is what lets an old build and a new one still pair.
    """
    parts = ["pair", peer_id, nonce]
    if tls_fingerprint:
        parts.append(tls_fingerprint)
    return "|".join(parts).encode("utf-8")


_ESC = 0x1B
_ESC_NUL = "B".encode()

CHUNK_ESCAPE_HEADER = "X-Chunk-Escape"
CHUNK_ESCAPE_VALUE = "stu"


def escape_chunk(data: bytes) -> tuple[bytes, str]:
    """Rewrite a PUT body so it contains no zero byte, and say which header declares that.

    A Harmony peer's TLS server hands JavaScript only the bytes in front of the first 0x00 and then stops
    reading that connection - the rest of the record never arrives (``.probe/nul.py``, four rows). Raw file
    contents are full of zeros, so a chunk as the contract defines it cannot cross to that end at all.
    This encoding keeps every other byte literal: ``0x1B`` doubles, and ``0x00`` becomes ``ESC B``.

    Returns ``(bytes, "")`` untouched when there is nothing to hide, so text-shaped chunks and peers that
    can take a zero byte see exactly the request they used to. ``X-Sha256`` stays the digest of the
    *original* chunk; the header only describes how the bytes travelled.
    """
    if b"\x00" not in data:
        return data, ""
    return data.replace(b"\x1b", b"\x1b\x1b").replace(b"\x00", b"\x1b" + _ESC_NUL), CHUNK_ESCAPE_VALUE


def unescape_chunk(data: bytes) -> bytes:
    """Undo :func:`escape_chunk`. Only called on a body whose header declared the encoding."""
    if b"\x1b" not in data:
        return data
    out = bytearray()
    i = 0
    while True:
        at = data.find(b"\x1b", i)
        if at < 0:
            out += data[i:]
            break
        out += data[i:at]
        following = data[at + 1] if at + 1 < len(data) else -1
        if following == 0x1B:
            out.append(_ESC)
            i = at + 2
        elif data[at + 1:at + 2] == _ESC_NUL:
            out.append(0)
            i = at + 2
        else:
            out.append(_ESC)
            i = at + 1
    return bytes(out)


def parse_qr(url: str) -> dict[str, str]:
    """Read a pairing payload off a QR or a typed-in string.

    Parsing is order-independent and ignores unknown keys, so a newer peer may add fields
    without making this end reject the code (spec §7: fields only grow).
    """
    from urllib.parse import parse_qsl, urlsplit

    proto = load()
    parts = urlsplit(url.strip())
    if f"{parts.scheme}://{parts.netloc}" != proto.qr_scheme:
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"qr_scheme": parts.scheme})
    fields = {k: v for k, v in parse_qsl(parts.query) if k in ("h", "p", "v", "f", "c", "k")}
    missing = {"h", "f"} - set(fields)
    if missing:
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"qr_missing_fields": sorted(missing)})
    if not is_fingerprint(fields["f"]):
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"qr_fingerprint": fields["f"][:16]})
    if not fields.get("v", "").isdigit() or not proto.supports(int(fields["v"])):
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"peer_version": fields.get("v")})
    if "p" in fields and not fields["p"].isdigit():
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"qr_port": fields["p"]})
    return fields
