"""Loader for the machine-readable protocol contract.

protocol/protocol.json is the single source of truth shared with the mobile repo;
nothing in app/net/ may hardcode a port, a chunk size or an error code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.i18n import _
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
    session_idle_timeout_s: int
    offer_idle_timeout_s: int
    pair_code_ttl_s: int
    pair_code_digits: int
    pair_code_static: bool
    passphrase_chars: int
    pair_code_max_fails: int
    pair_code_lock_s: int
    hello_features: tuple[str, ...]
    limits: dict[str, int]
    error_codes: dict[str, dict[str, Any]]

    def supports(self, peer_version: int) -> bool:
        return peer_version in self.compatible_versions

    def intersects(self, peer_versions: object, peer_version: int) -> bool:
        """spec §7: the two declared sets have to overlap before anything else is attempted.

        Reading only the peer's own ``protocol_version`` answers a different question - "which
        version is that machine", not "can we both speak one". A peer that names no set at all is
        one that predates the field, and the single number it prints is the only thing it can be
        speaking, so that number stands in for the set; refusing a missing field would turn every
        older device into a stranger, which is the same reason §3 falls back on ``fingerprint``
        when a peer has no ``served``.
        """
        if isinstance(peer_versions, (list, tuple)) and len(peer_versions) > 0:
            theirs = [int(one) for one in peer_versions]
        else:
            theirs = [peer_version]
        return any(one in self.compatible_versions for one in theirs)

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
        # spec §3/§4: floors for how long a stalled peer may hold the one session slot and how long
        # an accepted offer may go without a chunk before the receiver calls it abandoned.
        session_idle_timeout_s=int(transport["session_idle_timeout_s"]),
        offer_idle_timeout_s=int(transport["offer_idle_timeout_s"]),
        pair_code_ttl_s=int(transport["pair_code_ttl_s"]),
        pair_code_digits=int(transport["pair_code_digits"]),
        # A peer that has no opinion about this keeps rotating on pair_code_ttl_s, so the
        # field only ever opts a build out of rotation. Unknown keys are ignored by readers
        # that predate it (spec §7).
        pair_code_static=bool(transport.get("pair_code_static", False)),
        passphrase_chars=int(transport.get("passphrase_chars", 8)),
        # spec §3's throttle. Read from the contract like every other number here, with no fallback
        # value: a copy of this file that predates the keys must fail loudly at startup rather than
        # quietly pair-protect itself with a different 5 and 60 than the phone on the other end.
        pair_code_max_fails=int(transport["pair_code_max_fails"]),
        pair_code_lock_s=int(transport["pair_code_lock_s"]),
        # spec §7: hello's capability list. Nobody branches on it in v1 - compatibility is the
        # version intersection alone - but every end has to say the same three words.
        hello_features=tuple(str(one) for one in transport.get(
            "hello_features", ("resume", "chunk-hash", "directory"))),
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
        # A QR payload carries ONE version, so this is not §7's intersection - that question is asked
        # of the hello, which is the first thing read after the address in the payload is dialled.
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"peer_version": fields.get("v")})
    if "p" in fields and not fields["p"].isdigit():
        raise ProtocolError("UNSUPPORTED_PROTOCOL", {"qr_port": fields["p"]})
    return fields


def split_addr(text: str, proto: Protocol) -> tuple[str, int, str]:
    """Read ``host``, ``host:port`` or a pasted pairing payload.

    Returns ``(host, port, advertised_prefix)``; only the pasted form carries a prefix,
    which is why it gets checked against the certificate and the typed form does not.
    Shared by the window's 手输地址 dialog and ``python -m app.cli send``, because reaching a
    peer that never announced itself is the same three shapes on both sides.
    """
    if text.startswith(proto.qr_scheme):
        fields = parse_qr(text)
        return fields["h"], int(fields.get("p") or proto.transport_port), fields.get("f", "")
    host, sep, port = text.rpartition(":")
    if not sep:
        return text, proto.transport_port, ""
    if not host or not port.isdigit():
        raise ValueError(text)
    return host, int(port), ""


def pairing_secrets(text: str, proto: Protocol) -> tuple[str, str]:
    """The ``(code, passphrase)`` a pasted pairing payload carries; blanks for a bare ``host[:port]``.

    A payload is already the whole act of trust - the picture carries the same two secrets the
    screen shows (see ``DiscoveryService.pairing_qr``) - so a person who copied it should not have
    to read them aloud again. Explicit flags still win; this only fills what was left blank.
    """
    if not text.startswith(proto.qr_scheme):
        return "", ""
    fields = parse_qr(text)
    return fields.get("c", ""), fields.get("k", "")


#: No I/O/0/1: this is read out loud to another person and typed on a phone keypad. The one copy of
#: this table is what the minting side (``identity.new_passphrase``) and the two refusal sides below
#: both read, because a secret measured against a different alphabet than the one that minted it
#: would refuse a correct answer.
PASSPHRASE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

CODE_DIGITS = "0123456789"


def code_reject(code: str, proto: Protocol) -> str:
    """Why this code cannot be worth sending, or "" when it can.

    spec §3 hands the receiver one job with these two secrets: compare them for equality. So a
    hand-typed or pasted string that could never be what the other screen shows is not a weaker
    promise - it is one of the ``pair_code_max_fails`` wrong guesses that lock this source out of
    that peer for ``pair_code_lock_s``. Measuring it here is the difference between telling the
    person now and spending the quota for a typo.
    """
    if any(one not in CODE_DIGITS for one in code):
        return _("配对码只能是数字。")
    if len(code) != proto.pair_code_digits:
        return _("配对码是 {n} 位数字。").format(n=proto.pair_code_digits)
    return ""


def pass_reject(secret: str, proto: Protocol) -> str:
    """The same question about the second secret, where blank is an answer.

    Leaving the passphrase out means "this sender has none to offer" and pairs on the code alone
    (spec §3), so only what was actually typed gets measured. Case counts: the peer compares these
    bytes for equality, and a lowercase letter surfacing as an unexplained pairing failure is
    exactly the message this function exists to avoid.
    """
    if not secret:
        return ""
    if len(secret) != proto.passphrase_chars:
        return _("连接密码是 {m} 位。").format(m=proto.passphrase_chars)
    for one in secret:
        if one not in PASSPHRASE_ALPHABET:
            return _("连接密码只有大写字母和数字：{bad}").format(bad=one)
    return ""
