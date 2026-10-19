"""Peer identity: an Ed25519 self-signed certificate and the pinned-peer list.

The trust anchor is the certificate's SPKI fingerprint, never peer_id: reinstalling
the app mints a new peer_id but the same fingerprint only if the key survives, so
the key file and the peer_id live together and are written atomically.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import secrets
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from app.paths import identity_dir

log = logging.getLogger(__name__)

_KEY = "peer-key.pem"
_CERT = "peer-cert.pem"
_TRUSTED = "trusted.json"


def new_pair_code(digits: int) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(digits))


def _spki_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint_of(cert: x509.Certificate) -> str:
    """SHA-256 over the SubjectPublicKeyInfo, the value pinned at pairing time."""
    return hashlib.sha256(_spki_der(cert.public_key())).hexdigest()


def fingerprint_of_public_key(key) -> str:
    """The same digest computed from a bare public key, for pinning a peer we have
    no certificate for (only its Ed25519 key arrives in the pair request)."""
    return hashlib.sha256(_spki_der(key)).hexdigest()


class Identity:
    def __init__(self, directory: Path, peer_id: str, key: ed25519.Ed25519PrivateKey, cert: x509.Certificate):
        self.directory = directory
        self.peer_id = peer_id
        self.key = key
        self.cert = cert
        self._trusted: dict[str, dict] = {}
        self._trusted_path = directory / _TRUSTED
        self.load_trusted()

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.cert)

    def raw_public_key(self) -> bytes:
        """The 32-byte Ed25519 key, as it travels inside a pair request."""
        return self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    # --------------------------------------------------------------- trust

    def load_trusted(self) -> None:
        try:
            stored = json.loads(self._trusted_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            log.exception("trusted.json unreadable, starting with an empty pin list: %s", self._trusted_path)
            return
        if isinstance(stored, dict):
            self._trusted = stored

    def save_trusted(self) -> None:
        _atomic(self._trusted_path, json.dumps(self._trusted, ensure_ascii=False, indent=2))

    def is_trusted(self, fingerprint: str) -> bool:
        return fingerprint in self._trusted

    def trusted_entry(self, fingerprint: str) -> dict | None:
        return self._trusted.get(fingerprint)

    def trust(self, fingerprint: str, peer_id: str, name: str, public_key: str = "") -> None:
        """Pin a peer by key fingerprint; peer_id is metadata, never the anchor."""
        self._trusted[fingerprint] = {"peer_id": peer_id, "name": name, "public_key": public_key}
        self.save_trusted()
        log.info("pinned peer %s (%s)", name, fingerprint[:12])

    def remember_peer(self, fingerprint: str, peer_id: str, name: str) -> None:
        """Refresh metadata for an already pinned key after its peer_id changed."""
        entry = self._trusted.get(fingerprint)
        if entry is not None and (entry.get("peer_id") != peer_id or entry.get("name") != name):
            entry.update({"peer_id": peer_id, "name": name})
            self.save_trusted()

    def pinned_fingerprints(self) -> list[str]:
        return sorted(self._trusted)

    # ------------------------------------------------------------- TLS

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(self.directory / _CERT), str(self.directory / _KEY))
        return ctx


def _atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _self_signed(peer_id: str, key: ed25519.Ed25519PrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, peer_id)])
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, None)
    )


def load_or_create(directory: Path | None = None) -> Identity:
    directory = directory or identity_dir()
    directory.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = directory / _KEY, directory / _CERT
    if key_path.is_file() and cert_path.is_file():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        peer_id = str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        return Identity(directory, peer_id, key, cert)

    peer_id = secrets.token_hex(16)
    key = ed25519.Ed25519PrivateKey.generate()
    cert = _self_signed(peer_id, key)
    _atomic(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    _atomic(cert_path, cert.public_bytes(serialization.Encoding.PEM).decode())
    _atomic(
        directory / "peer.json",
        json.dumps({"peer_id": peer_id, "created": dt.datetime.now(dt.UTC).isoformat()}, indent=2),
    )
    log.info("created peer identity %s", peer_id[:12])
    return Identity(directory, peer_id, key, cert)


def _peer_fingerprint(conn: ssl.SSLSocket) -> str:
    der = conn.getpeercert(binary_form=True)
    if der is None:
        raise ssl.SSLError("peer sent no certificate")
    return fingerprint_of(x509.load_der_x509_certificate(der))


def verify_pinned(conn: ssl.SSLSocket, expected_fingerprint: str) -> None:
    """Accept a peer only if its SPKI digest is the one the QR/pin list promised.

    The client context runs with certificate verification off (there is no CA), so
    this check after the handshake is the entire authentication step. Note the digest
    is over the SubjectPublicKeyInfo, not over the whole certificate: a re-signed cert
    with the same key keeps the same fingerprint, which is what makes reinstalling a
    peer non-breaking.
    """
    if _peer_fingerprint(conn) != expected_fingerprint:
        raise ssl.SSLError("SPKI fingerprint does not match the pinned value")


def read_fingerprint(conn: ssl.SSLSocket, advertised_prefix: str = "") -> str:
    """Fingerprint of a peer we have not paired with yet, as advertised by discovery.

    A prefix is all mDNS and the UDP announce carry (spec §2), so this can only reject a
    wrong-address collision - it is not authentication. Real trust arrives with the
    4-digit code that both screens show at the same time (spec §3).
    """
    digest = _peer_fingerprint(conn)
    if advertised_prefix and not digest.startswith(advertised_prefix):
        raise ssl.SSLError("certificate does not match the discovered fingerprint prefix")
    return digest


def client_context() -> ssl.SSLContext:
    """No CA exists: verification happens by fingerprint in verify_pinned()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
