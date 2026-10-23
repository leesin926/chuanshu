"""Peer identity: an Ed25519 self-signed certificate and the pinned-peer list.

The trust anchor is the certificate's SPKI fingerprint, never peer_id: reinstalling
the app mints a new peer_id but the same fingerprint only if the key survives, so
the key file and the peer_id live together and are written atomically.

The pairing material (the code and the passphrase a user reads to the other side) is
stored next to the key for the same reason: it is only worth as much as the key that
signs with it, and both have to survive a restart so the QR a peer already scanned
still means something tomorrow.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import ssl
import threading
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
_PAIRING = "pairing.json"

#: No I/O/0/1: this is read out loud to another person and typed on a phone keypad.
PASSPHRASE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_pair_code(digits: int) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(digits))


def new_passphrase(chars: int) -> str:
    """The second secret. 8 of 32 symbols is far past what the 5-tries lockout can leak."""
    return "".join(secrets.choice(PASSPHRASE_ALPHABET) for _ in range(chars))


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


def _copy_pins(pins: dict[str, dict]) -> dict[str, dict]:
    return {k: dict(v) for k, v in pins.items()}


def _merge_pins(base: dict[str, dict], ours: dict[str, dict], theirs: dict[str, dict]) -> dict[str, dict]:
    """Three-way merge of two pin lists that both started from ``base``.

    A side that left an entry as it found it defers to the side that touched it, which is what
    keeps a peer pinned by the other process from being dropped and a peer revoked there from
    coming back. When both sides touched the same key ours wins, and it wins for a removal too:
    forgetting a device is the one change that must not be undone by a stale write.
    """
    merged: dict[str, dict] = {}
    for fingerprint in [*base, *ours, *theirs]:
        if fingerprint in merged:
            continue
        before, here, there = base.get(fingerprint), ours.get(fingerprint), theirs.get(fingerprint)
        if here == before:
            winner = there
        elif there == before:
            winner = here
        else:
            winner = here
        if winner is not None:
            merged[fingerprint] = dict(winner)
    return merged


class Identity:
    def __init__(self, directory: Path, peer_id: str, key: ed25519.Ed25519PrivateKey, cert: x509.Certificate):
        self.directory = directory
        self.peer_id = peer_id
        self.key = key
        self.cert = cert
        self._trusted: dict[str, dict] = {}
        #: The file as this process last saw it - the side both merges are taken against.
        self._trusted_on_disk: dict[str, dict] = {}
        #: One lock for both files, because both are read-modify-written against the disk copy.
        self._lock = threading.RLock()
        self._trusted_path = directory / _TRUSTED
        self._pairing: dict[str, str] = {}
        self._pairing_path = directory / _PAIRING
        self.load_trusted()
        self.load_pairing()

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.cert)

    # ------------------------------------------------------- pairing material

    @property
    def pair_code(self) -> str:
        self.sync_pairing()
        return self._pairing.get("code", "")

    @property
    def passphrase(self) -> str:
        self.sync_pairing()
        return self._pairing.get("passphrase", "")

    def _read_pairing(self) -> dict[str, str]:
        try:
            stored = json.loads(self._pairing_path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            log.exception("pairing.json unreadable, reminting: %s", self._pairing_path)
            return {}
        if isinstance(stored, dict) and stored.get("code") and stored.get("passphrase"):
            return {k: str(v) for k, v in stored.items() if k in ("code", "passphrase", "rotated")}
        return {}

    def load_pairing(self) -> None:
        with self._lock:
            self._pairing = self._read_pairing()

    def sync_pairing(self) -> None:
        """Pick up material the other process minted, as long as the file has some.

        The window shows the code in a QR and the terminal prints it, and only one of them can
        be right: whichever rotated last wrote the file, so the file wins over a cache that would
        otherwise keep offering a code the peer can no longer pair with.
        """
        with self._lock:
            stored = self._read_pairing()
            if stored:
                self._pairing = stored

    def ensure_pairing(self, code_digits: int, passphrase_chars: int) -> None:
        """Give this device its fixed code and passphrase, minting them on first run.

        Called by whoever is about to display or check them, because only that peer knows
        the lengths the contract asks for; the key itself has no opinion on the format.
        Material of a different length is reminted rather than kept: a code shorter or longer
        than the contract says is one the peer's input box will refuse to accept.
        """
        with self._lock:
            self.sync_pairing()
            if len(self._pairing.get("code") or "") == code_digits and len(self._pairing.get("passphrase") or "") == passphrase_chars:
                return
            self.rotate_pairing(code_digits, passphrase_chars)

    def rotate_pairing(self, code_digits: int, passphrase_chars: int) -> tuple[str, str]:
        """Replace both secrets with fresh ones. Pins and sessions are untouched: this
        only changes what a *stranger* has to get right before it can pin us."""
        self._pairing = {
            "code": new_pair_code(code_digits),
            "passphrase": new_passphrase(passphrase_chars),
            "rotated": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        }
        _atomic(self._pairing_path, json.dumps(self._pairing, ensure_ascii=False, indent=2))
        log.info("rotated pairing material (code and passphrase)")
        return self._pairing["code"], self._pairing["passphrase"]

    def raw_public_key(self) -> bytes:
        """The 32-byte Ed25519 key, as it travels inside a pair request."""
        return self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    # --------------------------------------------------------------- trust

    def _read_pins(self) -> dict[str, dict]:
        try:
            stored = json.loads(self._trusted_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            log.exception("trusted.json unreadable, treating it as empty: %s", self._trusted_path)
            return {}
        if not isinstance(stored, dict):
            return {}
        # Only name/peer_id records can be used at all - every read path does entry.get() -
        # so a hand-edited or half-written value of another shape is dropped rather than kept.
        return {k: v for k, v in stored.items() if isinstance(v, dict)}

    def load_trusted(self) -> None:
        """Take the pin list from the file, forgetting whatever was in memory."""
        with self._lock:
            self._trusted = _copy_pins(self._read_pins())
            self._trusted_on_disk = _copy_pins(self._trusted)

    def sync_trusted(self) -> None:
        """Reconcile with the file before believing an in-memory answer.

        The terminal ships next to the window now, and both open the same identity directory
        with a dict of their own. Without this, a long-running window neither notices the peer
        the CLI pinned a minute ago nor the one the CLI revoked.
        """
        with self._lock:
            self._trusted = _merge_pins(self._trusted_on_disk, self._trusted, self._read_pins())
            self._trusted_on_disk = _copy_pins(self._trusted)

    def save_trusted(self) -> None:
        """Merge with the file, then write the whole list.

        Writing memory over the file is what lost a peer the other process had just pinned;
        the merge also means this side's unsynced additions cannot resurrect a revocation.
        """
        with self._lock:
            self.sync_trusted()
            _atomic(self._trusted_path, json.dumps(self._trusted, ensure_ascii=False, indent=2))

    def is_trusted(self, fingerprint: str) -> bool:
        """Whether this number belongs to a pinned device - as its identity key, or as the
        certificate that device serves. A peer dialled by its TLS leaf is still the machine
        this end paired with (spec §3), so both numbers open the same door."""
        self.sync_trusted()
        if fingerprint in self._trusted:
            return True
        return any(str(entry.get("tls_fingerprint") or "") == fingerprint for entry in self._trusted.values())

    def trusted_entry(self, fingerprint: str) -> dict | None:
        self.sync_trusted()
        return self._trusted.get(fingerprint)

    def trust(self, fingerprint: str, peer_id: str, name: str, public_key: str = "", tls_fingerprint: str = "") -> None:
        """Pin a peer by key fingerprint; peer_id is metadata, never the anchor.

        ``tls_fingerprint`` is only for a peer whose served certificate is signed by a different key
        than the identity that just signed for it (spec §3). It is what lets this end recognise the
        device it dialled and the device that dialled in as one machine instead of two.
        """
        entry: dict = {"peer_id": peer_id, "name": name, "public_key": public_key}
        if tls_fingerprint:
            entry["tls_fingerprint"] = tls_fingerprint
        with self._lock:
            self._trusted[fingerprint] = entry
            self.save_trusted()
        log.info("pinned peer %s (%s)", name, fingerprint[:12])

    def remember_peer(self, fingerprint: str, peer_id: str, name: str, tls_fingerprint: str = "") -> None:
        """Refresh metadata for an already pinned key after its peer_id changed."""
        with self._lock:
            self.sync_trusted()
            entry = self._trusted.get(fingerprint)
            if entry is None:
                return
            before = dict(entry)
            if tls_fingerprint:
                entry["tls_fingerprint"] = tls_fingerprint
            entry.update({"peer_id": peer_id, "name": name})
            if entry != before:
                self.save_trusted()

    def same_peer(self, a: str, b: str) -> bool:
        """Two fingerprints, one device: a peer is pinned by its identity key but dialled by the
        certificate it serves, and only a device whose §3 declaration says they belong together
        has two different numbers here."""
        if not a or not b:
            return False
        if a == b:
            return True
        self.sync_trusted()
        for key, entry in self._trusted.items():
            leaf = str(entry.get("tls_fingerprint") or "")
            if leaf and ((key == a and leaf == b) or (key == b and leaf == a)):
                return True
        return False

    def pinned_fingerprints(self) -> list[str]:
        self.sync_trusted()
        return sorted(self._trusted)

    def untrust(self, fingerprint: str) -> bool:
        """Forget one pinned key. That device has to be paired again from scratch."""
        with self._lock:
            self.sync_trusted()
            gone = self._trusted.pop(fingerprint, None)
            if gone is None:
                return False
            self.save_trusted()
        log.info("unpinned peer %s (%s)", gone.get("name", "?"), fingerprint[:12])
        return True

    # ------------------------------------------------------------- TLS

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(self.directory / _CERT), str(self.directory / _KEY))
        return ctx


def _atomic(path: Path, text: str) -> None:
    """Write through a temp file so a crash cannot leave a half-written JSON or PEM.

    On POSIX the temp file is created 0600 instead of the umask's default: everything here
    is identity material, and one of those files is an unencrypted private key that a 0644
    would hand to every other account on the machine. Windows keeps its ACL inheritance.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if os.name == "posix":
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.close(fd)
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


def _harden_key_file(path: Path) -> None:
    """Bring a key written before this rule existed back to owner-only.

    The 0600 in ``_atomic`` only protects files created from now on; a machine that already
    ran an older build has a group- and world-readable private key sitting in it, and quietly
    leaving that alone would mean the fix only applies to fresh installs.
    """
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
        if mode & 0o077:
            path.chmod(0o600)
            log.info("tightened %s from %o to 600", path.name, mode & 0o777)
    except OSError as error:  # A read-only home or a foreign owner is not worth crashing over.
        log.warning("could not tighten %s: %s", path.name, error)


def load_or_create(directory: Path | None = None) -> Identity:
    directory = directory or identity_dir()
    directory.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = directory / _KEY, directory / _CERT
    if key_path.is_file() and cert_path.is_file():
        _harden_key_file(key_path)
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
    pair code that both screens show at the same time (spec §3).
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
