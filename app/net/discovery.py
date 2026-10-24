"""LAN discovery: mDNS first, UDP broadcast as backup, QR or a typed address as the way out.

Presence is not trust. Both channels advertise only a fingerprint *prefix*, because a
digest is the anchor you pin at pairing time (spec §1) and a broadcast cannot carry a
promise. A candidate therefore has to pass verify(), which reads the full fingerprint
from /v1/hello and checks it against that prefix, before it can be paired.

The reason each channel is up or down lives in ``channels`` rather than in the log: the
UI has to say "mDNS unavailable, use the code" instead of showing an empty device list.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from app.net import spec as protocol_spec
from app.net.identity import Identity, client_context, read_fingerprint

log = logging.getLogger(__name__)

#: How often the roster is pruned - finer than the expiry it enforces, coarser than the
#: announce that feeds it.
SWEEP_DIVISOR = 3
BROADCAST_TARGET = "255.255.255.255"


def local_ipv4() -> str:
    """The address other machines reach this one on.

    A UDP ``connect`` sends nothing; it only asks the routing table which interface and
    source address would be used, which is the portable way to get a real NIC address.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        return str(probe.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


@dataclass
class Channel:
    """One discovery path and why it is or is not usable - the UI shows this verbatim."""

    state: str = "stopped"  # stopped | ok | unavailable
    detail: str = ""


@dataclass
class Peer:
    prefix: str
    host: str
    port: int
    peer_id: str = ""
    name: str = ""
    version: int = 0
    fingerprint: str = ""
    via: set[str] = field(default_factory=set)
    seen: float = 0.0

    @property
    def verified(self) -> bool:
        return bool(self.fingerprint)

    def public(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "peer_id": self.peer_id,
            "name": self.name,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "via": sorted(self.via),
        }


def adopt_hello(proto: protocol_spec.Protocol, peer: Peer, digest: str, body: dict) -> None:
    """Fold a peer's /v1/hello into what we know about it.

    The port we dial is a fact about *this* machine's routing; the port in the hello is only the
    peer's description of itself, and behind a forward (adb/hdc fport, socat, WSL or SSH port
    mapping) it names the other side of the translation, which we cannot reach. Adopting it used to
    send every request after the hello to a dead port, and let a stranger redirect a client's
    traffic by declaring one. So a mismatch is logged, never followed.
    """
    peer.fingerprint = digest
    peer.peer_id = str(body.get("peer_id", peer.peer_id))
    peer.name = str(body.get("name", peer.name))
    peer.version = int(body["protocol_version"])
    advertised = int(body.get("port") or 0)
    if advertised and advertised != peer.port:
        log.info("%s calls its own port %d, but the connection lives on %d", peer.prefix, advertised, peer.port)
    log.info("verified %s as %s (%s)", peer.prefix, peer.name, digest[: proto.prefix_chars])


def verify_peer(proto: protocol_spec.Protocol, peer: Peer) -> Peer:
    """Read a peer's full SPKI digest over TLS and fill in what it says about itself.

    The advertised prefix only proves the machine at that address is the one that
    announced itself. Trust in the sense of spec §3 still needs the pair code both
    screens show, because an on-LAN attacker that hijacked the announcement would pass
    this check with its own key. This needs no discovery service, so a hand-typed
    address is checkable even while this machine is not listening.
    """
    conn = http.client.HTTPSConnection(peer.host, peer.port, context=client_context(), timeout=5.0)
    try:
        # connect() first, and read the certificate off that socket before any reply is consumed.
        # A peer that answers /v1/hello with Connection: close - the phones do - makes http.client
        # hang up the socket while read() finishes, and by then conn.sock is None: the address that
        # was reachable would report as unpinnable. Reading before the reply is also the honest order,
        # since the prefix check is what decides whether to believe anything this machine says.
        conn.connect()
        digest = read_fingerprint(conn.sock, peer.prefix)
        conn.request("GET", "/v1/hello")
        response = conn.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        if response.status != 200:
            raise protocol_spec.ProtocolError(str(body.get("code") or "UNSUPPORTED_PROTOCOL"), body)
    finally:
        conn.close()
    if not proto.supports(int(body.get("protocol_version") or 0)):
        raise protocol_spec.ProtocolError("UNSUPPORTED_PROTOCOL", {"peer_version": body.get("protocol_version")})
    adopt_hello(proto, peer, digest, body)
    return peer


class DiscoveryService:
    def __init__(
        self,
        identity: Identity,
        device_name: str,
        port: int,
        on_change: Callable[[], None] | None = None,
        broadcast_target: str = BROADCAST_TARGET,
    ) -> None:
        self.proto = protocol_spec.load()
        self.identity = identity
        self.device_name = device_name
        self.port = port
        # The prefix of the certificate the socket hands out, not of the identity key: verify_peer()
        # below reads a digest off a live TLS connection and compares it to this, and spec §2 only
        # excludes "地址撞错机器" if both numbers describe the same thing.
        self.prefix = identity.served_fingerprint[: self.proto.prefix_chars]
        self.on_change = on_change
        self.broadcast_target = broadcast_target
        self.channels: dict[str, Channel] = {"mdns": Channel(), "udp": Channel()}
        self.started_at = int(time.time())
        self._peers: dict[str, Peer] = {}
        self._mdns_names: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._zeroconf = None
        self._service_info = None
        self._browser = None
        self._udp_socket: socket.socket | None = None

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self._stop.clear()
        self._start_mdns()
        self._start_udp()
        self._spawn(self._announce_loop, "announce")
        self._spawn(self._sweep_loop, "sweep")
        log.info(
            "discovery started on %s (channels: %s)",
            self.prefix,
            {name: channel.state for name, channel in self.channels.items()},
        )

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=3.0)
        self._threads.clear()
        if self._zeroconf is not None:
            try:
                if self._browser is not None:
                    self._browser.cancel()
                if self._service_info is not None:
                    self._zeroconf.unregister_service(self._service_info)
                self._zeroconf.close()
            except Exception:  # noqa: BLE001 - shutdown must not raise into the UI
                log.exception("mDNS shutdown failed")
            self._zeroconf = None
        if self._udp_socket is not None:
            self._udp_socket.close()
            self._udp_socket = None
        for channel in self.channels.values():
            channel.state = "stopped"

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=target, name=f"chuanshu-{name}", daemon=True)
        self._threads.append(thread)
        thread.start()

    # ----------------------------------------------------------------------- mdns

    def _start_mdns(self) -> None:
        channel = self.channels["mdns"]
        try:
            from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
        except ImportError:
            channel.state, channel.detail = "unavailable", "zeroconf is not installed"
            log.warning("mDNS disabled: zeroconf is not installed")
            return

        service_type = self.proto.mdns_service_type
        instance = f"{self.proto.technical_name}-{self.identity.peer_id[:8]}"
        try:
            self._zeroconf = Zeroconf()
            self._service_info = ServiceInfo(
                service_type,
                f"{instance}.{service_type}",
                addresses=[socket.inet_aton(local_ipv4())],
                port=self.port,
                properties={
                    "ver": str(self.proto.version),
                    "name": self.device_name,
                    "fp": self.prefix,
                    "ts": str(self.started_at),
                },
                server=f"{instance}.local.",
            )
            self._zeroconf.register_service(self._service_info)
            self._browser = ServiceBrowser(self._zeroconf, service_type, listener=_MdnsListener(self))
            channel.state = "ok"
        except Exception as error:  # noqa: BLE001 - a broken multicast stack is not fatal
            channel.state, channel.detail = "unavailable", str(error)
            log.warning("mDNS registration failed: %s", error)

    def _on_mdns_record(self, info) -> None:
        if info is None:
            return
        properties = {
            (k.decode("utf-8") if isinstance(k, bytes) else k): (v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v))
            for k, v in (info.properties or {}).items()
        }
        prefix = properties.get("fp", "")
        if not prefix:
            log.debug("ignoring mDNS service without a fingerprint prefix: %s", info.name)
            return
        addresses = [a for a in info.parsed_addresses() if "." in a]
        if not addresses:
            return
        self._learn(
            prefix=prefix,
            host=addresses[0],
            port=int(info.port),
            peer_id="",
            name=properties.get("name", ""),
            version=int(properties.get("ver") or 0),
            via="mdns",
        )

    def _forget_mdns(self, prefix: str) -> None:
        """mDNS says the service left; UDP may still be announcing it, so only expire it."""
        with self._lock:
            peer = self._peers.get(prefix)
            if peer is not None:
                peer.via.discard("mdns")

    # ---------------------------------------------------------------- UDP announce

    def _start_udp(self) -> None:
        channel = self.channels["udp"]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.proto.discovery_port))
            sock.settimeout(1.0)
        except OSError as error:
            channel.state, channel.detail = "unavailable", str(error)
            sock.close()
            log.warning("UDP discovery disabled (%s); pairing still works by QR or IP", error)
            return
        self._udp_socket = sock
        channel.state = "ok"
        self._spawn(self._udp_listen_loop, "udp-listen")

    def _announce_packet(self) -> bytes:
        return json.dumps(
            {
                "peer_id": self.identity.peer_id,
                "port": self.port,
                "v": self.proto.version,
                "name": self.device_name,
                "fp": self.prefix,
                "ts": self.started_at,
            },
            ensure_ascii=False,
        ).encode("utf-8")

    def announce(self, target: str | None = None) -> None:
        """Send one announcement. Unicast works too, which is how a hidden network or a
        test can be fed without trusting broadcast to get through."""
        sock = self._udp_socket
        if sock is None:
            return
        try:
            sock.sendto(self._announce_packet(), (target or self.broadcast_target, self.proto.discovery_port))
        except OSError as error:
            log.debug("announce to %s failed: %s", target or self.broadcast_target, error)

    def _announce_loop(self) -> None:
        self.announce()
        while not self._stop.wait(self.proto.announce_interval_s):
            self.announce()

    def _udp_listen_loop(self) -> None:
        sock = self._udp_socket
        while not self._stop.is_set() and sock is not None:
            try:
                raw, addr = sock.recvfrom(4096)
            except OSError:
                continue
            except Exception:  # noqa: BLE001
                log.exception("UDP receive failed")
                continue
            try:
                body = json.loads(raw.decode("utf-8"))
                self._learn(
                    prefix=str(body["fp"]),
                    host=addr[0],
                    port=int(body["port"]),
                    peer_id=str(body.get("peer_id", "")),
                    name=str(body.get("name", "")),
                    version=int(body.get("v") or 0),
                    via="udp",
                )
            except (ValueError, KeyError, TypeError):
                log.debug("ignoring malformed announce from %s", addr)

    # --------------------------------------------------------------------- roster

    def _learn(self, *, prefix: str, host: str, port: int, peer_id: str, name: str, version: int, via: str) -> None:
        if prefix == self.prefix:
            # Own broadcast coming back (loopback delivers it right here), or own mDNS
            # record: you are not a device to pair with.
            return
        if not self.proto.supports(version):
            log.info("dropping %s (%s): protocol v%s is not compatible", prefix, name, version)
            return
        with self._lock:
            peer = self._peers.get(prefix)
            if peer is None:
                peer = Peer(prefix=prefix, host=host, port=port, seen=time.monotonic())
                self._peers[prefix] = peer
                log.info("discovered %s via %s", prefix, via)
            peer.host, peer.port = host, port
            peer.via.add(via)
            peer.seen = time.monotonic()
            if peer_id:
                peer.peer_id = peer_id
            if name and not peer.name:
                peer.name = name
            peer.version = version
        self._notify()

    def _sweep_loop(self) -> None:
        interval = self.proto.peer_expiry_s / SWEEP_DIVISOR
        while not self._stop.wait(interval):
            cutoff = time.monotonic() - self.proto.peer_expiry_s
            with self._lock:
                stale = [prefix for prefix, peer in self._peers.items() if peer.seen < cutoff]
                for prefix in stale:
                    del self._peers[prefix]
            if stale:
                log.debug("expired candidates: %s", ", ".join(stale))
                self._notify()

    def candidates(self) -> list[Peer]:
        with self._lock:
            return sorted(self._peers.values(), key=lambda p: (p.name or p.prefix, p.host))

    def _notify(self) -> None:
        if self.on_change is not None:
            try:
                self.on_change()
            except Exception:  # noqa: BLE001 - a UI callback must not kill discovery
                log.exception("discovery change callback failed")

    # -------------------------------------------------------------------- trust

    def verify(self, peer: Peer) -> Peer:
        """Turn a broadcast into a peer you may pin, then tell the roster about it."""
        verify_peer(self.proto, peer)
        self._notify()
        return peer

    def pairing_qr(self, code: str, host: str = "", passphrase: str = "") -> str:
        """What the receiving screen paints so the other side can skip discovery.

        The picture carries the same two secrets the screen shows, because scanning and
        reading-aloud are the same act of trust: whoever can photograph the QR can already
        read the code off it. ``k`` is left out when this build has no passphrase, so an
        older scanner still gets a payload it can parse. The ``f`` is the leaf the socket
        serves, because that is the number a scanner pins; the identity key that signs the
        pair message is a different number and goes inside that message (spec §3).
        """
        fields = {"h": host or local_ipv4(), "p": str(self.port), "v": str(self.proto.version)}
        if passphrase:
            fields["k"] = passphrase
        return protocol_spec.qr_url(f=self.identity.served_fingerprint, c=code, **fields)


class _MdnsListener:
    """Adapter for zeroconf's ServiceListener protocol."""

    def __init__(self, service: DiscoveryService) -> None:
        self.service = service

    def _resolve(self, zc, name: str) -> None:
        info = zc.get_service_info(self.service.proto.mdns_service_type, name, timeout=1500)
        if info is None:
            return
        prefix = ""
        for key, value in (info.properties or {}).items():
            text = key.decode("utf-8") if isinstance(key, bytes) else key
            if text == "fp":
                prefix = (value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value))
        if prefix:
            # remove_service only gets the service name, and the roster is keyed by
            # fingerprint prefix, so remember which name resolved to which prefix.
            self.service._mdns_names[name] = prefix
        self.service._on_mdns_record(info)

    def add_service(self, zc, type_: str, name: str) -> None:
        self._resolve(zc, name)

    def update_service(self, zc, type_: str, name: str) -> None:
        self._resolve(zc, name)

    def remove_service(self, zc, type_: str, name: str) -> None:
        prefix = self.service._mdns_names.pop(name, "")
        if prefix:
            self.service._forget_mdns(prefix)
