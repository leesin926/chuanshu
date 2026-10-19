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
    chunk_size: int
    max_parallel_chunks: int
    offer_wait_timeout_s: int
    pair_code_ttl_s: int
    pair_code_digits: int
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
    brand, ports, transport, limits = c["brand"], c["ports"], c["transport"], c["limits"]
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
        chunk_size=int(transport["chunk_size"]),
        max_parallel_chunks=int(transport["max_parallel_chunks"]),
        offer_wait_timeout_s=int(transport["offer_wait_timeout_s"]),
        pair_code_ttl_s=int(transport["pair_code_ttl_s"]),
        pair_code_digits=int(transport["pair_code_digits"]),
        limits={k: int(v) for k, v in limits.items()},
        error_codes=dict(c["error_codes"]),
    )


def qr_url(**fields: str) -> str:
    """chuanshu://p?... ; field order fixed so the two clients render the same string."""
    from urllib.parse import urlencode

    order = ("h", "p", "v", "f", "c")
    return f"{load().qr_scheme}?" + urlencode({k: fields[k] for k in order if k in fields})
