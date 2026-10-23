"""Localized text for protocol error codes.

protocol/protocol.json owns the codes and their Chinese msgids; the literals below
exist so Babel can extract them, and scripts/protocol_selftest.py asserts the two
sets stay identical. Do not add a code in one place only.

The table holds message ids, not translated strings: this module is imported while
the app is still starting up, so text picked here would freeze in whatever language
happened to be loaded at that moment, which for a headless run is Chinese.
"""

from __future__ import annotations

from app.i18n import N, _

_LABELS = {
    "UNSUPPORTED_PROTOCOL": N("对端版本不兼容"),
    "NOT_PAIRED": N("尚未与这台设备配对"),
    "BAD_PAIR_CODE": N("配对码不正确或已过期"),
    "DECLINED": N("对方拒绝了这次传输"),
    "OFFER_UNKNOWN": N("传输请求不存在或已结束"),
    "BAD_CHUNK_INDEX": N("分块序号超出文件范围"),
    "CHUNK_DIGEST_MISMATCH": N("分块校验失败"),
    "FILE_DIGEST_MISMATCH": N("文件校验失败"),
    "PATH_REJECTED": N("文件名被接收方拒绝"),
    "STORAGE_FULL": N("接收方存储空间不足"),
    "PEER_BUSY": N("对方正在处理另一个传输"),
}


def codes() -> set[str]:
    return set(_LABELS)


def describe(code: str) -> str:
    label = _LABELS.get(code)
    return _(label) if label is not None else code
