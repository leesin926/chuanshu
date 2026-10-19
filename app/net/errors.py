"""Localized text for protocol error codes.

protocol/protocol.json owns the codes and their Chinese msgids; the literals below
exist so Babel can extract them, and scripts/protocol_selftest.py asserts the two
sets stay identical. Do not add a code in one place only.
"""

from __future__ import annotations

from app.i18n import _

_LABELS = {
    "UNSUPPORTED_PROTOCOL": _("对端版本不兼容"),
    "NOT_PAIRED": _("尚未与这台设备配对"),
    "BAD_PAIR_CODE": _("配对码不正确或已过期"),
    "DECLINED": _("对方拒绝了这次传输"),
    "OFFER_UNKNOWN": _("传输请求不存在或已结束"),
    "BAD_CHUNK_INDEX": _("分块序号超出文件范围"),
    "CHUNK_DIGEST_MISMATCH": _("分块校验失败"),
    "FILE_DIGEST_MISMATCH": _("文件校验失败"),
    "PATH_REJECTED": _("文件名被接收方拒绝"),
    "STORAGE_FULL": _("接收方存储空间不足"),
    "PEER_BUSY": _("对方正在处理另一个传输"),
}


def codes() -> set[str]:
    return set(_LABELS)


def describe(code: str) -> str:
    return _LABELS.get(code, code)
