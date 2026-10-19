"""Icon loading driven by assets/icons/icons.json.

Any module can `from app import icons` and ask for an icon either by glyph name or by
the role it plays in the UI ("app", "theme", "tray", ...). Color is an argument rather
than a constant because the glyphs are re-rendered in the current palette on every
theme switch; the SVG files themselves say `currentColor` and stay valid on their own.
"""

from __future__ import annotations

import json
import logging

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication

from app.paths import icons_dir

log = logging.getLogger(__name__)

CONFIG_NAME = "icons.json"


class IconConfigError(RuntimeError):
    """The icon config is missing, unreadable, or points at a glyph that isn't declared."""


_config: dict | None = None
_svg_cache: dict[str, str] = {}
_pixmap_cache: dict[tuple[str, str, int, float], QPixmap] = {}
_icon_cache: dict[tuple[str, str], QIcon] = {}


def config() -> dict:
    """The parsed icons.json, read once and kept in memory."""
    global _config
    if _config is None:
        path = icons_dir() / CONFIG_NAME
        try:
            _config = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            log.exception("cannot read icon config: %s", path)
            raise IconConfigError(f"cannot read icon config: {path}") from None
    return _config


def glyph_names() -> list[str]:
    return sorted(config().get("glyphs", {}))


def _lookup(table: str, key: str):
    entries = config().get(table, {})
    if key not in entries:
        known = ", ".join(sorted(entries)) or "none"
        raise IconConfigError(f"{table} has no '{key}' entry (known: {known})")
    return entries[key]


def button_glyph(role: str, variant: str | None = None) -> str:
    """Glyph for a UI role. A role may map to a dict of variants with a "default" key."""
    entry = _lookup("buttons", role)
    if isinstance(entry, dict):
        return entry.get(variant or "default", entry["default"])
    return entry


def button_icon_size(role: str) -> int:
    sizes = config().get("icon_sizes", {})
    return int(sizes.get(role, config().get("default_icon_size", 24)))


def glyph_svg(name: str, color: str) -> str:
    """One glyph's SVG with the palette color substituted in."""
    filename = _lookup("glyphs", name)
    text = _svg_cache.get(name)
    if text is None:
        path = icons_dir() / filename
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            log.exception("icon file missing: %s", path)
            raise IconConfigError(f"icon file missing: {path}") from None
        _svg_cache[name] = text
    return text.replace(config().get("color_placeholder", "currentColor"), color)


def pixmap_sizes() -> tuple[int, ...]:
    """Logical sizes each QIcon carries, so Qt can pick one per DPI."""
    return tuple(config().get("pixmap_sizes", (16, 24, 32)))


def _dpr() -> float:
    app = QApplication.instance()
    if app is None:
        return 1.0
    screen = app.primaryScreen()
    return screen.devicePixelRatio() if screen else 1.0


def pixmap(name: str, color: str, size: int) -> QPixmap:
    """Rasterize one glyph at `size` logical pixels for the current DPI."""
    ratio = _dpr()
    key = (name, color, size, ratio)
    cached = _pixmap_cache.get(key)
    if cached is not None:
        return cached

    renderer = QSvgRenderer(glyph_svg(name, color).encode("utf-8"))
    if not renderer.isValid():
        raise IconConfigError(f"glyph is not valid SVG: {name}")

    pm = QPixmap(QSize(size, size) * ratio)
    pm.setDevicePixelRatio(ratio)
    pm.fill(Qt.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()

    _pixmap_cache[key] = pm
    return pm


def icon(name: str, color: str) -> QIcon:
    """Multi-resolution QIcon for a glyph name in the given color."""
    key = (name, color)
    cached = _icon_cache.get(key)
    if cached is not None:
        return QIcon(cached)

    result = QIcon()
    for size in pixmap_sizes():
        result.addPixmap(pixmap(name, color, size))
    _icon_cache[key] = result
    return result


def button_icon(role: str, color: str, variant: str | None = None) -> QIcon:
    """Icon for a UI role, honouring its size and (for theme/state buttons) variant."""
    return icon(button_glyph(role, variant), color)


def window_icon(color: str) -> QIcon:
    """The app logo, set once on QApplication so every window and dialog inherits it."""
    name = config().get("window_icon")
    if not name:
        raise IconConfigError("icons.json has no 'window_icon' entry")
    return icon(name, color)
