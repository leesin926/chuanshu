"""Runtime path resolution for both source checkout and frozen (PyInstaller) builds."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from app.meta import APP_NAME, ORG_NAME

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def resource_path(*relative: str) -> Path:
    """Path to a file bundled with the app (PyInstaller puts these in sys._MEIPASS)."""
    base = Path(getattr(sys, "_MEIPASS", _PROJECT_ROOT))
    return base.joinpath(*relative)


def locale_dir() -> Path:
    return resource_path("locale")


def icons_dir() -> Path:
    """Glyph SVGs plus icons.json, read by app/icons.py."""
    return resource_path("assets", "icons")


def protocol_dir() -> Path:
    """protocol.json plus spec.md, read by app/net/spec.py."""
    return resource_path("protocol")


def identity_dir() -> Path:
    """peer_id, keypair and the list of pinned peers."""
    return user_data_dir() / "identity"


#: Set by Settings so the whole app agrees on one folder without every caller having to
#: carry a config object - receive.py, the panel and the settings window all read this.
_receive_root: Path | None = None


def receive_root() -> Path:
    """Parent of the per-offer folders that incoming files land in."""
    return _receive_root if _receive_root is not None else user_data_dir() / "received"


def set_receive_root(path: str | Path | None) -> None:
    """Send incoming files somewhere else, or back to the default with ``None``."""
    global _receive_root
    _receive_root = Path(path).expanduser() if path else None


def user_data_dir() -> Path:
    """Writable per-user directory for settings and logs."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / ORG_NAME / APP_NAME


def logs_dir() -> Path:
    return user_data_dir() / "logs"


def autostart_desktop_path() -> Path:
    """The XDG autostart entry on Linux: ``$XDG_CONFIG_HOME`` or ``~/.config``, per spec.

    Windows has no equivalent file - it uses a registry value - so this is only asked for
    from the Linux branch of app/autostart.py.
    """
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "autostart" / f"{APP_NAME}.desktop"
