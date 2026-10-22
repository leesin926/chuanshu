"""User settings persisted as JSON under the per-user data directory."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app import paths
from app.paths import user_data_dir

log = logging.getLogger(__name__)

#: Values stored in settings.json for the question "what happens when you close the window".
CLOSE_ASK, CLOSE_TRAY, CLOSE_QUIT = "ask", "tray", "quit"

DEFAULTS: dict = {
    # "auto" follows the system locale; otherwise a locale code such as "en".
    "language": "auto",
    # "auto" follows the Windows app theme; otherwise "light" or "dark".
    "theme": "auto",
    "on_close": CLOSE_ASK,
    "autostart": False,
    # Empty means <data dir>/received; set it to move incoming files.
    "receive_dir": "",
    # 传输限速: how fast this machine pushes files out. The switch and the number are kept apart
    # so turning it back on restores the rate the user last chose.
    "limit_on": False,
    "limit_mbps": 10,
    # 通知: a tray message when a transfer lands, so a minimized window still says it happened.
    "notify": True,
    # The size the four-page design is drawn for. A saved window is clamped up to the layout's
    # own minimum when the window opens, so this is a starting size, not a floor.
    "window": {"width": 1080, "height": 680},
}


class Settings:
    def __init__(self) -> None:
        self._path: Path = user_data_dir() / "settings.json"
        self._data: dict = dict(DEFAULTS)
        self.load()

    @property
    def path(self) -> Path:
        return self._path

    def get(self, key: str, default=None):
        return self._data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value) -> None:
        self._data[key] = value
        self.save()
        self._apply()

    def load(self) -> None:
        try:
            # utf-8-sig: Notepad adds a BOM when a user hand-edits the file.
            stored = json.loads(self._path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            log.exception("settings.json unreadable, falling back to defaults: %s", self._path)
            return
        if isinstance(stored, dict):
            self._data.update(stored)
        self._apply()

    def _apply(self) -> None:
        """Push the values that are read deep inside the app into the modules owning them.

        Doing it here means every entry point - main.py, a selftest, a hand-built Settings -
        gets the same filesystem, instead of only the one that remembered to ask.
        """
        paths.set_receive_root(self._data.get("receive_dir") or None)

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            log.exception("failed to write settings: %s", self._path)
