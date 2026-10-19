"""User settings persisted as JSON under the per-user data directory."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.paths import user_data_dir

log = logging.getLogger(__name__)

DEFAULTS: dict = {
    # "auto" follows the system locale; otherwise a locale code such as "en".
    "language": "auto",
    # "auto" follows the Windows app theme; otherwise "light" or "dark".
    "theme": "auto",
    # What the close button does: "ask" prompts, "tray" hides, "quit" exits.
    "on_close": "ask",
    "autostart": False,
    "window": {"width": 720, "height": 480},
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

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            log.exception("failed to write settings: %s", self._path)
