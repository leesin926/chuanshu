"""Per-user autostart registration.

Windows writes the HKCU Run value it has always used. Linux follows the XDG autostart
spec: one ``<name>.desktop`` file in ``~/.config/autostart``, present means enabled.

Only a packaged build can register itself: in a source checkout there is no single
executable to point at, and a Run key - or an Exec line - holding ``python -m app`` would
depend on a working directory that neither mechanism can express.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from app.meta import APP_NAME, APP_TITLE_ZH
from app.paths import autostart_desktop_path, is_frozen

log = logging.getLogger(__name__)

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def is_supported() -> bool:
    return sys.platform in ("win32", "linux") and is_frozen()


def launch_command() -> str:
    return f'"{sys.executable}"'


def is_enabled() -> bool:
    if not is_supported():
        return False
    if sys.platform == "win32":
        return _windows_enabled()
    return _desktop_enabled()


def set_enabled(enabled: bool) -> bool:
    """Apply the setting; returns whether the machine now matches the request."""
    if not is_supported():
        log.info("autostart ignored: needs a packaged build (frozen=%s, platform=%s)", is_frozen(), sys.platform)
        return False
    if sys.platform == "win32":
        ok = _windows_set(enabled)
    else:
        ok = _desktop_set(enabled)
    if ok:
        log.info("autostart %s for %s", "enabled" if enabled else "disabled", APP_NAME)
    return ok


# ------------------------------------------------------------------ Windows

def _windows_enabled() -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
        return value == launch_command()
    except OSError:
        return False


def _windows_set(enabled: bool) -> bool:
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
        ) as key:
            if enabled:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, launch_command())
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
        return is_enabled() == enabled
    except OSError:
        log.exception("failed to update the autostart registry key")
        return False


# ------------------------------------------------------------------ Linux

def desktop_file_text() -> str:
    """The XDG autostart entry. ``X-GNOME-Autostart-enabled`` is what GNOME reads back;
    the file's presence is what every other desktop uses, so disabling deletes it."""
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_TITLE_ZH} ({APP_NAME})\n"
        f"Exec={launch_command()}\n"
        "Terminal=false\n"
        "Comment=局域网文件互传\n"
        "X-GNOME-Autostart-enabled=true\n"
    )


def _desktop_enabled() -> bool:
    path = autostart_desktop_path()
    try:
        return path.is_file() and f"Exec={launch_command()}" in path.read_text(encoding="utf-8")
    except OSError:
        log.exception("failed to read the autostart entry: %s", path)
        return False


def _desktop_set(enabled: bool) -> bool:
    path = autostart_desktop_path()
    try:
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(desktop_file_text(), encoding="utf-8")
        elif path.is_file():
            path.unlink()
        return _desktop_enabled() == enabled
    except OSError:
        log.exception("failed to update the autostart entry: %s", path)
        return False
